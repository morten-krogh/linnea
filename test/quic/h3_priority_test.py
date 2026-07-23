#!/usr/bin/env python3
# RFC 9218 response prioritisation. With the default priority (non-incremental,
# urgency 3), the server serves concurrent large responses to completion in
# ARRIVAL order rather than interleaving them all at once — so a page's images
# arrive one at a time, usable sooner. A request that signals a higher urgency
# (priority: u=0) jumps the queue. This drives the real thing lossless (so order
# is deterministic):
#   1. four large files requested at once, no priority -> they FIN in request
#      order, and when the first finishes the last has not even started (proof of
#      sequential, not round-robin, scheduling);
#   2. a fifth file requested LAST but with u=0 completes before the default ones.
# Usage: h3_priority_test.py <port>
import os
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

port = int(sys.argv[1])
here = os.path.dirname(__file__)

FILES = []
for i in range(5):
    n = 300000 + i * 20000
    body = bytes((j * (97 + i) + (j >> 8) * 13 + i) & 0xFF for j in range(n))
    name = f"h3p{i}.bin"
    with open(os.path.join(here, "..", "www", name), "wb") as f:
        f.write(body)
    FILES.append((name.encode(), body))


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def rvlq(b, i):
    k = 1 << (b[i] >> 6)
    v = b[i] & 0x3F
    for j in range(1, k):
        v = (v << 8) | b[i + j]
    return v, i + k


def parse_h3(stream):
    frames, i = [], 0
    while i < len(stream):
        ty, i = rvlq(stream, i)
        ln, i = rvlq(stream, i)
        frames.append((ty, stream[i:i + ln]))
        i += ln
    hdr = next((p for ty, p in frames if ty == 1), None)
    data = b"".join(p for ty, p in frames if ty == 0)
    st = None
    if hdr is not None:
        dec = pylsqpack.Decoder(0, 0)
        _, h = dec.feed_header(0, hdr)
        st = dict(h).get(b":status")
    return st, data


def get(conn, sid, path, priority=None):
    fields = [(b":method", b"GET"), (b":path", b"/" + path),
              (b":scheme", b"https"), (b":authority", b"localhost")]
    if priority is not None:
        fields.append((b"priority", priority))
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, f = enc.encode(0, fields)
    conn.send_stream_data(sid, vlq(1) + vlq(len(f)) + f, end_stream=True)


def connect():
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    vt = [0.0]

    def clk():
        vt[0] += 0.02
        return vt[0]

    conn.connect(("127.0.0.1", port), now=clk())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.3)

    def flush():
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ("127.0.0.1", port))

    flush()
    while not conn._handshake_confirmed:
        try:
            r, _ = s.recvfrom(4096)
            conn.receive_datagram(r, ("127.0.0.1", port), now=clk())
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
    while conn.next_event():
        pass
    return conn, s, clk, flush


def run(conn, s, clk, flush, order):
    # order: list of (name, priority). Returns fin order (names) and, at the moment
    # the FIRST stream finishes, the byte counts of every stream.
    sids = {}
    got = {}
    for name, prio in order:
        sid = conn.get_next_available_stream_id()
        get(conn, sid, name, prio)
        sids[sid] = name
        got[sid] = [b"", False]
    fin_order = []
    snapshot = None
    deadline = time.time() + 40
    while time.time() < deadline and not all(v[1] for v in got.values()):
        flush()
        try:
            r, _ = s.recvfrom(4096)
        except socket.timeout:
            conn.handle_timer(now=clk())
            continue
        conn.receive_datagram(r, ("127.0.0.1", port), now=clk())
        ev = conn.next_event()
        while ev:
            if isinstance(ev, StreamDataReceived) and ev.stream_id in got:
                got[ev.stream_id][0] += ev.data
                if ev.end_stream and not got[ev.stream_id][1]:
                    got[ev.stream_id][1] = True
                    if not fin_order:
                        snapshot = {sids[k]: len(v[0]) for k, v in got.items()}
                    fin_order.append(sids[ev.stream_id])
            ev = conn.next_event()
    # verify bodies intact
    for sid, name in sids.items():
        body = dict((n, b) for n, b in FILES)[name]
        st, data = parse_h3(got[sid][0])
        assert st == b"200" and data == body, f"{name.decode()} corrupt/incomplete"
    return fin_order, snapshot


# --- 1: four default-priority files complete in request order, sequentially ---
conn, s, clk, flush = connect()
order = [(FILES[i][0], None) for i in range(4)]
fin_order, snapshot = run(conn, s, clk, flush, order)
names = [FILES[i][0] for i in range(4)]
assert fin_order == names, f"not sequential by arrival: {[n.decode() for n in fin_order]}"
# when the first finished, the last-requested had barely started (sequential, not
# round-robin, which would have fed them all roughly equally)
first, last = names[0], names[-1]
assert snapshot[last] * 4 < snapshot[first], \
    f"scheduling looks concurrent, not sequential: {snapshot}"
conn.close()
for d, _ in conn.datagrams_to_send(now=clk()):
    s.sendto(d, ("127.0.0.1", port))
s.close()

# --- 2: a file requested LAST but with u=0 jumps ahead of default-urgency ones ---
conn, s, clk, flush = connect()
order = [(FILES[0][0], None), (FILES[1][0], None), (FILES[2][0], b"u=0")]
fin_order, _ = run(conn, s, clk, flush, order)
assert fin_order[0] == FILES[2][0], \
    f"urgent stream did not finish first: {[n.decode() for n in fin_order]}"
conn.close()
for d, _ in conn.datagrams_to_send(now=clk()):
    s.sendto(d, ("127.0.0.1", port))
s.close()
print("ok")
