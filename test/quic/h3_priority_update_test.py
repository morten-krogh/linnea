#!/usr/bin/env python3
# RFC 9218 PRIORITY_UPDATE. The `priority` header field only says what a request
# was born with; PRIORITY_UPDATE is how a client changes its mind afterwards —
# a browser promoting the image that just scrolled into view. linnea used to
# discard the frame as an unknown type, so a stream kept its arrival priority
# for life. It now reads it off the control stream and reprioritises.
#
# Ordering is observed the way h3_priority_test does it: drive the connection
# lossless so the scheduler is deterministic, request several large files, and
# watch which one FINs first. With the default priority the server runs them to
# completion in arrival order, so a later file finishing first can only be the
# reprioritisation taking effect.
#
# Two paths matter and are both covered: an update for a response already
# streaming, and one that OVERTAKES the request it names — the control stream
# and the request stream are independent, so that reordering is real, and RFC
# 9218 7 asks for the signal to be kept and applied when the stream opens.
# Usage: h3_priority_update_test.py <port>
import os
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived

PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)
here = os.path.dirname(__file__)

FILES = []
for i in range(3):
    n = 300000 + i * 20000
    body = bytes((j * (89 + i) + (j >> 8) * 7 + i) & 0xFF for j in range(n))
    name = f"h3pu{i}.bin"
    with open(os.path.join(here, "..", "www", name), "wb") as f:
        f.write(body)
    FILES.append((name.encode(), body))
BODIES = dict(FILES)


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    if n < 1073741824:
        return (0x80000000 | n).to_bytes(4, "big")
    return (0xC000000000000000 | n).to_bytes(8, "big")


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
        _, h = pylsqpack.Decoder(0, 0).feed_header(0, hdr)
        st = dict(h).get(b":status")
    return st, data


def priority_update(sid, value, push=False):
    """A PRIORITY_UPDATE frame as it appears on the control stream."""
    payload = vlq(sid) + value
    ty = 0xF0701 if push else 0xF0700
    return vlq(ty) + vlq(len(payload)) + payload


def get(conn, sid, path, priority=None):
    fields = [(b":method", b"GET"), (b":path", b"/" + path),
              (b":scheme", b"https"), (b":authority", b"localhost")]
    if priority is not None:
        fields.append((b"priority", priority))
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, f = enc.encode(0, fields)
    conn.send_stream_data(sid, vlq(1) + vlq(len(f)) + f, end_stream=True)


def connect(control=True):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    vt = [0.0]

    def clk():
        vt[0] += 0.02
        return vt[0]

    conn.connect(ADDR, now=clk())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.3)

    def flush():
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ADDR)

    flush()
    while not conn._handshake_confirmed:
        try:
            r, _ = s.recvfrom(4096)
            conn.receive_datagram(r, ADDR, now=clk())
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
    while conn.next_event():
        pass
    ctrl = None
    if control:
        ctrl = conn.get_next_available_stream_id(is_unidirectional=True)
        conn.send_stream_data(ctrl, b"\x00\x04\x00")   # control type + SETTINGS
        flush()
    return conn, s, clk, flush, ctrl


def drive(conn, s, clk, flush, sids, on_bytes=None):
    """Pump to completion. on_bytes(total) is called after each datagram until it
    returns True, which is how an update is injected mid-transfer."""
    got = {sid: [b"", False] for sid in sids}
    fin_order, fired = [], on_bytes is None
    deadline = time.time() + 60
    while time.time() < deadline and not all(v[1] for v in got.values()):
        flush()
        try:
            r, _ = s.recvfrom(4096)
        except socket.timeout:
            conn.handle_timer(now=clk())
            continue
        conn.receive_datagram(r, ADDR, now=clk())
        ev = conn.next_event()
        while ev:
            if isinstance(ev, StreamDataReceived) and ev.stream_id in got:
                got[ev.stream_id][0] += ev.data
                if ev.end_stream and not got[ev.stream_id][1]:
                    got[ev.stream_id][1] = True
                    fin_order.append(sids[ev.stream_id])
            ev = conn.next_event()
        if not fired:
            fired = on_bytes(sum(len(v[0]) for v in got.values()))
            flush()
    for sid, name in sids.items():
        st, data = parse_h3(got[sid][0])
        assert st == b"200" and data == BODIES[name], \
            f"{name.decode()} corrupt or incomplete ({len(data)}B)"
    return fin_order


fails = 0


def report(label, ok, detail):
    global fails
    print(f"{'ok  ' if ok else 'FAIL'} {label}: {detail}")
    fails += not ok


# --- 1: reprioritise a response that is already streaming --------------------
# Three files at the default priority serve to completion in arrival order. Once
# the transfer is under way, promote the LAST one to u=0; it must then finish
# first, which it could not do without the update being read and applied.
conn, s, clk, flush, ctrl = connect()
sids = {}
for name, _ in FILES:
    sid = conn.get_next_available_stream_id()
    get(conn, sid, name)
    sids[sid] = name
last_sid = sid
flush()


def promote(total):
    if total < 40000:
        return False
    conn.send_stream_data(ctrl, priority_update(last_sid, b"u=0"))
    return True


order = drive(conn, s, clk, flush, sids, on_bytes=promote)
report("PRIORITY_UPDATE promotes a streaming response",
       order[0] == FILES[2][0],
       f"fin order {[n.decode() for n in order]}")
s.close()

# --- 2: an update that overtakes the request it names ------------------------
# Sent BEFORE the request exists, so it lands with no response slot to apply to
# and has to be remembered. The stream is then requested LAST and with no
# priority header at all, so finishing first can only come from the kept signal.
conn, s, clk, flush, ctrl = connect()
base = conn.get_next_available_stream_id()
target = base + 8                                  # the third client bidi stream
conn.send_stream_data(ctrl, priority_update(target, b"u=0"))
flush()
sids = {}
for name, _ in FILES:
    sid = conn.get_next_available_stream_id()
    get(conn, sid, name)
    sids[sid] = name
assert sid == target, f"stream id prediction wrong: {sid} != {target}"
flush()
order = drive(conn, s, clk, flush, sids)
report("PRIORITY_UPDATE ahead of its request is remembered",
       order[0] == FILES[2][0],
       f"fin order {[n.decode() for n in order]}")
s.close()

# --- 3: the same, with the frame split across two STREAM frames --------------
conn, s, clk, flush, ctrl = connect()
base = conn.get_next_available_stream_id()
target = base + 8
frame = priority_update(target, b"u=0, i")
conn.send_stream_data(ctrl, frame[:3])
flush()
conn.send_stream_data(ctrl, frame[3:])
flush()
sids = {}
for name, _ in FILES:
    sid = conn.get_next_available_stream_id()
    get(conn, sid, name)
    sids[sid] = name
flush()
order = drive(conn, s, clk, flush, sids)
report("PRIORITY_UPDATE split across STREAM frames",
       order[0] == FILES[2][0],
       f"fin order {[n.decode() for n in order]}")
s.close()


# --- 4: the ids a PRIORITY_UPDATE may not name -------------------------------
def close_code(send):
    conn, s, clk, flush, ctrl = connect()
    send(conn, ctrl)
    flush()
    s.settimeout(0.5)
    try:
        for _ in range(6):
            r, _ = s.recvfrom(4096)
            conn.receive_datagram(r, ADDR, now=clk())
            if conn._close_event is not None:
                break
    except socket.timeout:
        pass
    ev = conn._close_event
    s.close()
    return ev.error_code if isinstance(ev, ConnectionTerminated) else None


# id 3 is a server-initiated unidirectional stream, not a request
code = close_code(lambda c, ctrl: c.send_stream_data(
    ctrl, priority_update(3, b"u=0")))
report("non-request element id is H3_ID_ERROR", code == 0x108,
       f"close={code and hex(code)}")

# we never promise a push, so no push id can be valid
code = close_code(lambda c, ctrl: c.send_stream_data(
    ctrl, priority_update(0, b"u=0", push=True)))
report("push element id is H3_ID_ERROR", code == 0x108,
       f"close={code and hex(code)}")

# and the frame belongs on the control stream and nowhere else
def on_request_stream(c, ctrl):
    sid = c.get_next_available_stream_id()
    c.send_stream_data(sid, priority_update(sid, b"u=0"), end_stream=True)


code = close_code(on_request_stream)
report("PRIORITY_UPDATE on a request stream is H3_FRAME_UNEXPECTED",
       code == 0x105, f"close={code and hex(code)}")

for name, _ in FILES:
    try:
        os.remove(os.path.join(here, "..", "www", name.decode()))
    except OSError:
        pass
if fails:
    sys.exit(1)
print("ok")
