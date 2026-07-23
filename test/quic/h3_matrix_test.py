#!/usr/bin/env python3
# Exercise the h3 response path across sizes, boundaries and request styles, each
# of which must terminate (deliver a FIN) — a request that never finishes is the
# bug this hunts. Covers the inline/chunked threshold and exact chunk multiples
# (where off-by-one stalls hide), 0- and 1-byte bodies, HEAD, and both sequential
# reuse on one connection and all-at-once concurrency under the priority
# scheduler. Every request has a hard per-run deadline; a body that never FINs is
# reported as a HANG rather than hanging the test.
# Usage: h3_matrix_test.py <port>
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

# sizes around the inline/chunked threshold and exact chunk (1100) multiples
SIZES = [0, 1, 100, 1000, 1023, 1024, 1025, 1099, 1100, 1101,
         2199, 2200, 2201, 3300, 5500, 50000, 200000]
FILES = {}
for n in SIZES:
    body = bytes((i * 73 + (i >> 8) * 19 + 5) & 0xFF for i in range(n))
    name = f"m{n}.bin"
    with open(os.path.join(here, "..", "www", name), "wb") as f:
        f.write(body)
    FILES[n] = (name.encode(), body)


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


def request(conn, sid, path, method=b"GET", priority=None):
    fields = [(b":method", method), (b":path", b"/" + path),
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


def drive(conn, s, clk, flush, streams, timeout=20):
    # streams: sid -> [accumulated, fin]; pump until all FIN or timeout
    deadline = time.time() + timeout
    while time.time() < deadline and not all(v[1] for v in streams.values()):
        flush()
        try:
            r, _ = s.recvfrom(4096)
        except socket.timeout:
            conn.handle_timer(now=clk())
            continue
        conn.receive_datagram(r, ("127.0.0.1", port), now=clk())
        ev = conn.next_event()
        while ev:
            if isinstance(ev, StreamDataReceived) and ev.stream_id in streams:
                streams[ev.stream_id][0] += ev.data
                streams[ev.stream_id][1] = streams[ev.stream_id][1] or ev.end_stream
            ev = conn.next_event()
    return all(v[1] for v in streams.values())


fails = []

# --- 1: each size on its own, sequentially reusing one connection ---
conn, s, clk, flush = connect()
for n in SIZES:
    name, body = FILES[n]
    sid = conn.get_next_available_stream_id()
    request(conn, sid, name)
    streams = {sid: [b"", False]}
    if not drive(conn, s, clk, flush, streams, timeout=20):
        fails.append(f"GET {n}B never finished (sequential)")
        continue
    st, data = parse_h3(streams[sid][0])
    if st != b"200" or data != body:
        fails.append(f"GET {n}B wrong: status={st} got={len(data)} want={n}")
# HEAD on a large file: headers only, must FIN
sid = conn.get_next_available_stream_id()
request(conn, sid, FILES[200000][0], method=b"HEAD")
streams = {sid: [b"", False]}
if not drive(conn, s, clk, flush, streams, timeout=15):
    fails.append("HEAD never finished")
else:
    st, data = parse_h3(streams[sid][0])
    if st != b"200" or data != b"":
        fails.append(f"HEAD wrong: status={st} body={len(data)}")
conn.close()
for d, _ in conn.datagrams_to_send(now=clk()):
    s.sendto(d, ("127.0.0.1", port))
s.close()

# --- 2: all sizes at once (concurrent), mixed priorities incl. incremental ---
conn, s, clk, flush = connect()
streams, want = {}, {}
for idx, n in enumerate(SIZES):
    name, body = FILES[n]
    sid = conn.get_next_available_stream_id()
    prio = [None, b"u=0", b"u=7", b"u=3, i", b"i"][idx % 5]
    request(conn, sid, name, priority=prio)
    streams[sid] = [b"", False]
    want[sid] = (n, body)
if not drive(conn, s, clk, flush, streams, timeout=40):
    for sid, v in streams.items():
        if not v[1]:
            fails.append(f"concurrent {want[sid][0]}B never finished")
else:
    for sid, (n, body) in want.items():
        st, data = parse_h3(streams[sid][0])
        if st != b"200" or data != body:
            fails.append(f"concurrent {n}B wrong: status={st} got={len(data)}")
conn.close()
for d, _ in conn.datagrams_to_send(now=clk()):
    s.sendto(d, ("127.0.0.1", port))
s.close()

if fails:
    for f in fails:
        print("FAIL:", f)
    sys.exit(1)
print(f"ok ({len(SIZES)} sizes x sequential + concurrent, HEAD)")
