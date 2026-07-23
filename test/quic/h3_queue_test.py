#!/usr/bin/env python3
# Several large (chunked) responses requested concurrently on one h3 connection.
# Every response streams at once, interleaved chunk by chunk by the server's pump
# over the shared congestion window — none is refused. Before concurrent response
# streams, a browser firing a full page load (html + css + a chunked favicon + a
# 600 KB image, all at once) got a 503 on whichever large request arrived while
# another chunked response was mid-flight, and gave up on h3. This drives the real
# thing: request FOUR differently-sized, differently-patterned large files at the
# same time and require ALL to arrive intact, byte-exact, none swapped. Four is
# past what any depth-1 hold could serve, so it exercises real multiplexing.
# Usage: h3_queue_test.py <port>
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

# four large fixtures, distinct sizes and patterns so a reorder/swap is caught
FILES = []
for idx, (name, n, a, b, c) in enumerate((
        ("h3big.bin", 600000, 131, 17, 7),
        ("h3big2.bin", 400000, 61, 29, 3),
        ("h3big3.bin", 500000, 97, 13, 11),
        ("h3big4.bin", 300000, 53, 23, 5))):
    body = bytes((i * a + (i >> 8) * b + c) & 0xFF for i in range(n))
    with open(os.path.join(here, "..", "www", name), "wb") as f:
        f.write(body)
    FILES.append((name, body))


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def rvlq(b, i):
    n = 1 << (b[i] >> 6)
    v = b[i] & 0x3F
    for k in range(1, n):
        v = (v << 8) | b[i + k]
    return v, i + n


def parse_h3(stream):
    frames = []
    i = 0
    while i < len(stream):
        ty, i = rvlq(stream, i)
        ln, i = rvlq(stream, i)
        frames.append((ty, stream[i:i + ln]))
        i += ln
    hdr = next(p for ty, p in frames if ty == 1)
    data = b"".join(p for ty, p in frames if ty == 0)
    dec = pylsqpack.Decoder(0, 0)
    _, headers = dec.feed_header(0, hdr)
    return dict(headers), data


def get(conn, stream_id, path):
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"GET"), (b":path", path),
                               (b":scheme", b"https"), (b":authority", b"h3.test")])
    conn.send_stream_data(stream_id, vlq(1) + vlq(len(fields)) + fields,
                          end_stream=True)


vt = [0.0]


def clk():
    vt[0] += 0.02
    return vt[0]


cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
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
while conn.next_event() is not None:
    pass

# fire ALL large requests at once — every one must stream, none refused
want = {}                             # stream id -> expected body
streams = {}                          # stream id -> [accumulated, fin]
for name, body in FILES:
    sid = conn.get_next_available_stream_id()
    get(conn, sid, b"/" + name.encode())
    want[sid] = body
    streams[sid] = [b"", False]

deadline = time.time() + 90
while time.time() < deadline and not all(v[1] for v in streams.values()):
    flush()
    try:
        r, _ = s.recvfrom(4096)
    except socket.timeout:
        conn.handle_timer(now=clk())
        continue
    conn.receive_datagram(r, ("127.0.0.1", port), now=clk())
    ev = conn.next_event()
    while ev is not None:
        if isinstance(ev, StreamDataReceived) and ev.stream_id in streams:
            streams[ev.stream_id][0] += ev.data
            streams[ev.stream_id][1] = streams[ev.stream_id][1] or ev.end_stream
        ev = conn.next_event()

for sid, want_body in want.items():
    assert streams[sid][1], f"stream {sid} never completed (refused with 503?)"
    hd, data = parse_h3(streams[sid][0])
    assert hd.get(b":status") == b"200", hd
    assert hd.get(b"content-length") == str(len(want_body)).encode(), hd
    assert data == want_body, f"stream {sid} body corrupted/swapped"

conn.close()
for d, _ in conn.datagrams_to_send(now=clk()):
    s.sendto(d, ("127.0.0.1", port))
s.close()
print("ok")
