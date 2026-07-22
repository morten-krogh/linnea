#!/usr/bin/env python3
# HTTP/3 request bodies. A request body arrives in DATA frames after the HEADERS
# frame; linnea now captures it rather than discarding it. A POST echoes its body
# back, which proves the body was read intact — we send a POST with a body and
# check the 200 response echoes exactly those bytes. (A GET on the same path
# still serves static files, unchanged.)
# Usage: h3_body_test.py <port>
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived


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


port = int(sys.argv[1])
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
conn.connect(("127.0.0.1", port), now=0.0)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)


def flush(t):
    for d, _ in conn.datagrams_to_send(now=t):
        s.sendto(d, ("127.0.0.1", port))


flush(0.0)
r, _ = s.recvfrom(4096)
conn.receive_datagram(r, ("127.0.0.1", port), now=0.1)
flush(0.2)
r, _ = s.recvfrom(4096)
conn.receive_datagram(r, ("127.0.0.1", port), now=0.3)
assert conn._handshake_confirmed, "handshake not confirmed"
while conn.next_event() is not None:
    pass

clock = [0.4]   # a monotonic clock shared across requests, for aioquic's pacer


def post_echo(body):
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"POST"), (b":path", b"/submit"),
                               (b":scheme", b"https"), (b":authority", b"h3.test")])
    # a HEADERS frame followed by a DATA frame carrying the body; a large body's
    # DATA frame is split by QUIC across several packets, which the server must
    # reassemble in offset order before it can decode the request.
    stream = vlq(1) + vlq(len(fields)) + fields + vlq(0) + vlq(len(body)) + body
    bidi = conn.get_next_available_stream_id()
    conn.send_stream_data(bidi, stream, end_stream=True)
    # aioquic paces sending, so a single flush releases only part of a large
    # body; flush with an advancing clock until the whole request is out and the
    # response comes back.
    resp = b""
    s.settimeout(0.3)
    deadline = time.time() + 5
    while not resp and time.time() < deadline:
        for d, _ in conn.datagrams_to_send(now=clock[0]):
            s.sendto(d, ("127.0.0.1", port))
        clock[0] += 0.2
        try:
            r, _ = s.recvfrom(4096)
        except socket.timeout:
            continue
        conn.receive_datagram(r, ("127.0.0.1", port), now=clock[0])
        ev = conn.next_event()
        while ev is not None:
            if isinstance(ev, StreamDataReceived) and ev.stream_id == bidi:
                resp += ev.data
            ev = conn.next_event()
    frames = []
    i = 0
    while i < len(resp):
        ty, i = rvlq(resp, i)
        ln, i = rvlq(resp, i)
        frames.append((ty, resp[i:i + ln]))
        i += ln
    hdr = next(p for ty, p in frames if ty == 1)
    data = next((p for ty, p in frames if ty == 0), b"")
    dec = pylsqpack.Decoder(0, 0)
    _, headers = dec.feed_header(0, hdr)
    return dict(headers), data


# a small body arrives in one packet (the fast path)
hd, data = post_echo(b"linnea echoes this body over http/3")
assert hd.get(b":status") == b"200", hd
assert data == b"linnea echoes this body over http/3", data

# a body large enough to span several QUIC packets exercises reassembly. Its
# echo would not fit one response packet, so the server returns a receipt: the
# length and a position-sensitive rolling hash (h = h*31 + byte, 32-bit), which
# only comes out right if every byte reassembled in the correct order.
big = bytes((i * 37 + 11) & 0xFF for i in range(2600))
h = 0
for byte in big:
    h = (h * 31 + byte) & 0xFFFFFFFF
hd, data = post_echo(big)
assert hd.get(b":status") == b"200", hd
assert data == f"{len(big)} {h}".encode(), f"receipt {data!r}, want {len(big)} {h}"
s.close()
print("ok")
