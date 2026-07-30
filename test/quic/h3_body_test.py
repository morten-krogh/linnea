#!/usr/bin/env python3
# A request body over HTTP/3 is still received whole, even now that nothing
# serves from it. POST used to be echoed back, which was how this test observed
# the body; POST is a 405 now (a static file does not take one, as h1 and h2 have
# always said), so what is checked here is what survives that:
#
#   - a body spanning several QUIC packets is reassembled and the request is
#     ANSWERED rather than left to stall or reset;
#   - the connection keeps serving afterwards, so the stream's flow-control
#     credit was settled rather than stranded;
#   - several large bodies in a row behave the same, so nothing accumulates.
#
# Byte-exactness moved to where it can still be seen: h3_test.py drives
# linnea_h3_read_headers directly through bin/linnea-h3test, which prints the
# recovered body — including a 900-byte body split across nine DATA frames,
# which is the split-DATA join this file used to cover end to end.
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


def post(body, chunk=0):
    """Send a POST with that body; return its :status."""
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"POST"), (b":path", b"/submit"),
                               (b":scheme", b"https"), (b":authority", b"h3.test")])
    # a HEADERS frame followed by the DATA frames carrying the body; a large
    # body's DATA frame is split by QUIC across several packets, which the server
    # must reassemble in offset order before it can decode the request. With
    # chunk set, the body is split across that many DATA frames instead of one.
    pieces = [body] if not chunk else [body[i:i + chunk]
                                       for i in range(0, len(body), chunk)]
    data = b"".join(vlq(0) + vlq(len(p)) + p for p in pieces)
    stream = vlq(1) + vlq(len(fields)) + fields + data
    bidi = conn.get_next_available_stream_id()
    conn.send_stream_data(bidi, stream, end_stream=True)
    return await_status(bidi)


def get(path):
    """A plain GET, to prove the connection still serves."""
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"GET"), (b":path", path),
                               (b":scheme", b"https"), (b":authority", b"h3.test")])
    bidi = conn.get_next_available_stream_id()
    conn.send_stream_data(bidi, vlq(1) + vlq(len(fields)) + fields, end_stream=True)
    return await_status(bidi)


def await_status(bidi):
    # aioquic paces sending, so a single flush releases only part of a large
    # body; flush with an advancing clock until the whole request is out and the
    # response comes back.
    resp = b""
    s.settimeout(0.3)
    deadline = time.time() + 8
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
    i = 0
    while i < len(resp):
        ty, i = rvlq(resp, i)
        ln, i = rvlq(resp, i)
        if ty == 1:
            _, headers = pylsqpack.Decoder(0, 0).feed_header(0, resp[i:i + ln])
            return dict(headers).get(b":status", b"?").decode()
        i += ln
    return "no reply"


# a small body arrives in one packet (the fast path)
assert post(b"linnea receives this body over http/3") == "405", "small body"

# a body large enough to span several QUIC packets exercises reassembly: the
# request must be ANSWERED, which it can only be once the whole stream arrived
big = bytes((i * 37 + 11) & 0xFF for i in range(2600))
assert post(big) == "405", "multi-packet body"

# the same body split across many DATA frames, which the frame walk joins
assert post(big, chunk=64) == "405", "split across DATA frames"

# and the connection is still healthy: the credit those bodies consumed was
# settled, not stranded
assert get(b"/hello.txt") == "200", "connection stopped serving after the bodies"

# several large bodies in a row, to be sure nothing accumulates
for _ in range(4):
    assert post(big, chunk=200) == "405", "repeated large body"
assert get(b"/hello.txt") == "200", "connection stopped serving after repeats"

s.close()
print("ok")
