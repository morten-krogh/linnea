#!/usr/bin/env python3
# End-to-end HTTP/3 over QUIC against linnea. Complete the handshake, send an
# HTTP/3 GET on a request stream (an HEADERS frame with a pylsqpack-encoded
# field section), and check linnea replies on the same stream with a HEADERS +
# DATA response that decodes to 200 / text/plain and the expected body.
# Usage: h3_e2e_test.py <port>
import socket
import ssl
import sys

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
flush(0.2)                                       # client Finished
r, _ = s.recvfrom(4096)
conn.receive_datagram(r, ("127.0.0.1", port), now=0.3)   # HANDSHAKE_DONE
assert conn._handshake_confirmed
while conn.next_event() is not None:
    pass

# HTTP/3 GET on request stream 0: a HEADERS frame wrapping a QPACK field section
enc = pylsqpack.Encoder()
enc.apply_settings(max_table_capacity=0, blocked_streams=0)
_, fields = enc.encode(0, [(b":method", b"GET"), (b":path", b"/"),
                           (b":scheme", b"https"), (b":authority", b"h3.test")])
conn.send_stream_data(0, vlq(1) + vlq(len(fields)) + fields, end_stream=True)
flush(0.4)

r, _ = s.recvfrom(4096)
conn.receive_datagram(r, ("127.0.0.1", port), now=0.5)
resp = b""
ev = conn.next_event()
while ev is not None:
    if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
        resp += ev.data
    ev = conn.next_event()
s.close()

# parse the HTTP/3 response frames
frames = []
i = 0
while i < len(resp):
    t, i = rvlq(resp, i)
    length, i = rvlq(resp, i)
    frames.append((t, resp[i:i + length]))
    i += length

hdr = next(p for t, p in frames if t == 1)
body = next(p for t, p in frames if t == 0)
dec = pylsqpack.Decoder(0, 0)
_, headers = dec.feed_header(0, hdr)
hd = dict(headers)

assert hd.get(b":status") == b"200", hd
assert hd.get(b"content-type") == b"text/plain", hd
assert body == b"served by linnea over http/3\n", body
print("ok")
