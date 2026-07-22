#!/usr/bin/env python3
# Retransmission / loss recovery. Complete the handshake, send an HTTP/3 GET,
# then DROP the server's reply instead of delivering it. With the reply left
# unacknowledged the server must resend it — under a fresh packet number, since
# QUIC forbids reusing one — once its probe timeout elapses. We collect the
# retransmission, feed it to the client, and confirm the HTTP/3 response arrives
# intact. Needs the real server (the io_uring loop's periodic timer drives the
# retransmission; the blocking test driver has no timer).
# Usage: h3_rtx_test.py <port>
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
flush(0.2)                                       # client Finished
r, _ = s.recvfrom(4096)
conn.receive_datagram(r, ("127.0.0.1", port), now=0.3)   # HANDSHAKE_DONE
assert conn._handshake_confirmed, "handshake not confirmed"
while conn.next_event() is not None:
    pass

# The request flush also carries the client's ACK of HANDSHAKE_DONE, so by the
# time the server sends its reply only the reply is left unacknowledged.
enc = pylsqpack.Encoder()
enc.apply_settings(max_table_capacity=0, blocked_streams=0)
_, fields = enc.encode(0, [(b":method", b"GET"), (b":path", b"/hello.txt"),
                           (b":scheme", b"https"), (b":authority", b"h3.test")])
conn.send_stream_data(0, vlq(1) + vlq(len(fields)) + fields, end_stream=True)
flush(0.4)

# The server's reply arrives first — drop it, as if lost in flight.
dropped, _ = s.recvfrom(4096)
assert dropped, "no reply to drop"
dropped_at = time.time()

# Now wait for the retransmission and deliver that instead.
resp = b""
got_at = None
t = 0.5
deadline = time.time() + 3.0
while not resp and time.time() < deadline:
    try:
        r, _ = s.recvfrom(4096)
    except socket.timeout:
        break
    conn.receive_datagram(r, ("127.0.0.1", port), now=t)
    t += 0.1
    ev = conn.next_event()
    while ev is not None:
        if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
            resp += ev.data
            got_at = time.time()
        ev = conn.next_event()

flush(t)                                         # ack it so probing can stop
s.close()

assert resp, "server never retransmitted the dropped reply"
# It must have waited for the probe timeout, not just sent a second copy at once.
assert got_at - dropped_at > 0.15, \
    f"reply came back in {got_at - dropped_at:.3f}s — too soon to be a probe"

frames = []
i = 0
while i < len(resp):
    ty, i = rvlq(resp, i)
    length, i = rvlq(resp, i)
    frames.append((ty, resp[i:i + length]))
    i += length
hdr = next(p for ty, p in frames if ty == 1)
body = next((p for ty, p in frames if ty == 0), b"")
dec = pylsqpack.Decoder(0, 0)
_, headers = dec.feed_header(0, hdr)
hd = dict(headers)
assert hd.get(b":status") == b"200", hd
assert body == open("test/www/hello.txt", "rb").read(), body
print("ok")
