#!/usr/bin/env python3
# content-length must equal the sum of the DATA payloads (audit Finding 18, RFC
# 9114 4.1.3). HTTP/2 reconciles this; HTTP/3 did not, so a short or long body
# was routed and proxied around the client's declared framing instead of being
# rejected. A matching declaration is served; a mismatch (or a non-decimal value)
# is a malformed message -> the request stream is reset (H3_MESSAGE_ERROR), so no
# :status comes back.
# Usage: h3_content_length.py <port>.  Prints OK or the first failure.
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived, StreamReset

PORT = int(sys.argv[1])


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


cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
conn.connect(("127.0.0.1", PORT), now=0.0)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
clock = [0.0]


def pump():
    for d, _ in conn.datagrams_to_send(now=clock[0]):
        s.sendto(d, ("127.0.0.1", PORT))


pump()
for _ in range(4):
    try:
        r, _ = s.recvfrom(4096)
    except socket.timeout:
        break
    clock[0] += 0.1
    conn.receive_datagram(r, ("127.0.0.1", PORT), now=clock[0])
    pump()
    if conn._handshake_confirmed:
        break
assert conn._handshake_confirmed, "handshake not confirmed"
while conn.next_event() is not None:
    pass
clock[0] = 0.4


def post(declared, body):
    """POST /api/echo with content-length=declared and `body` bytes of DATA.
    Returns the :status string, or 'RESET' if the stream was reset."""
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"POST"), (b":path", b"/api/echo"),
                               (b":scheme", b"https"), (b":authority", b"localhost"),
                               (b"content-length", str(declared).encode())])
    data = vlq(0) + vlq(len(body)) + body
    stream = vlq(1) + vlq(len(fields)) + fields + data
    bidi = conn.get_next_available_stream_id()
    conn.send_stream_data(bidi, stream, end_stream=True)
    resp = b""
    reset = False
    s.settimeout(0.3)
    deadline = time.time() + 8
    while not resp and not reset and time.time() < deadline:
        pump()
        clock[0] += 0.2
        try:
            r, _ = s.recvfrom(4096)
        except socket.timeout:
            continue
        conn.receive_datagram(r, ("127.0.0.1", PORT), now=clock[0])
        ev = conn.next_event()
        while ev is not None:
            if isinstance(ev, StreamDataReceived) and ev.stream_id == bidi:
                resp += ev.data
            elif isinstance(ev, StreamReset) and ev.stream_id == bidi:
                reset = True
            ev = conn.next_event()
    if reset and not resp:
        return "RESET"
    i = 0
    while i < len(resp):
        ty, i = rvlq(resp, i)
        ln, i = rvlq(resp, i)
        if ty == 1:
            _, headers = pylsqpack.Decoder(0, 0).feed_header(0, resp[i:i + ln])
            return dict(headers).get(b":status", b"?").decode()
        i += ln
    return "no reply"


# a matching content-length is served
st = post(10, b"a" * 10)
if st != "200":
    print(f"matching content-length:10 with 10 DATA bytes was not 200: {st}")
    sys.exit(1)
# a short body (declared more than sent) is rejected
st = post(100, b"a" * 10)
if st == "200":
    print(f"content-length:100 with 10 DATA bytes was served (200) -- not reconciled")
    sys.exit(1)
# a long body (declared less than sent) is rejected
st = post(5, b"a" * 10)
if st == "200":
    print(f"content-length:5 with 10 DATA bytes was served (200) -- not reconciled")
    sys.exit(1)
print("OK")
