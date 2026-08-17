#!/usr/bin/env python3
# max_body must bound a body carried by ONE offset-zero STREAM frame with FIN
# (audit Finding 19). That copy-free single-frame path reaches routing without
# either reassembly cap check, so a max_body below one packet's worth was
# ignored on exactly that shape -- the HTTP/3 twin of the HTTP/1 Finding 3 gap.
# curl cannot exercise it (it flushes HEADERS and DATA as separate STREAM
# frames, which take the reassembly path that was already capped), so this drives
# aioquic at the frame level: the whole request (HEADERS frame + DATA frame + FIN)
# goes out in one send_stream_data call, i.e. one STREAM frame at offset 0.
#
# The server must proxy /api to a backend and set max_body low. A body of exactly
# max_body is served (200), one byte over is refused (413).
# Usage: h3_single_frame_maxbody.py <port> <max_body>.  Prints OK or a failure.
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

PORT = int(sys.argv[1])
CAP = int(sys.argv[2])


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


def post_single_frame(body):
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"POST"), (b":path", b"/api/echo"),
                               (b":scheme", b"https"), (b":authority", b"localhost")])
    data = vlq(0) + vlq(len(body)) + body                 # one DATA frame
    stream = vlq(1) + vlq(len(fields)) + fields + data     # HEADERS then DATA
    bidi = conn.get_next_available_stream_id()
    conn.send_stream_data(bidi, stream, end_stream=True)   # ONE offset-0 frame, FIN
    resp = b""
    s.settimeout(0.3)
    deadline = time.time() + 8
    while not resp and time.time() < deadline:
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


at = post_single_frame(b"a" * CAP)
if at != "200":
    print(f"single-frame body of exactly max_body ({CAP}) was not 200: {at}")
    sys.exit(1)
over = post_single_frame(b"a" * (CAP + 1))
if over != "413":
    print(f"single-frame body of max_body+1 ({CAP + 1}) was not 413: {over} (bypass)")
    sys.exit(1)
print("OK")
