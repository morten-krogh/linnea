#!/usr/bin/env python3
# A second QPACK encoder or decoder stream must be H3_STREAM_CREATION_ERROR
# (audit Finding 10, RFC 9114 6.2.1), exactly as a second control stream already
# is. Before the fix the QPACK handlers overwrote the saved stream id instead of
# raising the error. This opens the normal h3 setup, then a second client
# unidirectional stream typed 0x02 (QPACK encoder), and requires the connection
# to close with 0x0103.
#
# Usage: h3_dup_qpack.py <port>.  Prints ok/FAIL.
import socket
import ssl
import sys
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated

PORT = int(sys.argv[1])
H3_STREAM_CREATION_ERROR = 0x0103


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
vt = [0.0]


def clk():
    vt[0] += 0.001
    return vt[0]


conn.connect(("127.0.0.1", PORT), now=clk())
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.2)


def flush():
    for d, _ in conn.datagrams_to_send(now=clk()):
        s.sendto(d, ("127.0.0.1", PORT))


flush()
dl = time.time() + 8
while not conn._handshake_confirmed and time.time() < dl:
    try:
        r, _ = s.recvfrom(4096)
        conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
    except socket.timeout:
        conn.handle_timer(now=clk())
    flush()
assert conn._handshake_confirmed, "handshake failed"

# control stream (type 0x00) + an empty SETTINGS frame (type 0x04, len 0)
control = conn.get_next_available_stream_id(is_unidirectional=True)
conn.send_stream_data(control, b"\x00" + vlq(0x04) + vlq(0))
# a QPACK encoder stream (type 0x02)
enc1 = conn.get_next_available_stream_id(is_unidirectional=True)
conn.send_stream_data(enc1, b"\x02")
# ...and a SECOND QPACK encoder stream: the violation
enc2 = conn.get_next_available_stream_id(is_unidirectional=True)
conn.send_stream_data(enc2, b"\x02")
flush()

code = None
dl = time.time() + 4
while code is None and time.time() < dl:
    try:
        r, _ = s.recvfrom(65535)
        conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        for ev in iter(conn.next_event, None):
            if isinstance(ev, ConnectionTerminated):
                code = ev.error_code
    except socket.timeout:
        conn.handle_timer(now=clk())
    ce = getattr(conn, "_close_event", None)
    if isinstance(ce, ConnectionTerminated):
        code = ce.error_code
    flush()

ok = code == H3_STREAM_CREATION_ERROR
print(f"ok (dup QPACK encoder -> 0x{code:x})" if ok
      else f"FAIL (dup QPACK encoder -> {code}, want 0x{H3_STREAM_CREATION_ERROR:x})")
sys.exit(0 if ok else 1)
