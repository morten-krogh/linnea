#!/usr/bin/env python3
# An HTTP/3 unidirectional stream type is a QUIC varint, not one byte (audit
# Finding 22, RFC 9114 6.2). Control type 0 may legally be sent as "40 00" and
# the QPACK types as "40 02"/"40 03". Before the fix a two-byte encoding was
# read as byte 0x40 -- an unknown type -- and the stream (its SETTINGS or QPACK
# role) was discarded.
#
# To make the classification observable, this opens the control and TWO QPACK
# encoder streams all with the two-byte type encoding: only if the multi-byte
# types are decoded do the two encoders count as duplicates and draw
# H3_STREAM_CREATION_ERROR (0x0103). Before the fix they were dropped as unknown
# and no error followed.
#
# Usage: h3_uni_type.py <port>.  Prints ok/FAIL.
import socket
import ssl
import sys
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated

PORT = int(sys.argv[1])
H3_STREAM_CREATION_ERROR = 0x0103

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

# control stream, two-byte type 40 00, then an empty SETTINGS frame (04 00)
c = conn.get_next_available_stream_id(is_unidirectional=True)
conn.send_stream_data(c, b"\x40\x00\x04\x00")
# two QPACK encoder streams, two-byte type 40 02 -- a duplicate only if decoded
e1 = conn.get_next_available_stream_id(is_unidirectional=True)
conn.send_stream_data(e1, b"\x40\x02")
e2 = conn.get_next_available_stream_id(is_unidirectional=True)
conn.send_stream_data(e2, b"\x40\x02")
flush()

code = None
dl = time.time() + 4
while code is None and time.time() < dl:
    try:
        r, _ = s.recvfrom(65535)
        conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
    except socket.timeout:
        conn.handle_timer(now=clk())
    ce = getattr(conn, "_close_event", None)
    if isinstance(ce, ConnectionTerminated):
        code = ce.error_code
    flush()

ok = code == H3_STREAM_CREATION_ERROR
print(f"ok (two-byte-typed streams decoded; dup -> 0x{code:x})" if ok
      else f"FAIL (two-byte type not decoded; got {code}, want 0x{H3_STREAM_CREATION_ERROR:x})")
sys.exit(0 if ok else 1)
