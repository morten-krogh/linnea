#!/usr/bin/env python3
# Complete the handshake against linnea, then send the client's Finished and let
# linnea verify it. aioquic's second flight coalesces an Initial (acking the
# server) and a Handshake packet carrying the client Finished; linnea walks the
# datagram, decrypts the Handshake packet with the client handshake keys, and
# checks the Finished MAC — printing "CFIN-OK" (the caller greps its stdout).
# Usage: cfin_test.py <port>
import socket
import ssl
import sys
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

port = int(sys.argv[1])
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"

conn = QuicConnection(configuration=cfg)
conn.connect(("127.0.0.1", port), now=0.0)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
for data, _ in conn.datagrams_to_send(now=0.0):
    s.sendto(data, ("127.0.0.1", port))
resp, _ = s.recvfrom(4096)
conn.receive_datagram(resp, ("127.0.0.1", port), now=0.1)
assert conn._handshake_complete, "handshake did not complete"

# The client's response carries its Finished; send it for linnea to verify.
for data, _ in conn.datagrams_to_send(now=0.2):
    s.sendto(data, ("127.0.0.1", port))
s.close()
time.sleep(0.3)
print("ok")
