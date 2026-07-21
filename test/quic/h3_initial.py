#!/usr/bin/env python3
# Send a real QUIC Initial (with an HTTP/3 ALPN ClientHello) to a UDP port,
# using aioquic to build the packet. The server under test decrypts it; this
# script only needs to put the Initial on the wire, so it does not wait for
# the (absent) server response.  Usage: h3_initial.py <port>
import socket
import ssl
import sys

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

port = int(sys.argv[1])
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"

conn = QuicConnection(configuration=cfg)
conn.connect(("127.0.0.1", port), now=0.0)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for data, _addr in conn.datagrams_to_send(now=0.0):
    sock.sendto(data, ("127.0.0.1", port))
sock.close()
print("sent %d-byte Initial" % len(data))
