#!/usr/bin/env python3
# Drive linnea's QUIC handshake responder with a real aioquic client: send the
# client Initial, receive linnea's server Initial, and confirm aioquic decrypts
# it and processes the ServerHello (advancing to expect EncryptedExtensions).
# Usage: hs_test.py <port>
import socket
import ssl
import sys

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.tls import State

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
s.close()

assert conn.tls.state == State.CLIENT_EXPECT_ENCRYPTED_EXTENSIONS, conn.tls.state
print("ok")
