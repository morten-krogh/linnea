#!/usr/bin/env python3
# Drive linnea's QUIC handshake responder with a real aioquic client and confirm
# the TLS 1.3 handshake completes. The client sends its Initial; linnea replies
# with one datagram coalescing an Initial (ACK + ServerHello) and a Handshake
# packet (EncryptedExtensions, Certificate, CertificateVerify, Finished). aioquic
# must decrypt both, verify the server Finished against its own transcript, and
# report the handshake complete with h3 negotiated.
# Usage: hs_test.py <port>
import socket
import ssl
import sys

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import HandshakeCompleted
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

assert conn.tls.state == State.CLIENT_POST_HANDSHAKE, conn.tls.state
assert conn._handshake_complete, "handshake did not complete"

completed = None
ev = conn.next_event()
while ev is not None:
    if isinstance(ev, HandshakeCompleted):
        completed = ev
    ev = conn.next_event()
assert completed is not None, "no HandshakeCompleted event"
assert completed.alpn_protocol == "h3", completed.alpn_protocol
print("ok")
