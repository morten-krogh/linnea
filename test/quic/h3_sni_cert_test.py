#!/usr/bin/env python3
# Over HTTP/3, the ClientHello's SNI must select the matching virtual host's
# certificate — the same as the TCP/kTLS path. Before per-vhost QUIC, h3 always
# served the first vhost's certificate, so a second name (e.g. linnea2) was handed
# the first name's cert; browsers reject the name mismatch and fall back to h2.
# Connects over h3 with the given SNI and asserts the served certificate's CN.
# Usage: h3_sni_cert_test.py <port> <sni> <expected-CN>
import socket
import ssl
import sys
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

port = int(sys.argv[1])
sni = sys.argv[2]
expect_cn = sys.argv[3]

cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = sni
conn = QuicConnection(configuration=cfg)
vt = [0.0]


def clk():
    vt[0] += 0.01
    return vt[0]


conn.connect(("127.0.0.1", port), now=clk())
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.3)


def flush():
    for d, _ in conn.datagrams_to_send(now=clk()):
        s.sendto(d, ("127.0.0.1", port))


flush()
deadline = time.time() + 8
while not conn._handshake_confirmed and time.time() < deadline:
    try:
        r, _ = s.recvfrom(4096)
        conn.receive_datagram(r, ("127.0.0.1", port), now=clk())
    except socket.timeout:
        conn.handle_timer(now=clk())
    flush()

assert conn._handshake_confirmed, f"SNI={sni}: handshake did not complete"
cert = getattr(conn.tls, "_peer_certificate", None)
assert cert is not None, f"SNI={sni}: no peer certificate"
subject = cert.subject.rfc4514_string()
assert f"CN={expect_cn}" in subject, \
    f"SNI={sni}: served cert {subject!r}, expected CN={expect_cn}"
print(f"ok (SNI={sni} -> CN={expect_cn})")
