#!/usr/bin/env python3
"""QUIC's max_idle_timeout comes from the config's `timeout`, like every other
protocol's idle clock.

`timeout` is documented as "seconds an idle client connection is held before
closing", with no protocol qualifier -- and HTTP/3 was the one protocol it did
not reach. The transport parameter was a hardcoded 30000 ms whatever the config
said, so a site that raised `timeout` to keep browser connections warm got no
h3 benefit from it at all, and one that lowered it kept h3 connections around
six times longer than it had asked for.

Two servers with DIFFERENT timeouts are checked, and neither value is 30: one
fixture proves nothing here, because a hardcoded 30 and a working lookup are
indistinguishable if the fixture happens to say 30. The old fixed value is
asserted against explicitly for the same reason.

RFC 9000 10.1 makes the effective timeout the minimum of the two peers', so
this client advertises a deliberately huge one -- otherwise it would be the
client's number coming back, not the server's, and the test would pass on a
server that ignored its config completely.

usage: h3_idle_timeout.py <port> <expected seconds>
"""
import socket
import ssl
import sys

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

port = int(sys.argv[1])
expected = float(sys.argv[2])
addr = ("127.0.0.1", port)

cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
cfg.idle_timeout = 600.0          # ...so the minimum is the SERVER's, not ours
conn = QuicConnection(configuration=cfg)
conn.connect(addr, now=0.0)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(0.4)
clock = 0.0
for _ in range(10):
    for d, _ in conn.datagrams_to_send(now=clock):
        sock.sendto(d, addr)
    try:
        while True:
            r, _ = sock.recvfrom(65536)
            clock += 0.01
            conn.receive_datagram(r, addr, now=clock)
    except socket.timeout:
        pass
    clock += 0.05
    if conn._handshake_confirmed:
        break

if not conn._handshake_confirmed:
    print("handshake not confirmed")
    sys.exit(1)

got = getattr(conn, "_remote_max_idle_timeout", None)
if got is None:
    print("server advertised no max_idle_timeout at all")
    sys.exit(1)
if abs(float(got) - expected) > 0.001:
    print(f"server advertised max_idle_timeout {got}s, config says {expected}s"
          + ("  -- that is the old hardcoded 30s, so the config is being ignored"
             if abs(float(got) - 30.0) < 0.001 else ""))
    sys.exit(1)
if abs(expected - 30.0) < 0.001:
    print("fixture timeout is 30s, which cannot tell a lookup from the old "
          "hardcoded value -- pick another fixture")
    sys.exit(1)
print("OK")
