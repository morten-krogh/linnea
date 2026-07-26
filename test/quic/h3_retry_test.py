#!/usr/bin/env python3
# Address validation under a flood of forged handshakes (RFC 9000 8.1).
#
# An Initial packet costs a connection slot, a key exchange and a signature, and
# its source address cannot be checked — UDP has no handshake. Left alone, a few
# hundred Initials that are never answered fill the pool and no real client can
# open h3 until the slots time out; repeating that a few times a second keeps h3
# down indefinitely, for almost nothing.
#
# The server answers with a Retry once enough slots are held by peers that have
# not proved their address: the client must echo a token, which only something
# that really receives our packets at that address can do. This sends the flood,
# then requires a normal client to still get its page — through the Retry, which
# the client handles exactly as a browser does.
# Usage: h3_retry_test.py <port> [flood]
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

port = int(sys.argv[1])
FLOOD = int(sys.argv[2]) if len(sys.argv) > 2 else 300
HOST = "127.0.0.1"


def client():
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    return QuicConnection(configuration=cfg)


# The flood: each connection sends its first flight from its own port and then
# goes silent, exactly like a spoofed source that never hears the reply.
socks = []
for _ in range(FLOOD):
    c = client()
    c.connect((HOST, port), now=0.0)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for d, _ in c.datagrams_to_send(now=0.0):
        s.sendto(d, (HOST, port))
    socks.append(s)                     # hold the ports so the sources stay live
time.sleep(0.5)

# A real client, pumped the way a browser drives a connection: it must complete,
# which after a flood means completing through a Retry.
c = client()
vt = [0.0]


def clk():
    vt[0] += 0.005
    return vt[0]


c.connect((HOST, port), now=clk())
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setblocking(False)
got = []


def pump(dur):
    end = time.time() + dur
    while time.time() < end:
        for d, _ in c.datagrams_to_send(now=clk()):
            sock.sendto(d, (HOST, port))
        try:
            while True:
                r, _ = sock.recvfrom(4096)
                c.receive_datagram(r, (HOST, port), now=clk())
        except (BlockingIOError, socket.error):
            pass
        try:
            c.handle_timer(now=clk())
        except TypeError:
            pass
        ev = c.next_event()
        while ev:
            if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
                got.append(ev.data)
            ev = c.next_event()
        time.sleep(0.002)


t0 = time.time()
while not c._handshake_confirmed and time.time() - t0 < 15:
    pump(0.05)
assert c._handshake_confirmed, (
    f"after {FLOOD} unanswered Initials a real client could not complete a "
    f"handshake — forged Initials are holding the connection pool")


def vlq(n):
    return bytes([n]) if n < 64 else (0x4000 | n).to_bytes(2, "big")


enc = pylsqpack.Encoder()
enc.apply_settings(max_table_capacity=0, blocked_streams=0)
_, f = enc.encode(0, [(b":method", b"GET"), (b":path", b"/hello.txt"),
                      (b":scheme", b"https"), (b":authority", b"localhost")])
c.send_stream_data(0, vlq(1) + vlq(len(f)) + f, end_stream=True)
t0 = time.time()
while not got and time.time() - t0 < 10:
    pump(0.05)
body = b"".join(got)
assert b"hello" in body, f"no response through the flood: {body!r}"

# the client counts the Retries it was sent; under this much pressure there must
# have been one, or the gate never engaged and the pass above was luck
retries = getattr(c, "_retry_count", None)
if retries is not None:
    assert retries >= 1, (
        "the client completed without a Retry: address validation never engaged "
        "under a flood that should have tripped it")

for s in socks:
    s.close()
sock.close()
print(f"ok (served through a {FLOOD}-Initial flood; retries seen: {retries})")
