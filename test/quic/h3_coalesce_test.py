#!/usr/bin/env python3
# Q124: connection coalescing must keep working. Two vhosts served under the
# SAME certificate (the multi-SAN case a browser coalesces onto one
# connection) are both names this connection can speak for, so ONE h3
# connection must serve both — each request judged on its own :authority,
# on its own stream. This is the other side of the 421 in
# h3_authority_test.py: strictness must not cost a connection per origin
# where one certificate already covers every name.
# Usage: h3_coalesce_test.py <port>   (localhost -> test/www, alias.test -> test/www/sub)
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

port = int(sys.argv[1])
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"          # one handshake, one certificate
conn = QuicConnection(configuration=cfg)
vt = [0.0]


def clk():
    vt[0] += 0.001
    return vt[0]


conn.connect(("127.0.0.1", port), now=clk())
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setblocking(False)
streams = {}


def pump(dur):
    end = time.time() + dur
    while time.time() < end:
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ("127.0.0.1", port))
        try:
            while True:
                r, _ = s.recvfrom(4096)
                conn.receive_datagram(r, ("127.0.0.1", port), now=clk())
        except (BlockingIOError, OSError):
            pass
        try:
            conn.handle_timer(now=clk())
        except TypeError:
            pass
        ev = conn.next_event()
        while ev:
            if isinstance(ev, StreamDataReceived):
                streams[ev.stream_id] = streams.get(ev.stream_id, b"") + ev.data
            ev = conn.next_event()
        time.sleep(0.002)


def vlq(n):
    return bytes([n]) if n < 64 else (0x4000 | n).to_bytes(2, "big")


def ask(sid, authority):
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, f = enc.encode(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                            (b":authority", authority), (b":path", b"/index.html")])
    conn.send_stream_data(sid, vlq(1) + vlq(len(f)) + f, end_stream=True)


pump(0.05)
deadline = time.time() + 5
while not conn._handshake_confirmed and time.time() < deadline:
    pump(0.05)
assert conn._handshake_confirmed, "handshake failed"

# two requests, two streams, two different authorities, one connection
ask(0, b"localhost")
ask(4, b"alias.test")
deadline = time.time() + 8
while not (streams.get(0) and streams.get(4)) and time.time() < deadline:
    pump(0.05)

first, second = streams.get(0, b""), streams.get(4, b"")
assert b"doctype" in first, f"localhost stream served the wrong page: {first[:60]}"
assert b"421" not in first, "the connection's own authority was refused"
assert b"sub index" in second, (
    f"alias.test was not served over the coalesced connection: {second[:60]} "
    "— a name the connection's own certificate covers must not need a new one")
assert b"421" not in second, "coalescing onto one certificate was refused"
print("ok")
