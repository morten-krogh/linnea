#!/usr/bin/env python3
# Q124: HTTP/3 authority handling. Until now h3 ignored :authority entirely
# and served whatever vhost the TLS SNI had chosen — so a request explicitly
# addressed to one site we host was answered with another's content. Now
# :authority selects the vhost, but only among names THIS connection's
# certificate covers; a name belonging to a vhost with a different
# certificate gets 421 Misdirected Request (RFC 9110 7.4), which tells the
# client to retry on a fresh connection where the right cert is presented.
# The config has two vhosts on one port with separate certs:
#   localhost -> test/www (main index)   sni.test -> test/www/sub (sub index)
# Usage: h3_authority_test.py <port>
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

port = int(sys.argv[1])


def vlq(n):
    return bytes([n]) if n < 64 else (0x4000 | n).to_bytes(2, "big")


def request(sni, fields):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = sni
    c = QuicConnection(configuration=cfg)
    t = [0.0]

    def clk():
        t[0] += 0.001
        return t[0]

    c.connect(("127.0.0.1", port), now=clk())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    out = []

    def pump(d):
        end = time.time() + d
        while time.time() < end:
            for dg, _ in c.datagrams_to_send(now=clk()):
                s.sendto(dg, ("127.0.0.1", port))
            try:
                while True:
                    r, _ = s.recvfrom(4096)
                    c.receive_datagram(r, ("127.0.0.1", port), now=clk())
            except (BlockingIOError, OSError):
                pass
            try:
                c.handle_timer(now=clk())
            except TypeError:
                pass
            ev = c.next_event()
            while ev:
                if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
                    out.append(ev.data)
                ev = c.next_event()
            time.sleep(0.002)

    pump(0.05)
    deadline = time.time() + 5
    while not c._handshake_confirmed and time.time() < deadline:
        pump(0.05)
    assert c._handshake_confirmed, f"handshake failed (sni={sni})"
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, f = enc.encode(0, fields)
    c.send_stream_data(0, vlq(1) + vlq(len(f)) + f, end_stream=True)
    deadline = time.time() + 5
    while not out and time.time() < deadline:
        pump(0.05)
    s.close()
    return b"".join(out)


M = (b":method", b"GET")
S = (b":scheme", b"https")
P = (b":path", b"/index.html")

# the connection's own vhost, named explicitly: served from its root
body = request("sni.test", [M, S, (b":authority", b"sni.test"), P])
assert b"sub index" in body, f"sni.test served the wrong content: {body[:60]}"
body = request("localhost", [M, S, (b":authority", b"localhost"), P])
assert b"doctype" in body, f"localhost served the wrong content: {body[:60]}"

# a name this connection's certificate does not cover: 421, NOT the other
# site's content (which is what shipped before Q124)
body = request("sni.test", [M, S, (b":authority", b"localhost"), P])
assert b"421" in body, f"cross-vhost request was not refused: {body[:60]}"
assert b"doctype" not in body, "cross-vhost request leaked the other vhost's page"
body = request("localhost", [M, S, (b":authority", b"sni.test"), P])
assert b"421" in body, f"cross-vhost request was not refused: {body[:60]}"
assert b"sub index" not in body, "cross-vhost request leaked the other vhost's page"

# a name we do not host at all (an IP literal, an alias) keeps being served by
# the connection's own vhost — this is how address-based access still works
body = request("sni.test", [M, S, (b":authority", b"127.0.0.1:47444"), P])
assert b"sub index" in body, f"unknown authority was not served locally: {body[:60]}"

# and the malformed rules apply here too (shared with HTTP/2): a request with
# no authority at all fails its stream rather than being served
body = request("sni.test", [M, S, P])
assert b"sub index" not in body and b"doctype" not in body, \
    "a request with no authority was served"
print("ok")
