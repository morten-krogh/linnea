#!/usr/bin/env python3
# An Initial packet's header includes the token the client echoes from a Retry,
# and the server copies that header into a fixed scratch buffer to use as the
# AEAD's associated data. The token is client-supplied and its only bound is the
# datagram, so a header longer than the scratch overruns it — and what follows the
# scratch is the rest of the frame, the saved registers and the return address.
# That is a remote, pre-handshake stack overwrite with attacker-chosen bytes, so
# the header length must be checked before the copy, not assumed small.
#
# This drives it: allocate connection state with a first Initial, then send a
# second Initial for the same connection carrying a huge token. The server must
# refuse the packet and keep serving.
# Usage: h3_initial_token_test.py <port>
import os
import socket
import ssl
import subprocess
import sys

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

port = int(sys.argv[1])
HOST = "127.0.0.1"
LOG = "test/linnea.log"


def respawns():
    # a worker that dies is respawned by the master, so process counts look
    # healthy afterwards — the log is what records the death
    try:
        with open(LOG, errors="replace") as f:
            return sum(1 for line in f if "respawning" in line)
    except FileNotFoundError:
        return 0


before = respawns()


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def initial(dcid, token, pad_to=1250):
    """A long-header Initial: valid enough to be parsed and routed, with a token
    of our choosing. It never decrypts — the overrun happens while the header is
    being copied, before any of it is authenticated, which is the whole point."""
    p = bytearray()
    p += bytes([0xC3])                      # long header, v1 Initial, pn length 4
    p += (1).to_bytes(4, "big")             # version 1
    p += bytes([len(dcid)]) + dcid
    p += bytes([0])                         # no source id
    p += vlq(len(token)) + token
    body = b"\x00" * 64                     # pn + payload + tag, whatever it is
    p += vlq(len(body)) + body
    if len(p) < pad_to:
        p += b"\x00" * (pad_to - len(p))
    return bytes(p)


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.0)
dcid = os.urandom(8)

# first Initial: gets connection state allocated (the allocation happens before
# anything in the packet is trusted), leaving the connection mid-handshake
s.sendto(initial(dcid, b""), (HOST, port))
try:
    s.recvfrom(2048)
except socket.timeout:
    pass

# second Initial on that connection, with a token far larger than any scratch
# buffer it could be copied into
for size in (200, 1000):
    s.sendto(initial(dcid, b"A" * size), (HOST, port))
try:
    s.recvfrom(2048)
except socket.timeout:
    pass
s.close()


def h3_get(path):
    """A normal HTTP/3 request, pumped properly so it survives any number of
    round trips."""
    import time

    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    c = QuicConnection(configuration=cfg)
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
    while not c._handshake_confirmed and time.time() - t0 < 10:
        pump(0.05)
    assert c._handshake_confirmed, "no handshake after the oversized-token Initials"
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, f = enc.encode(0, [(b":method", b"GET"), (b":path", path.encode()),
                          (b":scheme", b"https"), (b":authority", b"localhost")])
    c.send_stream_data(0, vlq(1) + vlq(len(f)) + f, end_stream=True)
    t0 = time.time()
    while not got and time.time() - t0 < 5:
        pump(0.05)
    sock.close()
    return b"".join(got)


body = h3_get("/hello.txt")
assert body, "the server stopped serving h3 after the oversized-token Initials"
assert b"hello" in body, body

# no worker may have died on the way — an oversized header that overruns the
# scratch it is copied into takes the return address with it
assert respawns() == before, (
    "a worker died handling the oversized Initial token: the header was copied "
    "past the buffer it belongs in")
out = subprocess.run(["pgrep", "-c", "-f", "bin/linnea"], capture_output=True,
                     text=True).stdout.strip()
assert out and int(out) > 0, "no linnea process left alive"

print("ok (oversized Initial token refused; h3 still served)")
