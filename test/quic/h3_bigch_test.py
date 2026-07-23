#!/usr/bin/env python3
# A ClientHello too large for one Initial packet, and a ClientHello with no
# x25519 key share. Both are shapes a real browser produces that aioquic's
# default (small, x25519-first) ClientHello does not:
#
#  * A browser offering a post-quantum key share (X25519MLKEM768, ~1.2 KB) sends
#    a ~1.6 KB ClientHello, which QUIC splits across several Initial packets,
#    each a CRYPTO frame at an increasing offset. Until it has our ServerHello
#    the client addresses every Initial to the original DCID it chose, so the
#    server must route them all to one connection and reassemble the CRYPTO
#    before it can find the (later) x25519 share and complete the handshake.
#    Here a large custom extension inflates the ClientHello past one packet, with
#    max_datagram_size pinned to the QUIC floor so it genuinely fragments.
#
#  * A ClientHello with no x25519 share at all (only secp256r1) must be refused
#    without dereferencing a missing share — the server does only x25519 ECDHE,
#    and a null share once crashed the worker. The handshake must simply not
#    complete, and the server must stay up (a following normal request is served).
#
# Usage: h3_bigch_test.py <port>
import socket
import ssl
import sys

import pylsqpack
import aioquic.tls as tls
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def rvlq(b, i):
    k = 1 << (b[i] >> 6)
    v = b[i] & 0x3F
    for j in range(1, k):
        v = (v << 8) | b[i + j]
    return v, i + k


def run(bloat=None, no_x25519=False):
    """Drive one handshake; return (confirmed, initial_datagrams, response_bytes)."""
    orig = tls.Context.__init__

    def patched(self, *a, **k):
        orig(self, *a, **k)
        if bloat:
            # a large GREASE-coded extension: pushes the ClientHello over one packet
            self.handshake_extensions = [(0x6A6A, b"\xab" * bloat)]
        if no_x25519:
            self._supported_groups = [tls.Group.SECP256R1]

    tls.Context.__init__ = patched
    try:
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
                                max_datagram_size=1200)
        cfg.verify_mode = ssl.CERT_NONE
        cfg.server_name = "localhost"
        conn = QuicConnection(configuration=cfg)
        conn.connect(ADDR, now=0.0)
    finally:
        tls.Context.__init__ = orig

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.3)
    vt = [0.0]
    initials = [0]

    def clk():
        vt[0] += 0.03
        return vt[0]

    def flush():
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ADDR)
            if d and (d[0] & 0xF0) == 0xC0:   # long header, Initial packet type
                initials[0] += 1

    for _ in range(60):
        flush()
        if conn._handshake_confirmed:
            break
        try:
            r, _ = s.recvfrom(4096)
        except socket.timeout:
            continue
        conn.receive_datagram(r, ADDR, now=clk())

    if not conn._handshake_confirmed:
        s.close()
        return False, initials[0], b""

    while conn.next_event() is not None:
        pass
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"GET"), (b":path", b"/"),
                               (b":scheme", b"https"), (b":authority", b"h3.test")])
    conn.send_stream_data(0, vlq(1) + vlq(len(fields)) + fields, end_stream=True)
    resp = b""
    fin = False
    for _ in range(40):
        if fin:
            break
        flush()
        try:
            r, _ = s.recvfrom(4096)
        except socket.timeout:
            continue
        conn.receive_datagram(r, ADDR, now=clk())
        ev = conn.next_event()
        while ev is not None:
            if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
                resp += ev.data
                fin = fin or ev.end_stream
            ev = conn.next_event()
    s.close()
    return True, initials[0], resp


def status_of(resp):
    i = 0
    frames = []
    while i < len(resp):
        t, i = rvlq(resp, i)
        ln, i = rvlq(resp, i)
        frames.append((t, resp[i:i + ln]))
        i += ln
    hdr = next(p for t, p in frames if t == 1)
    dec = pylsqpack.Decoder(0, 0)
    _, headers = dec.feed_header(0, hdr)
    return dict(headers).get(b":status")


# 1. a ClientHello that spans several Initial packets is reassembled and served
confirmed, initials, resp = run(bloat=2600)
assert confirmed, "split-ClientHello handshake did not complete"
assert initials >= 2, f"ClientHello was not split ({initials} Initial datagrams)"
assert resp and status_of(resp) == b"200", f"bad response: {resp!r}"

# 2. a ClientHello with no x25519 share is refused, and the server stays up:
# the handshake must not complete, and a normal request right after is served
# (a crash would take the worker down instead of failing this one handshake).
confirmed, _, _ = run(no_x25519=True)
assert not confirmed, "handshake completed without an x25519 share (impossible)"

confirmed, _, resp = run()
assert confirmed, "server did not survive the no-x25519 ClientHello"
assert resp and status_of(resp) == b"200", f"bad response after recovery: {resp!r}"

print(f"ok (split ClientHello reassembled across {initials} Initials; "
      f"no-x25519 refused without crashing)")
