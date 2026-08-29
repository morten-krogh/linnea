#!/usr/bin/env python3
# SETTINGS_MAX_FIELD_SECTION_SIZE against the responses this server actually
# builds -- proxied, static and interim (audit-report-143 Finding 1).
#
# RFC 9114 4.2.2 defines the limit over the UNCOMPRESSED field section: for
# every field, name length + value length + 32. Two things were wrong:
#
#  (a) the proxy path never consulted the setting at all. A proxied response is
#      encoded on an upstream completion, long after the per-request globals
#      stopped describing the connection that asked for it, so the size now
#      travels with the response and the delivery compares it against the
#      OWNING connection's advertised limit.
#  (b) the static path compared the ENCODED QPACK length to the setting. QPACK
#      only shrinks, so that never over-rejects -- and never catches the case
#      that matters: /hello.txt is 626 bytes of field section and encodes to
#      under 200, so a peer advertising 200 was sent exactly the message it had
#      said it would not accept.
#
# Sizes on test/configs/tls-h3-proxy.json, measured independently with
# curl --http3 and the RFC 9114 rule (name + value + 32 per field):
#   /api/simple    378   (proxied)
#   /hello.txt     626   (static; QPACK encodes it under 200)
#   /api/bigearly  six interim heads of 1670 each, then a 377 final -- a chain
#                  whose sum is 10397 and whose largest SECTION is 1670
#
# Every rejection row is paired with an acceptance row above the same response's
# size, so an implementation that reset every stream carrying a limit -- or one
# that added the interim sections together -- fails here rather than passing.
#
# Usage: h3_fss_limit.py <port>.  Prints ok/FAIL lines, exits 0 iff all ok.
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated
from aioquic.tls import Epoch

PORT = int(sys.argv[1])
H3_INTERNAL_ERROR = 0x0102

# aioquic surfaces no event for a RESET_STREAM, and it refuses the injected
# request stream as "wrong stream initiator" once it is answered -- so the reset
# is captured out of the frame parser directly, as h3_settings_validation.py does.
resets = []
_orig_reset = QuicConnection._handle_reset_stream_frame


class _StopInjectedParse(Exception):
    pass


def _cap_reset(self, context, frame_type, buf):
    sid = buf.pull_uint_var()
    err = buf.pull_uint_var()
    buf.pull_uint_var()
    resets.append((sid, err))
    raise _StopInjectedParse()


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def settings_frame(pairs):
    body = b"".join(vlq(i) + vlq(v) for i, v in pairs)
    return bytes([0x04]) + vlq(len(body)) + body     # H3 SETTINGS = 0x04


def control_stream(settings):
    return bytes([0x00]) + settings                  # control stream type 0x00


def stream_frame(sid, off, data, fin):
    t = 0x08 | 0x04 | 0x02 | (0x01 if fin else 0)
    return bytes([t]) + vlq(sid) + vlq(off) + vlq(len(data)) + data


def h3_request(path):
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, block = enc.encode(0, [(b":method", b"GET"), (b":path", path),
                              (b":scheme", b"https"), (b":authority", b"h3.test")])
    return bytes([0x01]) + vlq(len(block)) + block   # HEADERS frame


def handshake():
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    vt = [0.0]

    def clk():
        vt[0] += 0.001
        return vt[0]

    conn.connect(("127.0.0.1", PORT), now=clk())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.2)

    def flush():
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ("127.0.0.1", PORT))

    flush()
    dl = time.time() + 8
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            r, _ = s.recvfrom(4096)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        except socket.timeout:
            tick(conn, clk)
        flush()
    assert conn._handshake_confirmed, "handshake failed"
    return conn, s, clk


def tick(conn, clk):
    try:
        conn.handle_timer(now=clk())
    except TypeError:
        pass          # aioquic's timer on a connection it has already closed


def inject(conn, s, frames, pn_bump):
    dcid = conn._peer_cid.cid
    send = conn._cryptos[Epoch.ONE_RTT].send
    pn = conn._packet_number + pn_bump
    header = bytes([0x43]) + dcid + pn.to_bytes(4, "big")
    s.sendto(send.encrypt_packet(header, frames, pn), ("127.0.0.1", PORT))


def was_reset(path, limit):
    """Request <path> after advertising <limit> (None = advertise none).
    True when the server reset that stream with H3_INTERNAL_ERROR."""
    resets.clear()
    conn, s, clk = handshake()
    pairs = [] if limit is None else [(0x06, limit)]
    inject(conn, s, stream_frame(2, 0, control_stream(settings_frame(pairs)), fin=False), 5000)
    time.sleep(0.05)
    inject(conn, s, stream_frame(0, 0, h3_request(path.encode()), fin=True), 5001)
    dl = time.time() + 4
    while time.time() < dl:
        try:
            r, _ = s.recvfrom(65535)
            try:
                conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
            except _StopInjectedParse:
                pass
            if resets:
                break
            for ev in iter(conn.next_event, None):
                if isinstance(ev, ConnectionTerminated):
                    dl = 0
        except socket.timeout:
            tick(conn, clk)
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ("127.0.0.1", PORT))
    s.close()
    return any(err == H3_INTERNAL_ERROR for _, err in resets)


fails = 0


def check(what, path, limit, want_reset):
    global fails
    got = was_reset(path, limit)
    ok = got == want_reset
    if not ok:
        fails += 1
    print(("ok   " if ok else "FAIL ") + f"{what} (reset={got}, want {want_reset})")


QuicConnection._handle_reset_stream_frame = _cap_reset
try:
    # (a) the proxied response: 378 bytes of field section
    check("proxied response over the peer's limit is reset", "/api/simple", 300, True)
    check("proxied response under it is served", "/api/simple", 5000, False)
    check("proxied response with no limit advertised is served", "/api/simple", None, False)
    # (b) the static response: 626 uncompressed, under 200 encoded -- a limit
    # between the two is the whole point, and was served before the fix
    check("static response over the peer's limit is reset", "/hello.txt", 500, True)
    check("static response under it is served", "/hello.txt", 5000, False)
    # (c) an interim chain: judged per SECTION (largest 1670), not by the sum
    check("an interim head over the limit resets the stream", "/api/bigearly", 1000, True)
    check("an interim chain whose sum exceeds the limit still serves",
          "/api/bigearly", 2000, False)
finally:
    QuicConnection._handle_reset_stream_frame = _orig_reset

print("ok" if fails == 0 else f"FAIL ({fails})")
sys.exit(0 if fails == 0 else 1)
