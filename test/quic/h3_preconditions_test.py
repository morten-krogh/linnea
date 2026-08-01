#!/usr/bin/env python3
# If-Match and If-Unmodified-Since over HTTP/3 (RFC 9110 13.1.1, 13.1.4).
#
# h1 got these in Q187. Until h2 and h3 followed, the same request got a
# different answer depending on which protocol carried it — a 412 over h1 and a
# 200 (or worse, a 304) over h3. The fields are captured by the decoder h2 and h3
# share, so both were one change; this checks the h3 half end to end.
#
# 13.2.2 fixes the order, and the case that matters is a failing If-Match
# alongside a matching If-None-Match: that is a 412, not a 304.
#
# Usage: h3_preconditions_test.py <port>
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

PORT = int(sys.argv[1])


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def rvlq(b, i):
    n = 1 << (b[i] >> 6)
    v = b[i] & 0x3F
    for k in range(1, n):
        v = (v << 8) | b[i + k]
    return v, i + n


def fetch(extra_fields=()):
    """GET /hello.txt with extra request fields -> (status, response fields)."""
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    vt = [0.0]

    def clk():
        vt[0] += 0.002
        return vt[0]

    conn.connect(("127.0.0.1", PORT), now=clk())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.4)

    def flush():
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ("127.0.0.1", PORT))

    flush()
    dl = time.time() + 8
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
    assert conn._handshake_confirmed, "handshake failed"

    uni = conn.get_next_available_stream_id(is_unidirectional=True)
    conn.send_stream_data(uni, b"\x00\x04\x00")          # control + SETTINGS
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    fields = [(b":method", b"GET"), (b":path", b"/hello.txt"),
              (b":scheme", b"https"), (b":authority", b"h3.test")]
    fields.extend(extra_fields)
    _, block = enc.encode(0, fields)
    bidi = conn.get_next_available_stream_id()
    conn.send_stream_data(bidi, vlq(1) + vlq(len(block)) + block, end_stream=True)
    flush()

    resp = b""
    dl = time.time() + 6
    while time.time() < dl and not resp:
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        except socket.timeout:
            conn.handle_timer(now=clk())
        ev = conn.next_event()
        while ev is not None:
            if isinstance(ev, StreamDataReceived) and ev.stream_id == bidi:
                resp += ev.data
            ev = conn.next_event()
        flush()
    s.close()

    i, header = 0, None
    while i < len(resp):
        ty, i = rvlq(resp, i)
        ln, i = rvlq(resp, i)
        if ty == 1:
            header = resp[i:i + ln]
        i += ln
    assert header is not None, "no HEADERS frame in the response"
    dec = pylsqpack.Decoder(0, 0)
    _, headers = dec.feed_header(0, header)
    got = {k.decode(): v.decode() for k, v in headers}
    return int(got[":status"]), got


status, fields = fetch()
etag = fields.get("etag")
last_mod = fields.get("last-modified")
assert status == 200 and etag and last_mod, (status, fields)

OTHER = '"0000000000000000"'
PAST = "Wed, 01 Jan 2020 00:00:00 GMT"

fails = 0
for label, extra, want in (
        ("If-Match with our etag", [(b"if-match", etag.encode())], 200),
        ("If-Match with a different etag", [(b"if-match", OTHER.encode())], 412),
        ("If-Unmodified-Since before the mtime",
         [(b"if-unmodified-since", PAST.encode())], 412),
        ("If-Unmodified-Since at the mtime",
         [(b"if-unmodified-since", last_mod.encode())], 200),
        # 13.2.2: a failing If-Match wins over a matching If-None-Match
        ("a failing If-Match beats a matching If-None-Match",
         [(b"if-match", OTHER.encode()), (b"if-none-match", etag.encode())], 412),
):
    got, got_fields = fetch(extra)
    if got == want:
        print(f"ok   {label} -> {got}")
    else:
        print(f"FAIL {label} -> {got}, want {want}")
        fails += 1
    if want == 412 and got == 412 and got_fields.get("etag") != etag:
        print(f"FAIL the 412 did not carry the current etag "
              f"({got_fields.get('etag')!r})")
        fails += 1

sys.exit(1 if fails else 0)
