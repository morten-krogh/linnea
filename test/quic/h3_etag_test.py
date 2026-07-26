#!/usr/bin/env python3
# HTTP/3 response headers and conditional requests against linnea. A 200 must
# carry the validators (etag, last-modified) plus date and server; a request
# revalidating with If-None-Match (or If-Modified-Since) must draw a bodiless
# 304 that repeats the validators; a stale validator must draw the full 200.
# Usage: h3_etag_test.py <port>
import os
import re
import socket
import ssl
import sys

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived


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


def fetch(port, path, extra=()):
    """Handshake, GET `path` over HTTP/3 with the extra request fields,
    return (headers dict, body)."""
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    conn.connect(("127.0.0.1", port), now=0.0)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)

    def flush(t):
        for d, _ in conn.datagrams_to_send(now=t):
            s.sendto(d, ("127.0.0.1", port))

    flush(0.0)
    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ("127.0.0.1", port), now=0.1)
    flush(0.2)                                    # client Finished
    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ("127.0.0.1", port), now=0.3)   # HANDSHAKE_DONE
    assert conn._handshake_confirmed, "handshake not confirmed"
    while conn.next_event() is not None:
        pass

    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    fields = [(b":method", b"GET"),
              (b":path", path.encode()),
              (b":scheme", b"https"),
              (b":authority", b"h3.test")] + list(extra)
    _, block = enc.encode(0, fields)
    conn.send_stream_data(0, vlq(1) + vlq(len(block)) + block, end_stream=True)
    flush(0.4)

    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ("127.0.0.1", port), now=0.5)
    resp = b""
    ev = conn.next_event()
    while ev is not None:
        if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
            resp += ev.data
        ev = conn.next_event()
    s.close()

    frames = []
    i = 0
    while i < len(resp):
        t, i = rvlq(resp, i)
        length, i = rvlq(resp, i)
        frames.append((t, resp[i:i + length]))
        i += length
    hdr = next(p for t, p in frames if t == 1)
    body = next((p for t, p in frames if t == 0), b"")
    dec = pylsqpack.Decoder(0, 0)
    _, headers = dec.feed_header(0, hdr)
    return dict(headers), body


DATE_RE = rb"^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$"

port = int(sys.argv[1])

# a 200 carries the validators, date and server
hd, body = fetch(port, "/hello.txt")
assert hd.get(b":status") == b"200", hd
assert body == open("test/www/hello.txt", "rb").read(), body
st = os.stat("test/www/hello.txt")
etag = hd.get(b"etag")
assert etag == b'"%x-%x"' % (int(st.st_mtime), st.st_size), hd
assert re.match(DATE_RE, hd.get(b"last-modified", b"")), hd
assert re.match(DATE_RE, hd.get(b"date", b"")), hd
assert hd.get(b"server") == b"linnea", hd

# revalidation with the etag: a bodiless 304 repeating the validators
hd, body = fetch(port, "/hello.txt", [(b"if-none-match", etag)])
assert hd.get(b":status") == b"304", hd
assert body == b"", body
assert hd.get(b"etag") == etag, hd
assert b"content-length" not in hd and b"content-type" not in hd, hd
assert re.match(DATE_RE, hd.get(b"last-modified", b"")), hd
assert hd.get(b"server") == b"linnea", hd

# a weak or listed candidate still matches; "*" matches anything
hd, _ = fetch(port, "/hello.txt", [(b"if-none-match", b'W/' + etag)])
assert hd.get(b":status") == b"304", hd
hd, _ = fetch(port, "/hello.txt", [(b"if-none-match", b'"a", ' + etag)])
assert hd.get(b":status") == b"304", hd
hd, _ = fetch(port, "/hello.txt", [(b"if-none-match", b"*")])
assert hd.get(b":status") == b"304", hd

# a stale etag draws the full 200 again
hd, body = fetch(port, "/hello.txt", [(b"if-none-match", b'"stale"')])
assert hd.get(b":status") == b"200", hd
assert body == open("test/www/hello.txt", "rb").read(), body

# if-modified-since: current copy -> 304, older copy -> 200
lastmod = fetch(port, "/hello.txt")[0][b"last-modified"]
hd, _ = fetch(port, "/hello.txt", [(b"if-modified-since", lastmod)])
assert hd.get(b":status") == b"304", hd
hd, _ = fetch(port, "/hello.txt",
              [(b"if-modified-since", b"Mon, 01 Jan 2024 00:00:00 GMT")])
assert hd.get(b":status") == b"200", hd

# an INM mismatch answers 200 even when if-modified-since alone would not
hd, _ = fetch(port, "/hello.txt", [(b"if-none-match", b'"stale"'),
                                   (b"if-modified-since", lastmod)])
assert hd.get(b":status") == b"200", hd

# the vhost's configured security headers ride every response
assert hd.get(b"strict-transport-security") == b"max-age=31536000", hd
assert hd.get(b"x-content-type-options") == b"nosniff", hd

# a 404 carries date and server but no validators
hd, _ = fetch(port, "/nope.txt")
assert hd.get(b":status") == b"404", hd
assert b"etag" not in hd and b"last-modified" not in hd, hd
assert re.match(DATE_RE, hd.get(b"date", b"")), hd
assert hd.get(b"server") == b"linnea", hd
assert hd.get(b"strict-transport-security") == b"max-age=31536000", hd
assert hd.get(b"x-content-type-options") == b"nosniff", hd

print("ok")
