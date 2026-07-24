#!/usr/bin/env python3
# Content-encoding negotiation over HTTP/3: a pre-compressed "<path>.br" or
# "<path>.gz" beside the plain file is served — with content-encoding and
# vary — when the client's accept-encoding allows that coding; br wins over
# gzip; q=0 refuses a coding; without accept-encoding the plain file is
# served (still with vary). The validators describe the variant, so a
# revalidation of the variant's etag draws a 304 that keeps vary but does
# not restate content-encoding.
# Usage: h3_enc_test.py <port>
import gzip
import os
import socket
import ssl
import sys

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

port = int(sys.argv[1])

www = os.path.join(os.path.dirname(__file__), "..", "www")
open(os.path.join(www, "enc.txt"), "w").write("plain payload")
with gzip.open(os.path.join(www, "enc.txt.gz"), "wb") as f:
    f.write(b"gzip payload")
GZ = open(os.path.join(www, "enc.txt.gz"), "rb").read()
open(os.path.join(www, "enc.txt.br"), "wb").write(b"br payload")


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


def fetch(path, extra=()):
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
    flush(0.2)
    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ("127.0.0.1", port), now=0.3)
    assert conn._handshake_confirmed, "handshake not confirmed"
    while conn.next_event() is not None:
        pass

    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    fields = [(b":method", b"GET"), (b":path", path),
              (b":scheme", b"https"), (b":authority", b"h3.test")] + list(extra)
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
    body = b"".join(p for t, p in frames if t == 0)
    dec = pylsqpack.Decoder(0, 0)
    _, headers = dec.feed_header(0, hdr)
    return dict(headers), body


# accept-encoding br: the .br variant, with content-encoding + vary
hd, body = fetch(b"/enc.txt", [(b"accept-encoding", b"gzip, deflate, br")])
assert hd.get(b":status") == b"200", hd
assert hd.get(b"content-encoding") == b"br", hd
assert body == b"br payload", body
assert hd.get(b"vary") == b"accept-encoding", hd
etag_br = hd[b"etag"]

# gzip only: the .gz variant (real gzip bytes)
hd, body = fetch(b"/enc.txt", [(b"accept-encoding", b"gzip")])
assert hd.get(b"content-encoding") == b"gzip", hd
assert body == GZ, body

# br refused with q=0: gzip wins
hd, body = fetch(b"/enc.txt", [(b"accept-encoding", b"br;q=0, gzip")])
assert hd.get(b"content-encoding") == b"gzip", hd

# no accept-encoding: the plain file, no content-encoding, vary still set
hd, body = fetch(b"/enc.txt")
assert b"content-encoding" not in hd, hd
assert body == b"plain payload", body
assert hd.get(b"vary") == b"accept-encoding", hd
etag_plain = hd[b"etag"]
assert etag_plain != etag_br, (etag_plain, etag_br)

# an unknown coding: the plain file
hd, body = fetch(b"/enc.txt", [(b"accept-encoding", b"zstd")])
assert b"content-encoding" not in hd and body == b"plain payload", (hd, body)

# a file with no variants beside it is untouched by accept-encoding
hd, body = fetch(b"/hello.txt", [(b"accept-encoding", b"gzip, br")])
assert b"content-encoding" not in hd, hd
with open(os.path.join(www, "hello.txt"), "rb") as f:
    assert body == f.read(), body

# revalidating the variant's etag: a 304 that keeps vary, no content-encoding
hd, body = fetch(b"/enc.txt", [(b"accept-encoding", b"br"),
                               (b"if-none-match", etag_br)])
assert hd.get(b":status") == b"304", hd
assert body == b"", body
assert hd.get(b"etag") == etag_br, hd
assert hd.get(b"vary") == b"accept-encoding", hd
assert b"content-encoding" not in hd, hd

# a range applies to the variant's bytes (RFC 9110: the selected representation)
hd, body = fetch(b"/enc.txt", [(b"accept-encoding", b"br"),
                               (b"range", b"bytes=3-6")])
assert hd.get(b":status") == b"206", hd
assert body == b"br payload"[3:7], body
assert hd.get(b"content-range") == b"bytes 3-6/10", hd
assert hd.get(b"content-encoding") == b"br", hd

print("ok")
