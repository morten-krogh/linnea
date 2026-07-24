#!/usr/bin/env python3
# Range requests over HTTP/3 (plus Cache-Control / Accept-Ranges). A single
# bytes= range on a GET draws a 206 whose DATA is exactly the slice and whose
# Content-Range names it; If-Range gates the range on a strong validator
# match; an unsatisfiable range draws a bodiless 416 naming the length; and a
# ranged slice too large to inline streams as STREAM-frame chunks read from
# the middle of the file mapping (the foff path).
# Usage: h3_range_test.py <port>
import os
import re
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

port = int(sys.argv[1])

# the served fixture: patterned, so a slice from the wrong offset breaks equality
BIG = bytes((i * 131 + (i >> 8) * 17 + 7) & 0xFF for i in range(200000))
with open(os.path.join(os.path.dirname(__file__), "..", "www", "h3range.bin"),
          "wb") as f:
    f.write(BIG)
with open(os.path.join(os.path.dirname(__file__), "..", "www", "hello.txt"),
          "rb") as f:
    HELLO = f.read()


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


def parse_h3(stream):
    frames = []
    i = 0
    while i < len(stream):
        ty, i = rvlq(stream, i)
        ln, i = rvlq(stream, i)
        frames.append((ty, stream[i:i + ln]))
        i += ln
    hdr = next(p for ty, p in frames if ty == 1)
    data = b"".join(p for ty, p in frames if ty == 0)
    dec = pylsqpack.Decoder(0, 0)
    _, headers = dec.feed_header(0, hdr)
    return dict(headers), data


def fetch(path, extra=()):
    """Handshake, GET path with the extra request fields, read the whole
    response stream (however many datagrams it takes), return (headers, body)."""
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    conn.connect(("127.0.0.1", port), now=0.0)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)

    clock = [0.0]

    def flush():
        clock[0] += 0.05
        for d, _ in conn.datagrams_to_send(now=clock[0]):
            s.sendto(d, ("127.0.0.1", port))

    flush()
    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ("127.0.0.1", port), now=clock[0])
    flush()                                       # client Finished
    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ("127.0.0.1", port), now=clock[0])
    assert conn._handshake_confirmed, "handshake not confirmed"
    while conn.next_event() is not None:
        pass

    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    fields = [(b":method", b"GET"),
              (b":path", path),
              (b":scheme", b"https"),
              (b":authority", b"h3.test")] + list(extra)
    _, block = enc.encode(0, fields)
    conn.send_stream_data(0, vlq(1) + vlq(len(block)) + block, end_stream=True)
    flush()

    stream = b""
    fin = False
    s.settimeout(0.5)
    deadline = time.time() + 30
    while not fin and time.time() < deadline:
        try:
            r, _ = s.recvfrom(4096)
        except socket.timeout:
            flush()                               # keep acks moving
            continue
        conn.receive_datagram(r, ("127.0.0.1", port), now=clock[0])
        ev = conn.next_event()
        while ev is not None:
            if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
                stream += ev.data
                fin = fin or ev.end_stream
            ev = conn.next_event()
        flush()                                   # acks release the next chunks
    s.close()
    assert fin, "response stream did not finish"
    return parse_h3(stream)


DATE_RE = rb"^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$"

# a plain 200 advertises ranges and the configured cache policy, no content-range
hd, body = fetch(b"/hello.txt")
assert hd.get(b":status") == b"200", hd
assert body == HELLO, body
assert hd.get(b"accept-ranges") == b"bytes", hd
assert hd.get(b"cache-control") == b"max-age=60", hd
assert b"content-range" not in hd, hd
etag = hd[b"etag"]

# an inline 206: exact slice, content-range names it
hd, body = fetch(b"/hello.txt", [(b"range", b"bytes=5-9")])
assert hd.get(b":status") == b"206", hd
assert body == HELLO[5:10], body
assert hd.get(b"content-range") == b"bytes 5-9/%d" % len(HELLO), hd
assert hd.get(b"content-length") == b"5", hd
assert hd.get(b"etag") == etag, hd

# suffix and open-ended forms
hd, body = fetch(b"/hello.txt", [(b"range", b"bytes=-5")])
assert hd.get(b":status") == b"206" and body == HELLO[-5:], (hd, body)
hd, body = fetch(b"/hello.txt", [(b"range", b"bytes=12-")])
assert hd.get(b":status") == b"206" and body == HELLO[12:], (hd, body)

# unsatisfiable: bodiless 416 naming the actual length, no validators
hd, body = fetch(b"/hello.txt", [(b"range", b"bytes=999999-")])
assert hd.get(b":status") == b"416", hd
assert body == b"", body
assert hd.get(b"content-range") == b"bytes */%d" % len(HELLO), hd
assert b"etag" not in hd, hd

# If-Range: the range applies only on a strong validator match
hd, body = fetch(b"/hello.txt", [(b"range", b"bytes=5-9"), (b"if-range", etag)])
assert hd.get(b":status") == b"206" and body == HELLO[5:10], (hd, body)
hd, body = fetch(b"/hello.txt", [(b"range", b"bytes=5-9"),
                                 (b"if-range", b'"stale"')])
assert hd.get(b":status") == b"200" and body == HELLO, (hd, body)

# malformed / multi-range: ignored in favour of the full 200
hd, body = fetch(b"/hello.txt", [(b"range", b"bytes=1-2,4-5")])
assert hd.get(b":status") == b"200" and body == HELLO, (hd, body)

# a large mid-file slice: streamed as chunks read from the middle of the
# mapping — wrong-offset or wrong-length breaks the pattern equality
hd, body = fetch(b"/h3range.bin", [(b"range", b"bytes=50000-149999")])
assert hd.get(b":status") == b"206", hd
assert hd.get(b"content-length") == b"100000", hd
assert hd.get(b"content-range") == b"bytes 50000-149999/200000", hd
assert body == BIG[50000:150000], (len(body), body[:16].hex())
assert re.match(DATE_RE, hd.get(b"date", b"")), hd

print("ok")
