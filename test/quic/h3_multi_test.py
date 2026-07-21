#!/usr/bin/env python3
# Multiple HTTP/3 requests on one QUIC connection. After the handshake, send
# three GETs on three different client-initiated bidirectional streams in the
# same flush — they arrive coalesced as several STREAM frames in one packet —
# and check linnea walks them all and answers each on the stream it arrived on,
# with the correct file, MIME type and body.
# Usage: h3_multi_test.py <port>
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


PATHS = {0: ("/hello.txt", b"text/plain"),
         4: ("/style.css", b"text/css"),
         8: ("/index.html", b"text/html")}

port = int(sys.argv[1])
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
conn.connect(("127.0.0.1", port), now=0.0)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)


def flush(t):
    for d, _ in conn.datagrams_to_send(now=t):
        s.sendto(d, ("127.0.0.1", port))


flush(0.0)
r, _ = s.recvfrom(4096)
conn.receive_datagram(r, ("127.0.0.1", port), now=0.1)
flush(0.2)                                        # client Finished
r, _ = s.recvfrom(4096)
conn.receive_datagram(r, ("127.0.0.1", port), now=0.3)     # HANDSHAKE_DONE
assert conn._handshake_confirmed, "handshake not confirmed"
while conn.next_event() is not None:
    pass

for sid, (path, _) in PATHS.items():
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(sid, [(b":method", b"GET"),
                                 (b":path", path.encode()),
                                 (b":scheme", b"https"),
                                 (b":authority", b"h3.test")])
    conn.send_stream_data(sid, vlq(1) + vlq(len(fields)) + fields,
                          end_stream=True)
flush(0.4)

data = {}
for _ in range(8):
    try:
        r, _ = s.recvfrom(4096)
    except socket.timeout:
        break
    conn.receive_datagram(r, ("127.0.0.1", port), now=0.5)
    ev = conn.next_event()
    while ev is not None:
        if isinstance(ev, StreamDataReceived):
            data.setdefault(ev.stream_id, b"")
            data[ev.stream_id] += ev.data
        ev = conn.next_event()
    if len(data) == len(PATHS):
        break
s.close()

assert set(data) == set(PATHS), f"answered {sorted(data)} of {sorted(PATHS)}"
for sid, (path, ctype) in PATHS.items():
    resp = data[sid]
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
    _, headers = dec.feed_header(sid, hdr)
    hd = dict(headers)
    assert hd.get(b":status") == b"200", (sid, hd)
    assert hd.get(b"content-type") == ctype, (sid, hd)
    assert body == open("test/www" + path, "rb").read(), (sid, path)

print("ok")
