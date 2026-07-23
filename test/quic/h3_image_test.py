#!/usr/bin/env python3
# A real image over HTTP/3: fetch a PNG and confirm it comes back byte-exact with
# content-type image/png. Beyond a synthetic large body (h3_big_test), this
# checks the static file path end to end for a genuine binary asset — the MIME
# type from the extension and the chunked delivery of a multi-hundred-chunk file.
# Usage: h3_image_test.py <port> <docroot>
import os
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

PORT = int(sys.argv[1])
DOCROOT = sys.argv[2]
ADDR = ("127.0.0.1", PORT)
want = open(os.path.join(DOCROOT, "linnea.png"), "rb").read()


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


cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
conn.connect(ADDR, now=time.time())
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.5)


# A virtual clock that advances on every use. aioquic decides when to send ACKs
# from the time it is told, so a real-time clock over fast loopback (where a loop
# iteration is microseconds) makes it defer ACKs and starve the transfer — an
# artefact of this drive loop, not the server. Advancing the clock deliberately,
# as a real event loop effectively does, makes it acknowledge promptly.
vt = [0.0]


def clk():
    vt[0] += 0.02
    return vt[0]


def flush():
    for d, _ in conn.datagrams_to_send(now=clk()):
        s.sendto(d, ADDR)


flush()
while not conn._handshake_confirmed:
    try:
        r, _ = s.recvfrom(4096)
        conn.receive_datagram(r, ADDR, now=clk())
    except socket.timeout:
        conn.handle_timer(now=clk())
    flush()
while conn.next_event():
    pass

enc = pylsqpack.Encoder()
enc.apply_settings(max_table_capacity=0, blocked_streams=0)
_, f = enc.encode(0, [(b":method", b"GET"), (b":path", b"/linnea.png"),
                      (b":scheme", b"https"), (b":authority", b"h3.test")])
sid = conn.get_next_available_stream_id()
conn.send_stream_data(sid, vlq(1) + vlq(len(f)) + f, end_stream=True)

raw = b""
fin = False
deadline = time.time() + 30
while not fin and time.time() < deadline:
    flush()
    try:
        r, _ = s.recvfrom(4096)
    except socket.timeout:
        conn.handle_timer(now=clk())
        continue
    conn.receive_datagram(r, ADDR, now=clk())
    ev = conn.next_event()
    while ev:
        if isinstance(ev, StreamDataReceived) and ev.stream_id == sid:
            raw += ev.data
            fin = fin or ev.end_stream
        ev = conn.next_event()

assert fin, "image response did not finish"
i = 0
hdr = None
body = b""
while i < len(raw):
    t, i = rvlq(raw, i)
    ln, i = rvlq(raw, i)
    if t == 1:
        hdr = raw[i:i + ln]
    elif t == 0:
        body += raw[i:i + ln]
    i += ln
dec = pylsqpack.Decoder(0, 0)
_, headers = dec.feed_header(0, hdr)
headers = dict(headers)
assert headers.get(b":status") == b"200", headers
assert headers.get(b"content-type") == b"image/png", headers
assert headers.get(b"content-length") == str(len(want)).encode(), headers
assert body == want, f"image corrupted ({len(body)} vs {len(want)} bytes)"
s.close()
print(f"ok ({len(want)} B PNG served intact over h3, image/png)")
