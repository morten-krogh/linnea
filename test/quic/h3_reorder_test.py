#!/usr/bin/env python3
# A request whose field section spans several packets, delivered out of order.
#
# The request-stream reassembler places each STREAM frame at its offset and
# advances a contiguous prefix, tracking which bytes have arrived in a bitmap.
# Everything else in the h3 suite sends a request that fits one packet, so the
# reassembler only ever saw offset 0 with no gap; the interesting cases are a
# hole that opens and later fills, and offsets that do not land on a byte
# boundary of the bitmap.
#
# A large header makes the QPACK field section span several packets. The
# datagrams are collected and then sent in reverse (and shuffled), so the
# server sees the tail first and must buffer it, hold an incomplete prefix,
# and only serve once the hole is filled.
# Usage: h3_reorder_test.py <port>
import os
import random
import socket
import ssl
import sys

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

WWW = os.path.join(os.environ.get("LINNEA_TEST_RUNDIR", "test"), "www")
# the run's own document root: a copy, so a run may generate into it and
# delete from it without colliding with a suite running beside it

ADDR = None


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


def fetch_reordered(port, path, filler, order):
    """GET `path` with a big header, delivering the request datagrams in `order`."""
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    conn.connect(ADDR, now=0.0)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)

    def flush(t):
        for d, _ in conn.datagrams_to_send(now=t):
            s.sendto(d, ADDR)

    flush(0.0)
    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ADDR, now=0.1)
    flush(0.2)
    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ADDR, now=0.3)
    assert conn._handshake_confirmed, "handshake not confirmed"
    while conn.next_event() is not None:
        pass

    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"GET"),
                               (b":path", path.encode()),
                               (b":scheme", b"https"),
                               (b":authority", b"h3.test"),
                               (b"cookie", filler)])
    conn.send_stream_data(0, vlq(1) + vlq(len(fields)) + fields, end_stream=True)

    # collect rather than send, so the order is ours to choose
    dgrams = [d for d, _ in conn.datagrams_to_send(now=0.4)]
    assert len(dgrams) > 1, f"request fit in one datagram ({len(dgrams)}); no gap to test"
    for i in order(range(len(dgrams))):
        s.sendto(dgrams[i], ADDR)

    resp = b""
    deadline = 0.5
    try:
        while True:
            r, _ = s.recvfrom(4096)
            conn.receive_datagram(r, ADDR, now=deadline)
            deadline += 0.1
            ev = conn.next_event()
            while ev is not None:
                if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
                    resp += ev.data
                ev = conn.next_event()
            if resp:
                break
    except socket.timeout:
        pass
    s.close()

    frames, i = [], 0
    while i < len(resp):
        t, i = rvlq(resp, i)
        ln, i = rvlq(resp, i)
        frames.append((t, resp[i:i + ln]))
        i += ln
    hdr = next((p for t, p in frames if t == 1), None)
    assert hdr is not None, f"no HEADERS frame in {len(resp)} response bytes"
    body = next((p for t, p in frames if t == 0), b"")
    dec = pylsqpack.Decoder(0, 0)
    _, headers = dec.feed_header(0, hdr)
    return dict(headers), body


port = int(sys.argv[1])
ADDR = ("127.0.0.1", port)
want = open(os.path.join(WWW, "hello.txt"), "rb").read()

# Header sizes chosen so the field section ends at a variety of offsets — the
# bitmap is per bit, so a frame boundary that is not a multiple of 8 is exactly
# where a byte-per-byte map and a bit map would diverge. The larger sizes also
# cover the QPACK literal scratch: at 2048 it overflowed, and the overflow was
# reported as a decompression failure that killed the whole connection.
for size in (1500, 1701, 2001, 2500, 3003):
    filler = b"x" * size
    for name, order in (("in order", list),
                        ("reversed", lambda r: list(r)[::-1]),
                        ("shuffled", lambda r: random.sample(list(r), len(list(r))))):
        hd, body = fetch_reordered(port, "/hello.txt", filler, order)
        assert hd.get(b":status") == b"200", (size, name, hd)
        assert body == want, (size, name, len(body))
print("ok (multi-packet requests reassembled reversed and shuffled)")
