#!/usr/bin/env python3
# HTTP/3 across several workers. Each worker binds the QUIC port with
# SO_REUSEPORT and the kernel steers each datagram by its 4-tuple, so every
# packet of a given connection reaches the worker holding that connection's
# pool. Opening many connections from different source ports spreads them over
# the workers; each must still get its own file back intact.
# Usage: h3_workers_test.py <port> [count]
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


def fetch(port, path):
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

    try:
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
        _, fields = enc.encode(0, [(b":method", b"GET"),
                                   (b":path", path.encode()),
                                   (b":scheme", b"https"),
                                   (b":authority", b"h3.test")])
        conn.send_stream_data(0, vlq(1) + vlq(len(fields)) + fields,
                              end_stream=True)
        flush(0.4)
        r, _ = s.recvfrom(4096)
        conn.receive_datagram(r, ("127.0.0.1", port), now=0.5)
        resp = b""
        ev = conn.next_event()
        while ev is not None:
            if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
                resp += ev.data
            ev = conn.next_event()
    finally:
        s.close()

    frames = []
    i = 0
    while i < len(resp):
        t, i = rvlq(resp, i)
        length, i = rvlq(resp, i)
        frames.append((t, resp[i:i + length]))
        i += length
    return next(p for t, p in frames if t == 0)


port = int(sys.argv[1])
count = int(sys.argv[2]) if len(sys.argv) > 2 else 8
FILES = ["/hello.txt", "/style.css", "/index.html"]

failures = []
for j in range(count):
    path = FILES[j % len(FILES)]
    try:
        body = fetch(port, path)
        want = open("test/www" + path, "rb").read()
        if body != want:
            failures.append(f"connection {j} ({path}): body mismatch")
    except Exception as exc:                       # noqa: BLE001 - report and continue
        failures.append(f"connection {j} ({path}): {exc!r}")

if failures:
    for f in failures:
        print(f, file=sys.stderr)
    sys.exit(1)
print("ok")
