#!/usr/bin/env python3
"""Fuzz the linnea HTTP/2 frame layer and HPACK decoder.

Each case opens a real TLS 1.3 + ALPN "h2" connection, sends the client
preface followed by malformed / random frames and header blocks, and reads
whatever comes back. Every case must leave the worker alive: linnea either
GOAWAYs, RSTs, or closes, but never crashes. Between batches a live h2 GET
proves the server still serves real clients.

usage: fuzz_h2.py <cafile> <port> [count]   (default 400)

Dev-time harness; exits non-zero if the server dies or stops serving.
"""
import os
import random
import socket
import ssl
import struct
import sys


def h2ctx(cafile):
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    return ctx


def frame(typ, flags, sid, payload):
    return struct.pack(">I", len(payload))[1:] + bytes([typ & 0xff, flags & 0xff]) \
        + struct.pack(">I", sid & 0x7fffffff) + payload


def one(ctx, port, payload):
    raw = socket.create_connection(("127.0.0.1", port), timeout=3)
    s = ctx.wrap_socket(raw, server_hostname="localhost")
    try:
        s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, b"") + payload)
        s.settimeout(2)
        while True:
            if not s.recv(4096):
                break
    except OSError:
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass


def rnd_block(rng):
    return bytes(rng.randrange(256) for _ in range(rng.randint(0, 300)))


def make_payload(rng):
    pick = rng.random()
    if pick < 0.30:                                  # random bytes as frames
        return bytes(rng.randrange(256) for _ in range(rng.randint(1, 500)))
    if pick < 0.50:                                  # random type, random body
        return frame(rng.randrange(256), rng.randrange(256),
                     rng.randrange(1 << 31), rnd_block(rng))
    if pick < 0.72:                                  # HEADERS with junk HPACK
        flags = rng.choice([0x04, 0x05, 0x00, 0x01, 0x08, 0x24])
        return frame(1, flags, rng.choice([1, 3, 0, 2, 1 << 30]), rnd_block(rng))
    if pick < 0.82:                                  # oversized length claim
        body = rnd_block(rng)
        hdr = b"\xff\xff\xff" + bytes([1, 0x04]) + struct.pack(">I", 1)
        return hdr + body
    if pick < 0.90:                                  # CONTINUATION flood
        out = frame(1, 0x00, 1, rnd_block(rng))
        for _ in range(rng.randint(1, 40)):
            out += frame(9, 0x00, 1, rnd_block(rng))
        return out
    if pick < 0.96:                                  # WINDOW_UPDATE / RST / SETTINGS junk
        t = rng.choice([3, 6, 8, 4, 7])
        return frame(t, rng.randrange(256), rng.randrange(4),
                     bytes(rng.randrange(256) for _ in range(rng.choice([0, 3, 4, 8, 17, 100]))))
    # mutated valid request (literal-name HPACK) with a few flipped bytes
    def estr(b):
        return bytes([len(b)]) + b
    block = b"\x00" + estr(b":method") + estr(b"GET") \
        + b"\x00" + estr(b":path") + estr(b"/hello.txt")
    b = bytearray(block)
    for _ in range(rng.randint(1, 6)):
        b[rng.randrange(len(b))] = rng.randrange(256)
    return frame(1, 0x05, 1, bytes(b))


def live_probe(ctx, port):
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=3),
                        server_hostname="localhost")
    try:
        assert s.selected_alpn_protocol() == "h2"

        def estr(x):
            return bytes([len(x)]) + x
        block = b"\x00" + estr(b":method") + estr(b"GET") \
            + b"\x00" + estr(b":scheme") + estr(b"https") \
            + b"\x00" + estr(b":authority") + estr(b"localhost") \
            + b"\x00" + estr(b":path") + estr(b"/hello.txt")
        s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, b"")
                  + frame(1, 0x05, 1, block))
        body = b""
        s.settimeout(3)
        while True:
            h = b""
            while len(h) < 9:
                d = s.recv(9 - len(h))
                if not d:
                    raise AssertionError("closed before response body")
                h += d
            ln = int.from_bytes(h[:3], "big")
            p = b""
            while len(p) < ln:
                p += s.recv(ln - len(p))
            if h[3] == 0:                            # DATA
                body += p
                if h[4] & 1:
                    break
        assert b"hello from linnea" in body, body
    finally:
        s.close()


def main():
    cafile, port = sys.argv[1], int(sys.argv[2])
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 400
    ctx = h2ctx(cafile)
    rng = random.Random(20260721)
    for i in range(count):
        one(ctx, port, make_payload(rng))
        if i % 100 == 99:
            live_probe(ctx, port)
            print("%d fuzzed, server still serving h2" % (i + 1), file=sys.stderr)
    live_probe(ctx, port)
    print("%d malformed h2 streams survived; server still serves h2" % count)


if __name__ == "__main__":
    main()
