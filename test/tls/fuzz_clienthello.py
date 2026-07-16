#!/usr/bin/env python3
"""Fuzz the linnea TLS handshake with malformed ClientHellos.

Every case must leave the server alive and responsive: linnea either
completes/refuses the handshake or closes, but never crashes. Each
connection sends one payload, half-closes so the server sees EOF
promptly (no timeout stall), reads whatever comes back, and moves on.
A live-probe handshake with python ssl runs at the end to prove the
server still serves real clients.

usage: fuzz_clienthello.py <cafile> <port> [count]   (default 500)

Dev-time harness; run bigger counts for a soak. Exits non-zero if the
server dies or stops handshaking.
"""
import os
import random
import socket
import ssl
import sys


def one(port, payload, rng):
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall(payload)
        s.shutdown(socket.SHUT_WR)      # server reads EOF, won't block
        try:
            while s.recv(4096):
                pass
        except OSError:
            pass
    finally:
        s.close()


def live_probe(port, cafile):
    ctx = ssl.create_default_context(cafile=cafile)
    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as s:
            assert s.version() == "TLSv1.3"
            s.sendall(b"alive?")
            assert s.recv(16) == b"alive?"


def main():
    cafile, port = sys.argv[1], int(sys.argv[2])
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 500
    rng = random.Random(20260716)
    base = None
    seed_ch = os.path.join(os.path.dirname(__file__), "clienthello_seed.bin")
    if os.path.exists(seed_ch):
        base = open(seed_ch, "rb").read()

    for i in range(count):
        pick = rng.random()
        if pick < 0.35:                          # wholly random bytes
            n = rng.randint(1, 400)
            p = bytes(rng.randrange(256) for _ in range(n))
        elif pick < 0.55:                        # valid header, junk body
            n = rng.randint(0, 300)
            body = bytes(rng.randrange(256) for _ in range(n))
            p = b"\x16\x03\x01" + len(body).to_bytes(2, "big") + body
        elif base and pick < 0.85:               # mutated real ClientHello
            b = bytearray(base)
            for _ in range(rng.randint(1, 10)):
                b[rng.randrange(len(b))] = rng.randrange(256)
            cut = rng.randint(5, len(b))
            p = bytes(b[:cut])
        else:                                    # oversized length claims
            body = bytes(rng.randrange(256) for _ in range(rng.randint(0, 50)))
            p = b"\x16\x03\x01\xff\xff" + body
        one(port, p, rng)
        if i % 100 == 99:
            live_probe(port, cafile)             # still handshaking?
            print("%d fuzzed, server still serving" % (i + 1),
                  file=sys.stderr)

    live_probe(port, cafile)
    print("%d malformed ClientHellos survived; server still completes a "
          "real TLS 1.3 handshake" % count)


if __name__ == "__main__":
    main()
