#!/usr/bin/env python3
# Encode HTTP/3 request header sets with pylsqpack (the QPACK library aioquic
# uses) against a zero-capacity dynamic table — static-table references and
# literals only, exactly what linnea advertises — and check linnea_qpack_decode
# recovers the pseudo-headers. Exercises indexed fields, literal-with-name-ref,
# literal names, and Huffman-coded values.
# Usage: qpack_test.py   (needs pylsqpack; run from the repo root)
import subprocess
import sys

import pylsqpack

CASES = [
    # (headers, expected method, path, scheme, authority)
    ([(b":method", b"GET"), (b":path", b"/index.html"),
      (b":scheme", b"https"), (b":authority", b"example.com"),
      (b"user-agent", b"linnea-test"), (b"accept", b"*/*")],
     "GET", "/index.html", "https", "example.com"),
    # a longer, non-static path forces a literal value with Huffman coding
    ([(b":method", b"POST"), (b":path", b"/api/v1/resource?q=quic-h3"),
      (b":scheme", b"https"), (b":authority", b"linnea.amberbio.com"),
      (b"content-type", b"application/json"), (b"content-length", b"17")],
     "POST", "/api/v1/resource?q=quic-h3", "https", "linnea.amberbio.com"),
    # HEAD with a bare path and a custom (literal-name) header
    ([(b":method", b"HEAD"), (b":path", b"/"),
      (b":scheme", b"http"), (b":authority", b"h3.test"),
      (b"x-linnea-marker", b"z")],
     "HEAD", "/", "http", "h3.test"),
]

fails = 0
for headers, m, p, sch, auth in CASES:
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, data = enc.encode(0, headers)
    r = subprocess.run(["./bin/linnea-qpacktest"], input=data,
                       capture_output=True)
    got = r.stdout.decode().splitlines()
    want = [m, p, sch, auth]
    if r.returncode != 0 or got != want:
        fails += 1
        print(f"FAIL rc={r.returncode} got={got} want={want}", file=sys.stderr)

if fails:
    sys.exit(1)
print("ok")
