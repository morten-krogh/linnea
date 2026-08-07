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

# Each case also names the h1 header lines the decode must rebuild for an
# upstream request: emit_field appends every forwardable field as
# "name: value CRLF" once hb_start is armed, which is how a proxied h3 request
# carries a header the request struct has no field of its own for. Names that
# are hop-by-hop or that the proxy re-declares itself (host, content-length,
# te) must not appear; connection-specific ones are refused outright and are
# covered by REFUSED below.
CASES = [
    # (headers, expected method, path, scheme, authority, rebuilt lines)
    ([(b":method", b"GET"), (b":path", b"/index.html"),
      (b":scheme", b"https"), (b":authority", b"example.com"),
      (b"user-agent", b"linnea-test"), (b"accept", b"*/*")],
     "GET", "/index.html", "https", "example.com",
     ["user-agent: linnea-test", "accept: */*"]),
    # a longer, non-static path forces a literal value with Huffman coding
    ([(b":method", b"POST"), (b":path", b"/api/v1/resource?q=quic-h3"),
      (b":scheme", b"https"), (b":authority", b"linnea.amberbio.com"),
      (b"content-type", b"application/json"), (b"content-length", b"17")],
     "POST", "/api/v1/resource?q=quic-h3", "https", "linnea.amberbio.com",
     # content-length is the proxy's to declare, so it is not forwarded
     ["content-type: application/json"]),
    # HEAD with a bare path and a custom (literal-name) header
    ([(b":method", b"HEAD"), (b":path", b"/"),
      (b":scheme", b"http"), (b":authority", b"h3.test"),
      (b"x-linnea-marker", b"z")],
     "HEAD", "/", "http", "h3.test",
     ["x-linnea-marker: z"]),
    # the header an upload depends on has no field in the request struct, so it
    # reaches the backend only through the rebuild; host and te are dropped
    ([(b":method", b"POST"), (b":path", b"/api/upload"),
      (b":scheme", b"https"), (b":authority", b"one.test"),
      (b"x-filename", b"holiday%20photo.jpg"), (b"host", b"spoofed.example"),
      (b"te", b"trailers"), (b"content-length", b"1234")],
     "POST", "/api/upload", "https", "one.test",
     ["x-filename: holiday%20photo.jpg"]),
]

# Connection-specific fields make an h3 request malformed (RFC 9114 4.2), so
# they must be refused rather than merely stripped from the rebuild.
REFUSED = [
    [(b":method", b"GET"), (b":path", b"/"), (b":scheme", b"https"),
     (b":authority", b"a"), (b"connection", b"keep-alive")],
    [(b":method", b"GET"), (b":path", b"/"), (b":scheme", b"https"),
     (b":authority", b"a"), (b"keep-alive", b"timeout=5")],
]

fails = 0
for headers, m, p, sch, auth, rebuilt in CASES:
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, data = enc.encode(0, headers)
    r = subprocess.run(["./bin/linnea-qpacktest"], input=data,
                       capture_output=True)
    lines = r.stdout.decode().splitlines()
    got, got_rebuilt = lines[:4], [x.rstrip("\r") for x in lines[4:]]
    want = [m, p, sch, auth]
    if r.returncode != 0 or got != want or got_rebuilt != rebuilt:
        fails += 1
        print(f"FAIL rc={r.returncode} got={got} want={want} "
              f"rebuilt={got_rebuilt} wanted={rebuilt}", file=sys.stderr)

for headers in REFUSED:
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, data = enc.encode(0, headers)
    r = subprocess.run(["./bin/linnea-qpacktest"], input=data, capture_output=True)
    if r.returncode == 0:
        fails += 1
        name = headers[-1][0].decode()
        print(f"FAIL {name} was accepted; it is connection-specific",
              file=sys.stderr)

if fails:
    sys.exit(1)
print("ok")
