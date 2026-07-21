#!/usr/bin/env python3
# Frame HTTP/3 request streams and check linnea_h3_read_headers walks the frame
# layer, skips DATA/unknown frames, and QPACK-decodes the HEADERS frame to the
# right pseudo-headers. The field section is produced by pylsqpack against a
# zero-capacity dynamic table (static + literals), matching what linnea offers.
# Usage: h3_test.py   (needs pylsqpack; run from the repo root)
import subprocess
import sys

import pylsqpack


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def headers_frame(headers):
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, headers)
    return vlq(0x01) + vlq(len(fields)) + fields


REQ = [(b":method", b"GET"), (b":path", b"/hello.txt"), (b":scheme", b"https"),
       (b":authority", b"linnea.amberbio.com"), (b"accept", b"*/*")]
WANT = ["GET", "/hello.txt", "https", "linnea.amberbio.com"]

hf = headers_frame(REQ)
CASES = [
    ("plain", hf),
    # an unknown (grease) frame type before HEADERS must be skipped
    ("skip-unknown", vlq(0x21) + vlq(3) + b"\x00\x00\x00" + hf),
    # a DATA frame before HEADERS must be skipped
    ("skip-data", vlq(0x00) + vlq(4) + b"body" + hf),
]

fails = 0
for label, stream in CASES:
    r = subprocess.run(["./bin/linnea-h3test"], input=stream, capture_output=True)
    got = r.stdout.decode().splitlines()
    if r.returncode != 0 or got != WANT:
        fails += 1
        print(f"FAIL {label}: rc={r.returncode} got={got}", file=sys.stderr)

if fails:
    sys.exit(1)
print("ok")
