#!/usr/bin/env python3
# Build an HTTP/3 response with linnea_h3_build_response (via linnea-h3resp),
# parse the frame layer, and QPACK-decode the HEADERS frame with pylsqpack (the
# QPACK library aioquic uses) against a zero-capacity dynamic table. Checks the
# status, content-type, content-length and DATA body round-trip.
# Usage: h3resp_test.py   (needs pylsqpack; run from the repo root)
import subprocess
import sys

import pylsqpack


def rvlq(b, i):
    pre = b[i] >> 6
    n = 1 << pre
    v = b[i] & 0x3F
    for k in range(1, n):
        v = (v << 8) | b[i + k]
    return v, i + n


data = subprocess.run(["./bin/linnea-h3resp"], capture_output=True).stdout

frames = []
i = 0
while i < len(data):
    ftype, i = rvlq(data, i)
    flen, i = rvlq(data, i)
    frames.append((ftype, data[i:i + flen]))
    i += flen

headers_payload = next((p for t, p in frames if t == 1), None)
data_payload = next((p for t, p in frames if t == 0), None)
assert headers_payload is not None, "no HEADERS frame"
assert data_payload is not None, "no DATA frame"

dec = pylsqpack.Decoder(0, 0)
_, headers = dec.feed_header(0, headers_payload)
hd = dict(headers)

assert hd.get(b":status") == b"200", hd
assert hd.get(b"content-type") == b"text/plain", hd
assert hd.get(b"content-length") == str(len(data_payload)).encode(), hd
assert data_payload == b"hello over http/3\n", data_payload
print("ok")
