#!/usr/bin/env python3
# Frame HTTP/3 request streams and check linnea_h3_read_headers walks the frame
# layer, skips GREASE/unknown frames (a DATA before HEADERS is now rejected), and QPACK-decodes the HEADERS frame to the
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


def data_frame(body):
    return vlq(0x00) + vlq(len(body)) + body


REQ = [(b":method", b"GET"), (b":path", b"/hello.txt"), (b":scheme", b"https"),
       (b":authority", b"linnea.amberbio.com"), (b"accept", b"*/*")]
# The pseudo-headers, then the body, then the fields rebuilt as h1 lines. The
# rebuild is what a proxied request forwards, and printing it is what makes the
# LAST field of a block covered — checking pseudo-headers alone left it unseen,
# so a decode one byte short went unnoticed.
WANT = ["GET", "/hello.txt", "https", "linnea.amberbio.com"]
REBUILT = ["accept: */*"]

hf = headers_frame(REQ)
# The body is the concatenation of every DATA frame's payload (RFC 9114 4.1),
# however the encoder chose to split it — the last line of the harness's output
# is the body linnea recovered.
big = bytes((i * 7 + 3) % 26 + 97 for i in range(900))
CASES = [
    ("plain", hf, WANT + [""] + REBUILT),
    # an unknown (grease) frame type before HEADERS must be skipped
    ("skip-unknown", vlq(0x21) + vlq(3) + b"\x00\x00\x00" + hf, WANT + [""] + REBUILT),
    ("one-data", hf + data_frame(b"ABCDEFGH"), WANT + ["ABCDEFGH"] + REBUILT),
    ("split-data", hf + data_frame(b"ABCD") + data_frame(b"EFGH"),
     WANT + ["ABCDEFGH"] + REBUILT),
    # three frames, the middle one empty, and a trailing grease frame between two
    # of them: the payloads still join in order and nothing else leaks in
    ("split-data-gaps",
     hf + data_frame(b"AB") + data_frame(b"") + vlq(0x21) + vlq(2) + b"xx"
        + data_frame(b"CD") + data_frame(b"EF"),
     WANT + ["ABCDEF"] + REBUILT),
    # a split whose pieces are long enough that the moves overlap heavily
    ("split-data-big",
     hf + b"".join(data_frame(big[i:i + 100]) for i in range(0, len(big), 100)),
     WANT + [big.decode()] + REBUILT),
]

fails = 0
for label, stream, want in CASES:
    r = subprocess.run(["./bin/linnea-h3test"], input=stream, capture_output=True)
    got = r.stdout.decode().splitlines()
    if r.returncode != 0 or got != want:
        fails += 1
        print(f"FAIL {label}: rc={r.returncode} got={got}", file=sys.stderr)

# The same streams, fed to the walk a few bytes at a time. Every fragmentation
# must reach the same verdict and the same body as one call with the lot: a
# frame header, a field section and a payload can each be split at any byte,
# and a walk that carries its position wrongly across one of those boundaries
# is exactly the failure the incremental upload path would rest on. A size of 1
# is the brutal case — every varint arrives a byte at a time.
#
# The network cannot be made to split where a test wants, so this is driven
# through the walk directly rather than over QUIC.
for label, stream, want in CASES:
    for n in (1, 2, 3, 5, 7, 13, 64, 1000):
        r = subprocess.run(["./bin/linnea-h3test", str(n)],
                           input=stream, capture_output=True)
        got = r.stdout.decode().splitlines()
        if r.returncode != 0 or got != want:
            fails += 1
            print(f"FAIL {label} fragmented by {n}: rc={r.returncode} got={got}",
                  file=sys.stderr)

# ...and again with the body going to a SINK rather than being joined in place.
# That is the path a spilled upload takes, and it must recover the same body:
# the sink is handed one run per piece of DATA payload, in order, and appending
# them has to reconstruct exactly what the in-place join produces. Combined
# with fragmentation because that is the combination the real thing runs — a
# payload split across STREAM frames becomes two runs to the sink.
for label, stream, want in CASES:
    for n in (0, 1, 2, 5, 13, 1000):
        r = subprocess.run(["./bin/linnea-h3test", str(n or 1000000), "sink"],
                           input=stream, capture_output=True)
        got = r.stdout.decode().splitlines()
        if r.returncode != 0 or got != want:
            fails += 1
            print(f"FAIL {label} sink fragmented by {n}: rc={r.returncode} "
                  f"got={got}", file=sys.stderr)

# ...and with the field section HELD and decoded at the end, which is how a
# stream consumed as it arrives has to do it: decoding when the headers land
# would mean carrying the decoder's output -- the request, the arena its
# pointers reach into, the rebuilt header lines -- per stream until it is
# served. Deferring must reach the same request as decoding inline.
for label, stream, want in CASES:
    for n in (0, 1, 2, 5, 13, 1000):
        r = subprocess.run(["./bin/linnea-h3test", str(n or 1000000), "defer"],
                           input=stream, capture_output=True)
        got = r.stdout.decode().splitlines()
        if r.returncode != 0 or got != want:
            fails += 1
            print(f"FAIL {label} deferred fragmented by {n}: rc={r.returncode} "
                  f"got={got}", file=sys.stderr)

if fails:
    sys.exit(1)
print("ok")
