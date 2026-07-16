#!/usr/bin/env python3
"""Differential test: linnea's X25519 vs a Python reference (RFC 7748).

Two checks:
  1. Random (scalar, u) pairs streamed through `linnea-selftest x25519-stdin`,
     each result compared to the reference.
  2. The RFC's k=u=9 recurrence at 1,000,000 rounds via `x25519-iter`,
     compared to the published answer — the ladder's deepest stress.

Usage: diff_x25519.py [count]   (default 50000 random pairs)

Dev-time harness, not part of the fast suite. Exits non-zero on mismatch.
"""
import os
import random
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from gen_vectors import x25519, x25519_iter   # the reference

BIN = os.path.join(os.path.dirname(__file__), "..", "..", "bin",
                   "linnea-selftest")
RFC_1M = "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"


def random_check(count):
    rng = random.Random(20260716)
    proc = subprocess.Popen([BIN, "x25519-stdin"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    checked = 0
    try:
        for _ in range(count):
            scalar = rng.randbytes(32)
            u = rng.randbytes(32)
            proc.stdin.write(scalar)
            proc.stdin.write(u)
            proc.stdin.flush()
            got = proc.stdout.read(32)
            want = x25519(scalar, u)
            if got != want:
                print("MISMATCH at #%d\n  scalar %s\n  u     %s\n"
                      "  got   %s\n  want  %s"
                      % (checked, scalar.hex(), u.hex(),
                         got.hex(), want.hex()))
                sys.exit(1)
            checked += 1
            if checked % 10_000 == 0:
                print("%d ok" % checked, file=sys.stderr)
    finally:
        proc.stdin.close()
        proc.wait()
    print("%d random pairs, all match" % checked)


def iter_check():
    print("running the 1,000,000-round recurrence "
          "(both linnea and the reference)...", file=sys.stderr)
    got = subprocess.run([BIN, "x25519-iter", "1000000"],
                         capture_output=True).stdout
    if got.hex() != RFC_1M:
        print("1M MISMATCH\n  got  %s\n  want %s" % (got.hex(), RFC_1M))
        sys.exit(1)
    # cross-check the reference against the RFC constant too
    assert x25519_iter(1000) .hex() == \
        "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
    print("1,000,000-round recurrence matches RFC 7748")


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 50_000
    random_check(count)
    iter_check()


if __name__ == "__main__":
    main()
