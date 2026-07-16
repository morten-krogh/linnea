#!/usr/bin/env python3
"""Differential test: linnea's SHA-256 vs Python's hashlib over many random
inputs. Drives one `linnea-selftest sha256-stdin` process, streaming
length-prefixed frames and checking each returned digest.

Usage: diff_sha256.py [count]   (default 1_000_000)

This is a dev-time harness (minutes at a million), not part of the fast
suite — the precedent is the linnea_time module's differential check
against glibc. Exits non-zero on the first mismatch.
"""
import hashlib
import os
import random
import struct
import subprocess
import sys

BIN = os.path.join(os.path.dirname(__file__), "..", "..", "bin",
                   "linnea-selftest")

# A distribution weighted toward the sizes most likely to expose bugs:
# empty, sub-block, the 55/56/64 padding boundaries, multi-block.
def random_len(rng):
    bucket = rng.random()
    if bucket < 0.15:
        return rng.randint(0, 3)
    if bucket < 0.45:
        return rng.choice([54, 55, 56, 57, 63, 64, 65])
    if bucket < 0.8:
        return rng.randint(0, 200)
    return rng.randint(0, 4096)


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 1_000_000
    rng = random.Random(20260716)   # fixed seed: reproducible runs
    proc = subprocess.Popen([BIN, "sha256-stdin"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    checked = 0
    try:
        for _ in range(count):
            n = random_len(rng)
            data = rng.randbytes(n)
            proc.stdin.write(struct.pack("<I", n))
            proc.stdin.write(data)
            proc.stdin.flush()
            got = proc.stdout.read(32)
            want = hashlib.sha256(data).digest()
            if got != want:
                print("MISMATCH at #%d, len %d\n  got  %s\n  want %s"
                      % (checked, n, got.hex(), want.hex()))
                sys.exit(1)
            checked += 1
            if checked % 100_000 == 0:
                print("%d ok" % checked, file=sys.stderr)
    finally:
        proc.stdin.close()
        proc.wait()
    print("%d inputs, all match" % checked)


if __name__ == "__main__":
    main()
