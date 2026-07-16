#!/usr/bin/env python3
"""Differential test: linnea's Ed25519 signing vs the reference.

Ed25519 signatures are deterministic, so a correct signer is byte-exact.
Two layers:
  1. The Python reference (gen_vectors.ed25519_sign) is validated against
     OpenSSL over a sample — an independent, well-tested oracle.
  2. linnea's assembly (`ed25519-stdin`) is compared to the reference over
     many random (seed, message) pairs.

Usage: diff_ed25519.py [count]   (default 20000)

Dev-time harness. Exits non-zero on the first mismatch.
"""
import os
import random
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
from gen_vectors import ed25519_sign

BIN = os.path.join(os.path.dirname(__file__), "..", "..", "bin",
                   "linnea-selftest")
# PKCS#8 DER prefix for a raw Ed25519 private key, followed by the 32-byte seed.
PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")


def openssl_check(rng, n):
    """Confirm the Python reference matches OpenSSL on n random inputs."""
    with tempfile.TemporaryDirectory() as d:
        der, pem, mfile, sfile = (os.path.join(d, f)
                                  for f in ("k.der", "k.pem", "m", "s"))
        for i in range(n):
            seed = rng.randbytes(32)
            msg = rng.randbytes(rng.randint(0, 300))
            open(der, "wb").write(PKCS8_PREFIX + seed)
            subprocess.run(["openssl", "pkey", "-inform", "DER", "-in", der,
                            "-out", pem], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            open(mfile, "wb").write(msg)
            subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey",
                            pem, "-in", mfile, "-out", sfile], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if open(sfile, "rb").read() != ed25519_sign(seed, msg):
                print("reference disagrees with OpenSSL at #%d" % i)
                sys.exit(1)
    print("%d inputs: Python reference matches OpenSSL" % n)


def asm_check(rng, count):
    proc = subprocess.Popen([BIN, "ed25519-stdin"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    checked = 0
    try:
        for _ in range(count):
            seed = rng.randbytes(32)
            msg = rng.randbytes(rng.randint(0, 400))
            frame = seed + msg
            proc.stdin.write(struct.pack("<I", len(frame)))
            proc.stdin.write(frame)
            proc.stdin.flush()
            got = proc.stdout.read(64)
            want = ed25519_sign(seed, msg)
            if got != want:
                print("MISMATCH at #%d\n  seed %s\n  msg  %s\n"
                      "  got  %s\n  want %s"
                      % (checked, seed.hex(), msg.hex(),
                         got.hex(), want.hex()))
                sys.exit(1)
            checked += 1
            if checked % 5_000 == 0:
                print("%d ok" % checked, file=sys.stderr)
    finally:
        proc.stdin.close()
        proc.wait()
    print("%d random signatures match the reference" % checked)


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 20_000
    rng = random.Random(20260716)
    openssl_check(rng, 64)
    asm_check(rng, count)


if __name__ == "__main__":
    main()
