#!/usr/bin/env python3
"""Differential test: linnea's P-256 field arithmetic vs a Python reference.

Random and edge-weighted operands streamed through `linnea-selftest
p256-fe-stdin`, each result compared to gen_vectors.p256_fe. The selftest
converts each operand into Montgomery form, applies the op, and converts
back, so a frame exercises frombytes/tobytes as well as the op.

Why this harness earns its keep: the reduction's carry chain is where this
module can go wrong, and it goes wrong RARELY. A ripple that propagates one
limb short of correct -- the natural thing to write -- passes add, sub and
cmov completely and fails mul about once in 30,000 random operands. Fixed
vectors do not find that; volume does.

Usage: diff_p256_fe.py [count]   (default 50000 random cases per op)

Dev-time harness, not part of the fast suite. Exits non-zero on mismatch.
"""
import os
import random
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from gen_vectors import (P256_P, p256_fe, P256_FE_MUL, P256_FE_SQ,
                         P256_FE_ADD, P256_FE_SUB, P256_FE_INV)

BIN = os.path.join(os.path.dirname(__file__), "..", "..", "bin",
                   "linnea-selftest")

OPS = [("mul", P256_FE_MUL), ("sq", P256_FE_SQ), ("add", P256_FE_ADD),
       ("sub", P256_FE_SUB), ("inv", P256_FE_INV)]

# Operands around p and 2^256 are what drive the carry deep and force the
# conditional subtract; mixing them against random values covers the paths
# a uniform sample reaches only by luck.
EDGE = [0, 1, 2, P256_P - 2, P256_P - 1, P256_P, P256_P + 1,
        2**256 - 1, 2**256 - 2, (P256_P - 1) // 2, (P256_P + 1) // 2,
        2**224, 2**224 - 1, 2**192, 2**96, 2**96 - 1, 2**255,
        2**64, 2**64 - 1, 2**128 - 1]


def operands(count, rng):
    for a in EDGE:
        for b in EDGE:
            yield a, b
    for _ in range(count):
        yield rng.randrange(2**256), rng.randrange(2**256)
    for _ in range(count // 4):
        yield rng.choice(EDGE), rng.randrange(2**256)
        yield rng.randrange(2**256), rng.choice(EDGE)


def check(name, op, count, rng):
    proc = subprocess.Popen([BIN, "p256-fe-stdin"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE)
    bad = checked = 0
    try:
        for a, b in operands(count, rng):
            proc.stdin.write(bytes([op]) + a.to_bytes(32, "big")
                             + b.to_bytes(32, "big"))
            proc.stdin.flush()
            got = int.from_bytes(proc.stdout.read(32), "big")
            want = p256_fe(op, a, b)
            if got != want:
                if bad < 3:
                    print("MISMATCH %s #%d\n  a    %064x\n  b    %064x\n"
                          "  got  %064x\n  want %064x"
                          % (name, checked, a, b, got, want))
                bad += 1
            checked += 1
    finally:
        proc.stdin.close()
        proc.wait()
    print("  %-4s %7d cases  %s" % (name, checked,
                                    "ok" if not bad else "%d BAD" % bad))
    return bad


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 50000
    rng = random.Random(20260717)
    bad = 0
    for name, op in OPS:
        # inv is ~256 field multiplies a call; keep its sample proportionate
        n = count // 100 if op == P256_FE_INV else count
        bad += check(name, op, n, rng)
    if bad:
        print("FAIL: %d mismatches" % bad)
        return 1
    print("p256-fe differential OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
