#!/usr/bin/env python3
"""Differential test: linnea's P-256 Montgomery arithmetic vs a Python
reference, for both of the curve's moduli.

P-256 needs two: the field prime p, where point coordinates live, and the
group order n, where ECDSA's scalars live. One assembly core serves both,
bound to a modulus context; this drives each binding through its own selftest
stdin mode and compares against the reference in gen_vectors.

Why this harness earns its keep: the reduction's carry chain is where the
core can go wrong, and it goes wrong RARELY. A ripple that propagates one
limb short of correct -- the natural thing to write -- passes add and sub
completely and fails mul about once in 30,000 random operands. Fixed vectors
do not find that; volume does. Both moduli are checked, since n's carry
behaviour is not inherited from p's.

Usage: diff_p256.py [count] [fe|scalar]   (default 50000 per op, both)

Dev-time harness, not part of the fast suite. Exits non-zero on mismatch.
"""
import os
import random
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from gen_vectors import (P256_P, P256_N, p256_fe, p256_scalar, P256_FE_MUL,
                         P256_FE_SQ, P256_FE_ADD, P256_FE_SUB, P256_FE_INV)

BIN = os.path.join(os.path.dirname(__file__), "..", "..", "bin",
                   "linnea-selftest")

# (name, stdin mode, modulus, reference, ops). sq exists only on the field
# side: nothing squares a scalar.
BINDINGS = [
    ("fe", "p256-fe-stdin", P256_P, p256_fe,
     [("mul", P256_FE_MUL), ("sq", P256_FE_SQ), ("add", P256_FE_ADD),
      ("sub", P256_FE_SUB), ("inv", P256_FE_INV)]),
    ("scalar", "p256-scalar-stdin", P256_N, p256_scalar,
     [("mul", P256_FE_MUL), ("add", P256_FE_ADD), ("sub", P256_FE_SUB),
      ("inv", P256_FE_INV)]),
]


def edges(m):
    """Operands around the modulus and 2^256 are what drive the carry deep
    and force the conditional subtract; mixing them against random values
    covers paths a uniform sample reaches only by luck."""
    return [0, 1, 2, m - 2, m - 1, m, m + 1, 2**256 - 1, 2**256 - 2,
            (m - 1) // 2, (m + 1) // 2, 2**224, 2**224 - 1, 2**192,
            2**128, 2**96, 2**96 - 1, 2**255, 2**64, 2**64 - 1]


def operands(count, rng, edge):
    for a in edge:
        for b in edge:
            yield a, b
    for _ in range(count):
        yield rng.randrange(2**256), rng.randrange(2**256)
    for _ in range(count // 4):
        yield rng.choice(edge), rng.randrange(2**256)
        yield rng.randrange(2**256), rng.choice(edge)


def check(mode, name, op, ref, edge, count, rng):
    proc = subprocess.Popen([BIN, mode], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE)
    bad = checked = 0
    try:
        for a, b in operands(count, rng, edge):
            proc.stdin.write(bytes([op]) + a.to_bytes(32, "big")
                             + b.to_bytes(32, "big"))
            proc.stdin.flush()
            got = int.from_bytes(proc.stdout.read(32), "big")
            want = ref(op, a, b)
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
    print("    %-4s %7d cases  %s" % (name, checked,
                                      "ok" if not bad else "%d BAD" % bad))
    return bad


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 50000
    only = sys.argv[2] if len(sys.argv) > 2 else None
    rng = random.Random(20260717)
    bad = 0
    for label, mode, m, ref, ops in BINDINGS:
        if only and only != label:
            continue
        print("  %s (mod %s)" % (label, "p" if m == P256_P else "n"))
        edge = edges(m)
        for name, op in ops:
            # inv is ~256 multiplies a call; keep its sample proportionate
            n = count // 100 if op == P256_FE_INV else count
            bad += check(mode, name, op, ref, edge, n, rng)
    if bad:
        print("FAIL: %d mismatches" % bad)
        return 1
    print("p256 differential OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
