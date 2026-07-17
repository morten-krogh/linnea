#!/usr/bin/env python3
"""Differential test: linnea's P-256 ECDSA signing, two independent ways.

  1. Against the Python reference in gen_vectors, BYTE FOR BYTE. That is only
     possible because RFC 6979 makes the nonce a function of the key and the
     message, so a signature is a pure function of its inputs. The reference
     is itself pinned to RFC 6979 A.2.5's published k, r and s at import time.

  2. Against OpenSSL, which VERIFIES what we signed. OpenSSL signs with a
     random nonce and so can never match us byte for byte -- it can only
     arbitrate. This is the same two-step diff_ed25519.py uses: the reference
     is pinned to the RFC, and an independent implementation confirms the
     output is a valid signature under the public key.

Check 1 catches "we compute something deterministic but wrong"; check 2
catches "the reference and the assembly are wrong in the same way".

Usage: diff_p256_ecdsa.py [count] [ossl_count]   (default 2000, 100)

Dev-time harness, not part of the fast suite. Exits non-zero on mismatch.
"""
import base64
import hashlib
import os
import random
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
from gen_vectors import (P256_N, P256_GX, P256_GY, p256_ecdsa_sign,
                         p256_der_sig, p256_mul, p256_affine)

BIN = os.path.join(os.path.dirname(__file__), "..", "..", "bin",
                   "linnea-selftest")

# SubjectPublicKeyInfo prefix for id-ecPublicKey + prime256v1, followed by an
# uncompressed point. Fixed for the curve, so the key is a splice.
SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


class Signer:
    def __init__(self):
        self.proc = subprocess.Popen([BIN, "p256-ecdsa-stdin"],
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE)

    def sign(self, digest, priv):
        self.proc.stdin.write(digest + priv.to_bytes(32, "big"))
        self.proc.stdin.flush()
        n = self.proc.stdout.read(1)[0]
        return self.proc.stdout.read(n)

    def close(self):
        self.proc.stdin.close()
        self.proc.wait()


def pubkey_pem(d):
    x, y = p256_affine(p256_mul(d))
    der = SPKI_PREFIX + b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    b64 = base64.encodebytes(der).decode().replace("\n", "")
    body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n" % body


def against_reference(signer, count, rng):
    bad = 0
    for i in range(count):
        d = rng.randrange(1, P256_N)
        msg = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300)))
        h = hashlib.sha256(msg).digest()
        got = signer.sign(h, d)
        r, s = p256_ecdsa_sign(d, h)
        want = p256_der_sig(r, s)
        if got != want:
            if bad < 3:
                print("MISMATCH #%d\n  priv %064x\n  hash %s\n"
                      "  got  %s\n  want %s"
                      % (i, d, h.hex(), got.hex(), want.hex()))
            bad += 1
    print("  vs reference  %5d signatures  %s"
          % (count, "ok" if not bad else "%d BAD" % bad))
    return bad


def against_openssl(signer, count, rng):
    tmp = tempfile.mkdtemp(prefix="linnea-p256-")
    pub, sigf, dgst = (os.path.join(tmp, n) for n in
                       ("pub.pem", "sig.der", "digest.bin"))
    bad = 0
    for i in range(count):
        d = rng.randrange(1, P256_N)
        msg = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300)))
        h = hashlib.sha256(msg).digest()
        sig = signer.sign(h, d)
        with open(pub, "w") as f:
            f.write(pubkey_pem(d))
        with open(sigf, "wb") as f:
            f.write(sig)
        with open(dgst, "wb") as f:
            f.write(h)
        res = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin",
                              "-inkey", pub, "-sigfile", sigf, "-in", dgst],
                             capture_output=True)
        if res.returncode != 0 or b"Success" not in res.stdout:
            if bad < 3:
                print("OPENSSL REJECTED #%d\n  priv %064x\n  sig  %s\n  %s"
                      % (i, d, sig.hex(),
                         (res.stdout + res.stderr).decode(errors="replace")))
            bad += 1
    for f in (pub, sigf, dgst):
        os.path.exists(f) and os.unlink(f)
    os.rmdir(tmp)
    print("  vs openssl    %5d signatures  %s"
          % (count, "ok" if not bad else "%d REJECTED" % bad))
    return bad


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    ossl = int(sys.argv[2]) if len(sys.argv) > 2 else 100
    rng = random.Random(20260717)
    signer = Signer()
    try:
        bad = against_reference(signer, count, rng)
        bad += against_openssl(signer, ossl, rng)
    finally:
        signer.close()
    if bad:
        print("FAIL: %d bad" % bad)
        return 1
    print("p256 ecdsa differential OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
