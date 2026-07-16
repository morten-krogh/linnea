#!/usr/bin/env python3
"""Differential test: linnea's AES-128-GCM vs the Linux kernel (AF_ALG).

The kernel's gcm(aes) is a fully independent implementation, and fast
enough to drive large counts; the pure-Python reference in gen_vectors
is additionally cross-checked on a sample of cases (it is slow, so not
on all of them). Each random case runs three ways:

  1. seal:  linnea `aesgcm-stdin` vs the kernel's ciphertext+tag,
  2. open:  the kernel ciphertext through `aesgcm-open-stdin` must be
     accepted and round-trip the plaintext,
  3. tamper (one case in four): a random bit flipped in the AAD,
     ciphertext or tag must be rejected with the output zeroed.

Lengths concentrate on block boundaries (0/1/15/16/17/...), with AAD
sizes including 5 (a TLS 1.3 record header) and 13.

Usage: diff_aesgcm.py [count]   (default 20000 cases)

Dev-time harness, not part of the fast suite. Exits non-zero on mismatch.
"""
import os
import random
import socket
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from gen_vectors import aesgcm_seal   # the Python reference

BIN = os.path.join(os.path.dirname(__file__), "..", "..", "bin",
                   "linnea-selftest")

PT_LENS = [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
           255, 256, 257, 511, 512, 1024]
AAD_LENS = [0, 1, 5, 13, 15, 16, 17, 32, 48]


def kernel_seal(key, nonce, aad, pt):
    tfm = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    tfm.bind(("aead", "gcm(aes)"))
    tfm.setsockopt(socket.SOL_ALG, socket.ALG_SET_KEY, key)
    tfm.setsockopt(socket.SOL_ALG, socket.ALG_SET_AEAD_AUTHSIZE, None, 16)
    op, _ = tfm.accept()
    op.sendmsg_afalg([aad + pt], op=socket.ALG_OP_ENCRYPT, iv=nonce,
                     assoclen=len(aad))
    want = len(aad) + len(pt) + 16
    out = b""
    while len(out) < want:
        chunk = op.recv(want - len(out))
        if not chunk:
            raise IOError("AF_ALG short read")
        out += chunk
    op.close()
    tfm.close()
    return out[len(aad):]          # the kernel echoes the AAD back


def read_full(stream, n):
    out = b""
    while len(out) < n:
        chunk = stream.read(n - len(out))
        if not chunk:
            raise IOError("selftest died (short read)")
        out += chunk
    return out


def frame(key, nonce, aad, body):
    payload = key + nonce + struct.pack("<I", len(aad)) + aad + body
    return struct.pack("<I", len(payload)) + payload


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 20_000
    rng = random.Random(20260716)
    seal = subprocess.Popen([BIN, "aesgcm-stdin"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    opener = subprocess.Popen([BIN, "aesgcm-open-stdin"],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    checked = tampered = ref_checked = 0
    try:
        for i in range(count):
            ptl = rng.choice(PT_LENS) if rng.random() < 0.7 \
                else rng.randrange(0, 600)
            aadl = rng.choice(AAD_LENS) if rng.random() < 0.7 \
                else rng.randrange(0, 64)
            key = rng.randbytes(16)
            nonce = rng.randbytes(12)
            aad = rng.randbytes(aadl)
            pt = rng.randbytes(ptl)
            want = kernel_seal(key, nonce, aad, pt)

            seal.stdin.write(frame(key, nonce, aad, pt))
            seal.stdin.flush()
            got = read_full(seal.stdout, ptl + 16)
            if got != want:
                print("SEAL MISMATCH at #%d\n  key %s nonce %s\n"
                      "  aad %s\n  pt  %s\n  got  %s\n  want %s"
                      % (i, key.hex(), nonce.hex(), aad.hex(), pt.hex(),
                         got.hex(), want.hex()))
                sys.exit(1)

            if i % 200 == 0:       # sample the slow Python reference too
                assert aesgcm_seal(key, nonce, aad, pt) == want, \
                    "python reference disagrees with the kernel at #%d" % i
                ref_checked += 1

            tamper = rng.random() < 0.25
            ct = want
            if tamper:
                which = rng.random()
                if which < 0.4 or not (aad or len(ct) > 16):
                    pos, kind = rng.randrange(len(ct)), "ct/tag"
                    ct = bytearray(ct)
                    ct[pos] ^= 1 << rng.randrange(8)
                    ct = bytes(ct)
                elif which < 0.7 and aad:
                    pos, kind = rng.randrange(len(aad)), "aad"
                    aad = bytearray(aad)
                    aad[pos] ^= 1 << rng.randrange(8)
                    aad = bytes(aad)
                else:
                    kind = "truncated"
                    ct = ct[:rng.randrange(16, len(ct))] if len(ct) > 16 \
                        else ct[:15]
            opener.stdin.write(frame(key, nonce, aad, ct))
            opener.stdin.flush()
            reply = read_full(opener.stdout, 1 + max(len(ct) - 16, 0))
            rc, out = reply[0], reply[1:]
            if tamper:
                if rc != 1 or out.count(0) != len(out):
                    print("TAMPER (%s) NOT REJECTED at #%d (rc=%d)"
                          % (kind, i, rc))
                    sys.exit(1)
                tampered += 1
            else:
                if rc != 0 or out != pt:
                    print("OPEN MISMATCH at #%d (rc=%d)" % (i, rc))
                    sys.exit(1)
            checked += 1
            if checked % 2_000 == 0:
                print("%d ok (%d tampered, %d vs python ref)"
                      % (checked, tampered, ref_checked), file=sys.stderr)
    finally:
        seal.stdin.close()
        opener.stdin.close()
        seal.wait()
        opener.wait()
    print("%d cases, all match (%d tampered rejected, %d python-ref checked)"
          % (checked, tampered, ref_checked))


if __name__ == "__main__":
    main()
