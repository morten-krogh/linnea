#!/usr/bin/env python3
"""Differential test for linnea's TLS 1.3 CertificateVerify check (client side).

linnea_tls_client_verify_certverify rebuilds the RFC 8446 4.4.3 signed content
(64*0x20 || "TLS 1.3, server CertificateVerify" || 0x00 || transcript-hash),
hashes it, and ECDSA-verifies the DER signature under the server's P-256 key.

OpenSSL is the independent signer here: it signs the exact signed content with
the test key, and linnea must accept only a signature that matches both the
transcript hash and the public key. Drives the selftest `tls-certverify-stdin`
mode (frame: transcript_hash(32) | pubkey X||Y (64) | derlen(1) | DER).

Dev-time harness (needs openssl); wired into the base crypto shard, skipped when
openssl is absent. Exits non-zero on any mismatch.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(__file__)
BIN = os.path.join(HERE, "..", "..", "bin", "linnea-selftest")
KEY = os.path.join(HERE, "..", "tls", "server.key")
CRT = os.path.join(HERE, "..", "tls", "server.crt")
CTX = b"TLS 1.3, server CertificateVerify\x00"
fails = 0


def pubkey():
    pub = subprocess.run(["openssl", "x509", "-in", CRT, "-noout", "-pubkey"],
                         capture_output=True, check=True).stdout
    spki = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"],
                          input=pub, capture_output=True, check=True).stdout
    return spki[-64:]


def sign(th):
    return subprocess.run(["openssl", "dgst", "-sha256", "-sign", KEY],
                          input=b"\x20" * 64 + CTX + th,
                          capture_output=True, check=True).stdout


def cv(th, pub, der):
    out = subprocess.run([BIN, "tls-certverify-stdin"],
                         input=th + pub + bytes([len(der) & 0xff]) + der,
                         capture_output=True).stdout
    return out[0] if out else -1


def flip(b, i=0):
    a = bytearray(b)
    a[i] ^= 1
    return bytes(a)


def ck(name, cond):
    global fails
    if not cond:
        fails += 1
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")


def main():
    if not os.path.exists(BIN):
        print("linnea-selftest not built; run 'make selftest'", file=sys.stderr)
        return 2
    pub = pubkey()
    print("TLS 1.3 CertificateVerify vs OpenSSL-signed content:")
    good = sum(cv(th, pub, sign(th)) == 1 for th in (os.urandom(32) for _ in range(50)))
    ck("50 valid CertificateVerify signatures accept", good == 50)
    th = os.urandom(32)
    der = sign(th)
    ck("wrong transcript hash rejects", cv(flip(th), pub, der) == 0)
    ck("flipped signature rejects", cv(th, pub, flip(der, 8)) == 0)
    ck("wrong public key rejects", cv(th, flip(pub, 3), der) == 0)
    ck("empty signature rejects", cv(th, pub, b"") == 0)
    print("ALL PASS" if fails == 0 else f"{fails} FAILURE(S)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
