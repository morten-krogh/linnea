#!/usr/bin/env python3
"""Differential test for linnea's X.509 leaf-certificate key extraction.

For backend TLS, linnea pins a server's certificate and verifies its
CertificateVerify. Both need the leaf's public key, and the pin needs the
SubjectPublicKeyInfo bytes: linnea_x509_find_spki walks the (untrusted)
certificate to the SPKI, and linnea_x509_spki_point reads the prime256v1 point.

This drives the selftest `x509-p256-stdin` mode (frame: u32-LE DER length | DER;
reply: status(1) | point X||Y (64) | sha256(SPKI) (32)) against the committed
test certificates, with OpenSSL as the independent oracle:

  * the extracted point must equal OpenSSL's public-key point, and
  * sha256(extracted SPKI) must equal sha256 of OpenSSL's SPKI DER (the pin),

and a battery of malformed inputs (random bytes, a truncated leaf, an empty
frame) must be rejected (status 0) rather than faulting or mis-extracting.

Dev-time harness (needs openssl); also wired into the base crypto shard, which
skips it when openssl is absent. Exits non-zero on any mismatch.
"""
import hashlib
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(__file__)
BIN = os.path.join(HERE, "..", "..", "bin", "linnea-selftest")
CERTS = [os.path.join(HERE, "..", "tls", n) for n in ("server.crt", "sni.crt")]
fails = 0


def extract(der):
    frame = struct.pack("<I", len(der)) + der
    out = subprocess.run([BIN, "x509-p256-stdin"], input=frame,
                         capture_output=True).stdout
    if len(out) < 97:
        return None
    return out[0], out[1:65], out[65:97]


def cert_der(path):
    return subprocess.run(["openssl", "x509", "-in", path, "-outform", "DER"],
                          capture_output=True, check=True).stdout


def ossl_ref(path):
    pub = subprocess.run(["openssl", "x509", "-in", path, "-noout", "-pubkey"],
                         capture_output=True, check=True).stdout
    spki = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"],
                          input=pub, capture_output=True, check=True).stdout
    assert spki[-65] == 0x04
    return spki[-64:], spki


def ck(name, cond):
    global fails
    if not cond:
        fails += 1
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")


def main():
    if not os.path.exists(BIN):
        print("linnea-selftest not built; run 'make selftest'", file=sys.stderr)
        return 2
    print("X.509 leaf key extraction vs OpenSSL:")
    for crt in CERTS:
        der = cert_der(crt)
        r = extract(der)
        pt, spki = ossl_ref(crt)
        name = os.path.basename(crt)
        if r is None:
            ck(f"{name}: output present", False)
            continue
        st, got_pt, got_hash = r
        ck(f"{name}: status ok", st == 1)
        ck(f"{name}: point matches OpenSSL", got_pt == pt)
        ck(f"{name}: SPKI pin (sha256) matches", got_hash == hashlib.sha256(spki).digest())

    print("malformed inputs must reject (status 0, no fault):")
    leaf = cert_der(CERTS[0])
    # (Trailing bytes after a valid cert are not tested: the TLS caller passes
    # exact-length DER from the CertificateEntry framing, and ignoring slack is
    # a benign, accepted contract.)
    for name, bad in [("random 300B", os.urandom(300)),
                      ("truncated leaf", leaf[:120]),
                      ("leaf minus last byte", leaf[:-1]),
                      ("empty", b"")]:
        r = extract(bad)
        ck(f"reject {name}", r is not None and r[0] == 0)

    print("ALL PASS" if fails == 0 else f"{fails} FAILURE(S)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
