#!/usr/bin/env python3
"""Differential + adversarial test for linnea's P-256 ECDSA VERIFY.

Verify is the mirror of the signer, added for backend TLS (checking a server's
CertificateVerify). Unlike signing it touches only PUBLIC data, so the risk is
not a timing leak but (a) accepting a bad signature and (b) faulting or
mis-accepting on malformed input. This driver attacks both:

  1. Known-answer: RFC 6979 A.2.5's published (Q, r, s) for message "sample"
     must ACCEPT; a battery of tampered variants must REJECT -- including an
     OFF-CURVE public key, which a missing on-curve check would wrongly accept
     (the class of the all-zero X25519 omission).
  2. OpenSSL interop: OpenSSL signs with a RANDOM nonce, producing signatures
     the deterministic signer never emits, and linnea must accept every one --
     through both the raw (r,s) entry and the strict-DER entry. A one-byte flip
     must reject.
  3. Round-trip: linnea's own signer -> linnea's verify.
  4. Strict DER: BER / non-minimal / trailing-garbage / wrong-tag encodings of
     an otherwise valid signature must all REJECT (the Wycheproof surface).
  5. Fuzz: random and mutated DER and random (hash,Q,r,s) must never fault, and
     a known-good control interleaved through the fuzz must still accept (proof
     the path under test is actually reached).

Two entry points are exercised: `p256-ecdsa-verify-stdin` (raw hash|X||Y|r|s,
160 bytes) and `p256-ecdsa-verifyder-stdin` (hash|X||Y|len|DER).

Dev-time harness, not part of the fast suite (needs openssl for 2/3). Exits
non-zero on any mismatch. Usage: diff_p256_ecdsa_verify.py [ossl_count] [fuzz]
"""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

BIN = os.path.join(os.path.dirname(__file__), "..", "..", "bin", "linnea-selftest")
h2b = bytes.fromhex
fails = 0


def run(mode, data):
    return subprocess.run([BIN, mode], input=data, capture_output=True).stdout


def vraw(e, pub, r, s):
    out = run("p256-ecdsa-verify-stdin", e + pub + r + s)
    return out[0] if out else -1


def vder(e, pub, der):
    out = run("p256-ecdsa-verifyder-stdin", e + pub + bytes([len(der) & 0xff]) + der)
    return out[0] if out else -1


def check(name, got, want):
    global fails
    ok = got == want
    if not ok:
        fails += 1
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: got={got} want={want}")


def flip(b, i=0):
    a = bytearray(b)
    a[i] ^= 0x01
    return bytes(a)


def encint(mag):
    mag = mag.lstrip(b"\0") or b"\0"
    if mag[0] & 0x80:
        mag = b"\0" + mag
    return b"\x02" + bytes([len(mag)]) + mag


def seq(body):
    return b"\x30" + bytes([len(body)]) + body


# ---- 1. RFC 6979 A.2.5 known-answer + tampered negatives -------------------
def kat():
    print("RFC 6979 A.2.5 known-answer + negatives:")
    Ux = h2b("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6")
    Uy = h2b("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")
    r = h2b("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716")
    s = h2b("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")
    e = hashlib.sha256(b"sample").digest()
    pub, Z = Ux + Uy, b"\x00" * 32
    n = h2b("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
    check("valid vector", vraw(e, pub, r, s), 1)
    check("flip r", vraw(e, pub, flip(r), s), 0)
    check("flip s", vraw(e, pub, r, flip(s, 7)), 0)
    check("flip hash", vraw(flip(e), pub, r, s), 0)
    check("r = 0", vraw(e, pub, Z, s), 0)
    check("s = 0", vraw(e, pub, r, Z), 0)
    check("r = n", vraw(e, pub, n, s), 0)
    check("s = n", vraw(e, pub, r, n), 0)
    check("swap r,s", vraw(e, pub, s, r), 0)
    check("off-curve Q (flip Uy)", vraw(e, Ux + flip(Uy, 31), r, s), 0)
    check("off-curve Q (X||X)", vraw(e, Ux + Ux, r, s), 0)
    check("Q = (0,0)", vraw(e, Z + Z, r, s), 0)


# ---- openssl helpers -------------------------------------------------------
def have_openssl():
    return shutil.which("openssl") is not None


def new_key(d):
    key = os.path.join(d, "k.pem")
    subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey",
                    "-noout", "-out", key], check=True)
    spki = subprocess.run(["openssl", "ec", "-in", key, "-pubout", "-outform", "DER"],
                          capture_output=True, check=True).stdout
    assert spki[-65] == 0x04
    return key, spki[-64:]


def priv_of(key):
    import re
    t = subprocess.run(["openssl", "ec", "-in", key, "-text", "-noout"],
                       capture_output=True, check=True).stdout.decode()
    pv = re.search(r"priv:\n((?:\s+[0-9a-f:]+\n)+)", t).group(1)
    return bytes.fromhex("".join(pv.split()).replace(":", ""))[-32:].rjust(32, b"\0")


def der_split(der):
    def rd(i):
        assert der[i] == 0x02
        L = der[i + 1]
        return der[i + 2:i + 2 + L], i + 2 + L
    r, i = rd(2)
    s, _ = rd(i)
    return r.lstrip(b"\0").rjust(32, b"\0"), s.lstrip(b"\0").rjust(32, b"\0")


# ---- 2 + 3. OpenSSL interop and round-trip ---------------------------------
def interop(n):
    print(f"OpenSSL random-nonce interop + round-trip (N={n}):")
    with tempfile.TemporaryDirectory() as d:
        key, pub = new_key(d)
        priv = priv_of(key)
        raw = der = flp = rt = 0
        for _ in range(n):
            msg = os.urandom(32)
            e = hashlib.sha256(msg).digest()
            sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key],
                                 input=msg, capture_output=True, check=True).stdout
            r, s = der_split(sig)
            raw += vraw(e, pub, r, s) == 1
            der += vder(e, pub, sig) == 1
            flp += vraw(e, pub, flip(r, 9), s) == 0
            lin = run("p256-ecdsa-stdin", e + priv)            # linnea sign
            rt += vder(e, pub, lin[1:1 + lin[0]]) == 1          # -> linnea verify
        check("openssl sig, raw entry accept", raw, n)
        check("openssl sig, DER entry accept", der, n)
        check("one-byte flip rejects", flp, n)
        check("linnea sign -> linnea verify", rt, n)


# ---- 4. strict DER --------------------------------------------------------
def der_strict():
    print("strict-DER malformed encodings (all must reject):")
    if not have_openssl():
        print("  [skip] openssl unavailable")
        return
    with tempfile.TemporaryDirectory() as d:
        key, pub = new_key(d)
        msg = os.urandom(32)
        e = hashlib.sha256(msg).digest()
        sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key],
                             input=msg, capture_output=True, check=True).stdout
        r, s = der_split(sig)
        rm, sm = r.lstrip(b"\0"), s.lstrip(b"\0")
        canon = seq(encint(rm) + encint(sm))
        check("canonical accepts", vder(e, pub, canon), 1)
        # A genuine non-minimal INTEGER: prepend 0x00 to the CANONICAL magnitude
        # (which already carries the required pad when rm's top bit is set), so
        # this is a superfluous leading zero for any key, not the legal pad.
        cmag = (b"\x00" + rm) if (rm and rm[0] & 0x80) else rm
        nonmin = b"\x00" + cmag
        bad = {
            "trailing byte": canon + b"\x00",
            "SEQ long-form len": b"\x30\x81" + bytes([len(canon) - 2]) + canon[2:],
            "r non-minimal 00": seq(b"\x02" + bytes([len(nonmin)]) + nonmin + encint(sm)),
            "r long-form len": seq(b"\x02\x81" + bytes([len(rm)]) + rm + encint(sm)),
            "r wrong tag": seq(b"\x03" + bytes([len(rm)]) + rm + encint(sm)),
            "r len overruns": seq(b"\x02" + bytes([len(rm) + 9]) + rm + encint(sm)),
            "empty r": seq(b"\x02\x00" + encint(sm)),
            "missing s": seq(encint(rm)),
            "s wrong tag": seq(encint(rm) + b"\x05" + bytes([len(sm)]) + sm),
            "empty input": b"",
            "bare 30 00": b"\x30\x00",
            "not a sequence": b"\x02" + canon[1:],
        }
        for name, der in bad.items():
            check(name, vder(e, pub, der), 0)


# ---- 5. fuzz (never fault; control still accepts) --------------------------
def fuzz(iters):
    print(f"fuzz ({iters} iters; must not fault, control must still accept):")
    Ux = h2b("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6")
    Uy = h2b("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")
    r = h2b("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716")
    s = h2b("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")
    e = hashlib.sha256(b"sample").digest()
    pub = Ux + Uy
    faulted = accepted_bad = control = 0
    for i in range(iters):
        # random raw quad -- overwhelmingly invalid; must return 0 or 1, never crash
        q = os.urandom(160)
        rc = subprocess.run([BIN, "p256-ecdsa-verify-stdin"], input=q,
                            capture_output=True)
        if rc.returncode != 0 or rc.stdout not in (b"\x00", b"\x01"):
            faulted += 1
        if rc.stdout == b"\x01":
            accepted_bad += 1        # a random 160B quad verifying would be a break
        # random DER of random length
        dl = os.urandom(1)[0] % 90
        rc2 = subprocess.run([BIN, "p256-ecdsa-verifyder-stdin"],
                             input=e + pub + bytes([dl]) + os.urandom(dl),
                             capture_output=True)
        if rc2.returncode != 0 or rc2.stdout not in (b"\x00", b"\x01"):
            faulted += 1
        # interleaved control: the real vector must still accept
        if i % 64 == 0 and vraw(e, pub, r, s) == 1:
            control += 1
    check("no faults / illegal output", faulted, 0)
    check("no random quad accepted", accepted_bad, 0)
    check("control vector still accepts (path reached)", control > 0, True)


if __name__ == "__main__":
    ossl_n = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    fuzz_n = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
    if not os.path.exists(BIN):
        print("linnea-selftest not built; run 'make selftest'", file=sys.stderr)
        sys.exit(2)
    kat()
    if have_openssl():
        interop(ossl_n)
        der_strict()
    else:
        print("OpenSSL interop + strict-DER: [skip] openssl unavailable")
    fuzz(fuzz_n)
    print("ALL PASS" if fails == 0 else f"{fails} FAILURE(S)")
    sys.exit(1 if fails else 0)
