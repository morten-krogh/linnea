#!/usr/bin/env python3
"""Emit NASM data tables of SHA-256 / HMAC / HKDF test vectors.

The expected outputs are computed here with Python's hashlib/hmac, which
are the authoritative reference; the linnea selftest binary compares its
own assembly output against these tables. Inputs are the canonical RFC /
NIST cases plus a spread of sizes that exercise the block boundary and
the incremental buffering path. Run: python3 gen_vectors.py > sha256_vectors.inc
"""
import hashlib
import hmac
import json
import os
import random
import re


def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


# --- X25519 reference (RFC 7748), for generating and cross-checking ------
_P = 2 ** 255 - 19


def _decode_le(b):
    return sum(b[i] << (8 * i) for i in range(len(b)))


def _decode_u(u):
    u = bytearray(u)
    u[31] &= 0x7f
    return _decode_le(u)


def _decode_scalar(k):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return _decode_le(k)


def _encode_u(x):
    return bytes([(x >> (8 * i)) & 0xff for i in range(32)])


def x25519(k_bytes, u_bytes):
    k = _decode_scalar(k_bytes)
    u = _decode_u(u_bytes)
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + 121665 * e) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return _encode_u(x2 * pow(z2, _P - 2, _P) % _P)


def x25519_iter(n):
    k = bytes([9] + [0] * 31)
    u = k
    for _ in range(n):
        r = x25519(k, u)
        u = k
        k = r
    return k


# --- Ed25519 reference (RFC 8032), for vectors and the differential ------
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_L = 2 ** 252 + 27742317777372353535851937790883648493
_I = pow(2, (_P - 1) // 4, _P)


def _ed_recover_x(y, sign):
    xx = ((y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != sign:
        x = _P - x
    return x


_ED_BY = (4 * pow(5, _P - 2, _P)) % _P
_ED_B = (_ed_recover_x(_ED_BY, 0), _ED_BY)


def _ed_add(p, q):
    x1, y1 = p
    x2, y2 = q
    x3 = (x1 * y2 + x2 * y1) * pow(1 + _D * x1 * x2 * y1 * y2, _P - 2, _P)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - _D * x1 * x2 * y1 * y2, _P - 2, _P)
    return (x3 % _P, y3 % _P)


def _ed_scalarmult(p, e):
    q = (0, 1)
    while e > 0:
        if e & 1:
            q = _ed_add(q, p)
        p = _ed_add(p, p)
        e >>= 1
    return q


def _ed_encode(p):
    x, y = p
    return bytes((y | ((x & 1) << 255)).to_bytes(32, "little"))


def ed25519_sign(seed, msg):
    h = hashlib.sha512(seed).digest()
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    s = _decode_le(a)
    prefix = h[32:]
    pub = _ed_encode(_ed_scalarmult(_ED_B, s))
    r = _decode_le(hashlib.sha512(prefix + msg).digest()) % _L
    rr = _ed_encode(_ed_scalarmult(_ED_B, r))
    k = _decode_le(hashlib.sha512(rr + pub + msg).digest()) % _L
    ss = (r + k * s) % _L
    return rr + ss.to_bytes(32, "little")


def ed25519_pubkey(seed):
    h = hashlib.sha512(seed).digest()
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return _ed_encode(_ed_scalarmult(_ED_B, _decode_le(a)))


# --- AES-128-GCM reference (NIST SP 800-38D), for vectors and the ------
# --- differential. The S-box is generated, not typed, to avoid typos. ---
def _aes_build_sbox():
    exp, log = [0] * 256, [0] * 256
    x = 1
    for i in range(255):
        exp[i], log[x] = x, i
        x ^= (x << 1) ^ (0x11B if x & 0x80 else 0)
    exp[255] = exp[0]          # 3^255 = 3^0; inv(1) reads this slot
    sbox = [0x63] * 256
    for b in range(1, 256):
        inv = exp[255 - log[b]]
        s = 0
        for shift in (0, 1, 2, 3, 4):
            s ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        sbox[b] = s ^ 0x63
    return sbox


_SBOX = _aes_build_sbox()


def _xtime(b):
    return ((b << 1) ^ 0x1B) & 0xFF if b & 0x80 else b << 1


def _aes128_expand(key):
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [_SBOX[t[1]] ^ rcon, _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
            rcon = _xtime(rcon)
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [sum(w[4 * r + c][i] << (8 * (4 * c + i) - 0) for c in range(4)
                for i in range(4)) for r in range(11)]


def _aes128_encrypt(rk, block):
    s = [b for b in block]
    def add_rk(r):
        k = rk[r]
        for i in range(16):
            s[i] ^= (k >> (8 * i)) & 0xFF
    add_rk(0)
    for rnd in range(1, 11):
        s[:] = [_SBOX[b] for b in s]
        s[:] = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]  # ShiftRows
        if rnd < 10:
            for c in range(0, 16, 4):
                a = s[c:c + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                s[c + 0] ^= t ^ _xtime(a[0] ^ a[1])
                s[c + 1] ^= t ^ _xtime(a[1] ^ a[2])
                s[c + 2] ^= t ^ _xtime(a[2] ^ a[3])
                s[c + 3] ^= t ^ _xtime(a[3] ^ a[0])
        add_rk(rnd)
    return bytes(s)


def _gmul(x, y):
    R = 0xE1 << 120
    z, v = 0, x
    for i in range(127, -1, -1):
        if (y >> i) & 1:
            z ^= v
        v = (v >> 1) ^ (R if v & 1 else 0)
    return z


def _ghash(h, aad, ct):
    def pad(b):
        return b + bytes(-len(b) % 16)
    data = pad(aad) + pad(ct) + (len(aad) * 8).to_bytes(8, "big") \
        + (len(ct) * 8).to_bytes(8, "big")
    y = 0
    for i in range(0, len(data), 16):
        y = _gmul(y ^ int.from_bytes(data[i:i + 16], "big"), h)
    return y.to_bytes(16, "big")


def _gcm_keystream(rk, nonce, nbytes):
    ks, ctr = b"", 2
    while len(ks) < nbytes:
        ks += _aes128_encrypt(rk, nonce + ctr.to_bytes(4, "big"))
        ctr += 1
    return ks[:nbytes]


def aesgcm_seal(key, nonce, aad, pt):
    """Returns ct || tag, the same shape linnea_aesgcm_seal writes."""
    rk = _aes128_expand(key)
    h = int.from_bytes(_aes128_encrypt(rk, bytes(16)), "big")
    ct = bytes(a ^ b for a, b in zip(pt, _gcm_keystream(rk, nonce, len(pt))))
    s = _ghash(h, aad, ct)
    tmask = _aes128_encrypt(rk, nonce + b"\x00\x00\x00\x01")
    return ct + bytes(a ^ b for a, b in zip(s, tmask))


# --- TLS 1.3 KDF (RFC 8446 section 7.1) ----------------------------------
def hkdf_expand_label(secret, label, context, length):
    lbl = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(lbl)]) + lbl \
        + bytes([len(context)]) + context
    return hkdf_expand(secret, info, length)


def derive_secret(secret, label, transcript_hash):
    return hkdf_expand_label(secret, label, transcript_hash, 32)


def _rfc8448_entries():
    """Parse every labeled hex payload out of RFC 8448 section 3."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "rfc8448.txt")
    with open(path) as f:
        text = f.read()
    section = text[text.index("\n3.  Simple 1-RTT Handshake"):
                   text.index("\n4.  Resumed 0-RTT Handshake")]
    out = []
    cur = None                     # [name, size, hex-so-far]
    for line in section.splitlines():
        m = re.match(r"^ {6}([A-Za-z][A-Za-z0-9 ]*?) \((\d+) octets\):(.*)$",
                     line)
        if m:
            assert cur is None, ("unterminated entry", cur[0])
            cur = [m.group(1), int(m.group(2)),
                   m.group(3).replace("(empty)", "")]
        elif cur is not None and re.match(r"^ +([0-9a-f]{2} ?)+$", line):
            cur[2] += " " + line.strip()
        else:
            continue               # page breaks etc. inside long payloads
        data = bytes.fromhex(cur[2].replace(" ", ""))
        assert len(data) <= cur[1], ("overrun", cur[0], len(data), cur[1])
        if len(data) == cur[1]:
            out.append((cur[0], data))
            cur = None
    assert cur is None, ("truncated entry", cur and cur[0])
    return out


def rfc8448():
    """Replay the RFC 8448 simple 1-RTT trace through the Python
    reference (x25519, HKDF, expand-label, AES-GCM records) and assert
    every intermediate value byte-for-byte. Returns what the vector
    tables need."""
    ent = _rfc8448_entries()
    pos = [0]

    def take(name):
        assert pos[0] < len(ent), "ran off the trace looking for " + name
        got_name, data = ent[pos[0]]
        assert got_name == name, ("trace walk", pos[0], got_name, name)
        pos[0] += 1
        return data

    t = {}
    t["empty_hash"] = hashlib.sha256(b"").digest()
    t["client_priv"] = take("private key")
    t["client_pub"] = take("public key")
    t["ch"] = take("ClientHello")
    take("payload")
    t["ch_record"] = take("complete record")
    assert take("IKM") == bytes(32)
    early = take("secret")
    assert early == hkdf_extract(b"", bytes(32))
    t["early"] = early
    t["server_priv"] = take("private key")
    t["server_pub"] = take("public key")
    assert x25519(t["server_priv"], b"\x09" + bytes(31)) == t["server_pub"]
    t["sh"] = take("ServerHello")
    t["server_random"] = t["sh"][6:38]

    def take_derive(prk, label):
        assert take("PRK") == prk
        ctx = take("hash")
        info = take("info")
        got = take("expanded")
        assert derive_secret(prk, label, ctx) == got
        lbl = b"tls13 " + label
        assert info == (32).to_bytes(2, "big") + bytes([len(lbl)]) + lbl \
            + bytes([len(ctx)]) + ctx
        return ctx, got

    empty_hash = hashlib.sha256(b"").digest()
    ctx, derived = take_derive(early, b"derived")
    assert ctx == empty_hash
    assert take("salt") == derived
    shared = take("IKM")
    assert shared == x25519(t["server_priv"], t["client_pub"])
    assert shared == x25519(t["client_priv"], t["server_pub"])
    t["shared"] = shared
    hs = take("secret")
    assert hs == hkdf_extract(derived, shared)
    t["hs"] = hs
    th_ch_sh = hashlib.sha256(t["ch"] + t["sh"]).digest()
    ctx, t["c_hs"] = take_derive(hs, b"c hs traffic")
    assert ctx == th_ch_sh
    t["th_ch_sh"] = th_ch_sh
    ctx, t["s_hs"] = take_derive(hs, b"s hs traffic")
    ctx, derived2 = take_derive(hs, b"derived")
    assert ctx == empty_hash
    assert take("salt") == derived2
    assert take("IKM") == bytes(32)
    master = take("secret")
    assert master == hkdf_extract(derived2, bytes(32))
    t["master"] = master
    assert take("payload") == t["sh"]
    t["sh_record"] = take("complete record")
    assert t["sh_record"] == b"\x16\x03\x03" + len(t["sh"]).to_bytes(2, "big") \
        + t["sh"]

    def take_keys(prk):
        assert take("PRK") == prk
        take("key info")
        key = take("key expanded")
        take("iv info")
        iv = take("iv expanded")
        assert key == hkdf_expand_label(prk, b"key", b"", 16)
        assert iv == hkdf_expand_label(prk, b"iv", b"", 12)
        return key, iv

    t["s_hs_key"], t["s_hs_iv"] = take_keys(t["s_hs"])
    t["ee"] = take("EncryptedExtensions")
    t["cert"] = take("Certificate")
    t["cv"] = take("CertificateVerify")
    ctx, t["s_fin_key"] = take_derive(t["s_hs"], b"finished")
    assert ctx == b""
    s_verify = take("finished")
    th_to_cv = hashlib.sha256(t["ch"] + t["sh"] + t["ee"] + t["cert"]
                              + t["cv"]).digest()
    assert s_verify == hmac.new(t["s_fin_key"], th_to_cv,
                                hashlib.sha256).digest()
    t["s_fin"] = take("Finished")
    assert t["s_fin"] == b"\x14\x00\x00\x20" + s_verify
    t["flight"] = take("payload")
    assert t["flight"] == t["ee"] + t["cert"] + t["cv"] + t["s_fin"]
    t["flight_record"] = take("complete record")

    def seal_record(key, iv, seq, rtype, payload):
        nonce = bytes(a ^ b for a, b in
                      zip(iv, bytes(4) + seq.to_bytes(8, "big")))
        hdr = b"\x17\x03\x03" + (len(payload) + 17).to_bytes(2, "big")
        return hdr + aesgcm_seal(key, nonce, hdr, payload + bytes([rtype]))

    assert t["flight_record"] == seal_record(t["s_hs_key"], t["s_hs_iv"], 0,
                                             0x16, t["flight"])
    th_to_sfin = hashlib.sha256(t["ch"] + t["sh"] + t["flight"]).digest()
    ctx, t["c_ap"] = take_derive(master, b"c ap traffic")
    assert ctx == th_to_sfin
    t["th_to_sfin"] = th_to_sfin
    ctx, t["s_ap"] = take_derive(master, b"s ap traffic")
    ctx, t["exp_master"] = take_derive(master, b"exp master")
    t["s_ap_key"], t["s_ap_iv"] = take_keys(t["s_ap"])
    t["c_hs_key"], t["c_hs_iv"] = take_keys(t["c_hs"])
    ctx, _ = take_derive(early, b"derived")   # the client-side replay of the
    assert ctx == empty_hash                  # schedule repeats this one
    ctx, t["c_fin_key"] = take_derive(t["c_hs"], b"finished")
    assert ctx == b""
    c_verify = take("finished")
    assert c_verify == hmac.new(t["c_fin_key"], th_to_sfin,
                                hashlib.sha256).digest()
    t["c_fin"] = take("Finished")
    assert take("payload") == t["c_fin"]
    t["c_fin_record"] = take("complete record")
    assert t["c_fin_record"] == seal_record(t["c_hs_key"], t["c_hs_iv"], 0,
                                            0x16, t["c_fin"])
    t["c_ap_key"], t["c_ap_iv"] = take_keys(t["c_ap"])
    ctx, res_master = take_derive(master, b"res master")
    assert ctx == hashlib.sha256(t["ch"] + t["sh"] + t["flight"]
                                 + t["c_fin"]).digest()
    assert take("PRK") == res_master
    take("hash")
    take("info")
    take("expanded")
    t["nst"] = take("NewSessionTicket")
    assert take("payload") == t["nst"]
    t["nst_record"] = take("complete record")     # server app write, seq 0
    assert t["nst_record"] == seal_record(t["s_ap_key"], t["s_ap_iv"], 0,
                                          0x16, t["nst"])
    t["c_app"] = take("payload")                  # client app data, seq 0
    t["c_app_record"] = take("complete record")
    assert t["c_app_record"] == seal_record(t["c_ap_key"], t["c_ap_iv"], 0,
                                            0x17, t["c_app"])
    t["s_app"] = take("payload")                  # server app data, seq 1
    t["s_app_record"] = take("complete record")
    assert t["s_app_record"] == seal_record(t["s_ap_key"], t["s_ap_iv"], 1,
                                            0x17, t["s_app"])
    t["c_alert"] = take("payload")                # client close_notify, seq 1
    t["c_alert_record"] = take("complete record")
    assert t["c_alert_record"] == seal_record(t["c_ap_key"], t["c_ap_iv"], 1,
                                              0x15, t["c_alert"])
    t["s_alert"] = take("payload")                # server close_notify, seq 2
    t["s_alert_record"] = take("complete record")
    assert t["s_alert_record"] == seal_record(t["s_ap_key"], t["s_ap_iv"], 2,
                                              0x15, t["s_alert"])
    return t


# --- P-256 field reference (GF(p), p = 2^256-2^224+2^192+2^96-1) ---------
# Montgomery form is private to the assembly; this reference works in plain
# integers and speaks the big-endian SEC1 encoding that frombytes/tobytes
# use. Inputs at or above p are reduced, which is what the asm does too.
P256_P = 2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1

# opcodes shared with test/crypto/linnea_selftest.asm
P256_FE_MUL = 0
P256_FE_SQ = 1
P256_FE_ADD = 2
P256_FE_SUB = 3
P256_FE_INV = 4


def p256_fe(op, a, b):
    a %= P256_P
    b %= P256_P
    if op == P256_FE_MUL:
        return (a * b) % P256_P
    if op == P256_FE_SQ:
        return (a * a) % P256_P
    if op == P256_FE_ADD:
        return (a + b) % P256_P
    if op == P256_FE_SUB:
        return (a - b) % P256_P
    if op == P256_FE_INV:
        return pow(a, P256_P - 2, P256_P)     # inv(0) = 0, as Fermat gives
    raise ValueError(op)


def p256_fe_cases():
    """(op, a, b) triples for the embedded table.

    Weighted towards the operands that drive the reduction's carry chain:
    values just under p and just under 2^256 are what make a Montgomery
    round's carry ripple past its four-limb window, and what force the
    final conditional subtract. A one-limb-short ripple survives ordinary
    random testing at roughly 1 case in 30000 -- these are the cases that
    catch it cheaply.
    """
    edge = [
        0, 1, 2,
        P256_P - 2, P256_P - 1, P256_P, P256_P + 1,     # around the modulus
        2 ** 256 - 1, 2 ** 256 - 2,                     # non-canonical input
        (P256_P - 1) // 2, (P256_P + 1) // 2,
        2 ** 224, 2 ** 224 - 1,                         # the prime's own
        2 ** 192, 2 ** 96, 2 ** 96 - 1,                 # structural powers
        2 ** 255, 2 ** 64, 2 ** 64 - 1, 2 ** 128 - 1,
    ]
    cases = []
    for op in (P256_FE_MUL, P256_FE_ADD, P256_FE_SUB):
        for a in edge:
            for b in edge:
                cases.append((op, a, b))
    for op in (P256_FE_SQ, P256_FE_INV):
        for a in edge:
            cases.append((op, a, 0))
    # a spread of fixed pseudo-random operands, so the table covers the
    # ordinary path too and not only the extremes
    rng = random.Random(20260717)
    for op in (P256_FE_MUL, P256_FE_SQ, P256_FE_ADD, P256_FE_SUB, P256_FE_INV):
        for _ in range(24):
            cases.append((op, rng.randrange(2 ** 256), rng.randrange(2 ** 256)))
    return cases


def _det_bytes(tag, n):
    """Deterministic pseudo-random test data (stable across runs)."""
    out = b""
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(b"linnea-gcm:%s:%d" % (tag, ctr)).digest()
        ctr += 1
    return out[:n]


def blob(label, data):
    """One db line naming a byte string; empty strings still get a label."""
    if not data:
        return "%s: db 0   ; (empty)\n" % label   # a valid address; len 0
    body = ", ".join(str(b) for b in data)
    return "%s: db %s\n" % (label, body)


def main():
    out = []
    out.append("; Generated by test/crypto/gen_vectors.py — do not edit.\n")
    out.append("section .rodata\n")

    # ---- SHA-256: messages of assorted lengths ----------------------
    sha_msgs = [
        b"",
        b"abc",
        b"The quick brown fox jumps over the lazy dog",
        b"a" * 55,     # the largest that still fits one padded block
        b"a" * 56,     # forces a second, length-only block
        b"a" * 63,
        b"a" * 64,     # exactly one block
        b"a" * 65,     # one block plus a byte
        b"a" * 127,
        b"a" * 128,
        bytes(range(256)) * 4,   # 1024 bytes, several blocks
    ]
    labels = []
    for n, m in enumerate(sha_msgs):
        out.append(blob("sha_msg_%d" % n, m))
        out.append(blob("sha_exp_%d" % n, hashlib.sha256(m).digest()))
        labels.append((n, len(m)))
    out.append("align 8\nsha256_tests:\n")
    for n, ln in labels:
        out.append("    dq sha_msg_%d, %d, sha_exp_%d\n" % (n, ln, n))
    out.append("sha256_test_count equ (($ - sha256_tests) / 24)\n")

    # ---- SHA-512: same messages, exercising the 128-byte block/pad ----
    sha512_msgs = [
        b"",
        b"abc",
        b"The quick brown fox jumps over the lazy dog",
        b"a" * 111,     # largest that still fits one padded block
        b"a" * 112,     # forces a second, length-only block
        b"a" * 127,
        b"a" * 128,     # exactly one block
        b"a" * 129,
        bytes(range(256)) * 4,
    ]
    labels = []
    for n, m in enumerate(sha512_msgs):
        out.append(blob("sha5_msg_%d" % n, m))
        out.append(blob("sha5_exp_%d" % n, hashlib.sha512(m).digest()))
        labels.append((n, len(m)))
    out.append("align 8\nsha512_tests:\n")
    for n, ln in labels:
        out.append("    dq sha5_msg_%d, %d, sha5_exp_%d\n" % (n, ln, n))
    out.append("sha512_test_count equ (($ - sha512_tests) / 24)\n")

    # ---- HMAC-SHA256: RFC 4231 test cases 1-7 -----------------------
    hmac_cases = [
        (b"\x0b" * 20, b"Hi There"),
        (b"Jefe", b"what do ya want for nothing?"),
        (b"\xaa" * 20, b"\xdd" * 50),
        (bytes(range(1, 26)), b"\xcd" * 50),
        (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First"),
        (b"\xaa" * 131,
         b"This is a test using a larger than block-size key and a larger "
         b"than block-size data. The key needs to be hashed before being "
         b"used by the HMAC algorithm."),
    ]
    labels = []
    for n, (k, m) in enumerate(hmac_cases):
        out.append(blob("hmac_key_%d" % n, k))
        out.append(blob("hmac_msg_%d" % n, m))
        out.append(blob("hmac_exp_%d" % n,
                        hmac.new(k, m, hashlib.sha256).digest()))
        labels.append((n, len(k), len(m)))
    out.append("align 8\nhmac_tests:\n")
    for n, kl, ml in labels:
        out.append("    dq hmac_key_%d, %d, hmac_msg_%d, %d, hmac_exp_%d\n"
                    % (n, kl, n, ml, n))
    out.append("hmac_test_count equ (($ - hmac_tests) / 40)\n")

    # ---- HKDF-Extract: RFC 5869 cases 1-3 ---------------------------
    ext_cases = [
        (b"\x00" * 13, b"\x0b" * 22),                       # salt, IKM
        (bytes(range(0x00, 0x50)), bytes(range(0x00, 0x22))),
        (b"", b"\x0b" * 22),                                # empty salt
    ]
    labels = []
    for n, (salt, ikm) in enumerate(ext_cases):
        out.append(blob("ext_salt_%d" % n, salt))
        out.append(blob("ext_ikm_%d" % n, ikm))
        out.append(blob("ext_exp_%d" % n, hkdf_extract(salt, ikm)))
        labels.append((n, len(salt), len(ikm)))
    out.append("align 8\nhkdf_extract_tests:\n")
    for n, sl, il in labels:
        out.append("    dq ext_salt_%d, %d, ext_ikm_%d, %d, ext_exp_%d\n"
                    % (n, sl, n, il, n))
    out.append("hkdf_extract_test_count equ (($ - hkdf_extract_tests) / 40)\n")

    # ---- HKDF-Expand: RFC 5869 cases 1-3 plus a short one -----------
    prk1 = hkdf_extract(b"\x00" * 13, b"\x0b" * 22)
    prk2 = hkdf_extract(bytes(range(0x00, 0x50)), bytes(range(0x00, 0x22)))
    prk3 = hkdf_extract(b"", b"\x0b" * 22)
    exp_cases = [
        (prk1, bytes(range(0xf0, 0xfa)), 42),
        (prk2, bytes(range(0xb0, 0x100)), 82),   # crosses several T blocks
        (prk3, b"", 42),
        (prk1, b"", 1),                          # a single byte of output
        (prk1, b"tls13 label context", 32),      # one exact block
    ]
    labels = []
    for n, (prk, info, ln) in enumerate(exp_cases):
        out.append(blob("exp_prk_%d" % n, prk))
        out.append(blob("exp_info_%d" % n, info))
        out.append(blob("exp_out_%d" % n, hkdf_expand(prk, info, ln)))
        labels.append((n, len(prk), len(info), ln))
    out.append("align 8\nhkdf_expand_tests:\n")
    for n, pl, il, ol in labels:
        out.append("    dq exp_prk_%d, %d, exp_info_%d, %d, exp_out_%d, %d\n"
                    % (n, pl, n, il, n, ol))
    out.append("hkdf_expand_test_count equ (($ - hkdf_expand_tests) / 48)\n")

    # ---- X25519: RFC 7748 section 5.2 single-shot vectors ------------
    x_cases = [
        (bytes.fromhex("a546e36bf0527c9d3b16154b82465edd"
                       "62144c0ac1fc5a18506a2244ba449ac4"),
         bytes.fromhex("e6db6867583030db3594c1a424b15f7c"
                       "726624ec26b3353b10a903a6d0ab1c4c")),
        (bytes.fromhex("4b66e9d4d1b4673c5ad22691957d6af5"
                       "c11b6421e0ea01d42ca4169e7918ba0d"),
         bytes.fromhex("e5210f12786811d3f4b7959d0538ae2c"
                       "31dbe7106fc03c3efc4cd549c715a493")),
    ]
    # RFC 7748's published answers, to fail loudly if the reference drifts.
    expect = [
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
    ]
    # Adversarial u-coordinates random pairs never hit: low-order points
    # (which must yield an all-zero shared secret), the 0 and 1 points,
    # and non-canonical encodings at and above p. Expected values come
    # from the reference; the point is that the assembly agrees on them.
    fixed_scalar = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    edge_u = [
        bytes(32),                                  # 0
        bytes([1]) + bytes(31),                     # 1
        # canonical low-order points of the curve (order 1, 2, 4, 8)
        bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd"
                      "866205165f49b800"),
        bytes.fromhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86"
                      "d8224eddd09f1157"),
        bytes(b"\xff" * 32),                        # non-canonical, > p
        bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffff"
                      "ffffffffffffff7f"),          # p - 1
        bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffff"
                      "ffffffffffffff7f"),          # p
    ]
    for u in edge_u:
        x_cases.append((fixed_scalar, u))

    labels = []
    for n, (scalar, u) in enumerate(x_cases):
        got = x25519(scalar, u)
        if n < len(expect):
            assert got.hex() == expect[n], (got.hex(), expect[n])
        out.append(blob("x_scalar_%d" % n, scalar))
        out.append(blob("x_u_%d" % n, u))
        out.append(blob("x_exp_%d" % n, got))
        labels.append(n)
    out.append("align 8\nx25519_tests:\n")
    for n in labels:
        out.append("    dq x_scalar_%d, x_u_%d, x_exp_%d\n" % (n, n, n))
    out.append("x25519_test_count equ (($ - x25519_tests) / 24)\n")

    # ---- X25519 iterated: the RFC's k=u=9 recurrence ----------------
    # 1 and 1000 rounds are in-suite; the million-round check runs in the
    # dev harness (test/crypto/diff_x25519.py).
    iters = [
        (1, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"),
        (1000, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"),
    ]
    labels = []
    for n, (rounds, exp) in enumerate(iters):
        got = x25519_iter(rounds)
        assert got.hex() == exp, (got.hex(), exp)
        out.append(blob("x_iter_exp_%d" % n, got))
        labels.append((n, rounds))
    out.append("align 8\nx25519_iter_tests:\n")
    for n, rounds in labels:
        out.append("    dq %d, x_iter_exp_%d\n" % (rounds, n))
    out.append("x25519_iter_test_count equ (($ - x25519_iter_tests) / 16)\n")

    # ---- Ed25519 signing vectors ------------------------------------
    # Expected signatures come from the reference above, which is
    # cross-checked byte-for-byte against OpenSSL in diff_ed25519.py. The
    # messages (empty, one byte, and lengths that straddle a SHA-512 block)
    # exercise the update path inside signing.
    ed_seeds = [
        "00" * 32,
        "9d61b19deffebc3a6c66682ee73310e75a20e33ddf8e37b37b19a11e4e5b8e1e",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "ff" * 32,
    ]
    ed_msgs = [b"", bytes.fromhex("72"), bytes.fromhex("af82"), b"a" * 260]
    labels = []
    for n, (seed_hex, msg) in enumerate(zip(ed_seeds, ed_msgs)):
        seed = bytes.fromhex(seed_hex)
        got = ed25519_sign(seed, msg)
        out.append(blob("ed_seed_%d" % n, seed))
        out.append(blob("ed_msg_%d" % n, msg))
        out.append(blob("ed_sig_%d" % n, got))
        labels.append((n, len(msg)))
    out.append("align 8\ned25519_tests:\n")
    for n, mlen in labels:
        out.append("    dq ed_seed_%d, ed_msg_%d, %d, ed_sig_%d\n"
                    % (n, n, mlen, n))
    out.append("ed25519_test_count equ (($ - ed25519_tests) / 32)\n")

    # ---- AES-128-GCM ------------------------------------------------
    # The reference above is asserted against the McGrew-Viega spec
    # vectors and every Wycheproof case for our exact profile (128-bit
    # key, 96-bit nonce, 128-bit tag) before anything is emitted.
    mv = [
        ("00" * 16, "00" * 12, "", "",
         "58e2fccefa7e3061367f1d57a4e7455a"),
        ("00" * 16, "00" * 12, "", "00" * 16,
         "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"),
        ("feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "",
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
         "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
         "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
         "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
         "4d5c2af327cd64a62cf35abd2ba6fab4"),
        ("feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
         "feedfacedeadbeeffeedfacedeadbeefabaddad2",
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
         "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
         "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
         "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
         "5bc94fbc3221a5db94fae95ae7121a47"),
    ]
    mv_cases = []
    for keyh, ivh, aadh, pth, exph in mv:
        key, iv, aad, pt, exp = (bytes.fromhex(h)
                                 for h in (keyh, ivh, aadh, pth, exph))
        got = aesgcm_seal(key, iv, aad, pt)
        assert got == exp, ("McGrew-Viega", got.hex(), exph)
        mv_cases.append((key, iv, aad, pt, exp))

    wy_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "wycheproof_aes_gcm.json")
    with open(wy_path) as f:
        wy_data = json.load(f)
    wy = []
    for g in wy_data["testGroups"]:
        if g["keySize"] == 128 and g["ivSize"] == 96 and g["tagSize"] == 128:
            for t in g["tests"]:
                key, iv, aad, msg, ct, tag = (
                    bytes.fromhex(t[k])
                    for k in ("key", "iv", "aad", "msg", "ct", "tag"))
                valid = t["result"] == "valid"
                assert (aesgcm_seal(key, iv, aad, msg) == ct + tag) == valid, \
                    ("wycheproof tcId", t["tcId"])
                wy.append((key, iv, aad, msg, ct + tag, valid))

    # Boundary lengths: empty, one byte, straddling every block edge, a
    # TLS-record-header-sized AAD (5), and one multi-KB message.
    gen_lens = [(0, 0), (0, 5), (1, 0), (15, 5), (16, 0), (16, 13),
                (17, 5), (31, 0), (32, 32), (33, 1), (63, 5), (64, 0),
                (65, 17), (255, 5), (256, 16), (1024, 5), (4109, 5)]
    gen_cases = []
    for n, (ptl, aadl) in enumerate(gen_lens):
        key = _det_bytes(b"key%d" % n, 16)
        nonce = _det_bytes(b"nonce%d" % n, 12)
        aad = _det_bytes(b"aad%d" % n, aadl)
        pt = _det_bytes(b"pt%d" % n, ptl)
        gen_cases.append((key, nonce, aad, pt,
                          aesgcm_seal(key, nonce, aad, pt)))

    seal_cases = gen_cases + mv_cases \
        + [(k, i, a, m, ct) for (k, i, a, m, ct, valid) in wy if valid]
    labels = []
    for n, (key, nonce, aad, pt, exp) in enumerate(seal_cases):
        out.append(blob("gcm_s_key_%d" % n, key))
        out.append(blob("gcm_s_nonce_%d" % n, nonce))
        out.append(blob("gcm_s_aad_%d" % n, aad))
        out.append(blob("gcm_s_pt_%d" % n, pt))
        out.append(blob("gcm_s_exp_%d" % n, exp))
        labels.append((n, len(aad), len(pt)))
    out.append("align 8\naesgcm_seal_tests:\n")
    for n, al, pl in labels:
        out.append("    dq gcm_s_key_%d, gcm_s_nonce_%d, gcm_s_aad_%d, %d, "
                   "gcm_s_pt_%d, %d, gcm_s_exp_%d\n" % (n, n, n, al, n, pl, n))
    out.append("aesgcm_seal_test_count equ (($ - aesgcm_seal_tests) / 56)\n")

    # Open cases: every Wycheproof case (the invalid ones must be
    # rejected with the output zeroed), round-trips of the boundary
    # cases, plus local tampering: tag bit, ciphertext byte, AAD byte,
    # and inputs shorter than a tag.
    def flipped(b, i, bit):
        b = bytearray(b)
        b[i] ^= bit
        return bytes(b)

    open_cases = []
    for (key, iv, aad, msg, cttag, valid) in wy:
        exp_pt = msg if valid else bytes(max(len(cttag) - 16, 0))
        open_cases.append((key, iv, aad, cttag, exp_pt, 1 if valid else 0))
    for (key, nonce, aad, pt, cttag) in gen_cases:
        open_cases.append((key, nonce, aad, cttag, pt, 1))
    key, nonce, aad, pt, cttag = gen_cases[5]      # 16-byte pt, 13-byte aad
    zero_pt = bytes(len(pt))
    open_cases.append((key, nonce, aad,
                       flipped(cttag, len(cttag) - 1, 1), zero_pt, 0))
    open_cases.append((key, nonce, aad, flipped(cttag, 0, 0x80), zero_pt, 0))
    open_cases.append((key, nonce, flipped(aad, 0, 1), cttag, zero_pt, 0))
    open_cases.append((key, nonce, aad, cttag[:15], b"", 0))
    open_cases.append((key, nonce, aad, b"", b"", 0))
    labels = []
    for n, (key, nonce, aad, ct, exp_pt, ok) in enumerate(open_cases):
        out.append(blob("gcm_o_key_%d" % n, key))
        out.append(blob("gcm_o_nonce_%d" % n, nonce))
        out.append(blob("gcm_o_aad_%d" % n, aad))
        out.append(blob("gcm_o_ct_%d" % n, ct))
        out.append(blob("gcm_o_pt_%d" % n, exp_pt))
        labels.append((n, len(aad), len(ct), ok))
    out.append("align 8\naesgcm_open_tests:\n")
    for n, al, cl, ok in labels:
        out.append("    dq gcm_o_key_%d, gcm_o_nonce_%d, gcm_o_aad_%d, %d, "
                   "gcm_o_ct_%d, %d, gcm_o_pt_%d, %d\n"
                   % (n, n, n, al, n, cl, n, ok))
    out.append("aesgcm_open_test_count equ (($ - aesgcm_open_tests) / 64)\n")

    # ---- TLS 1.3: HKDF-Expand-Label and record vectors, all anchored --
    # ---- in the RFC 8448 trace which rfc8448() replayed and asserted --
    tr = rfc8448()
    hel_cases = [
        (tr["early"], b"derived", tr["empty_hash"], 32),
        (tr["hs"], b"c hs traffic", tr["th_ch_sh"], 32),
        (tr["hs"], b"s hs traffic", tr["th_ch_sh"], 32),
        (tr["hs"], b"derived", tr["empty_hash"], 32),
        (tr["s_hs"], b"key", b"", 16),
        (tr["s_hs"], b"iv", b"", 12),
        (tr["s_hs"], b"finished", b"", 32),
        (tr["c_hs"], b"finished", b"", 32),
        (tr["master"], b"c ap traffic", tr["th_to_sfin"], 32),
        (tr["master"], b"s ap traffic", tr["th_to_sfin"], 32),
        (tr["master"], b"exp master", tr["th_to_sfin"], 32),
        (tr["s_ap"], b"key", b"", 16),
        (tr["s_ap"], b"iv", b"", 12),
        (tr["c_hs"], b"key", b"", 16),
        (tr["c_hs"], b"iv", b"", 12),
        (tr["c_ap"], b"key", b"", 16),
        (tr["c_ap"], b"iv", b"", 12),
    ]
    labels = []
    for n, (secret, label, ctx, outlen) in enumerate(hel_cases):
        exp = hkdf_expand_label(secret, label, ctx, outlen)
        out.append(blob("hel_sec_%d" % n, secret))
        out.append(blob("hel_lbl_%d" % n, label))
        out.append(blob("hel_ctx_%d" % n, ctx))
        out.append(blob("hel_exp_%d" % n, exp))
        labels.append((n, len(label), len(ctx), outlen))
    out.append("align 8\ntls_hel_tests:\n")
    for n, ll, cl, ol in labels:
        out.append("    dq hel_sec_%d, hel_lbl_%d, %d, hel_ctx_%d, %d, "
                   "hel_exp_%d, %d\n" % (n, n, ll, n, cl, n, ol))
    out.append("tls_hel_test_count equ (($ - tls_hel_tests) / 56)\n")

    # Record protection: seal cases are (traffic secret, seq, inner type,
    # payload) -> the trace's exact wire record, covering handshake
    # coalescing, post-handshake NST, app data and alerts at seq 0/1/2.
    seal_cases = [
        (tr["s_hs"], 0, 0x16, tr["flight"], tr["flight_record"]),
        (tr["c_hs"], 0, 0x16, tr["c_fin"], tr["c_fin_record"]),
        (tr["s_ap"], 0, 0x16, tr["nst"], tr["nst_record"]),
        (tr["c_ap"], 0, 0x17, tr["c_app"], tr["c_app_record"]),
        (tr["s_ap"], 1, 0x17, tr["s_app"], tr["s_app_record"]),
        (tr["c_ap"], 1, 0x15, tr["c_alert"], tr["c_alert_record"]),
        (tr["s_ap"], 2, 0x15, tr["s_alert"], tr["s_alert_record"]),
    ]
    labels = []
    for n, (secret, seq, rtype, payload, exp) in enumerate(seal_cases):
        out.append(blob("tsl_sec_%d" % n, secret))
        out.append(blob("tsl_pay_%d" % n, payload))
        out.append(blob("tsl_exp_%d" % n, exp))
        labels.append((n, seq, rtype, len(payload), len(exp)))
    out.append("align 8\ntls_seal_tests:\n")
    for n, seq, rtype, pl, el in labels:
        out.append("    dq tsl_sec_%d, %d, %d, tsl_pay_%d, %d, tsl_exp_%d, "
                   "%d\n" % (n, seq, rtype, n, pl, n, el))
    out.append("tls_seal_test_count equ (($ - tls_seal_tests) / 56)\n")

    # Open direction: the same records decrypted, plus a padded record, a
    # padding-only record (no content type -> reject), a corrupted tag
    # and a wrong sequence number.
    def raw_seal(secret, seq, inner):
        key = hkdf_expand_label(secret, b"key", b"", 16)
        iv = hkdf_expand_label(secret, b"iv", b"", 12)
        nonce = bytes(a ^ b for a, b in
                      zip(iv, bytes(4) + seq.to_bytes(8, "big")))
        hdr = b"\x17\x03\x03" + (len(inner) + 16).to_bytes(2, "big")
        return hdr + aesgcm_seal(key, nonce, hdr, inner)

    padded = raw_seal(tr["c_ap"], 0, tr["c_app"] + b"\x17" + bytes(9))
    padding_only = raw_seal(tr["c_ap"], 0, bytes(24))
    corrupt = bytearray(tr["c_fin_record"])
    corrupt[-1] ^= 0x40
    open_cases = [
        (tr["s_hs"], 0, tr["flight_record"], tr["flight"], 0x16, 1),
        (tr["c_hs"], 0, tr["c_fin_record"], tr["c_fin"], 0x16, 1),
        (tr["s_ap"], 0, tr["nst_record"], tr["nst"], 0x16, 1),
        (tr["c_ap"], 0, tr["c_app_record"], tr["c_app"], 0x17, 1),
        (tr["s_ap"], 1, tr["s_app_record"], tr["s_app"], 0x17, 1),
        (tr["c_ap"], 1, tr["c_alert_record"], tr["c_alert"], 0x15, 1),
        (tr["s_ap"], 2, tr["s_alert_record"], tr["s_alert"], 0x15, 1),
        (tr["c_ap"], 0, padded, tr["c_app"], 0x17, 1),
        (tr["c_ap"], 0, padding_only, b"", 0, 0),
        (tr["c_hs"], 0, bytes(corrupt), b"", 0, 0),
        (tr["c_ap"], 1, tr["c_app_record"], b"", 0, 0),
    ]
    labels = []
    for n, (secret, seq, rec, exp, rtype, ok) in enumerate(open_cases):
        out.append(blob("top_sec_%d" % n, secret))
        out.append(blob("top_rec_%d" % n, rec))
        out.append(blob("top_exp_%d" % n, exp))
        labels.append((n, seq, len(rec), len(exp), rtype, ok))
    out.append("align 8\ntls_open_tests:\n")
    for n, seq, rl, el, rtype, ok in labels:
        out.append("    dq top_sec_%d, %d, top_rec_%d, %d, top_exp_%d, %d, "
                   "%d, %d\n" % (n, seq, n, rl, n, el, rtype, ok))
    out.append("tls_open_test_count equ (($ - tls_open_tests) / 64)\n")

    # ---- P-256 field arithmetic -------------------------------------
    # Records are (op, a, b, want); a/b/want are 32-byte big-endian, which
    # is what linnea_p256_fe_frombytes/tobytes speak. The selftest converts
    # in, applies the op, converts out, and compares.
    cases = p256_fe_cases()
    labels = []
    for n, (op, a, b) in enumerate(cases):
        want = p256_fe(op, a, b)
        out.append(blob("p256a_%d" % n, (a % (2 ** 256)).to_bytes(32, "big")))
        out.append(blob("p256b_%d" % n, (b % (2 ** 256)).to_bytes(32, "big")))
        out.append(blob("p256w_%d" % n, want.to_bytes(32, "big")))
        labels.append((n, op))
    out.append("align 8\np256_fe_tests:\n")
    for n, op in labels:
        out.append("    dq %d, p256a_%d, p256b_%d, p256w_%d\n" % (op, n, n, n))
    out.append("p256_fe_test_count equ (($ - p256_fe_tests) / 32)\n")

    # The deterministic handshake check: feed the trace's ClientHello
    # record into linnea_tls with the trace's server key/random injected;
    # the emitted ServerHello record and the c/s handshake traffic and
    # master secrets must equal the trace's (the flight beyond that is
    # Ed25519 where the trace is RSA, so the transcripts then diverge).
    out.append(blob("trace_ch_rec", tr["ch_record"]))
    out.append(blob("trace_srv_priv", tr["server_priv"]))
    out.append(blob("trace_srv_rand", tr["server_random"]))
    out.append(blob("trace_sh_rec", tr["sh_record"]))
    out.append(blob("trace_c_hs", tr["c_hs"]))
    out.append(blob("trace_s_hs", tr["s_hs"]))
    out.append(blob("trace_master", tr["master"]))
    out.append("align 8\ntls_trace_ch_rec_len equ %d\n" % len(tr["ch_record"]))
    out.append("tls_trace_sh_rec_len equ %d\n" % len(tr["sh_record"]))

    print("".join(out), end="")


if __name__ == "__main__":
    main()
