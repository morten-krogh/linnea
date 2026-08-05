#!/usr/bin/env python3
# tls-8 / tls-9: the server refuses the right things, but for years it named the
# wrong reason. An alert code is the only thing a client has to act on, so a
# plausible-but-wrong one sends it to fix the wrong problem: handshake_failure
# for a version mismatch tells an old client to change its cipher list.
#
# Each case here drives a hand-built ClientHello and reads the DESCRIPTION BYTE
# of the alert that comes back. Most arrive in the clear, before any key is
# agreed. The last one does not: an AEAD failure is reported under the server's
# handshake key, so this client runs the TLS 1.3 key schedule as far as
# server_handshake_traffic_secret -- which needs only CH and SH -- and decrypts
# it. Without that, the one finding whose fix is about ciphertext could only be
# tested by watching the connection die, which is what it did before too.
# Usage: alert_codes.py <port> [host]   (host defaults to 127.0.0.1)
import hashlib
import hmac
import os
import socket
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PORT = int(sys.argv[1])
HOST = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
ADDR = (HOST, PORT)

CLOSE_NOTIFY, UNEXPECTED_MESSAGE, BAD_RECORD_MAC = 0, 10, 20
RECORD_OVERFLOW = 22
HANDSHAKE_FAILURE, DECODE_ERROR, DECRYPT_ERROR = 40, 50, 51
PROTOCOL_VERSION, MISSING_EXTENSION = 70, 109

NAMES = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
         22: "record_overflow",
         40: "handshake_failure", 47: "illegal_parameter", 50: "decode_error",
         51: "decrypt_error", 70: "protocol_version", 80: "internal_error",
         109: "missing_extension", 120: "no_application_protocol"}


def ext(kind: int, body: bytes) -> bytes:
    return struct.pack(">HH", kind, len(body)) + body


def client_hello(pub: bytes = None, sigalgs=(0x0403,), tls13=True,
                 suites=(0x1301,), groups=(0x001d,)) -> bytes:
    """A ClientHello with each piece switchable, so one case can differ from the
    next by exactly the thing under test."""
    exts = b""
    if tls13:
        exts += ext(43, bytes([2]) + struct.pack(">H", 0x0304))   # supported_versions
    if groups:
        exts += ext(10, struct.pack(">H", 2 * len(groups))
                    + b"".join(struct.pack(">H", g) for g in groups))
    if pub is not None:
        share = struct.pack(">HH", 0x001d, len(pub)) + pub
        exts += ext(51, struct.pack(">H", len(share)) + share)     # key_share
    elif tls13:
        exts += ext(51, struct.pack(">H", 0))                      # empty: draws an HRR
    if sigalgs:
        exts += ext(13, struct.pack(">H", 2 * len(sigalgs))
                    + b"".join(struct.pack(">H", a) for a in sigalgs))
    body = (struct.pack(">H", 0x0303) + os.urandom(32)
            + bytes([32]) + os.urandom(32)
            + struct.pack(">H", 2 * len(suites))
            + b"".join(struct.pack(">H", c) for c in suites)
            + bytes([1, 0])
            + struct.pack(">H", len(exts)) + exts)
    hs = bytes([1]) + len(body).to_bytes(3, "big") + body
    return hs


def rec(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + b"\x03\x03" + struct.pack(">H", len(body)) + body


def read_record(s):
    """-> (type, body) or None if the peer closed."""
    head = b""
    while len(head) < 5:
        chunk = s.recv(5 - len(head))
        if not chunk:
            return None
        head += chunk
    n = struct.unpack(">H", head[3:5])[0]
    body = b""
    while len(body) < n:
        chunk = s.recv(n - len(body))
        if not chunk:
            return None
        body += chunk
    return head[0], body, head


def alert_from(s):
    """Read records until an alert arrives; -> its description, or None."""
    while True:
        r = read_record(s)
        if r is None:
            return None
        kind, body, _ = r
        if kind == 21 and len(body) >= 2:
            return body[1]


# ---- the TLS 1.3 key schedule, only as far as this test needs ----
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand_label(secret: bytes, label: bytes, ctx: bytes, n: int) -> bytes:
    info = struct.pack(">H", n) + bytes([6 + len(label)]) + b"tls13 " + label \
        + bytes([len(ctx)]) + ctx
    out, prev, i = b"", b"", 1
    while len(out) < n:
        prev = hmac.new(secret, prev + info + bytes([i]), hashlib.sha256).digest()
        out += prev
        i += 1
    return out[:n]


def server_hs_key(priv, server_pub: bytes, transcript: bytes):
    shared = priv.exchange(_pub(server_pub))
    early = hkdf_extract(b"\x00" * 32, b"\x00" * 32)
    derived = hkdf_expand_label(early, b"derived", hashlib.sha256(b"").digest(), 32)
    handshake = hkdf_extract(derived, shared)
    s_hs = hkdf_expand_label(handshake, b"s hs traffic",
                             hashlib.sha256(transcript).digest(), 32)
    return (hkdf_expand_label(s_hs, b"key", b"", 16),
            hkdf_expand_label(s_hs, b"iv", b"", 12))


def _pub(raw: bytes):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    return X25519PublicKey.from_public_bytes(raw)


def sh_key_share(sh_body: bytes) -> bytes:
    """The server's x25519 share, out of a ServerHello handshake message."""
    p = 4 + 2 + 32                      # type+len, version, random
    p += 1 + sh_body[p]                 # legacy_session_id_echo
    p += 2 + 1                          # cipher_suite, compression
    ext_len = struct.unpack(">H", sh_body[p:p + 2])[0]
    p += 2
    end = p + ext_len
    while p + 4 <= end:
        kind, n = struct.unpack(">HH", sh_body[p:p + 4])
        if kind == 51:                  # key_share
            return sh_body[p + 4 + 4: p + 4 + 4 + 32]
        p += 4 + n
    raise AssertionError("no key_share in the ServerHello")


results = []


def case(name, want, got):
    ok = got == want
    results.append(ok)
    w = NAMES.get(want, "?")
    g = NAMES.get(got, got if got is not None else "no alert / connection closed")
    print(f"{'ok  ' if ok else 'FAIL'} {name}: want {w}({want}), got {g}"
          + ("" if ok else f"({got})"))


def connect():
    s = socket.create_connection(ADDR, timeout=5)
    s.settimeout(5)
    return s


# 1. a record type that has no business here at all (RFC 8446 5.1)
s = connect()
s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
case("plain HTTP on the TLS port", UNEXPECTED_MESSAGE, alert_from(s))
s.close()

# 2. a TLS 1.2 client: the version is what is wrong, not the cipher list
s = connect()
s.sendall(rec(22, client_hello(pub=None, tls13=False, suites=(0xc02b,),
                               groups=(0x0017,), sigalgs=(0x0403,))))
case("TLS 1.2 ClientHello", PROTOCOL_VERSION, alert_from(s))
s.close()

# 3. signature_algorithms left out entirely (RFC 8446 9.2 / 4.2)
priv = X25519PrivateKey.generate()
pub = priv.public_key().public_bytes_raw()
s = connect()
s.sendall(rec(22, client_hello(pub=pub, sigalgs=())))
case("no signature_algorithms", MISSING_EXTENSION, alert_from(s))
s.close()

# 4. ...but present and listing nothing we sign with is a different fault, and
#    must keep the code it always had -- this is the control for case 3
s = connect()
s.sendall(rec(22, client_hello(pub=pub, sigalgs=(0x0806,))))   # rsa_pss_rsae_sha256
case("signature_algorithms without our scheme", HANDSHAKE_FAILURE, alert_from(s))
s.close()

# 5. a ChangeCipherSpec carrying something other than 0x01 (RFC 8446 5). It is
#    only tolerated after a HelloRetryRequest, so draw one first with a hello
#    that lists x25519 but sends no share for it.
s = connect()
s.sendall(rec(22, client_hello(pub=None)))
r = read_record(s)                                    # the HelloRetryRequest
assert r and r[0] == 22, f"expected a HelloRetryRequest, got {r[0] if r else None}"
s.sendall(rec(20, b"\x02"))                           # CCS with the wrong byte
case("ChangeCipherSpec with a bad value", UNEXPECTED_MESSAGE, alert_from(s))
s.close()

# 6. an unencrypted handshake record longer than a TLSPlaintext may be (tls-10).
#    2^14 is the plaintext bound (5.1); 2^14+256 is the CIPHERTEXT one (5.2) and
#    was being applied here, so 16385..16640 got in.
s = connect()
s.sendall(rec(22, b"\x01" + (16385 - 1).to_bytes(3, "big") + b"\x00" * (16385 - 4)))
case("handshake record over 2^14", RECORD_OVERFLOW, alert_from(s))
s.close()

# 7. a record that does not open (tls-8). The alert is sealed under the server's
#    handshake key, so derive it and read the description out.
s = connect()
ch = client_hello(pub=pub)
s.sendall(rec(22, ch))
r = read_record(s)
assert r and r[0] == 22, "expected a ServerHello"
sh = r[1]
key, iv = server_hs_key(priv, sh_key_share(sh), ch + sh)
s.sendall(rec(23, os.urandom(64)))                    # nothing that can authenticate
seq, got = 0, None
while got is None:
    r = read_record(s)
    if r is None:
        break
    kind, body, head = r
    if kind != 23:
        continue                                      # the compatibility CCS
    nonce = bytes(a ^ b for a, b in zip(iv, b"\x00" * 4 + struct.pack(">Q", seq)))
    seq += 1
    try:
        pt = AESGCM(key).decrypt(nonce, body, head)
    except Exception:
        continue                                      # not ours to read
    inner = pt.rstrip(b"\x00")                       # strip record padding
    if inner and inner[-1] == 21 and len(inner) >= 3: # inner type 21 = alert;
        got = inner[1]                                # body is level, description
case("a record that fails to decrypt", BAD_RECORD_MAC, got)
s.close()

print(f"\n{sum(results)}/{len(results)} alert codes correct")
sys.exit(0 if all(results) else 1)
