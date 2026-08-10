#!/usr/bin/env python3
"""Malformed QUIC TRANSPORT frames, in Initial packets, at an unauthenticated
attacker's reach.

The frame parsers in src/lib/linnea_quic.asm walk raw attacker bytes:
frame_skip, frames_check, stream_frame, crypto_frame, ack_record, tp_parse.
Every length in them comes off the wire as a varint that can claim up to 2^62,
so the whole of their safety is bounds checks that must hold for every shape.
Reading them is not the same as trying them.

Initial packets are the sharpest place to try: their keys derive from the
Destination Connection ID, which is public, so none of this needs a handshake.
test/tls/fuzz_clienthello.py and fuzz_h2.py do the same job one layer up;
h3_malformed_test.py covers HTTP/3 application frames, not these.

What counts as a failure is not a rejection — refusing malformed input is the
point. It is the server dying, hanging, or coming back changed: the check is
that every worker survives and the port still serves afterwards.

Usage: fuzz_quic_frames.py <port> [rounds]
"""
import os
import random
import socket
import struct
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

PORT = int(sys.argv[1])
ROUNDS = int(sys.argv[2]) if len(sys.argv) > 2 else 400
ADDR = ("127.0.0.1", PORT)
INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def hkdf_extract(salt, ikm):
    """HKDF-Extract is just HMAC(salt, ikm) — spelled out rather than reached
    for through HKDF's private _extract, which is not API and has moved."""
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(ikm)
    return h.finalize()


def expand_label(secret, label, n):
    info = struct.pack(">H", n) + bytes([6 + len(label)]) + b"tls13 " + label + b"\x00"
    return HKDFExpand(algorithm=SHA256(), length=n, info=info).derive(secret)


def initial_keys(dcid):
    initial = hkdf_extract(INITIAL_SALT, dcid)
    cs = expand_label(initial, b"client in", 32)
    return (expand_label(cs, b"quic key", 16),
            expand_label(cs, b"quic iv", 12),
            expand_label(cs, b"quic hp", 16))


def varint(v):
    if v < 0x40:
        return bytes([v])
    if v < 0x4000:
        return struct.pack(">H", v | 0x4000)
    if v < 0x40000000:
        return struct.pack(">I", v | 0x80000000)
    return struct.pack(">Q", v | 0xC000000000000000)


HUGE = [0, 1, 63, 64, 16383, 16384, 2**30 - 1, 2**30, 2**62 - 1, 2**62 - 2]


def rand_varint(r):
    """Biased hard toward the values that break length arithmetic."""
    if r.random() < 0.55:
        return varint(r.choice(HUGE))
    return varint(r.randrange(0, 2**62))


def rand_frame(r):
    """One transport frame, its lengths deliberately at odds with reality."""
    t = r.choice([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                  0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
                  0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                  0x1e, 0x30, 0x31, r.randrange(0, 0x40)])
    body = b""
    if t in (0x02, 0x03):                       # ACK: count vs actual ranges
        body = (rand_varint(r) + rand_varint(r) + rand_varint(r)
                + rand_varint(r) + b"".join(rand_varint(r)
                                            for _ in range(r.randrange(0, 4))))
        if t == 0x03:
            body += rand_varint(r) * 3
    elif 0x08 <= t <= 0x0f:                     # STREAM, flags in the low bits
        body = rand_varint(r)
        if t & 0x04:
            body += rand_varint(r)
        if t & 0x02:
            body += rand_varint(r) + os.urandom(r.randrange(0, 24))
        else:
            body += os.urandom(r.randrange(0, 24))
    elif t == 0x06:                             # CRYPTO: offset, length, data
        body = rand_varint(r) + rand_varint(r) + os.urandom(r.randrange(0, 24))
    elif t == 0x07:                             # NEW_TOKEN
        body = rand_varint(r) + os.urandom(r.randrange(0, 16))
    elif t == 0x18:                             # NEW_CONNECTION_ID
        body = (rand_varint(r) + rand_varint(r) + bytes([r.randrange(0, 256)])
                + os.urandom(r.randrange(0, 24)))
    elif t in (0x1c, 0x1d):                     # CONNECTION_CLOSE
        body = rand_varint(r) + (rand_varint(r) if t == 0x1c else b"")
        body += rand_varint(r) + os.urandom(r.randrange(0, 16))
    elif t in (0x1a, 0x1b):
        body = os.urandom(r.randrange(0, 8))    # short PATH_* on purpose
    else:
        body = b"".join(rand_varint(r) for _ in range(r.randrange(0, 3)))
    return bytes([t]) + body


def initial_packet(dcid, scid, payload, pn=0):
    key, iv, hp = initial_keys(dcid)
    pnb = struct.pack(">I", pn)
    hdr = (bytes([0xC3]) + struct.pack(">I", 1)
           + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
           + varint(0))                              # token length
    # pad so the datagram reaches the 1200 floor a server will process
    need = 1200 - len(hdr) - 2 - 4 - 16
    if len(payload) < need:
        payload += b"\x00" * (need - len(payload))
    length = len(payload) + 16 + 4
    hdr += struct.pack(">H", length | 0x4000) + pnb
    nonce = bytes(a ^ b for a, b in zip(iv, b"\x00" * 8 + pnb))
    ct = AESGCM(key).encrypt(nonce, payload, hdr)
    # RFC 9001 5.4.2: the sample starts four bytes past the start of the
    # packet number field. The number is four bytes here, so that is exactly
    # the first ciphertext byte.
    sample = ct[0:16]
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    out = bytearray(hdr + ct)
    out[0] ^= mask[0] & 0x0F
    off = len(hdr) - 4
    for i in range(4):
        out[off + i] ^= mask[1 + i]
    return bytes(out)


def workers_of(master):
    try:
        return set(subprocess.run(["pgrep", "-P", str(master)],
                                  capture_output=True, text=True).stdout.split())
    except Exception:
        return set()


master = sys.argv[3] if len(sys.argv) > 3 else None
before = workers_of(master) if master else set()

r = random.Random(20260810)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.02)
sent = 0
for i in range(ROUNDS):
    dcid = os.urandom(8)
    payload = b"".join(rand_frame(r) for _ in range(r.randrange(1, 14)))
    try:
        s.sendto(initial_packet(dcid, os.urandom(8), payload, pn=r.randrange(0, 4)),
                 ADDR)
        sent += 1
    except Exception as e:
        print("send failed:", e)
        break
    try:
        while True:
            s.recvfrom(4096)
    except socket.timeout:
        pass
s.close()

print("sent %d malformed Initial packets" % sent)

after = workers_of(master) if master else set()
if master:
    if before != after:
        print("FAIL workers changed: %s -> %s (a worker died and respawned)"
              % (sorted(before), sorted(after)))
        sys.exit(1)
    print("workers unchanged: %s" % sorted(after))

# ...and the port still answers. This fixture is TLS, so the liveness check has
# to speak it: a plaintext GET would fail here whatever the fuzz did, which is
# the sort of check that reports a fault it did not find.
ok = False
for _ in range(3):
    try:
        out = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", "8", "--cacert", "test/tls/server.crt",
             "https://localhost:%d/hello.txt" % PORT],
            capture_output=True, text=True, timeout=15).stdout
        ok = out.strip() == "200"
        if ok:
            break
    except Exception:
        pass
print("still serving afterwards: %s" % ok)
sys.exit(0 if ok else 1)
