#!/usr/bin/env python3
# Verify linnea's Finished (stdin): parse it with aioquic, then recompute the
# verify_data independently and compare. verify_data =
# HMAC(HKDF-Expand-Label(s_hs, "finished"), transcript_hash).
import hashlib
import hmac
import sys

from aioquic.buffer import Buffer
from aioquic import tls
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes


def hkdf_expand_label(secret, label, context, length):
    full = b"tls13 " + label
    info = (length.to_bytes(2, "big") + bytes([len(full)]) + full
            + bytes([len(context)]) + context)
    return HKDFExpand(hashes.SHA256(), length, info).derive(secret)


fin = tls.pull_finished(Buffer(data=sys.stdin.buffer.read()))
s_hs = bytes(range(32))
th = bytes(range(32, 64))
fkey = hkdf_expand_label(s_hs, b"finished", b"", 32)
expected = hmac.new(fkey, th, hashlib.sha256).digest()
assert fin.verify_data == expected, (fin.verify_data.hex(), expected.hex())
print("ok")
