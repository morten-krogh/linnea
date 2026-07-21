#!/usr/bin/env python3
# Parse linnea's QUIC ServerHello (read from stdin) with aioquic's TLS parser
# and confirm the negotiated profile, proving the message interoperates.
import sys

from aioquic.buffer import Buffer
from aioquic import tls

sh = tls.pull_server_hello(Buffer(data=sys.stdin.buffer.read()))
assert sh.cipher_suite == tls.CipherSuite.AES_128_GCM_SHA256, sh.cipher_suite
assert sh.supported_version == tls.TLS_VERSION_1_3, hex(sh.supported_version)
group, key = sh.key_share
assert group == tls.Group.X25519, group
assert key == bytes(range(0xa0, 0xc0)), key.hex()
print("ok")
