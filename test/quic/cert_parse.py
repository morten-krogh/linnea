#!/usr/bin/env python3
# Parse linnea's TLS Certificate handshake message (stdin) with aioquic and
# confirm it wraps the test certificate chain correctly.
import sys

from aioquic.buffer import Buffer
from aioquic import tls

cert = tls.pull_certificate(Buffer(data=sys.stdin.buffer.read()))
assert cert.request_context == b"", cert.request_context
assert len(cert.certificates) >= 1, "no certificates"
der, exts = cert.certificates[0]
assert len(der) > 0, "empty certificate"
print("ok")
