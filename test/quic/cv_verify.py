#!/usr/bin/env python3
# Verify linnea's CertificateVerify (stdin): parse it with aioquic, then check
# the ECDSA signature against the test certificate's public key over the
# reconstructed signed content — a real cryptographic verification.
import sys

from aioquic.buffer import Buffer
from aioquic import tls
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

cv = tls.pull_certificate_verify(Buffer(data=sys.stdin.buffer.read()))
assert cv.algorithm == tls.SignatureAlgorithm.ECDSA_SECP256R1_SHA256, cv.algorithm

transcript = bytes(range(32))
content = (b" " * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00" + transcript)

cert = x509.load_pem_x509_certificate(open("test/tls/server.crt", "rb").read())
cert.public_key().verify(cv.signature, content, ec.ECDSA(hashes.SHA256()))
print("ok")
