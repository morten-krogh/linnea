# Security policy

**Please report vulnerabilities privately — do not open a public issue.**

Use this repository's private vulnerability reporting on GitHub (Security →
Report a vulnerability), or email **morten.krogh@amberbio.com**. A clear
reproduction against a real binary is the most useful thing you can send.

Linnea implements its own TLS 1.3 and cryptography and is written in unmanaged
assembly, so security is taken seriously and stated honestly. For the threat
model, the trade-offs of self-contained crypto, the audit history, and what
linnea is and is not suitable for, see [`docs/security.md`](docs/security.md).
