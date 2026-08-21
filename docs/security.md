# Security

Linnea terminates TLS and QUIC from the open internet and is written in
unmanaged assembly with its own cryptography. That combination demands honesty
about what is and is not defended, and about where the real risks are. This
document is that account. How the code is written and reviewed is in
[`ai-development.md`](ai-development.md).

## Reporting a vulnerability

**Please report security issues privately — do not open a public issue.**

Use this repository's **private vulnerability reporting** on GitHub (Security →
Report a vulnerability), or email the maintainer directly at
**morten.krogh@amberbio.com**. We will acknowledge, investigate, and coordinate
a fix and disclosure. Given the nature of the project, a clear reproduction
against a real binary is the most useful thing you can send.

## What linnea is exposed to

Everything before authentication. A client can open a TCP or QUIC connection and
drive the TLS handshake, the HTTP/1, HTTP/2 or HTTP/3 machinery, and the request
router before linnea has any reason to trust it. The hardened surface is
therefore the whole protocol stack: the TLS 1.3 handshake, the QUIC transport,
HPACK/QPACK header decoding, request parsing and routing, and the proxy's
handling of upstream responses.

Backends are reached over loopback only and are trusted to the extent that
loopback is; linnea still refuses to relay a malformed upstream response rather
than pass it through.

## The self-contained cryptography

Linnea implements its own TLS 1.3 and every primitive under it — X25519, P-256
and ECDSA, AES-GCM, SHA-2, the HKDF key schedule — rather than linking a
cryptographic library. This cuts both ways, and both sides are real:

- **In its favour:** there is no OpenSSL/BoringSSL in the trust base, so linnea
  inherits none of that surface's vulnerabilities, and the entire cryptographic
  path is auditable in one tree.
- **Against it:** this code is far less battle-tested than a mature library. It
  has not had the years of adversarial attention, fuzzing and formal work that
  BoringSSL has. Treat it accordingly, and weigh it in any decision to deploy.

The profile is deliberately minimal — a single cipher suite
(`TLS_AES_128_GCM_SHA256`), X25519, and ECDSA P-256 — which shrinks the surface
to one path rather than a matrix, but is also a hard constraint on what clients
and certificates linnea can serve.

The sharpest illustration of the risk is a real one, now fixed: the required
check that the computed X25519 shared secret is not all-zero
([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) §6.1) was **missing from both
handshake paths**, and it survived a 71-finding audit before a later review
caught it. It was not exploitable, for separate reasons, and that too was stated
at the time — but a MUST-level check was absent, and thousands of green
cryptographic test vectors could not have found it, because they exercised the
code that was present. This is the shape of the danger with self-contained
crypto: omissions, not the arithmetic.

## The substrate: no memory safety

The server is hand-written assembly. There is no memory safety, no bounds
checking by the language, and no type system. Every buffer is fixed and sized at
build time, and every copy into one is meant to be bounded before it happens —
those bounds *are* the safety, because nothing underneath provides any. A large
part of the audit work is proving each buffer is big enough for the largest
input the configuration can produce, and that no path writes past it.

## Auditing

Linnea has been through repeated, structured security and RFC-conformance
audits — across HTTP/1, HTTP/2, HTTP/3, QUIC and TLS — most of them AI-driven,
each producing a numbered report whose findings are fixed and verified one at a
time. These have closed, among much else, a pre-authentication QUIC issue, a
method-parsing flaw, and several HPACK/QPACK decoding hazards.

Two honest lessons run through that history and shape how the project works:

- **A green test suite proves the presence of correct behaviour, not the absence
  of a missing one.** The most serious findings have been omissions, which no
  passing test detects.
- **"Audited and unchanged" predicts no regressions and says nothing about
  omissions.** The X25519 gap predated every audit that missed it.

The response to both is method, not confidence: findings are demonstrated
against a running binary before they are believed, and fixes are proven by
running the old and new binaries side by side. See
[`ai-development.md`](ai-development.md).

## What to trust it for

Linnea is suitable as a self-contained, hardened edge server for a site you
control and can watch. It is **not** offered as a hardened cryptographic library
for other software to build on, and its own crypto should not be extracted and
trusted as though it were one. If your threat model requires the assurance of a
mature, widely deployed TLS stack, use one; if it values a tiny, dependency-free,
auditable-in-one-tree edge and you accept the trade-offs above, linnea is built
for that.
