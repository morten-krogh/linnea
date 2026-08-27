# Audit Report 99

Audited at `7fb0ef0` (`quic: send nothing rather than a packet built from stale entropy (report 98)`), 2026-08-27.

Report 98's two QUIC entropy fixes are correct: both packet builders now test
the shared exact-length helper, unwind their live stack frames, and return
without `sendto` on failure. This pass then widened from runtime cryptographic
material to the startup boundary that loads the long-term TLS identity.

Three independently reproducible validation defects are batched here:

1. **Medium: any nonempty decoded byte string is accepted as a certificate,
   even when it is not an X.509 object.**
2. **Medium: a valid certificate and a valid but unrelated private key pass
   `--test`, producing a CertificateVerify every client must reject.**
3. **Low: both certificate and private-key PEM files are accepted without an
   END encapsulation boundary.**

These findings are operator-input defects rather than remote parsing attacks.
Their operational significance comes from the documented role of `--test`:
the command says it checks the configuration and certificates, and the reload
workflow relies on that result to keep a bad credential update from replacing
a working generation
([docs/config.md:11](/home/linnea/linnea/docs/config.md:11), [docs/config.md:30](/home/linnea/linnea/docs/config.md:30), [docs/deployment.md:53](/home/linnea/linnea/docs/deployment.md:53)). All three malformed configurations currently exit 0.

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — the certificate loader accepts arbitrary nonempty bytes

Severity: **Medium (P2 TLS availability and false-positive configuration validation)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

The startup loader maps the configured certificate file, calls
`linnea_pem_cert_list`, and accepts every positive result. Its only additional
certificate-side check is that the framed list fits the handshake-flight size
budget
([src/server/linnea_ktls.asm:136](/home/linnea/linnea/src/server/linnea_ktls.asm:136), [src/server/linnea_ktls.asm:149](/home/linnea/linnea/src/server/linnea_ktls.asm:149)).

`linnea_pem_cert_list` does not parse the decoded object as ASN.1 or X.509. It
rejects a zero-length body, then prefixes the raw bytes with TLS
`CertificateEntry` length fields and records them as a successfully loaded
certificate
([src/server/linnea_pem.asm:152](/home/linnea/linnea/src/server/linnea_pem.asm:152), [src/server/linnea_pem.asm:184](/home/linnea/linnea/src/server/linnea_pem.asm:184), [src/server/linnea_pem.asm:187](/home/linnea/linnea/src/server/linnea_pem.asm:187), [src/server/linnea_pem.asm:189](/home/linnea/linnea/src/server/linnea_pem.asm:189)). The handshake later copies this pre-framed byte string directly into its
Certificate message
([src/server/linnea_tls.asm:1698](/home/linnea/linnea/src/server/linnea_tls.asm:1698)).

RFC 8446 requires an ordinary server certificate to be an X.509v3 certificate
and requires its public key to be compatible with the selected authentication
algorithm
([RFC 8446 §4.4.2.2](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.2.2)). The loader establishes neither property. This is not merely incomplete trust
validation: it does not verify that the purported certificate is an ASN.1
object at all.

### Reproduction

Use the normal `test/configs/tls.json` and `test/tls/server.key`, but point
`cert` at this file:

```text
-----BEGIN CERTIFICATE-----
QQ==
-----END CERTIFICATE-----
```

`QQ==` decodes to the single byte `0x41`, which cannot be an X.509 Certificate.
Nevertheless:

```text
$ ./bin/linnea --config one-byte.json --test
$ echo $?
0

$ openssl x509 -in one-byte.crt -noout
Could not find certificate from one-byte.crt
```

The executable result follows directly from the length-only gate: one decoded
byte is greater than zero and fits the list budget. A fresh TLS handshake then
sends that byte as the leaf `CertificateEntry`; a conforming client cannot
parse it and aborts before application traffic.

### Impact

A truncated, accidentally replaced, or otherwise malformed certificate can
pass the exact preflight documented to protect startup and hot reload. The new
generation can therefore replace a healthy one while being unable to complete
any fresh TLS authentication. Both TLS-over-TCP and QUIC consume the same
loaded `cert_list`, so the outage spans HTTP/1, HTTP/2, and HTTP/3.

No remote peer controls the configured file, and accepting arbitrary bytes
does not expose the private key. The consequence is a self-inflicted service
outage and a misleading success result, which keeps the severity at Medium.

### Recommended fix

At minimum, parse the first decoded entry as a complete DER X.509 Certificate,
require its outer object to consume the entry exactly, extract a supported
P-256 SubjectPublicKeyInfo, and reject trailing or malformed ASN.1. The tree
already has bounded DER walkers and `linnea_x509_find_spki` /
`linnea_x509_spki_point` for backend TLS; reuse or extend them instead of adding
a second certificate grammar. Validate every additional chain entry as a
complete certificate as well, even if full path validation remains the
client's responsibility.

Add `--test` cases for a one-byte body, truncated DER, an outer object with
trailing bytes, a non-P-256 leaf, and the current valid single- and multi-cert
chains.

## Finding 2 — the configured certificate is never paired with its key

Severity: **Medium (P2 complete failure of fresh TLS authentication after an accepted reload)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

Even when both files are individually well-formed, startup never proves they
describe the same key pair. The certificate is decoded and unmapped first.
The private-key path is then decoded independently, checks that it is a P-256
PKCS#8 structure, verifies that the scalar lies in `[1,n-1]`, copies the scalar,
and advances to the next server
([src/server/linnea_ktls.asm:136](/home/linnea/linnea/src/server/linnea_ktls.asm:136), [src/server/linnea_ktls.asm:159](/home/linnea/linnea/src/server/linnea_ktls.asm:159), [src/server/linnea_ktls.asm:169](/home/linnea/linnea/src/server/linnea_ktls.asm:169), [src/server/linnea_ktls.asm:178](/home/linnea/linnea/src/server/linnea_ktls.asm:178)). There is no comparison with the leaf certificate's public key between those
steps or after them.

At handshake time the server sends the configured certificate verbatim, but
signs CertificateVerify with the independently configured scalar
([src/server/linnea_tls.asm:1698](/home/linnea/linnea/src/server/linnea_tls.asm:1698), [src/server/linnea_tls.asm:1718](/home/linnea/linnea/src/server/linnea_tls.asm:1718), [src/server/linnea_tls.asm:1733](/home/linnea/linnea/src/server/linnea_tls.asm:1733)). TLS 1.3 defines CertificateVerify specifically as proof of possession of the
private key corresponding to the certificate, and the sender-side signature
input requires that corresponding key
([RFC 8446 §4.4.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.3)). A signature from an unrelated valid key is therefore guaranteed to fail client
verification.

### Reproduction

The repository already contains two valid P-256 identities. Configure
`test/tls/server.crt` with `test/tls/sni.key`. Their public-key DER SHA-256
values are different:

```text
server.crt public key: 2f0a3d3d61802f1ccc2aa39628720f4fb91eae4779a727c588dbaf6b88b1ee82
sni.key public key:    c274cc8a56125b9af9ec60d59e05d303c93a80c434a8389c5de30765cb19fd90
```

The current binary still reports success:

```text
$ ./bin/linnea --config mismatch.json --test
$ echo $?
0
```

No malformed encoding is involved in this case: each file is accepted by its
own parser. The missing relation between them is the entire defect. On a fresh
connection the client verifies the signature made by `sni.key` against the
public key carried in `server.crt`; verification fails.

### Impact

Certificate-renewal tooling commonly updates a chain and private key as
separate files. A partial deployment, wrong path, or stale half of the pair
passes preflight. The documented reload sequence can consequently retire a
working generation in favor of one that cannot authenticate any fresh client.
Existing resumption cannot make this safe: tickets expire, new clients have no
PSK, and an identity mismatch must not be hidden by resumption behavior.

This is not an authentication bypass; clients correctly reject the server.
It is a deterministic full TLS outage caused by a validator that reports the
credentials usable.

### Recommended fix

After parsing the leaf SPKI and private scalar, prove equality before startup
succeeds. Derive the P-256 public point from the scalar and compare its
canonical coordinates with the leaf SPKI point, or perform an equivalent
fixed-message sign/verify self-check using the existing P-256 primitives.
Reject with a distinct “certificate and key do not match” diagnostic so the
operator does not waste time treating two individually valid files as corrupt.

Add both directions to `doc_claims_test.py`: the normal matching pair succeeds,
and `server.crt` + `sni.key` fails. Repeat with a multi-entry chain to ensure
the comparison always uses the first/leaf entry rather than an issuer.

## Finding 3 — Base64 completion substitutes for the PEM END boundary

Severity: **Low (P3 malformed credential files pass preflight)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

`linnea_pem_decode` carefully validates the complete BEGIN boundary, including
the expected label and five closing dashes
([src/server/linnea_pem.asm:62](/home/linnea/linnea/src/server/linnea_pem.asm:62), [src/server/linnea_pem.asm:69](/home/linnea/linnea/src/server/linnea_pem.asm:69), [src/server/linnea_pem.asm:79](/home/linnea/linnea/src/server/linnea_pem.asm:79)). Its completion logic is not symmetric:

- the first `=` byte jumps directly to success without consuming or validating
  the rest of the Base64 quantum or finding an END boundary; and
- without padding, any occurrence of the nine-byte prefix `-----END ` jumps
  to success without checking a label, the five closing dashes, or a line end
  ([src/server/linnea_pem.asm:96](/home/linnea/linnea/src/server/linnea_pem.asm:96), [src/server/linnea_pem.asm:101](/home/linnea/linnea/src/server/linnea_pem.asm:101), [src/server/linnea_pem.asm:106](/home/linnea/linnea/src/server/linnea_pem.asm:106), [src/server/linnea_pem.asm:113](/home/linnea/linnea/src/server/linnea_pem.asm:113)).

RFC 7468's standard and lax grammars both contain a post-encapsulation
boundary; the boundary is an `END`, a label, and exactly five dashes
([RFC 7468 §§2–3](https://www.rfc-editor.org/rfc/rfc7468.html#section-3)). The RFC permits a parser to ignore non-Base64 characters and even to disregard a
mismatched END label, so those permissive choices are not findings here. It
does not make an absent or truncated boundary into a complete textual encoding.

### Reproduction

Start with either repository credential, preserve its entire Base64 body, and
replace its END line with a line containing only `=`. Both malformed files are
accepted:

```text
$ ./bin/linnea --config no-end-cert.json --test; echo $?
0
$ ./bin/linnea --config no-end-key.json --test; echo $?
0
```

OpenSSL rejects both corresponding inputs. A second certificate control that
ends with the truncated wrong-label text `-----END PRIVATE KEY` also passes
Linnea's `--test`, because the decoder recognizes only the prefix.

Unlike Finding 1, preserving the full Base64 body means the decoded DER remains
usable; the server can successfully use the credential despite its incomplete
container. The defect is therefore parser acceptance and misleading
validation, not necessarily a runtime outage. That narrower consequence makes
it Low severity.

### Recommended fix

Treat `=` as Base64 padding state, not as a successful function return. Validate
the legal two- or three-character final quantum, zero padding bits, and at most
two `=` bytes; then skip permitted whitespace and require a complete
post-encapsulation boundary. Validate five closing dashes and a boundary end.
Matching the END label is preferable for operator diagnostics even though RFC
7468 permits mismatch-tolerant parsing.

Add certificate and key cases for missing END, truncated END, bare padding,
bad padding count, nonzero pad bits, and complete valid padded/unpadded bodies.
Retain a whitespace/non-Base64 control so tightening termination does not
accidentally reject the interoperability tolerance RFC 7468 recommends.

---

## Resolution (2026-08-27)

**All three CONFIRMED and FIXED.** Fast suite **1166/0**; seven new
`doc_claims_test.py` rows.

Reproduced exactly as written — one-byte cert, mismatched pair, and three
malformed-boundary files all exited 0, while `openssl` rejected each.

### F2 is the one that matters on this host

Certbot renews unattended here with a deploy hook that reloads, and a renewal
updates the chain and the key as separate files. A half-landed pair passed
preflight, so the reload would have retired a working generation for one that
cannot authenticate any fresh client.

Fixed by signing a fixed digest with the configured key and verifying it under
the leaf certificate's point — identity proven through the primitive the
handshake itself uses, rather than by comparing encodings. Distinct diagnostic,
so two individually valid files are not mistaken for corrupt ones.

**F1 comes free with it**: a leaf SPKI cannot be extracted from a byte string
that is not X.509, so the one-byte body now fails where it used to be framed
and sent.

### F3

`=` no longer returns success on its own, and `-----END ` now requires its five
closing dashes. The END **label is deliberately not compared** — RFC 7468's lax
grammar tolerates a mismatch, and enforcing it would reject files other tools
accept. The report agreed label matching was preferable but optional; this
takes the tolerant side and says so.

### Controls

The report asked for a multi-entry chain, to prove the comparison uses the leaf
rather than an issuer: `bigchain.crt` (7 certificates) with `server.key` is
accepted. Both real pairs in the tree still load.

### Two of my own, both about believing a green result

**A harness bug reported F2 as still broken after it was fixed.** My throwaway
test helper captured `$?` from a pipeline rather than from linnea, and judged
success by an empty output variable that a trailing blank line had emptied. The
fix was already correct; the harness lied. Third time in one day that a test's
own defect produced a wrong conclusion about the server.

**A scripted edit failed its assertion and wrote nothing — and `make` still
said "builds clean",** because it rebuilt an unchanged file. A green build
after a failed patch is not evidence the patch landed. Check that the edit
applied, not that the tree still compiles.
