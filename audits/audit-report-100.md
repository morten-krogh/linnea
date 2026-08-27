# Audit Report 100

Audited at `063688d` (`tls: prove the certificate and key are one identity (audit-report-99)`), 2026-08-27.

Report 99's key-pair fix correctly rejects the reported one-byte leaf and the
repository's mismatched credential pair. Its sign/verify self-check uses the
same deterministic P-256 primitives as the handshake, selects the first
`CertificateEntry`, and distinguishes a malformed leaf from a valid but
unrelated key. The PEM decoder also now requires a post-encapsulation boundary.

The broader credential-validation pass found three remaining acceptance gaps:

1. **Medium: the new leaf check accepts a structurally invalid Certificate as
   long as its TBSCertificate contains an SPKI-shaped sequence.**
2. **Medium: every certificate after the leaf still receives only the old
   nonempty-length check, so malformed intermediates pass `--test`.**
3. **Low: the tightened PEM decoder still accepts an unbounded number of
   Base64 padding characters.**

All three were reproduced against the current `bin/linnea`; each malformed
configuration exits 0 under `--test`. They remain operator-input and deployment
validation defects rather than remotely supplied certificate-parser attacks.

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — SPKI discovery is mistaken for complete X.509 validation

Severity: **Medium (P2 TLS availability and false-positive credential preflight)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

The report-99 fix reads the first TLS `CertificateEntry`, calls
`linnea_x509_find_spki`, extracts its P-256 point, and proves that the configured
private key signs for that point
([src/server/linnea_ktls.asm:201](/home/linnea/linnea/src/server/linnea_ktls.asm:201), [src/server/linnea_ktls.asm:214](/home/linnea/linnea/src/server/linnea_ktls.asm:214), [src/server/linnea_ktls.asm:224](/home/linnea/linnea/src/server/linnea_ktls.asm:224), [src/server/linnea_ktls.asm:233](/home/linnea/linnea/src/server/linnea_ktls.asm:233)). That proves the key relation, but the called function is a targeted key extractor,
not a Certificate validator.

`linnea_x509_find_spki` verifies only that the input starts with a SEQUENCE,
that its first child is another SEQUENCE, and that some direct child of that
second sequence begins with the expected P-256 AlgorithmIdentifier
([src/server/linnea_pem.asm:503](/home/linnea/linnea/src/server/linnea_pem.asm:503), [src/server/linnea_pem.asm:515](/home/linnea/linnea/src/server/linnea_pem.asm:515), [src/server/linnea_pem.asm:525](/home/linnea/linnea/src/server/linnea_pem.asm:525), [src/server/linnea_pem.asm:532](/home/linnea/linnea/src/server/linnea_pem.asm:532), [src/server/linnea_pem.asm:542](/home/linnea/linnea/src/server/linnea_pem.asm:542)). It returns immediately when it finds that shape. It does not require the
TBSCertificate fields in their defined order, nor does it parse or even require
the enclosing Certificate's `signatureAlgorithm` and `signatureValue` fields.

RFC 5280 defines a Certificate as exactly a SEQUENCE of TBSCertificate,
AlgorithmIdentifier, and BIT STRING; TBSCertificate itself has required ordered
fields before and around SubjectPublicKeyInfo
([RFC 5280 §4.1](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1)). Finding one valid SPKI-shaped child establishes only a public key, not that
the surrounding bytes encode that structure.

### Reproduction

Decode `test/tls/server.crt` to DER. At byte offset 327, change the tag of the
outer Certificate's required `signatureAlgorithm` from `0x30` (SEQUENCE) to
`0x31` (SET), then Base64-wrap it again as a CERTIFICATE. The TBSCertificate and
SPKI remain byte-for-byte unchanged, as does the configured matching key.

```text
$ ./bin/linnea --config bad-leaf.json --test
$ echo $?
0

$ openssl x509 -in bad-leaf.crt -noout
[fails]
```

OpenSSL's ASN.1 view of the unmodified fixture identifies offset 327 as the
Certificate-level signatureAlgorithm. Linnea never reaches that element: the
SPKI search ends inside the preceding TBSCertificate, and the pairing
signature therefore succeeds. The malformed certificate is stored and later
copied verbatim into the TLS and QUIC Certificate messages.

The same structural weakness can be exercised with a much smaller synthetic
object: an outer SEQUENCE whose first child is a SEQUENCE containing only a
valid P-256 SubjectPublicKeyInfo is sufficient for discovery and pairing,
despite omitting all other required certificate fields.

### Impact

A structurally damaged certificate can pass the preflight that the deployment
guide relies on before reload. The replacement generation then sends an object
that clients cannot parse as X.509, causing every fresh handshake using that
vhost to fail. Both TCP TLS and QUIC use the same pre-framed certificate list.

The configured private key is not exposed, and a remote client cannot supply
this startup file. The result is a deterministic operator-induced outage, not
an authentication bypass, so the severity remains Medium.

### Recommended fix

Separate “locate a pinned SPKI in untrusted peer input” from “validate a local
credential as a complete Certificate.” The local path should walk the exact
RFC 5280 structure: require the outer SEQUENCE to consume the entire
`CertificateEntry`, parse exactly one TBSCertificate, AlgorithmIdentifier, and
BIT STRING, and validate the required TBSCertificate field order far enough to
identify its actual SubjectPublicKeyInfo position rather than searching for a
matching child. It need not perform CA trust or hostname validation to reject
malformed syntax.

Add mutations for each required outer field, reordered/omitted TBSCertificate
fields, an SPKI-shaped sequence placed in the wrong field, and trailing bytes.
Keep the current valid P-256 leaves and mismatched-key case as controls.

## Finding 2 — non-leaf chain entries are never parsed as certificates

Severity: **Medium (P2 certificate-chain availability after accepted reload)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

`linnea_pem_cert_list` loops over every `CERTIFICATE` block. For each decoded
body its only semantic condition is `length != 0`; every positive-length value
is framed immediately as a TLS `CertificateEntry`
([src/server/linnea_pem.asm:217](/home/linnea/linnea/src/server/linnea_pem.asm:217), [src/server/linnea_pem.asm:240](/home/linnea/linnea/src/server/linnea_pem.asm:240), [src/server/linnea_pem.asm:241](/home/linnea/linnea/src/server/linnea_pem.asm:241), [src/server/linnea_pem.asm:243](/home/linnea/linnea/src/server/linnea_pem.asm:243), [src/server/linnea_pem.asm:245](/home/linnea/linnea/src/server/linnea_pem.asm:245)). The startup check later reads only the first entry's length and SPKI. It never
iterates over the remaining framed entries
([src/server/linnea_ktls.asm:210](/home/linnea/linnea/src/server/linnea_ktls.asm:210), [src/server/linnea_ktls.asm:214](/home/linnea/linnea/src/server/linnea_ktls.asm:214)).

TLS 1.3 says that when X.509 certificate type is in use, each
`CertificateEntry` contains a DER-encoded X.509 certificate; the sender's leaf
is first and each following certificate should directly certify its predecessor
([RFC 8446 §4.4.2](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.2)). The implementation checks the leaf/key relation but still does not establish the
mandatory per-entry encoding rule for any issuer.

### Reproduction

Concatenate the valid `test/tls/server.crt` with this second block, and retain
the matching `test/tls/server.key`:

```text
-----BEGIN CERTIFICATE-----
QQ==
-----END CERTIFICATE-----
```

The first entry passes the new SPKI and pairing checks. The second decodes to
one byte, passes `test rax` at the list builder, and is transmitted as an issuer:

```text
$ ./bin/linnea --config bad-chain.json --test
$ echo $?
0

$ openssl crl2pkcs7 -nocrl -certfile bad-chain.crt -outform DER -out /dev/null
[fails]
```

This is distinct from Finding 1: the leaf can be a completely valid
certificate and can match its key. Only a later chain entry is malformed, so
the new self-check has no reason to reject it.

### Impact

In the repository's self-signed test case, a client that already trusts the
leaf might ignore an unnecessary trailing entry. In the deployment case that
matters, however, the second block is the intermediate needed to build the
public trust path. A truncated or half-written intermediate passes `--test` and
reload, after which clients without a cached usable issuer cannot authenticate
the server. Other clients reject malformed chain objects outright.

The defect can therefore turn an ordinary certificate-chain renewal error into
a broad TLS outage while the documented validator reports success. It remains
local to operator-managed files and does not weaken private-key security.

### Recommended fix

Validate every decoded block as a complete DER Certificate before framing it,
using the same exact structural validator recommended for Finding 1. Apply the
P-256 SPKI and private-key equality requirement only to the first entry; issuer
certificates may use other signature/public-key algorithms and do not need a
configured private key. Full trust-path validation is optional, but malformed
DER is not.

Add a valid leaf followed by a one-byte entry, truncated intermediate, and
valid `bigchain.crt` control. A separate chain-order/signature check can be a
policy choice; it should not be conflated with the mandatory syntactic gate.

## Finding 3 — PEM accepts unlimited Base64 padding

Severity: **Low (P3 noncanonical malformed credentials pass preflight)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

After the PEM decoder sees its first `=`, it enters a padding state. Every
further `=` is skipped unconditionally until the END boundary; no counter or
relationship to the completed data quantum is maintained
([src/server/linnea_pem.asm:142](/home/linnea/linnea/src/server/linnea_pem.asm:142), [src/server/linnea_pem.asm:148](/home/linnea/linnea/src/server/linnea_pem.asm:148), [src/server/linnea_pem.asm:153](/home/linnea/linnea/src/server/linnea_pem.asm:153)). None of RFC 7468's standard, lax, or strict Base64 grammars permits
unbounded padding; even the explicitly lax grammar spells padding as one
optional `=` followed by at most one more
([RFC 7468 §3](https://www.rfc-editor.org/rfc/rfc7468.html#section-3)).

### Reproduction

Insert a line containing four `=` characters immediately before the END
boundary in the otherwise valid `test/tls/server.crt`. Its original DER length
is divisible by three and needs no padding at all:

```text
$ ./bin/linnea --config excess-pad.json --test
$ echo $?
0

$ openssl x509 -in excess-pad.crt -noout
[fails]
```

Linnea ignores all four padding bytes, reconstructs the original DER, and the
report-99 SPKI/pairing check succeeds. OpenSSL rejects the same PEM text.

### Impact

The decoded credential can remain exactly the intended one, so this does not
by itself break TLS or change identity. It does make `--test` bless malformed,
non-interoperable files that other tooling rejects, leaving renewal behavior
dependent on which parser sees the file. This is parser and diagnostic
correctness, hence Low severity.

### Recommended fix

Track the Base64 position modulo four. On `=`, require the correct position,
accept exactly the one or two padding characters implied by the number of data
symbols, and reject further payload or padding. Make END legal only after a
complete padded or unpadded quantum; optionally reject nonzero unused pad bits
for canonical encoding as RFC 4648 permits
([RFC 4648 §3.5](https://www.rfc-editor.org/rfc/rfc4648.html#section-3.5)).

Add too many `=`, padding in the wrong position, incomplete final quanta, and
valid padded/unpadded controls for both certificate and key files.

---

## Resolution (2026-08-27)

**All three CONFIRMED and FIXED**, then corrected again by audit-report-101,
which audited this remediation before it was committed and found that F1's
envelope check was too shallow and that the new positional SPKI walk had
DROPPED an algorithm check the old code made. The committed version is the
corrected one; see report 101. Fast suite **1166/0**.

- **F1**: local credentials now go through `linnea_x509_cert_wellformed`, kept
  deliberately separate from `linnea_x509_find_spki` — that one searches
  untrusted PEER input for a pinned key and is right to be permissive;
  this validates bytes we are about to send to every client.
- **F2**: every chain entry is validated before framing, not just the leaf. A
  half-written INTERMEDIATE is exactly what a renewal produces.
- **F3**: padding is decided by the final quantum. This was a defect in report
  99's own fix: that padding state skipped `=` unconditionally.

### Two of my own

**My first attempt segfaulted on every valid certificate, and my harness called
it "rejected".** I passed `r8` as the DER pointer inside
`linnea_pem_cert_list`, but `linnea_pem_decode` takes `r8` as its own out
parameter and clobbers it. The helper only tested `$? -eq 0`, so a SIGSEGV and
a clean refusal were indistinguishable. **A test that maps "non-zero" to
"rejected" cannot see a crash.** It now separates 0 / 1 / signal.

**None of the repository's credentials use base64 padding**, so two of the
three branches of the F3 fix were untestable with the existing fixtures. I
generated self-signed P-256 pairs until I had certificates needing 0, 1 and 2
padding characters: all three load, each is refused with one `=` too many.
Without that, a bug in the two-`=` path would have shipped invisibly.
