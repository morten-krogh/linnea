# Audit Report 101

Audited the uncommitted remediation for Audit Report 100 on top of `063688d`
(`tls: prove the certificate and key are one identity (audit-report-99)`),
2026-08-27.

The remediation correctly makes every chain entry pass an outer Certificate
envelope check, makes SPKI selection positional, and rejects excess PEM
padding. It also closes the three cases in report 100's added regression tests.

This follow-up found two remaining acceptance gaps in that new local-
credential validator:

1. **Medium: `linnea_x509_cert_wellformed` validates only the Certificate
   envelope, not the required types and contents of its children.**
2. **Medium: positional leaf-SPKI extraction no longer verifies that the
   selected SPKI declares P-256.**

Both were reproduced against the freshly built `bin/linnea` containing the
uncommitted remediation. In each case, `--test` exited 0 for a certificate that
the reference OpenSSL implementation cannot use as a TLS server credential.
These are local configuration/preflight failures, not remotely reachable parser
issues or private-key disclosure.

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — the new Certificate gate accepts invalid TBSCertificate fields

Severity: **Medium (P2 TLS availability and false-positive credential preflight)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

`linnea_x509_cert_wellformed` has the right outer-level intent: it requires a
single DER SEQUENCE consuming the entire entry and exactly three direct
children whose tags are SEQUENCE, SEQUENCE, and BIT STRING
([src/server/linnea_pem.asm:566](/home/linnea/linnea/src/server/linnea_pem.asm:566), [src/server/linnea_pem.asm:573](/home/linnea/linnea/src/server/linnea_pem.asm:573), [src/server/linnea_pem.asm:578](/home/linnea/linnea/src/server/linnea_pem.asm:578), [src/server/linnea_pem.asm:585](/home/linnea/linnea/src/server/linnea_pem.asm:585), [src/server/linnea_pem.asm:592](/home/linnea/linnea/src/server/linnea_pem.asm:592)). It never parses any child of the TBSCertificate and never checks that either
AlgorithmIdentifier or the BIT STRING has valid contents.

The subsequent leaf-SPKI routine merely skips six generic TLVs after an
optional version field. It checks the sixth tag is a SEQUENCE, but does not
verify the preceding serial number, signature, issuer, validity, or subject
types ([src/server/linnea_pem.asm:641](/home/linnea/linnea/src/server/linnea_pem.asm:641), [src/server/linnea_pem.asm:644](/home/linnea/linnea/src/server/linnea_pem.asm:644), [src/server/linnea_pem.asm:656](/home/linnea/linnea/src/server/linnea_pem.asm:656), [src/server/linnea_pem.asm:669](/home/linnea/linnea/src/server/linnea_pem.asm:669)). Thus the outer gate does not provide the syntactic guarantee claimed by its
comment.

RFC 5280 specifies ordered, typed TBSCertificate fields: optional explicit
version, serial number, signature, issuer, validity, subject, and
SubjectPublicKeyInfo. It also defines the Certificate's second and third fields
as AlgorithmIdentifier and BIT STRING, not merely objects bearing their outer
tags ([RFC 5280 §4.1](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1), [RFC 5280 §4.1.2](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2)).

### Reproduction

Decode `test/tls/server.crt` to DER and change byte offset 13, the leaf
TBSCertificate's serialNumber tag, from `0x02` (INTEGER) to `0x04` (OCTET
STRING). Do not change its length or contents; the SPKI and configured matching
key therefore remain intact. Rewrap the bytes as a `CERTIFICATE` PEM and run:

```text
$ ./bin/linnea --test --config bad-tbs.json
$ echo $?
0

$ openssl x509 -in bad-tbs.crt -noout
Could not find certificate ... unsupported
```

The modified value is still a bounded TLV, so the local routine steps over it
and arrives at the original SPKI. The certificate envelope check succeeds, the
P-256 sign/verify pairing succeeds, and Linnea stores the invalid DER for the
TLS and QUIC Certificate messages. OpenSSL rejects the same object because a
TBSCertificate serialNumber is not an OCTET STRING.

This is not limited to serial numbers. The same trace accepts malformed
signature/issuer/validity/subject fields, an empty AlgorithmIdentifier, and a
zero-length BIT STRING, provided enough generic TLVs remain to reach an
SPKI-shaped sixth field.

### Impact

An operator can deploy or reload with a damaged certificate while `--test`
reports success. Clients then reject the emitted Certificate before completing
the handshake, causing a full outage for the affected TLS and QUIC vhost.
The private key and remote attack surface are unaffected, hence Medium rather
than High severity.

### Recommended fix

Make the local validator parse the mandatory TBSCertificate fields by their
specified tags and minimal substructure, rather than counting arbitrary TLVs.
At minimum require INTEGER serialNumber; complete AlgorithmIdentifiers for the
TBS and outer signature fields; SEQUENCE Names; two valid Time values inside
Validity; a SEQUENCE SubjectPublicKeyInfo; and a nonempty, well-formed BIT
STRING signature. Require every parsed object's end to equal the expected
container boundary.

Add mutations for each required TBSCertificate field tag, an empty outer
AlgorithmIdentifier, invalid BIT STRING unused-bit count, and valid v1/v2/v3
controls. The existing report-100 outer-tag case should remain a control, not
the sole definition of a complete certificate.

## Finding 2 — the new positional SPKI path drops the P-256 algorithm check

Severity: **Medium (P2 TLS availability after accepted reload)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

Before the remediation, `linnea_x509_find_spki` accepted an SPKI only after
its AlgorithmIdentifier content exactly matched `id-ecPublicKey` plus
`prime256v1` ([src/server/linnea_pem.asm:728](/home/linnea/linnea/src/server/linnea_pem.asm:728), [src/server/linnea_pem.asm:733](/home/linnea/linnea/src/server/linnea_pem.asm:733), [src/server/linnea_pem.asm:735](/home/linnea/linnea/src/server/linnea_pem.asm:735), [src/server/linnea_pem.asm:737](/home/linnea/linnea/src/server/linnea_pem.asm:737)). The replacement `linnea_x509_leaf_spki` selects the sixth TBS element solely
because it is a SEQUENCE ([src/server/linnea_pem.asm:656](/home/linnea/linnea/src/server/linnea_pem.asm:656), [src/server/linnea_pem.asm:669](/home/linnea/linnea/src/server/linnea_pem.asm:669)).

`linnea_x509_spki_point` then parses and skips *any* first child of that
sequence. It checks only the following BIT STRING's length, unused-bits byte,
and uncompressed point marker; it never requires the skipped child to be an
AlgorithmIdentifier or compare it with `alg_ec`
([src/server/linnea_pem.asm:771](/home/linnea/linnea/src/server/linnea_pem.asm:771), [src/server/linnea_pem.asm:779](/home/linnea/linnea/src/server/linnea_pem.asm:779), [src/server/linnea_pem.asm:784](/home/linnea/linnea/src/server/linnea_pem.asm:784), [src/server/linnea_pem.asm:789](/home/linnea/linnea/src/server/linnea_pem.asm:789), [src/server/linnea_pem.asm:809](/home/linnea/linnea/src/server/linnea_pem.asm:809)). The key-pair proof consequently succeeds for a P-256-shaped point even when the
certificate declares a different or unusable public-key algorithm.

RFC 5280's SubjectPublicKeyInfo binds a public-key BIT STRING to its
AlgorithmIdentifier; the algorithm field identifies both the algorithm and its
associated parameters ([RFC 5280 §4.1.2.7](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.7)). Treating those bytes as ignorable metadata breaks that binding for the
local credential check.

### Reproduction

In the same DER fixture, the `prime256v1` OID's final subidentifier is at byte
offset 145. Change it from `0x07` to `0x08`, leaving all lengths, the original
65-byte P-256 point, and the matching private key unchanged. The resulting
certificate has a syntactically valid SPKI wrapper but declares a different EC
parameter OID for a P-256-sized point:

```text
$ ./bin/linnea --test --config bad-curve.json
$ echo $?
0

$ openssl x509 -in bad-curve.crt -noout -text
... Public Key Algorithm: id-ecPublicKey
... Unable to load Public Key: decode error

$ openssl s_server -cert bad-curve.crt -key test/tls/server.key ...
error setting certificate ... unable to get certs public key
```

Linnea accepts it because its point extractor never examines the altered OID;
the configured key still signs for the copied X/Y coordinates. OpenSSL can read
the outer certificate but cannot instantiate the declared public key, and
refuses to install it for TLS.

### Impact

This allows a certificate whose advertised key algorithm or curve does not
describe the actual key material to pass preflight and reload. Conforming TLS
stacks reject it during certificate loading or handshake parsing, so all new
connections to that vhost fail. This is an operator-controlled availability
failure, not a way to impersonate a certificate without its matching key.

### Recommended fix

Restore the exact `alg_ec` comparison on the positional SPKI path. First
require exactly two SPKI children: an AlgorithmIdentifier SEQUENCE whose
content equals the accepted `id-ecPublicKey`/`prime256v1` OID pair, followed by
the existing 66-byte BIT STRING; then require that the second child ends the
SPKI. Sharing a single strict P-256 SPKI parser between the positional local
path and the peer-key extractor would avoid another divergence.

Add regression cases for a changed curve OID, changed key-algorithm OID,
non-SEQUENCE AlgorithmIdentifier, missing AlgorithmIdentifier, and trailing
SPKI children, alongside the valid P-256 control.

---

## Resolution (2026-08-27)

**Both CONFIRMED and FIXED**, and both are defects in report 100's remediation,
which had not been committed. Fast suite **1166/0**.

**F2 is a regression I introduced.** `linnea_x509_find_spki` had always
required the SPKI's AlgorithmIdentifier to equal `id-ecPublicKey` +
`prime256v1`. My positional replacement silently dropped that comparison, so a
certificate declaring a different curve over a P-256-sized point was accepted.
The fix that was supposed to tighten validation removed a check that existed —
worth stating plainly, because a rewrite that "obviously improves" a routine is
exactly where a dropped condition hides.

**F1** was the weaker half of the same code: counting six anonymous TLVs
accepted a `serialNumber` retagged from INTEGER to OCTET STRING, because a
bounded TLV of ANY tag still advances the cursor.

Both entry points now share one `tbs_walk`, which is what the report asked for
and is why they cannot drift again. It validates field TYPES — INTEGER serial,
four SEQUENCEs, a SEQUENCE SPKI, a non-empty outer AlgorithmIdentifier and a
BIT STRING whose unused-bits octet is 0..7 with content after it. It is
algorithm-agnostic because it runs on EVERY chain entry and an issuer need not
be P-256; the `alg_ec` comparison lives in the leaf entry point, where the
private key actually has to match.

Verified across all three reports: eight malformed cases rejected — one-byte
body, mismatched pair, missing END, corrupt outer field, malformed issuer,
excess padding, retagged serial, altered curve — and six real credentials
accepted, including `bigchain.crt`, whose six intermediates now pass the typed
walk as issuers.

### Scope this does NOT cover

This is syntax, not trust. `--test` still says nothing about expiry, chain
order, issuer signatures, or hostname. It now says the credential is
well-formed, self-consistent, and P-256 at the leaf — which is what a preflight
can honestly promise, and considerably more than "the bytes were not empty".
