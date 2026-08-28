# Audit Report 103

Audited `b4da3ac` (`tls: open the nested certificate fields, not just their
tags (report 102)`), 2026-08-28.

The report-102 remediation validates certificate field nesting, version values,
and Validity child count. Two local-certificate grammar gaps remain in the
algorithm and public-key structures:

1. **Medium: the Certificate signatureAlgorithm accepts non-AlgorithmIdentifier
   contents.**
2. **Medium: the leaf SubjectPublicKeyInfo accepts a third child after the
   public-key BIT STRING.**

Both were reproduced against the current `bin/linnea`: `--test` exits 0, while
OpenSSL rejects the same certificate. These are operator-input preflight and
availability defects, not remote parsing vulnerabilities or private-key
exposure.

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — Certificate signatureAlgorithm is only checked for non-emptiness

Severity: **Medium (P2 TLS availability after accepted reload)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

`tbs_walk` opens the outer Certificate `signatureAlgorithm`, checks that its
tag is SEQUENCE, and rejects only an empty content range
([src/server/linnea_pem.asm:618](/home/linnea/linnea/src/server/linnea_pem.asm:618), [src/server/linnea_pem.asm:620](/home/linnea/linnea/src/server/linnea_pem.asm:620), [src/server/linnea_pem.asm:623](/home/linnea/linnea/src/server/linnea_pem.asm:623), [src/server/linnea_pem.asm:625](/home/linnea/linnea/src/server/linnea_pem.asm:625)). It neither requires a child OBJECT IDENTIFIER nor verifies that the content is
an exactly consumed `AlgorithmIdentifier`. The similarly named TBS signature
field reaches only the generic `der_tiles` check, so it too can contain any
sequence of unrelated TLVs
([src/server/linnea_pem.asm:684](/home/linnea/linnea/src/server/linnea_pem.asm:684), [src/server/linnea_pem.asm:695](/home/linnea/linnea/src/server/linnea_pem.asm:695), [src/server/linnea_pem.asm:699](/home/linnea/linnea/src/server/linnea_pem.asm:699)).

RFC 5280 defines the Certificate-level field as `signatureAlgorithm
AlgorithmIdentifier`, and requires it to contain the same algorithm identifier
as the TBSCertificate signature field ([RFC 5280 §4.1.1.2](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.1.2)). A nonempty SEQUENCE is not an AlgorithmIdentifier.

### Reproduction

Decode `test/tls/server.crt` to DER. At offset 329, change the outer
signatureAlgorithm's child tag from `0x06` (OBJECT IDENTIFIER) to `0x05`
(NULL), without changing its length or any later bytes. The leaf SPKI and
matching configured private key are untouched. Rewrap as CERTIFICATE PEM:

```text
$ ./bin/linnea --test --config bad-alg.json
$ echo $?
0

$ openssl x509 -in bad-alg.crt -noout
Could not find certificate ... unsupported
```

The malformed SEQUENCE remains nonempty, so the certificate gate and the
separate P-256 key-pair proof both succeed. OpenSSL rejects the emitted object
because its signature algorithm is not decodable.

### Impact

`--test` can bless a malformed leaf or issuer certificate, after which clients
cannot parse the transmitted chain and fresh TLS/QUIC handshakes fail. No
attacker-controlled network input reaches this path, and the changed bytes do
not alter the configured private key, so the impact is availability rather than
authentication bypass.

### Recommended fix

Add a small `AlgorithmIdentifier` helper that requires exactly one OID followed
by permitted, fully consumed parameters (or the narrow supported set), and use
it for both signature fields. Compare the two complete encoded identifiers as
RFC 5280 requires. Add wrong first-child tag, empty OID, trailing child, and
mismatched-inner/outer-algorithm regressions.

## Finding 2 — SPKI point extraction ignores trailing children

Severity: **Medium (P2 TLS availability after accepted reload)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

The positional leaf path verifies the first SPKI child is precisely the expected
P-256 AlgorithmIdentifier ([src/server/linnea_pem.asm:807](/home/linnea/linnea/src/server/linnea_pem.asm:807), [src/server/linnea_pem.asm:812](/home/linnea/linnea/src/server/linnea_pem.asm:812), [src/server/linnea_pem.asm:815](/home/linnea/linnea/src/server/linnea_pem.asm:815), [src/server/linnea_pem.asm:817](/home/linnea/linnea/src/server/linnea_pem.asm:817)). But `linnea_x509_spki_point` then opens the first child, parses the second as a
66-byte uncompressed-point BIT STRING, copies X/Y, and returns success without
requiring that the second child end the enclosing SPKI SEQUENCE
([src/server/linnea_pem.asm:925](/home/linnea/linnea/src/server/linnea_pem.asm:925), [src/server/linnea_pem.asm:928](/home/linnea/linnea/src/server/linnea_pem.asm:928), [src/server/linnea_pem.asm:931](/home/linnea/linnea/src/server/linnea_pem.asm:931), [src/server/linnea_pem.asm:933](/home/linnea/linnea/src/server/linnea_pem.asm:933), [src/server/linnea_pem.asm:938](/home/linnea/linnea/src/server/linnea_pem.asm:938), [src/server/linnea_pem.asm:948](/home/linnea/linnea/src/server/linnea_pem.asm:948)).

`SubjectPublicKeyInfo` is exactly a SEQUENCE of AlgorithmIdentifier and BIT
STRING; a third child is not permitted ([RFC 5280 §4.1.2.7](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.7)).

### Reproduction

Decode the fixture and insert `05 00` (NULL) immediately after its SPKI BIT
STRING, at original offset 214. Increase the SPKI, TBSCertificate, and outer
Certificate declared lengths by two, preserving valid DER lengths everywhere
else. The original AlgorithmIdentifier, 65-byte P-256 point, and matching key
remain unchanged:

```text
$ ./bin/linnea --test --config bad-spki.json
$ echo $?
0

$ openssl x509 -in bad-spki.crt -noout
Could not find certificate ... unsupported
```

Linnea finds the expected AlgorithmIdentifier and copies the unchanged point
from the second child; it never observes the inserted third child. OpenSSL
rejects the malformed SPKI.

### Impact

The local validator accepts and transmits a certificate that strict clients
cannot load. The result is a TLS and QUIC service outage after an apparently
successful credential preflight. This does not permit a mismatched private key
or remote credential injection.

### Recommended fix

After parsing the public-key BIT STRING, compute its end and require equality
with the SPKI SEQUENCE end. Apply the same exact-consumption rule to the
untrusted peer-SPKI extractor where compatible with its pinning semantics.
Add third-child and trailing-byte SPKI mutations plus the current valid P-256
control.

---

## Resolution (2026-08-28)

**Both CONFIRMED and FIXED.** Fast suite **1166/0**; 150 claims (was 148).

**F1**: the outer `signatureAlgorithm` now has to be an `AlgorithmIdentifier` —
an OBJECT IDENTIFIER, then optional parameters, consuming the SEQUENCE exactly
— rather than merely non-empty. The same check is applied to the TBS
`signature` field.

**And the comparison I declined in report 102 is now made.** That report also
asked for the two algorithm identifiers to be compared; I left it out as
possibly "unusual but legal". RFC 5280 4.1.1.2 makes it a MUST, so two
differing identifiers is malformed DER, which is squarely on the side of the
line I said I was holding. 103 raising it again was a fair prompt to revisit,
and the earlier call was wrong.

**F2**: the SPKI's BIT STRING must END the sequence. The key was copied out of
the second child with no check that it was the last, so a third child was never
observed. The check went into `linnea_x509_spki_point`, which hardens the
backend-pin path as well — an SPKI with three children is malformed wherever it
appears, and a pin computed over one was never going to match anyway.

### A bug I wrote, caught before it shipped

My first version stashed the outer AlgorithmIdentifier's span in the RED ZONE
(`[rsp-8]`, `[rsp-16]`). That is only safe in a leaf function, and `tbs_walk`
calls `der_any` continuously — the next `call` would have overwritten it with a
return address. **It assembled and built cleanly**, which is the same failure
mode recorded in report 97: the assembler is not the check. Replaced with
`r15`/`rbp`, with the two extra pushes threaded through all three exit paths.

### Regression surface

All eleven malformed cases from reports 99-102 remain rejected — one-byte body,
mismatched pair, missing END, truncated END, corrupt outer field, malformed
issuer, excess padding, retagged serial, altered curve, retagged version,
version out of range. All seven real credentials still load: `server.crt`,
`sni.crt`, `bigchain.crt` (7 entries), the hand-built v1, and the three
generated pairs covering 0/1/2 base64 padding.
