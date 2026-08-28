# Audit Report 109

Audited `46e6137` (`tls: OIDs must encode, and Names must be Names (reports 107, 108)`), 2026-08-28.

The new Name parser enforces RDN SET and AttributeTypeAndValue SEQUENCE tags. Its attribute-OID validation is weaker than the AlgorithmIdentifier OID check, however:

1. **Medium: Name attribute OIDs accept non-minimal base-128 subidentifier encodings.**

The malformed issuer passes current `bin/linnea --test` and OpenSSL rejects it. This remains a local credential-validation and TLS/QUIC availability defect, not remote parser exposure or key disclosure.

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — AttributeType OID validation only checks the final byte

Severity: **Medium (P2 TLS availability after accepted reload)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

The `alg_id_ok` helper added for report 107 walks every OID byte and rejects `0x80` at the start of a subidentifier, preventing non-minimal base-128 encodings ([src/server/linnea_pem.asm:710](/home/linnea/linnea/src/server/linnea_pem.asm:710), [src/server/linnea_pem.asm:712](/home/linnea/linnea/src/server/linnea_pem.asm:712), [src/server/linnea_pem.asm:715](/home/linnea/linnea/src/server/linnea_pem.asm:715), [src/server/linnea_pem.asm:721](/home/linnea/linnea/src/server/linnea_pem.asm:721)).

The new Name `attr_ok` helper only requires an OBJECT IDENTIFIER tag, nonempty content, and a final byte without the continuation bit ([src/server/linnea_pem.asm:836](/home/linnea/linnea/src/server/linnea_pem.asm:836), [src/server/linnea_pem.asm:839](/home/linnea/linnea/src/server/linnea_pem.asm:839), [src/server/linnea_pem.asm:841](/home/linnea/linnea/src/server/linnea_pem.asm:841), [src/server/linnea_pem.asm:843](/home/linnea/linnea/src/server/linnea_pem.asm:843)). It does not examine the start of subsequent subidentifiers. An `0x80 0x03` pair encodes the same subidentifier value as `0x03` with a leading zero group, which DER forbids.

RFC 5280 requires issuer and subject Names to consist of AttributeTypeAndValue values identified by OIDs ([RFC 5280 §4.1.2.4](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.4), [RFC 5280 §4.1.2.6](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.6)). A tag and an eventual terminating byte do not establish a valid DER OID.

### Reproduction

Decode `test/tls/server.crt` to DER. Its issuer commonName AttributeType OID is `06 03 55 04 03` at offsets 53–57. Change offset 56 from `0x04` to `0x80`, producing the non-minimal OID content `55 80 03`, while leaving lengths, the leaf SPKI, and private key unchanged. Rewrap as CERTIFICATE PEM:

```text
$ ./bin/linnea --test --config bad-attr-oid.json
$ echo $?
0

$ openssl x509 -in bad-attr-oid.crt -noout
Could not find certificate ... unsupported
```

The final OID byte remains `0x03`, so `attr_ok` accepts the malformed AttributeType. The RDN and all later certificate/key checks pass. OpenSSL rejects the malformed issuer OID.

### Impact

An operator can preflight and deploy a certificate with an invalid issuer or subject AttributeType. Strict TLS clients reject it while parsing the Certificate message, causing fresh TLS and QUIC connections to fail. The altered data is local and does not weaken private-key possession, so severity is Medium.

### Recommended fix

Factor the base-128 OID validator out of `alg_id_ok` and call it from `attr_ok`, rather than maintaining two partial implementations. Apply it to every accepted OID, including Name attributes and optional key parameters. Add unterminated and non-minimal Name-attribute OID regressions for both issuer and subject, alongside valid multi-attribute Name controls.

---

## Resolution (2026-08-28)

**CONFIRMED and FIXED**, and the report's diagnosis of the cause is exactly
right: two partial implementations of one rule.

Report 107 added the base-128 OID check inside `alg_id_ok`. Report 108 — one
report later — then wrote a **weaker copy** in `attr_ok` that tested only the
final byte. Report 109 is that copy being wrong. **I wrote the duplicate myself,
having written the original a report earlier.**

Fixed as recommended: one `oid_ok`, called by both. `grep` confirms a single
non-minimal check remains in the file.

Verified with acceptance controls first — 10 real credentials load, including
`bigchain.crt` (14 Names) and the 5-RDN certificate — then 11 rejections
spanning reports 99-109. OpenSSL rejects the new mutation.

**The suite was not run: the operator asked for the fix only.** One new claim
(165), `doc_claims_test.py` green standalone. The last full suite was 1193/0 at
`0e3fe0e`, which prod runs; reports 107-109 are not covered by it.
