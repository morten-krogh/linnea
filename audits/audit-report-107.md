# Audit Report 107

Audited `0e3fe0e` (`pem: an unpadded body must end on a whole base64 quantum (report 106)`), 2026-08-28.

The report-106 Base64 completion check is present. One certificate AlgorithmIdentifier validation gap remains:

1. **Medium: nonempty but malformed OBJECT IDENTIFIER encodings pass local certificate preflight.**

The malformed certificate passes current `bin/linnea --test` and OpenSSL rejects it. This is a local credential-validation and TLS/QUIC availability defect, not remote parser exposure or private-key disclosure.

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — AlgorithmIdentifier accepts an unterminated OID

Severity: **Medium (P2 TLS availability after accepted reload)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

The shared `alg_id_ok` helper opens the first child, requires tag `0x06` (OBJECT IDENTIFIER), and rejects only a zero-length content. It does not parse the OID's base-128 subidentifiers, require a terminating subidentifier, or check minimal encoding ([src/server/linnea_pem.asm:686](/home/linnea/linnea/src/server/linnea_pem.asm:686), [src/server/linnea_pem.asm:687](/home/linnea/linnea/src/server/linnea_pem.asm:687), [src/server/linnea_pem.asm:590](/home/linnea/linnea/src/server/linnea_pem.asm:590), [src/server/linnea_pem.asm:592](/home/linnea/linnea/src/server/linnea_pem.asm:592), [src/server/linnea_pem.asm:594](/home/linnea/linnea/src/server/linnea_pem.asm:594)).

`tbs_walk` invokes that helper for both the outer Certificate signatureAlgorithm and the TBSCertificate signature, then compares the two opaque encodings byte-for-byte ([src/server/linnea_pem.asm:657](/home/linnea/linnea/src/server/linnea_pem.asm:657), [src/server/linnea_pem.asm:663](/home/linnea/linnea/src/server/linnea_pem.asm:663), [src/server/linnea_pem.asm:754](/home/linnea/linnea/src/server/linnea_pem.asm:754), [src/server/linnea_pem.asm:761](/home/linnea/linnea/src/server/linnea_pem.asm:761)). Equality is necessary, but it does not establish that either byte string encodes an AlgorithmIdentifier.

RFC 5280 defines both fields as AlgorithmIdentifier and requires them to contain the same identifier ([RFC 5280 §4.1.1.2](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.1.2), [RFC 5280 §4.1.2.3](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.3)). A DER OBJECT IDENTIFIER with a final byte whose continuation bit is set is incomplete and cannot identify an algorithm.

### Reproduction

Decode `test/tls/server.crt` to DER. The final byte of the TBS ECDSA-with-SHA256 OID is at offset 46, and the equivalent outer signatureAlgorithm OID byte is at offset 338. Change both from `0x02` to `0x82`. This preserves the object lengths and cross-field equality but makes both OIDs unterminated. Rewrap as CERTIFICATE PEM:

```text
$ ./bin/linnea --test --config bad-oid.json
$ echo $?
0

$ openssl x509 -in bad-oid.crt -noout
Could not find certificate ... unsupported
```

Linnea sees two nonempty tag-`0x06` values that compare equal, then extracts the untouched leaf SPKI and proves the matching key. OpenSSL rejects the malformed OID before the certificate can be loaded.

### Impact

An operator can deploy a certificate whose advertised signing algorithm is not decodable. The preflight succeeds, but strict clients reject the Certificate message, causing fresh TLS and QUIC handshakes to fail. The file is local and the matching private key is unchanged, so this is an availability issue rather than an authentication bypass.

### Recommended fix

Extend `alg_id_ok` with DER OID validation: require a complete base-128 final component, reject non-minimal continuation encodings, and validate the first combined arc. Apply it to every AlgorithmIdentifier accepted by the local certificate path. Add unterminated, non-minimal, empty, and valid OID regressions for both matching signature fields and SPKI algorithm identifiers.

---

## Resolution (2026-08-28)

**CONFIRMED and FIXED.** `alg_id_ok` now validates the OID's base-128 encoding:
the final subidentifier must terminate (continuation bit clear), and none may
begin `0x80`, which is a non-minimal leading zero.

The report is sharp about why the earlier work did not catch this: the
reproduction edits **both** copies of the OID, so the cross-field equality check
added in report 103 agreed as well. **Equality was never evidence that either
side WAS an AlgorithmIdentifier** — only that they matched.

Verified with acceptance controls first: 9 real credentials still load
(`server.crt`, `bigchain.crt` with its 6 issuers, the `sni` pair, three
generated pairs covering 0/1/2 padding, the hand-built v1, and two hand-built
keys); 9 rejections from reports 99-107 still hold.

The **non-minimal** branch had no fixture — the sixth such branch in this arc —
so one was built by making a subidentifier start `0x80`. OpenSSL rejects both
mutations, which is what distinguishes malformed from merely unusual.

**The suite was not run: the operator asked for the fix only.** Two new claims
(161), `doc_claims_test.py` green standalone.
