# Audit Report 108

Audited the uncommitted remediation for Audit Report 107 on top of `0e3fe0e` (`pem: an unpadded body must end on a whole base64 quantum (report 106)`), 2026-08-28.

The in-progress OID validation now preserves its callee-saved registers and closes report 107's malformed-OID case. One X.509 Name grammar gap remains:

1. **Medium: issuer and subject are accepted as arbitrary TLV-tiled SEQUENCEs rather than RDNSequence Names.**

The reproduced malformed issuer passes current `bin/linnea --test` and OpenSSL rejects it. This is a local credential-validation and TLS/QUIC availability defect, not remote parser exposure or key disclosure.

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — Name validation only checks generic TLV tiling

Severity: **Medium (P2 TLS availability after accepted reload)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

`tbs_walk` treats issuer and subject as two of its generic SEQUENCE fields. For each, it calls `der_tiles`, which succeeds whenever the content is exactly covered by bounded TLVs regardless of their tags or nesting ([src/server/linnea_pem.asm:875](/home/linnea/linnea/src/server/linnea_pem.asm:875), [src/server/linnea_pem.asm:880](/home/linnea/linnea/src/server/linnea_pem.asm:880), [src/server/linnea_pem.asm:886](/home/linnea/linnea/src/server/linnea_pem.asm:886), [src/server/linnea_pem.asm:890](/home/linnea/linnea/src/server/linnea_pem.asm:890), [src/server/linnea_pem.asm:657](/home/linnea/linnea/src/server/linnea_pem.asm:657), [src/server/linnea_pem.asm:672](/home/linnea/linnea/src/server/linnea_pem.asm:672)). It does not require the Name grammar: an outer RDNSequence containing SETs of AttributeTypeAndValue SEQUENCEs with an OBJECT IDENTIFIER and a string value.

RFC 5280 defines both issuer and subject as `Name`, whose prescribed form is an RDNSequence; each RelativeDistinguishedName is a SET of AttributeTypeAndValue values ([RFC 5280 §4.1.2.4](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.4), [RFC 5280 §4.1.2.6](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.6)). A generic nested SEQUENCE is not a substitute.

### Reproduction

Decode `test/tls/server.crt` to DER. The issuer Name begins at offset 47; its first RDN is a SET at offset 49. Change that byte from `0x31` (SET) to `0x30` (SEQUENCE), preserving all lengths, the leaf SPKI, and matching private key. Rewrap as CERTIFICATE PEM:

```text
$ ./bin/linnea --test --config bad-name.json
$ echo $?
0

$ openssl x509 -in bad-name.crt -noout
Could not find certificate ... unsupported
```

The changed issuer remains a SEQUENCE whose contents tile into complete TLVs, so `der_tiles` and the later key-pair proof succeed. OpenSSL rejects the certificate because its issuer no longer encodes a valid Name.

### Impact

An operator can pass preflight with a corrupted issuer or subject then deploy a chain strict clients cannot parse, causing fresh TLS and QUIC handshakes to fail. The private key and leaf P-256 relation are unchanged, and the file is local, so severity is Medium rather than High.

### Recommended fix

Add a bounded Name parser for the local certificate path: require the outer RDNSequence to contain SET-tagged RDNs; require each SET to contain one or more AttributeTypeAndValue SEQUENCEs; require each attribute to contain a nonempty, valid OID and exactly one supported ASN.1 string value. Require exact consumption at every level. Add wrong-RDN-tag, empty-SET, wrong-attribute-OID-tag, malformed string, and valid multi-RDN regressions for both issuer and subject.

---

## Resolution (2026-08-28)

**CONFIRMED and FIXED.** `issuer` and `subject` reached only `der_tiles`, which
any bounded TLVs satisfy — so an RDN retagged from SET to SEQUENCE tiled just
as well and passed. They now go through a real Name parser: RDNSequence of
SETs, each holding one or more AttributeTypeAndValue SEQUENCEs, each an OID
plus exactly one value, consuming exactly at every level.

### Two deliberate limits

- **The attribute value's tag is not enumerated.** RFC 5280 lists several
  string types and real certificates use more; refusing an unlisted-but-legal
  one would reject certificates every client accepts. "Exactly one value" is
  the structural property that matters.
- **An empty RDNSequence stays legal.** It is valid DER and some issuers have
  one.

Both sit on the interop side of the line this arc has held: malformed DER, not
unusual-but-legal.

### Verification

Controls first: all 9 real credentials load, including `bigchain.crt` — 7
certificates, so **14 Names** now through the new parser. A real 5-RDN
certificate (`/C/ST/O/OU/CN`) was generated because every existing fixture has
a single-RDN Name and the multi-RDN loop was otherwise unexercised: the seventh
unreachable branch in this arc.

Then 10 rejections from reports 99-108, plus two new attribute-level mutations
(ATV retagged to SET, attribute type retagged from OID). OpenSSL rejects each.

**The suite was not run: the operator asked for the fix only.** Three new claims
(164), `doc_claims_test.py` green standalone.
