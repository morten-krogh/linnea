# Audit Report 111

Audited `81f7ee3` (`pem: [1] publicKey is one BIT STRING, not a container (report 110)`), 2026-08-28.

The report-110 wrapper-consumption fix is present. The local Name parser still treats every AttributeType value as an unconstrained ASN.1 element:

1. **Medium: certificate Name attributes accept values outside the syntax required by their OID.**

The reproduced commonName with an INTEGER value passes current `bin/linnea --test` and OpenSSL rejects it. This is a local credential-validation and TLS/QUIC availability defect, not remote parser exposure or key disclosure.

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — AttributeTypeAndValue accepts arbitrary value tags

Severity: **Medium (P2 TLS availability after accepted reload)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

`attr_ok` correctly requires an AttributeType OBJECT IDENTIFIER and exactly one following TLV. It deliberately performs no validation of that value's tag or encoding ([src/server/linnea_pem.asm:856](/home/linnea/linnea/src/server/linnea_pem.asm:856), [src/server/linnea_pem.asm:864](/home/linnea/linnea/src/server/linnea_pem.asm:864), [src/server/linnea_pem.asm:867](/home/linnea/linnea/src/server/linnea_pem.asm:867), [src/server/linnea_pem.asm:875](/home/linnea/linnea/src/server/linnea_pem.asm:875), [src/server/linnea_pem.asm:879](/home/linnea/linnea/src/server/linnea_pem.asm:879)). Its comment calls the second value "any string type", but the implementation accepts INTEGER, NULL, constructed values, or any other bounded tag.

The commonName attribute OID requires a DirectoryString value, not an arbitrary ASN.1 `ANY`; RFC 5280 defines Name through AttributeTypeAndValue and relies on the distinguished-name attribute syntax ([RFC 5280 §4.1.2.4](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.4), [RFC 4519 §2.3](https://www.rfc-editor.org/rfc/rfc4519.html#section-2.3)).

### Reproduction

Decode `test/tls/server.crt` to DER. The issuer commonName's UTF8String tag is at offset 58. Change it from `0x0c` to `0x02` (INTEGER), preserving its nine-byte payload, all container lengths, the leaf SPKI, and matching private key. Rewrap as CERTIFICATE PEM:

```text
$ ./bin/linnea --test --config bad-cn.json
$ echo $?
0

$ openssl x509 -in bad-cn.crt -noout
Could not find certificate ... unsupported
```

The INTEGER is one complete value TLV, so `attr_ok` accepts the AttributeTypeAndValue and every subsequent certificate/key check succeeds. OpenSSL rejects the issuer because commonName is not encoded as a DirectoryString.

### Impact

An operator can preflight and deploy a certificate that strict clients cannot parse, causing fresh TLS and QUIC handshakes to fail. The credential remains local and its actual P-256 key relation is unchanged, so the defect affects availability rather than authentication or confidentiality.

### Recommended fix

For the Name attributes used by supported deployments, map known OIDs to their required ASN.1 value syntax: at minimum require commonName to be PrintableString or UTF8String and validate its contents. For unknown attribute OIDs, either validate a conservative DirectoryString/IA5String set or explicitly limit the preflight promise to BER container syntax rather than "complete X.509 Certificate." Reject non-string primitive and constructed values. Add commonName INTEGER, NULL, malformed UTF8String, and valid PrintableString/UTF8String controls for both issuer and subject.

---

## Resolution (2026-08-28)

**CONFIRMED and FIXED**, and this overturns a call I made in report 108.

There I deliberately left the attribute value's tag unchecked, reasoning that
enumerating string types risks refusing a legal certificate. The reasoning was
sound but the conclusion was too loose: a commonName carrying an INTEGER is
malformed, OpenSSL refuses it, and "malformed DER" is the side of the line this
arc has been holding. Accepting *any* bounded element was not a conservative
choice — it was no choice at all.

The value must now be one of the string types that appear in distinguished
names: UTF8String, PrintableString, TeletexString/T61String, IA5String,
NumericString, VisibleString, UniversalString, BMPString. It is an ALLOW-LIST,
so if a real certificate ever needs a type that is missing, widening it is one
line. A survey of every certificate in the tree — including `bigchain.crt`'s 14
Names and a generated 5-RDN certificate — found only `0x0c` and `0x13` in use,
so the list is comfortably wider than practice.

### Not taken

The report also suggests validating UTF8String *contents* and mapping known
OIDs to their specific required syntax (commonName -> DirectoryString only).
Neither is taken: content validation of UTF-8 is a much larger surface with its
own interop risk, and per-OID syntax mapping would refuse, for example, a
legitimate `emailAddress` IA5String if the table were incomplete. The
allow-list catches the reported defect class — non-string values — without
that exposure.

Verified controls-first: 8 credentials load; INTEGER, NULL and SEQUENCE
commonName values are all rejected, as are the earlier mutations from reports
108-110. OpenSSL rejects each new one.

**The suite was not run: the operator asked for the fix only.** Three new claims
(169). The last full suite remains 1193/0 at `0e3fe0e`, which is what prod runs;
reports 107-111 are not covered by it.
