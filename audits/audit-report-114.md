# Audit Report 114

Audited commit `895493a` (`x509: finish the TBS, and check every entry's SPKI (report 113)`), 2026-08-28.

This continued the full PEM/X.509 credential-loader sweep after report 113's TBS-tail remediation. It confirms two errors in the new `tbs_suffix_ok` parser: unique identifiers are matched as constructed explicit wrappers rather than their required implicit BIT STRING tags, and extensions are accepted as an opaque `[3]` wrapper. Each discrepancy is reproducible through the normal `--test` credential path against OpenSSL.

No production code or test was changed in this audit. Only this report was added.

## Finding 1 — Unique identifiers use the wrong context-specific tag

**Severity:** Medium  
**Confidence:** High  
**Status:** Open

[`tbs_suffix_ok`](/home/linnea/linnea/src/server/linnea_pem.asm:1211) accepts only constructed `a1` and `a2` as issuer and subject unique identifiers at [lines 1232–1235](/home/linnea/linnea/src/server/linnea_pem.asm:1232). RFC 5280 defines these fields as `[1] IMPLICIT UniqueIdentifier OPTIONAL` and `[2] IMPLICIT UniqueIdentifier OPTIONAL`; `UniqueIdentifier` is a BIT STRING. Their DER tags are therefore primitive context-specific `81` and `82`, whose first content octet is the BIT STRING unused-bits count—not constructed `a1`/`a2` wrappers ([RFC 5280 §4.1.2](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2)).

This has both compatibility and acceptance consequences:

- A valid `81 01 00` issuerUniqueID inserted before the extensions block is accepted by OpenSSL but rejected by Linnea.
- The malformed constructed alternative `a1 01 00` is accepted by Linnea but rejected by OpenSSL.

### Reproduction

Convert `test/tls/server.crt` to DER. At offset 214, before its existing `[3]` extensions element, insert either of these three-byte elements and increase the outer Certificate and TBS declared lengths by three (`0x019a -> 0x019d`, `0x013f -> 0x0142`):

```text
81 01 00   # valid IMPLICIT issuerUniqueID: zero unused bits, no data
a1 01 00   # invalid constructed encoding
```

With the unchanged matching key:

```text
                          Linnea --test     OpenSSL x509 -noout
81 01 00 (valid)          reject             accept
a1 01 00 (malformed)      accept             reject
```

### Impact

The loader rejects standards-conformant certificates using a legacy optional field and can bless an invalid alternative that peers reject. In either direction, a successful local preflight no longer accurately predicts whether a client can parse the transmitted certificate.

### Recommended fix

Handle tags `81` and `82`, not `a1` and `a2`. For each, require nonempty content, validate its first octet as a BIT STRING unused-bits count in `0..7`, and require zero padding bits in the final content octet when the count is nonzero. Preserve the existing ordering and uniqueness checks. Add positive and negative fixtures for the two encodings above.

## Finding 2 — The extensions wrapper is not opened or validated

**Severity:** Medium  
**Confidence:** High  
**Status:** Open

The same function recognizes `[3]` (`a3`) at [line 1236](/home/linnea/linnea/src/server/linnea_pem.asm:1236), records its order, and advances over its declared content at [line 1251](/home/linnea/linnea/src/server/linnea_pem.asm:1251). It never verifies that the explicit wrapper contains exactly the required `Extensions` SEQUENCE, nor that the sequence's entries are valid `Extension` values.

RFC 5280 defines `extensions [3] EXPLICIT Extensions OPTIONAL`, where `Extensions` is a SEQUENCE OF `Extension`; accepting a `NULL` in the wrapper is not a valid encoding ([RFC 5280 §4.1.2.9](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.9)).

### Reproduction

In the repository's DER fixture, the extensions wrapper begins at offset 214 and its inner `Extensions` SEQUENCE tag is at offset 216. Change only that byte from `30` to `05`, producing an `a3` wrapper whose content is a NULL of the pre-existing length.

```sh
./bin/linnea --config config.json --test  # exits 0 (incorrect)
openssl x509 -in bad-extensions.crt -noout # rejects the certificate
```

The leaf SPKI and configured private key are unchanged, so this reaches the suffix parser after all key-pair checks succeed.

### Impact

Linnea can preflight, load, and transmit a certificate with malformed extension framing. Clients that parse the certificate reject the handshake, making an invalid renewal or hot-upgrade look healthy locally.

### Recommended fix

For tag `a3`, require exactly one inner `SEQUENCE` filling the wrapper. Walk its children as `Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }`, requiring valid OID encoding and exact containment. The parser may keep extension values opaque, but it must validate their outer ASN.1 structure. Add the retagged inner-SEQUENCE case as a regression test.

---

## Resolution (2026-08-28)

**Both CONFIRMED and FIXED.** 178 claims (was 175). Both are defects in the
`tbs_suffix_ok` I added one report earlier.

**F1 is the one that matters, and it is the mistake I have been most careful to
avoid all arc: linnea REJECTED a certificate OpenSSL ACCEPTS.** RFC 5280 makes
`[1]`/`[2]` IMPLICIT UniqueIdentifier — a BIT STRING — so their DER tags are
PRIMITIVE `81`/`82`. I wrote the constructed `a1`/`a2`, which is wrong in both
directions: a conformant certificate carrying `81 01 00` was refused, and the
malformed constructed form was accepted. Every previous finding in this arc had
been "too permissive"; this one was **too strict**, which is worse, because it
turns a preflight into an outage on a legal file.

Now: `81`/`82` only, with the unused-bits octet required to be 0..7.

**F2**: `[3]` is EXPLICIT, so the wrapper must hold exactly one `Extensions`
SEQUENCE, and its children are walked as
`Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
extnValue OCTET STRING }`. Extension *values* stay opaque — the framing is the
point, not the policy.

### A better verification method, adopted here

This round the control table prints **OpenSSL's verdict beside linnea's and
flags any disagreement**. That is what should have been done from report 99
onward: two of my reversals in this arc came from assuming what OpenSSL would
do instead of asking it. Every row now agrees.

The one row it flagged turned out to be the tool's limitation, not linnea's:
`openssl x509` reads only the FIRST certificate in a chain file, so it
"accepted" a two-cert fixture whose *intermediate* is malformed. Checked alone,
OpenSSL rejects that intermediate too.

**The suite was not run: the operator asked for the fix only.** The last full
suite remains 1193/0 at `0e3fe0e`, which is what prod runs; reports 107-114 are
not covered by it.
