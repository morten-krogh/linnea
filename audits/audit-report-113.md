# Audit Report 113

Audited commit `2cdf269` (`pem: validate a string's content, not just its tag (report 112)`), 2026-08-28.

This was a full sweep of the local-credential path: PEM boundary/base64 decoding, PKCS#8 P-256 parsing, certificate-list framing, the common X.509 walk, leaf-SPKI extraction, and the certificate/key pairing check. The PEM and key paths correctly reject the malformed cases exercised here; this report batches the two confirmed gaps in the remaining X.509 walk. Both let `--test` approve malformed certificate bytes that OpenSSL rejects.

No production code or test was changed in this audit. Only this report was added.

## Finding 1 — The TBSCertificate walk accepts arbitrary fields after SPKI

**Severity:** Medium  
**Confidence:** High  
**Status:** Open

[`tbs_walk`](/home/linnea/linnea/src/server/linnea_pem.asm:1181) carefully validates the certificate envelope and the mandatory fields preceding SubjectPublicKeyInfo. After it reads the SPKI element at [line 1379](/home/linnea/linnea/src/server/linnea_pem.asm:1379), however, it returns without comparing the SPKI end to the `TBSCertificate` end and without parsing the only legal suffix fields (`issuerUniqueID`, `subjectUniqueID`, and `extensions`).

RFC 5280's `TBSCertificate` grammar permits only those explicitly tagged optional fields after `subjectPublicKeyInfo`; an untagged `NULL` is not one of them ([RFC 5280 §4.1.2](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2)).

### Reproduction

Starting with `test/tls/server.crt` converted to DER, insert `05 00` (DER NULL) at byte offset 327, exactly after the TBS content, and increase the outer Certificate and TBS lengths from 410 to 412 and from 319 to 321, respectively. Re-wrap as a `CERTIFICATE` PEM and reference it with the unchanged matching `test/tls/server.key`.

```text
original TBS end: 327
inserted bytes:   05 00
Certificate len:  0x019a -> 0x019c
TBS len:          0x013f -> 0x0141

./bin/linnea --config config.json --test  # exits 0 (incorrect)
openssl x509 -in bad.crt -noout           # rejects the certificate
```

The appended `NULL` lies outside the SPKI, so it is neither an algorithm nor key-pair mismatch. It reaches the premature-success return in `tbs_walk`.

### Impact

An operator can successfully preflight a certificate that conforming TLS tooling cannot parse. Linnea then transmits the malformed credential and clients may fail the TLS handshake, turning an invalid certificate update into an availability incident.

### Recommended fix

After SPKI, walk the remainder of the TBS sequence to its exact end. Accept only the optional context-specific fields defined by RFC 5280, at most once and in order, and validate their inner structures; otherwise reject the certificate. Add the inserted-NULL fixture above as a regression case.

## Finding 2 — Intermediate certificates are checked only through the SPKI wrapper

**Severity:** Medium  
**Confidence:** High  
**Status:** Open

[`linnea_pem_cert_list`](/home/linnea/linnea/src/server/linnea_pem.asm:266) calls [`linnea_x509_cert_wellformed`](/home/linnea/linnea/src/server/linnea_pem.asm:1431) for every chain entry. That wrapper only calls `tbs_walk`; it never opens the intermediate's SubjectPublicKeyInfo. Only the configured leaf subsequently reaches [`linnea_x509_leaf_spki`](/home/linnea/linnea/src/server/linnea_pem.asm:1452) and [`linnea_x509_spki_point`](/home/linnea/linnea/src/server/linnea_pem.asm:1569).

Therefore a chain whose valid first certificate is followed by an intermediate whose SPKI AlgorithmIdentifier tag is changed from `SEQUENCE` (`30`) to `NULL` (`05`) passes Linnea's preflight. OpenSSL rejects that intermediate. RFC 5280 requires SubjectPublicKeyInfo to contain an `AlgorithmIdentifier` and a `BIT STRING`, not arbitrary contents ([RFC 5280 §4.1.2.7](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.7)).

### Reproduction

Use an ordinary valid leaf as the first PEM block, then append a second copy whose DER byte offset 125 (the SPKI AlgorithmIdentifier tag in the repository fixture) has been changed from `30` to `05`.

```sh
./bin/linnea --config chain-config.json --test  # exits 0 (incorrect)
openssl x509 -in malformed-intermediate.crt -noout  # rejects it
```

The first certificate remains a valid matching leaf, so the pairing proof succeeds. The result specifically demonstrates that every non-leaf entry is framed for transmission without an SPKI grammar check.

### Impact

The server can start or hot-upgrade with an unusable intermediate certificate and send it to clients. Clients that parse the chain reject the handshake; the `--test` result is again misleading precisely when it is relied upon to protect a credential rollout.

### Recommended fix

Make the common certificate validator finish the whole TBSCertificate, including a structurally exact SPKI. It need not require intermediates to use P-256: a generic validator can require `SEQUENCE { AlgorithmIdentifier, BIT STRING }` with a valid AlgorithmIdentifier and exact containment. Keep the leaf-only P-256 and key-pair checks as the stricter second stage. Add a two-certificate PEM regression case with the retagged intermediate SPKI.

---

## Resolution (2026-08-28)

**Both CONFIRMED and FIXED.** 175 claims (was 173).

**F1**: `tbs_walk` returned the moment it had the SPKI, so anything appended
after it inside the TBS was never seen. A new `tbs_suffix_ok` walks the
remainder to the exact TBS end, accepting only `[1] issuerUniqueID`,
`[2] subjectUniqueID` and `[3] extensions`, each at most once and in ascending
order.

**F2**: only the leaf ever reached an SPKI check — via
`linnea_x509_leaf_spki`'s P-256 path — so a malformed INTERMEDIATE was framed
and transmitted unexamined. `spki_ok` now runs inside `tbs_walk`, on every
entry. It is deliberately **generic**: `SEQUENCE { AlgorithmIdentifier, BIT
STRING }` filling the sequence exactly, with no curve or algorithm requirement,
because an issuer may be RSA or any curve. The leaf's P-256 and key-pairing
checks stay as the stricter second stage, exactly as the report recommends.

The reproduction is a good demonstration of why this was invisible: the same
malformed certificate is REJECTED as a leaf and was ACCEPTED as an
intermediate. A fixture that only ever appears first cannot find this.

### Controls

Nine credentials load, including `bigchain.crt` — whose six issuers now each go
through `spki_ok` — and the hand-built v1, which has **no optional tail at
all** and so exercises the empty case of the new suffix walk. Seven rejections
spanning reports 100-113 still hold.

**The suite was not run: the operator asked for the fix only.** The last full
suite remains 1193/0 at `0e3fe0e`, which is what prod runs; reports 107-113 are
not covered by it.
