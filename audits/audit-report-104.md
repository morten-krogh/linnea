# Audit Report 104

Audited `9451649` (`tls: require real AlgorithmIdentifiers and an exact SPKI
(report 103)`), 2026-08-28.

The report-103 remediation closes both reported certificate cases. The adjacent
PKCS#8/SEC1 private-key parser still accepts malformed data after the private
scalar, however:

1. **Low: malformed optional SEC1 public-key fields are ignored during local
   key preflight.**

The case was reproduced against the current `bin/linnea`: `--test` exits 0,
while OpenSSL rejects the same private key. The scalar and certificate remain
matching, so Linnea can still serve it; this is malformed-credential acceptance
and tooling-interoperability risk, not a key-identity bypass.

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — PKCS#8 parser stops at the SEC1 scalar and ignores remaining fields

Severity: **Low (P3 false-positive credential preflight)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

`linnea_pem_p256_key` opens PrivateKeyInfo, its P-256 AlgorithmIdentifier, the
private-key OCTET STRING, ECPrivateKey, version, and 32-byte scalar
([src/server/linnea_pem.asm:400](/home/linnea/linnea/src/server/linnea_pem.asm:400), [src/server/linnea_pem.asm:421](/home/linnea/linnea/src/server/linnea_pem.asm:421), [src/server/linnea_pem.asm:438](/home/linnea/linnea/src/server/linnea_pem.asm:438), [src/server/linnea_pem.asm:447](/home/linnea/linnea/src/server/linnea_pem.asm:447), [src/server/linnea_pem.asm:456](/home/linnea/linnea/src/server/linnea_pem.asm:456), [src/server/linnea_pem.asm:468](/home/linnea/linnea/src/server/linnea_pem.asm:468)). Immediately after checking the scalar length, it returns success
([src/server/linnea_pem.asm:471](/home/linnea/linnea/src/server/linnea_pem.asm:471), [src/server/linnea_pem.asm:474](/home/linnea/linnea/src/server/linnea_pem.asm:474), [src/server/linnea_pem.asm:476](/home/linnea/linnea/src/server/linnea_pem.asm:476)).

Consequently it does not require that the scalar end the inner ECPrivateKey
SEQUENCE, parse the optional `[0] parameters` or `[1] publicKey` fields, or
reject unknown/malformed trailing children. The comment explicitly describes
`[1] BIT STRING publicKey` as optional and ignored
([src/server/linnea_pem.asm:367](/home/linnea/linnea/src/server/linnea_pem.asm:367), [src/server/linnea_pem.asm:378](/home/linnea/linnea/src/server/linnea_pem.asm:378), [src/server/linnea_pem.asm:381](/home/linnea/linnea/src/server/linnea_pem.asm:381)), but ignoring an *absent* optional field is different from accepting an ill-formed
one.

RFC 5915 defines ECPrivateKey as exactly version, privateKey, optional `[0]`
parameters, and optional `[1]` BIT STRING publicKey. If a public-key field is
present, it has that specified type and semantics
([RFC 5915 §3](https://www.rfc-editor.org/rfc/rfc5915.html#section-3)).

### Reproduction

Decode `test/tls/server.key` to DER. Its SEC1 ECPrivateKey has an optional
public-key field beginning at offset 68: `a1 44 03 42 00 04 ...`. Change only
that first byte from `0xa1` (`[1]`) to `0x04` (OCTET STRING), preserving all
lengths, the private scalar, and the configured matching certificate. Rewrap
the result as a `PRIVATE KEY` PEM:

```text
$ ./bin/linnea --test --config bad-opt.json
$ echo $?
0

$ openssl pkey -in bad-opt.key -noout
Could not find private key ... unsupported
```

Linnea returns after extracting the original scalar and then independently
proves that scalar signs for the certificate leaf. It never reaches the
retagged field. OpenSSL parses the complete ECPrivateKey structure and rejects
it.

### Impact

Unlike the certificate findings, this particular malformed field does not
change Linnea's operational private scalar, so the server can continue to
present its matching certificate. It nevertheless lets `--test` approve a key
file that standard tooling cannot read, making renewal validation depend on
which parser sees the artifact and concealing truncation or corruption in an
optional section. The issue remains Low because there is no remote input path,
no key disclosure, and no demonstrated handshake failure.

### Recommended fix

After the scalar, parse the remaining ECPrivateKey bytes to its exact end:
allow no field, or an optional `[0]` named-curve parameter followed by an
optional `[1]` BIT STRING public key; reject duplicates, wrong tags, malformed
contents, and trailing bytes. Require every enclosing PrivateKeyInfo and OCTET
STRING boundary to be consumed exactly as well. If accepting `[1]`, either
verify it is a valid P-256 point derived from the scalar or reject it as
unsupported rather than silently ignoring it.

Add valid keys with no optional fields and with a valid public-key field, plus
wrong-tag, duplicate, truncated, conflicting-public-key, and trailing-child
cases.

---

## Resolution (2026-08-28)

**CONFIRMED and FIXED.** Fast suite **1166/0**; 152 claims (was 150).

`linnea_pem_p256_key` returned the moment it had the scalar, so everything
after it was unexamined and a `[1] publicKey` retagged to OCTET STRING passed
while OpenSSL refuses the file. It now walks ECPrivateKey to its exact end:
optional `[0]` parameters, then optional `[1]` publicKey, in order, with `[1]`
required to hold a 66-byte uncompressed-point BIT STRING. The report's framing
is the right one — ignoring an ABSENT optional field is not the same as
accepting an ill-formed one.

### One recommendation NOT followed

The report also asks that every enclosing boundary be consumed exactly, which
would reject trailing bytes after the outer structure. **OpenSSL accepts that
case** — I built the fixture and checked. Rejecting it would make linnea
stricter than the reference implementation in a way that could refuse a real
file, which is the wrong side of the "malformed DER, not unusual but legal"
line this arc has been holding. It stays accepted.

Structurally validating `[1]` rather than cryptographically deriving it from
the scalar is also deliberate: the ktls pairing already proves the SCALAR signs
for the certificate's leaf point, which is the property that actually matters.
A `[1]` that disagreed with the scalar would be caught the moment the
certificate is paired.

### Two harness faults of mine, and a fourth unreachable branch

`sni.key` first reported as "rejected": my helper hardcoded `server.crt`, so
the report-99 mismatch check was firing correctly. Paired properly it loads.

And the **no-optional-fields** path of the new loop was unreachable, because
every OpenSSL-generated key includes `[1]`. I built one by stripping the field
and re-encoding the enclosing lengths; it loads. That is the FOURTH branch in
this arc (reports 100, 102, 104) that no existing fixture could enter —
padding lengths, the v1 version-absent path, and now the absent optional key
field. The pattern is consistent enough to state as a rule: **a new optional-
or-variant branch almost never has a fixture already; make one before believing
the suite covers it.**
