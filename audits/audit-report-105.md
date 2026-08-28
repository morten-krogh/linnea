# Audit Report 105

Audited `49e5d66` (`tls: parse ECPrivateKey to its end, not just to the scalar (report 104)`), 2026-08-28.

The report-104 remediation validates the outer shape of optional SEC1 fields. Two semantic gaps remain:

1. **Low: `[0] parameters` is accepted without validation of its named-curve content.**
2. **Low: a well-shaped optional `[1] publicKey` is not checked against the private scalar.**

Both cases pass current `bin/linnea --test` and OpenSSL rejects them. The scalar still matches the leaf certificate, so these are local credential-integrity and tooling-interoperability defects rather than remote attacks or key exposure.

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — SEC1 parameters are accepted as arbitrary `[0]` content

Severity: **Low (P3 malformed private-key acceptance)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

After the scalar, the tail walker accepts any TLV tagged `0xa0` as optional parameters and immediately advances over it. It neither opens its content nor requires a named-curve OID matching P-256 ([src/server/linnea_pem.asm:485](/home/linnea/linnea/src/server/linnea_pem.asm:485), [src/server/linnea_pem.asm:488](/home/linnea/linnea/src/server/linnea_pem.asm:488), [src/server/linnea_pem.asm:493](/home/linnea/linnea/src/server/linnea_pem.asm:493), [src/server/linnea_pem.asm:494](/home/linnea/linnea/src/server/linnea_pem.asm:494), [src/server/linnea_pem.asm:518](/home/linnea/linnea/src/server/linnea_pem.asm:518)).

RFC 5915 defines this field as `[0] ECParameters`; its permitted form is a named-curve OBJECT IDENTIFIER that identifies the curve's domain parameters ([RFC 5915 §3](https://www.rfc-editor.org/rfc/rfc5915.html#section-3)).

### Reproduction

The fixture's optional SEC1 public-key field starts at DER offset 68 as `a1 44 03 42 00 04 ...`. Change its first byte from `0xa1` to `0xa0`, leaving the BIT STRING payload, scalar, and outer P-256 AlgorithmIdentifier unchanged:

```text
$ ./bin/linnea --test --config bad-param.json
$ echo $?
0

$ openssl pkey -in bad-param.key -noout
Could not find private key ... unsupported
```

Linnea categorizes the BIT STRING as arbitrary parameters and skips it; OpenSSL rejects it because parameters cannot have that content.

### Impact and recommended fix

The malformed field does not change the scalar Linnea uses, but preflight approves a key file standard tools cannot reload. Open `[0]`, require exactly one P-256 OID, and reject duplicate `[0]` or `[1]` fields. A simpler policy is to reject inner parameters entirely because the outer PKCS#8 identifier already pins the curve.

## Finding 2 — embedded SEC1 public key is not tied to the private scalar

Severity: **Low (P3 internally inconsistent private-key acceptance)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

For `[1]`, the parser checks the tag, BIT STRING framing, fixed P-256 point length, unused-bits byte, and uncompressed marker ([src/server/linnea_pem.asm:497](/home/linnea/linnea/src/server/linnea_pem.asm:497), [src/server/linnea_pem.asm:505](/home/linnea/linnea/src/server/linnea_pem.asm:505), [src/server/linnea_pem.asm:508](/home/linnea/linnea/src/server/linnea_pem.asm:508), [src/server/linnea_pem.asm:510](/home/linnea/linnea/src/server/linnea_pem.asm:510), [src/server/linnea_pem.asm:514](/home/linnea/linnea/src/server/linnea_pem.asm:514)). It does not verify the point is on P-256 or that it equals the public key derived from the extracted scalar. The later pairing proof uses only the scalar and certificate leaf ([src/server/linnea_ktls.asm:233](/home/linnea/linnea/src/server/linnea_ktls.asm:233), [src/server/linnea_ktls.asm:238](/home/linnea/linnea/src/server/linnea_ktls.asm:238), [src/server/linnea_ktls.asm:244](/home/linnea/linnea/src/server/linnea_ktls.asm:244)).

RFC 5915 defines `publicKey` as the EC public key associated with the private key in question ([RFC 5915 §3](https://www.rfc-editor.org/rfc/rfc5915.html#section-3)).

### Reproduction

Flip one byte of the optional public point's X coordinate at DER offset 74, retaining its tag, lengths, uncompressed marker, and original private scalar:

```text
$ ./bin/linnea --test --config bad-pub.json
$ echo $?
0

$ openssl pkey -in bad-pub.key -noout
Could not find private key ... unsupported
```

The altered point remains structurally P-256-sized, so Linnea accepts it and continues signing with the original scalar. OpenSSL rejects the inconsistent private-key object.

### Impact and recommended fix

Linnea can serve, but the stored key claims a conflicting public identity and `--test` gives a false all-clear. When `[1]` is present, validate the point and compare it with scalar multiplication of the P-256 base point; otherwise reject `[1]` rather than accepting an unchecked advisory identity. Add malformed-parameter, duplicate-field, off-curve, and scalar/public-mismatch regressions.

---

## Resolution (2026-08-28)

**Both CONFIRMED and FIXED.** Fast suite **1166/0**; 156 claims (was 152).

**F1**: `[0] ECParameters` must now hold exactly the `prime256v1` OID, and a
second `[0]` or `[1]` is refused. The report offered a simpler policy — reject
inner parameters outright, since PKCS#8 already pins the curve. Not taken:
**OpenSSL accepts a valid inner `[0]`** (checked, with a hand-built key), so
refusing it would make linnea stricter than the reference for a legal file.
Validating it is the same outcome for malformed input without that cost.

**F2**: an embedded `[1]` is now tied to the private scalar. The report
suggested comparing against a base-point multiplication; this instead reuses
the signature ktls already produces for the certificate pairing and verifies it
under the embedded point — no second signing, no base point, and it exercises
the same primitive the handshake uses. Its own diagnostic: *"the key file
embeds a public key that its own private scalar does not sign for."*

### I broke every real key on the way, and the controls caught it

The `[1]` handler FELL THROUGH into the newly inserted `[0]` handler, which
demanded `rcx == 10` and failed. Every credential in the tree carries a `[1]`,
so **all of them were rejected** — server, sni, bigchain, all three generated
pairs. It built cleanly.

**That is the third fall-through I have introduced in this session**, always
the same shape: putting a labelled block into a path that reached the next
label by falling into it. The `jmp .pk_next` now carries a comment saying so.
What caught it was running the ACCEPTANCE controls, not the rejection cases —
the two report-105 fixtures were "rejected" either way, and only the real
credentials showed the damage.

### A fifth unreachable branch

No real key carries `[0]` at all: PKCS#8 pins the curve in the outer
AlgorithmIdentifier, so every generator omits the inner one. Both sides of the
new check were reachable only from a hand-built key — one with a valid
`prime256v1` field (accepted, and OpenSSL agrees) and one naming a different
curve (rejected). That is the fifth such branch across reports 100-105.
