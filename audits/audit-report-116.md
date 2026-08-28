# Audit Report 116

Audited commit `c8966b6` (`pkcs8: keep the outer PrivateKeyInfo end (report 115)`), 2026-08-28.

This full-sweep pass rechecked report 115's outer PKCS#8 boundary, the nested SEC1 parser, PEM framing, and certificate/key pairing. The prior bare-NULL case is now rejected. One gap remains in the newly supported optional `PrivateKeyInfo.attributes`: its wrapper is recognized but its contents are not parsed.

No production code or test was changed in this audit. Only this report was added.

## Finding 1 — PKCS#8 attributes are accepted as opaque content

**Severity:** Medium  
**Confidence:** High  
**Status:** Open

After the nested `ECPrivateKey` ends, [`linnea_pem_p256_key`](/home/linnea/linnea/src/server/linnea_pem.asm:593) correctly preserves and checks the outer `PrivateKeyInfo` boundary. Its optional-attributes branch then requires tag `a0` and exact containment at [lines 601–610](/home/linnea/linnea/src/server/linnea_pem.asm:601), but never opens the implicit `Attributes` payload. Any bounded bytes inside the wrapper are therefore accepted.

RFC 5208 defines `attributes [0] IMPLICIT Attributes OPTIONAL`, with `Attributes ::= SET OF Attribute`; the content must be attribute values, not an arbitrary NULL ([RFC 5208 §5](https://www.rfc-editor.org/rfc/rfc5208.html#section-5)).

### Reproduction

Convert `test/tls/server.key` to unencrypted PKCS#8 DER, append `a0 02 05 00` within the outer `PrivateKeyInfo` sequence, and increase its declared content length from `0x87` to `0x8b`:

```sh
openssl pkcs8 -topk8 -nocrypt -in test/tls/server.key -outform DER -out good.der
cp good.der bad.der
printf '\240\002\005\000' >> bad.der
printf '\213' | dd of=bad.der bs=1 seek=2 conv=notrunc status=none
# Wrap bad.der as BEGIN/END PRIVATE KEY and use it with test/tls/server.crt.

./bin/linnea --config config.json --test  # exits 0 (incorrect)
openssl pkey -in bad.key -noout            # rejects the key
```

The scalar, inner SEC1 object, and certificate/key pairing are unchanged. The acceptance occurs solely because the `a0` content is skipped.

### Impact

The local preflight can approve a malformed private-key file that normal credential tooling rejects. This weakens the value of `--test` during key rollout or hot upgrade and leaves an invalid PKCS#8 representation in the operational configuration.

### Recommended fix

Walk the implicit attributes content to its exact end. Require each entry to be an `Attribute` SEQUENCE containing a valid OID and a nonempty SET OF complete value elements; reject NULLs, empty/mistagged entries, and trailing bytes. If attribute support is intentionally out of scope, reject any outer `[0]` field instead of accepting it opaque. Add the `a0 02 05 00` regression fixture.

---

## Resolution (2026-08-28)

**CONFIRMED and FIXED.** 182 claims (was 180). The `[0]` wrapper added in report
115 was recognised but skipped whole; its content is now walked as zero or more
`Attribute ::= SEQUENCE { type OID, values SET OF AttributeValue }`, tiling the
wrapper exactly.

### One recommendation deliberately NOT followed, on measurement

The report asks for "a nonempty SET OF complete value elements". I built all
four shapes and asked OpenSSL first:

    a NULL in the wrapper              linnea accept / openssl REJECT   <- the defect
    an EMPTY attributes set            accept / accept                  <- must stay
    a well-formed friendlyName         accept / accept                  <- must stay
    an Attribute with an EMPTY values  accept / accept                  <- must stay

**OpenSSL accepts an Attribute whose values SET is empty**, so requiring
non-empty would refuse a file the reference takes — report 114's mistake. The
implementation requires the SET's children to tile it exactly and stops there.

The report's alternative — "if attribute support is out of scope, reject any
outer `[0]`" — is also refused for the same reason: OpenSSL accepts `a0 00`,
which report 115 had already measured.

All fifteen control rows now print OpenSSL's verdict beside linnea's and agree.

**The suite was not run: the operator asked for the fix only.** The last full
suite remains 1193/0 at `0e3fe0e`, which is what prod runs; reports 107-116 are
not covered by it.
