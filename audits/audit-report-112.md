# Audit Report 112

Audited commit `0750669` (`pem: a Name attribute value must be a string (report 111)`), 2026-08-28.

This pass continued from report 111's type allow-list for distinguished-name
attributes.  It finds one remaining certificate-loader discrepancy: the
allow-list identifies UTF8String (and other ASN.1 string types) by tag, but
does not validate the selected string's contents.  Consequently `--test` can
bless a configured certificate which common TLS tooling refuses to parse.

No production code was changed in this audit.  Only this report was added.

## Finding 1 — Name string payloads are accepted without validating their encoding

**Severity:** Medium  
**Confidence:** High  
**Status:** Open

[`attr_ok`](/home/linnea/linnea/src/server/linnea_pem.asm:864) verifies that
an AttributeTypeAndValue has an OID and exactly one value.  The new logic then
allows a fixed set of string tags, including UTF8String at
[line 896](/home/linnea/linnea/src/server/linnea_pem.asm:896), and accepts the
element once it fills the enclosing sequence at
[lines 912–915](/home/linnea/linnea/src/server/linnea_pem.asm:912).  It does
not inspect the value bytes.  Thus `0c 09 ff 6f 63 61 6c 68 6f 73 74` is
accepted as the issuer commonName although `ff` is not a UTF-8 byte sequence.

RFC 5280 defines `DirectoryString` as a choice that includes `UTF8String` and
states that an attribute's value type is determined by its attribute type;
the profile's expanded `commonName` syntax has `UTF8String` as one of its
choices ([RFC 5280 §§4.1.2.4 and A.1](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.4)).
`UTF8String` content must be UTF-8, whose well-formed encoding rules reject a
standalone `ff` byte ([RFC 3629 §3](https://www.rfc-editor.org/rfc/rfc3629.html#section-3)).

### Reproduction

Starting with the repository's `test/tls/server.crt`, convert it to DER and
replace byte offset 60, the first content byte of its issuer `UTF8String
("localhost")`, with `ff`.  Re-wrap the altered DER as a PEM CERTIFICATE and
use it with the unchanged matching `test/tls/server.key` in an ordinary TLS
server configuration.

```sh
openssl x509 -in test/tls/server.crt -outform DER -out good.der
cp good.der bad.der
printf '\377' | dd of=bad.der bs=1 seek=60 conv=notrunc status=none
{ printf '%s\n' '-----BEGIN CERTIFICATE-----'; base64 -w 64 bad.der; \
  printf '%s\n' '-----END CERTIFICATE-----'; } > bad.crt

# config.json is a normal TLS server config referencing bad.crt and
# test/tls/server.key.
./bin/linnea --config config.json --test  # exits 0 (incorrect)
openssl x509 -in bad.crt -noout           # rejects the certificate
```

The mutation does not alter the subject public key or signature framing, so it
also demonstrates that the successful Linnea result reaches the intended
credential-loader and key-pair check rather than merely parsing JSON.

### Impact

An operator can receive a successful preflight result during startup or hot
upgrade for a certificate that standard TLS tooling refuses.  The server then
retains and transmits malformed certificate bytes; peers can abort certificate
processing, causing an avoidable TLS availability failure.  The same missing
content validation applies to every string tag accepted by `attr_ok`, not just
UTF8String.

### Recommended fix

After choosing the string tag, validate its contents before accepting the
AttributeTypeAndValue.  At minimum, add a bounded UTF-8 validator for tag
`0x0c`; reject malformed leading, continuation, overlong, surrogate, and
out-of-range sequences.  Either implement the corresponding defined character
sets and fixed-width rules for every other admitted tag, or reduce the
allow-list to the string encodings the loader can validate correctly.  Add a
regression case to `test/configs/doc_claims_test.py` that mutates the issuer
commonName byte as above and expects `--test` to fail.

---

## Resolution (2026-08-28)

**CONFIRMED and FIXED**, and this overturns the limit I set in report 111 — the
second reversal in this arc, and the same reasoning error both times.

In 111 I declined content validation as "a much larger surface with its own
interop risk". But OpenSSL rejects all four mutations, so they are malformed,
and "the reference refuses it" is the test I claimed to be applying. **Invoking
interop risk to avoid a check is only sound if the reference actually accepts
the input — which is measurable, and I did not measure it.**

`str_ok` now owns both halves of the rule: which tags are admitted, and whether
the content matches the tag. UTF8String gets full RFC 3629 validation
(overlong leads, lone continuations, truncation, surrogates, beyond U+10FFFF);
PrintableString, IA5String, VisibleString and NumericString get their character
sets; BMPString and UniversalString get their fixed-width constraints.

**TeletexString (0x14) is DROPPED from the allow-list**, taking report 112's
second option. Its real-world contents are a mix of T.61 and Latin-1 and cannot
be validated correctly, and admitting it unchecked would preserve exactly the
defect being fixed. Re-adding it is one line if a real certificate needs it.

### The multi-byte paths had no fixture — the eighth in this arc

Every certificate in the tree is ASCII, so the 2-, 3- and 4-byte branches of a
new UTF-8 validator were exercised by nothing. A bug there would have refused
every real certificate with a non-ASCII name and no test would have shown it.
Generated one with `/O=Ünïcödé Tëst/CN=пример.test` (2- and 3-byte sequences,
accepted), then spliced in a valid 4-byte U+1F600 (accepted), a UTF-16
surrogate `ED A0 80` (rejected) and `F4 90 80 80`, past U+10FFFF (rejected).

**The suite was not run: the operator asked for the fix only.** Four new claims
(173). The last full suite remains 1193/0 at `0e3fe0e`, which is what prod runs;
reports 107-112 are not covered by it.
