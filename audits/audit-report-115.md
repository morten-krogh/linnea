# Audit Report 115

Audited commit `28e2fa6` (`x509: implicit unique-ID tags, and real extension framing (report 114)`), 2026-08-28.

This full-sweep pass rechecked the report-114 X.509 suffix handling, the common DER helpers, certificate-list framing, leaf pairing, and the PKCS#8 P-256 key walk. The X.509 fixes hold for the previously reported cases. One independently reproducible PKCS#8 boundary defect remains: the parser stops after the `privateKey` OCTET STRING and never accounts for the remainder of the outer `PrivateKeyInfo` sequence.

No production code or test was changed in this audit. Only this report was added.

## Finding 1 — PKCS#8 trailing fields inside PrivateKeyInfo are silently accepted

**Severity:** Medium  
**Confidence:** High  
**Status:** Open

[`linnea_pem_p256_key`](/home/linnea/linnea/src/server/linnea_pem.asm:405) opens the outer `PrivateKeyInfo` SEQUENCE and sets its parse boundary to that sequence's content at [lines 420–427](/home/linnea/linnea/src/server/linnea_pem.asm:420). After it opens the `privateKey` OCTET STRING, though, it replaces that boundary with the OCTET STRING's content end at [lines 458–465](/home/linnea/linnea/src/server/linnea_pem.asm:458). The later exact-end check therefore applies only to the nested SEC1 `ECPrivateKey`; bytes that remain in the outer PKCS#8 SEQUENCE are never inspected.

RFC 5208 defines `PrivateKeyInfo` as version, AlgorithmIdentifier, privateKey OCTET STRING, and at most an optional implicit `[0] Attributes` field. A bare `NULL` after `privateKey` is not legal ([RFC 5208 §5](https://www.rfc-editor.org/rfc/rfc5208.html#section-5)).

### Reproduction

Convert `test/tls/server.key` to unencrypted PKCS#8 DER. Its outer header is `30 81 87`, declaring 135 bytes of content. Append `05 00` to the outer sequence and change that declared length to `0x89`:

```sh
openssl pkcs8 -topk8 -nocrypt -in test/tls/server.key -outform DER -out good.der
cp good.der bad.der
printf '\005\000' >> bad.der
printf '\211' | dd of=bad.der bs=1 seek=2 conv=notrunc status=none
# Wrap bad.der as BEGIN/END PRIVATE KEY and use it with test/tls/server.crt.

./bin/linnea --config config.json --test  # exits 0 (incorrect)
openssl pkey -in bad.key -noout            # rejects the key
```

The private scalar, nested SEC1 object, optional public-key check, and certificate/key pairing all remain unchanged. The successful result specifically comes from losing the outer-sequence end after opening the OCTET STRING.

### Impact

An operator can receive a successful configuration preflight for a malformed private-key file that common tooling cannot load. This makes a key-file deployment or hot upgrade appear healthy locally while other credential-management and recovery tooling rejects the same file.

### Recommended fix

Preserve a separate `PrivateKeyInfo` end pointer. After validating the `privateKey` OCTET STRING and its nested SEC1 content, require the remaining outer bytes to be either absent or exactly one valid `[0] IMPLICIT Attributes` field; reject every other tag, duplicate, or trailing byte. Add the appended-NULL fixture as a regression test.

---

## Resolution (2026-08-28)

**CONFIRMED and FIXED.** 180 claims (was 178).

The parser set its boundary to `PrivateKeyInfo`'s content, then **replaced** it
with the `privateKey` OCTET STRING's end, so the outer sequence's remaining
bytes were never inspected. The outer end is now kept in its own register and
the remainder is required to be nothing, or exactly one `[0] IMPLICIT
Attributes` filling it.

### The line was measured, not assumed

Before writing the fix I checked both candidate encodings against OpenSSL:

    NULL after privateKey    linnea: accept   openssl: REJECT   <- the defect
    trailing [0] Attributes  linnea: accept   openssl: accept   <- must stay

Rejecting everything after `privateKey` would have been the simpler patch and
would have repeated report 114's mistake — refusing a file OpenSSL accepts.
The `[0]` row is the reason the fix allows exactly one thing rather than none.
Every control row now prints OpenSSL's verdict beside linnea's, and all fourteen
agree.

**The suite was not run: the operator asked for the fix only.** The last full
suite remains 1193/0 at `0e3fe0e`, which is what prod runs; reports 107-115 are
not covered by it.
