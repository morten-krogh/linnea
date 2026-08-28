# Audit Report 110

Audited `375f7f1` (`pem: one OID validator, shared by both callers (report 109)`), 2026-08-28.

The report-109 OID fix is present. One exact-consumption gap remains in the optional SEC1 public-key wrapper:

1. **Low: optional `[1] publicKey` accepts a trailing child after its BIT STRING.**

The malformed PKCS#8 key passes current `bin/linnea --test` and OpenSSL rejects it. The scalar and leaf certificate remain matching, so this is malformed-credential acceptance and tooling-interoperability risk, not a remote attack or key-identity bypass.

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — SEC1 public-key wrapper does not require exact consumption

Severity: **Low (P3 malformed private-key acceptance)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

When the SEC1 tail walker sees `[1]`, it opens one child, requires a 66-byte uncompressed-point BIT STRING, copies the point, and advances using the outer wrapper's original length ([src/server/linnea_pem.asm:1010](/home/linnea/linnea/src/server/linnea_pem.asm:1010), [src/server/linnea_pem.asm:1014](/home/linnea/linnea/src/server/linnea_pem.asm:1014), [src/server/linnea_pem.asm:1018](/home/linnea/linnea/src/server/linnea_pem.asm:1018), [src/server/linnea_pem.asm:1021](/home/linnea/linnea/src/server/linnea_pem.asm:1021), [src/server/linnea_pem.asm:1023](/home/linnea/linnea/src/server/linnea_pem.asm:1023), [src/server/linnea_pem.asm:1039](/home/linnea/linnea/src/server/linnea_pem.asm:1039), [src/server/linnea_pem.asm:1067](/home/linnea/linnea/src/server/linnea_pem.asm:1067)).

It never compares the BIT STRING end to the `[1]` wrapper end. The enclosing ECPrivateKey walker therefore sees its declared boundary as consumed even if `[1]` contains a valid public-key BIT STRING followed by another TLV.

RFC 5915 defines `publicKey [1] BIT STRING OPTIONAL`, not a container of an arbitrary BIT STRING plus extensions ([RFC 5915 §3](https://www.rfc-editor.org/rfc/rfc5915.html#section-3)).

### Reproduction

Decode `test/tls/server.key` to DER. Its `[1]` wrapper at offset 68 is `a1 44`, containing the valid `03 42 00 04 || X || Y` BIT STRING. Insert `05 00` immediately after that BIT STRING, then increase the declared lengths of the `[1]` wrapper, ECPrivateKey SEQUENCE, privateKey OCTET STRING, and outer PrivateKeyInfo SEQUENCE by two. The scalar and point remain otherwise unchanged:

```text
$ ./bin/linnea --test --config bad-pub-tail.json
$ echo $?
0

$ openssl pkey -in bad-pub-tail.key -noout
Could not find private key ... unsupported
```

Linnea extracts and verifies the original point against the scalar, then skips over the enlarged `[1]` wrapper. OpenSSL rejects the private-key structure because publicKey is not exactly one BIT STRING.

### Impact

Linnea can still serve because it uses the unchanged scalar and matching certificate. However, its preflight approves a key file standard tooling cannot parse, hiding accidental or malicious trailing data in the identity container. The file is local and no secret is exposed, making this Low severity.

### Recommended fix

After parsing the inner BIT STRING, require `rax + rcx` to equal the `[1]` content end before copying the point. Apply exact-consumption checks consistently to every constructed optional field. Add a valid `[1]` control and trailing-TLV, second-BIT-STRING, and truncated-wrapper regressions.

---

## Resolution (2026-08-28)

**CONFIRMED and FIXED.** The `[1]` wrapper's own declared length was used to
advance the tail walk, so a trailing TLV inside it was stepped over unseen. The
BIT STRING must now end exactly at the wrapper's content end.

This is the same shape as report 103's SPKI finding — a child parsed and used
without checking it was the LAST child — in a different container. Worth noting
because it suggests the rule generalises: **every constructed field that is
"exactly one X" needs the end comparison, not just the tag and length of X.**
Applied here to `[1]`; already applied to the SPKI (103) and the outer
Certificate (100).

Verified controls-first: 10 credentials load, covering every key shape now
reachable — with a `[1]`, with a valid `[0]` and a `[1]`, and with neither —
plus 7 rejections spanning reports 104-110. OpenSSL rejects the new mutation.

**The suite was not run: the operator asked for the fix only.** One new claim
(166), `doc_claims_test.py` green standalone. The last full suite remains
1193/0 at `0e3fe0e`, which is what prod runs; reports 107-110 are not covered.
