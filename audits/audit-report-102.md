# Audit Report 102

Audited `cd1e15a` (`tls: validate local certificates by structure, not by shape
(reports 100, 101)`), 2026-08-27.

The current worktree closes the previously reported outer-envelope, chain-entry,
PEM-padding, field-tag, and leaf-curve cases. Its shared `tbs_walk` routine,
however, still treats several nested mandatory structures as opaque objects.

One confirmed issue remains:

1. **Medium: the local certificate preflight accepts an invalid explicit
   TBSCertificate version wrapper, and similarly does not validate required
   nested field contents.**

The reproduced case passes the freshly built `bin/linnea --test` with exit 0
but is rejected by OpenSSL's X.509 decoder. It is a local credential-validation
and availability defect, not a remote parser attack or key-disclosure issue.

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — nested mandatory X.509 fields are accepted as opaque TLVs

Severity: **Medium (P2 TLS availability and false-positive credential preflight)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

The new `tbs_walk` correctly requires the optional version wrapper to carry a
context-specific `[0]` tag, then requires an INTEGER serial number and four
SEQUENCE-tagged fields before the positional SPKI
([src/server/linnea_pem.asm:613](/home/linnea/linnea/src/server/linnea_pem.asm:613), [src/server/linnea_pem.asm:616](/home/linnea/linnea/src/server/linnea_pem.asm:616), [src/server/linnea_pem.asm:619](/home/linnea/linnea/src/server/linnea_pem.asm:619), [src/server/linnea_pem.asm:626](/home/linnea/linnea/src/server/linnea_pem.asm:626), [src/server/linnea_pem.asm:629](/home/linnea/linnea/src/server/linnea_pem.asm:629)).

It never opens the content of the optional `[0]` wrapper. Any bounded content,
including an OCTET STRING rather than the required INTEGER version, is skipped
at [src/server/linnea_pem.asm:621](/home/linnea/linnea/src/server/linnea_pem.asm:621).
Likewise, the TBS signature, issuer, validity, and subject only need a SEQUENCE
tag: no AlgorithmIdentifier, Name, or two-Time Validity structure is verified
([src/server/linnea_pem.asm:630](/home/linnea/linnea/src/server/linnea_pem.asm:630), [src/server/linnea_pem.asm:636](/home/linnea/linnea/src/server/linnea_pem.asm:636)).

RFC 5280 defines `version` as `[0] EXPLICIT Version DEFAULT v1`, where
`Version` is an INTEGER with only v1/v2/v3 values. It also gives required
typed content to Validity and SubjectPublicKeyInfo, rather than allowing an
arbitrary SEQUENCE payload ([RFC 5280 §4.1.2](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2), [RFC 5280 §4.1.2.1](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.1), [RFC 5280 §4.1.2.5](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.5)).

### Reproduction

Decode `test/tls/server.crt` to DER. Its version wrapper starts at byte offset
8 (`a0 03 02 01 02`). Change byte offset 10 from `0x02` (INTEGER) to `0x04`
(OCTET STRING), preserving the length and value. The configured key, leaf
SPKI, and every later field remain byte-for-byte unchanged. Base64-wrap the
mutated DER as `CERTIFICATE` PEM and run:

```text
$ ./bin/linnea --test --config bad-version.json
$ echo $?
0

$ openssl x509 -in bad-version.crt -noout
Could not find certificate ... unsupported
```

`tbs_walk` sees `0xa0`, advances past its content without inspection, finds the
unchanged INTEGER serial and P-256 SPKI, and the key-pair sign/verify check
succeeds. Linnea will therefore frame and send a Certificate that conforming
X.509 decoders cannot parse.

The same defect class covers an empty or wrongly typed version value, an
out-of-range version INTEGER, and malformed contents of the SEQUENCE-tagged
TBS signature, issuer, validity, or subject fields. The reproduction changes
only the smallest nested field and demonstrates that the current tag-level
checks are insufficient.

### Impact

An operator can successfully run the documented preflight and reload with a
partially damaged certificate. Fresh TLS and QUIC handshakes then fail when
clients parse the Certificate message. The malformed input is local and the
private key is unchanged, so the effect is an availability failure rather than
an authentication bypass.

### Recommended fix

Continue the structural walk into each mandatory nested field:

- Require `[0]` to contain exactly one one-byte INTEGER value in `0..2`.
- Require the TBS signature AlgorithmIdentifier to be nonempty and fully
  consumed; require it to equal the outer signature AlgorithmIdentifier if
  this parser claims complete certificate syntax.
- Require issuer and subject to be fully consumable Name sequences.
- Require Validity to contain exactly two UTCTime or GeneralizedTime objects,
  each with a valid encoded time value.
- Require the selected SPKI to contain exactly AlgorithmIdentifier and BIT
  STRING children, with no trailing child.

The validator need not perform trust-path, hostname, expiration-policy, or
signature verification to reject malformed syntax. Add the retagged-version
fixture above plus empty/wrong-tag version, invalid validity child, malformed
Name, and extra-SPKI-child regression cases; retain valid v1/v2/v3 fixtures as
controls.

---

## Resolution (2026-08-27)

**CONFIRMED and FIXED.** Fast suite **1166/0**; three new claims (148 total).

The `[0]` wrapper was matched by tag and skipped unopened, so a `Version`
retagged as an OCTET STRING — or holding 9 — passed. It now requires exactly
one INTEGER of value 0..2 filling the wrapper. The other nested fields are
opened too: `signature`, `issuer` and `subject` must have children that tile
them exactly (a right tag over rubbish is not a field), and `Validity` must
hold exactly two UTCTime/GeneralizedTime values and nothing more.

### Scope taken, and not taken

Taken: version, the four TBS SEQUENCEs, Validity's two Times, and — from
report 101 — the leaf's declared curve. **Not taken:** requiring the TBS
signature AlgorithmIdentifier to equal the outer one, and parsing Name
structure beyond well-formedness. Those are real parts of the report's list.
They are omitted deliberately: this validator is a syntax preflight, and each
further rule is another way to refuse a certificate that every client would
accept. The line drawn is "malformed DER", not "unusual but legal".

### The control was harder than the fix

The version check has an ABSENT-wrapper path, because a v1 certificate omits
the field under DEFAULT v1 — and **nothing in the tree is v1**, so that branch
was exercised by nothing. Two attempts to generate one failed: OpenSSL 3.5 adds
extensions and produced v3 anyway, and my byte probe reported "no wrapper"
because I assumed offset 8 where it sits at 7 in that certificate. A real v1
was built by stripping the wrapper and re-encoding the lengths; OpenSSL
confirms `Version: 1`, and it loads.

Same shape as report 100's padding branches: **a fixture set that cannot reach
a branch makes a green suite meaningless for it.**

### And the same trap inside my own test code

My first version of the two rejection claims guarded on `_der[7] == 0xa0 and
_der[9] == 0x02` — the wrong offsets. The guard was false, **both claims
silently did not run**, and the file still printed "all claims hold". Only
counting PASS lines showed 146 where 148 were expected. That is the
guard-the-check-never-the-fixture trap this tree has recorded before: a skipped
check is indistinguishable from a passing one. The guard now SEARCHES for the
wrapper and, failing to find one, appends a failure and prints FAIL.
