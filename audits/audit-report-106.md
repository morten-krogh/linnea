# Audit Report 106

Audited `7daf85b` (`tls: tie the embedded public key to the scalar, and type [0] (report 105)`), 2026-08-28.

The report-105 remediation closes its two SEC1 optional-field findings. One PEM Base64 completion error remains:

1. **Low: an incomplete one-symbol final Base64 quantum is silently discarded at the END boundary.**

The malformed certificate passes the current `bin/linnea --test` but OpenSSL rejects it. This is a local credential-preflight and interoperability defect; the decoded DER, certificate identity, and key remain unchanged.

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — END boundary accepts an incomplete Base64 quantum

Severity: **Low (P3 malformed PEM acceptance)**

Confidence: **High**

Status: **Confirmed by source trace and executable reproduction; unfixed.**

The decoder maintains the number of unconsumed Base64 bits in `r9d` while it emits completed octets ([src/server/linnea_pem.asm:102](/home/linnea/linnea/src/server/linnea_pem.asm:102), [src/server/linnea_pem.asm:130](/home/linnea/linnea/src/server/linnea_pem.asm:130), [src/server/linnea_pem.asm:132](/home/linnea/linnea/src/server/linnea_pem.asm:132), [src/server/linnea_pem.asm:133](/home/linnea/linnea/src/server/linnea_pem.asm:133)). On detecting `-----END `, it immediately validates the boundary and returns `r10`, the emitted DER length ([src/server/linnea_pem.asm:109](/home/linnea/linnea/src/server/linnea_pem.asm:109), [src/server/linnea_pem.asm:111](/home/linnea/linnea/src/server/linnea_pem.asm:111), [src/server/linnea_pem.asm:203](/home/linnea/linnea/src/server/linnea_pem.asm:203), [src/server/linnea_pem.asm:227](/home/linnea/linnea/src/server/linnea_pem.asm:227), [src/server/linnea_pem.asm:228](/home/linnea/linnea/src/server/linnea_pem.asm:228)). It does not require `r9d == 0` or a valid padded final state on that path.

Appending one Base64 alphabet character to a complete unpadded body leaves six held bits and emits no byte. The decoder therefore returns the exact original DER and all later certificate/key checks pass, even though the PEM text is not a complete Base64 encoding.

RFC 4648 requires appropriate padding in the general Base64 case and describes Base64 output in four-symbol groups ([RFC 4648 §3.2](https://www.rfc-editor.org/rfc/rfc4648.html#section-3.2), [RFC 4648 §4](https://www.rfc-editor.org/rfc/rfc4648.html#section-4)). RFC 7468 in turn defines the encapsulated text between PEM boundaries as Base64 data ([RFC 7468 §2](https://www.rfc-editor.org/rfc/rfc7468.html#section-2)). A lone final symbol is neither a complete group nor a valid unpadded terminal quantum.

### Reproduction

Insert a line containing one `A` immediately before the END boundary of the otherwise valid `test/tls/server.crt`:

```text
-----BEGIN CERTIFICATE-----
... original Base64 body ...
A
-----END CERTIFICATE-----
```

```text
$ ./bin/linnea --test --config incomplete.json
$ echo $?
0

$ openssl x509 -in incomplete.crt -noout
Could not find certificate ... unsupported
```

The original fixture has a completed final quantum. Linnea absorbs the added `A`, holds its six bits, encounters the END boundary, and returns the original DER length; OpenSSL rejects the invalid Base64 text.

### Impact

The TLS server can still operate because the silently reconstructed DER is the original valid certificate. The problem is that `--test` approves a malformed renewal artifact that standard deployment tooling rejects, creating parser-dependent behavior and concealing accidental trailing Base64 characters. No remote input controls this file and no key material changes, so the severity is Low.

### Recommended fix

Before accepting the direct END-boundary path, require a completed final Base64 state: `r9d == 0` for an unpadded body, or reach END only through the existing verified padding path. Reject residual 2, 4, or 6 bits on the direct path. Add one-symbol, two-symbol, and three-symbol unpadded-tail tests, valid full-quantum control, and valid `=`/`==` padded controls for both certificate and key files.

---

## Resolution (2026-08-28)

**CONFIRMED and FIXED.** **Full suite 1193/0**; 159 claims (was 156).

An unpadded body must now end on a whole four-symbol group. The check is on the
DIRECT boundary path only — the padded path legitimately holds 2 or 4 bits and
was already validated when the `=` was consumed.

The report is precise about something worth restating: **+2 and +3 strays were
already rejected, but only because their extra emitted bytes corrupted the DER**
and a downstream structural check caught it. That is luck, not a check. Only
the +1 case — which emits no byte at all — showed that the quantum itself was
never validated.

### The fourth fall-through of this session, minutes after recording the third

`.at_dash` (the padded path) reaches `.end_boundary` by FALLING INTO it, and I
inserted `.end_unpadded` immediately above. Every padded credential was then
rejected: `bigchain.crt`, the `sni` pair, two of three generated pairs, the
hand-built v1 certificate, and two hand-built keys — nine valid files.

**Both of this report's own fixtures said "rejected" the whole time**, correct
before the fix and correct after, and blind to the damage in between. What
caught it was reading the ACCEPTANCE controls first — the rule recorded one
report earlier, applied here for the first time in the right order.

The count for the session is now four fall-throughs (`mark_unanswered`,
`.proxy_unix`, `.pk_params`, `.end_unpadded`), every one the same shape: a
labelled block inserted into a path that reached the following label by falling
into it. Knowing the trap has not been enough; the reliable defence has been
the acceptance controls, not the vigilance.
