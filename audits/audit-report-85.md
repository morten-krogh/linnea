# Audit Report 85

Audited at `2f91708` (`h3: priority parameters have a grammar too, and it is now checked`), 2026-08-27.

Audit report 84's parameter-value grammar is present. The next Structured Fields edge is duplicate parameter names:

1. **Low: duplicate priority parameter keys are accepted.**

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — duplicate parameters are not rejected as a malformed value

Severity: **Low (P3, malformed HTTP/3 priority input is accepted with implementation-defined interpretation)**  
Confidence: **Medium**  
Status: **Confirmed by source trace.**

RFC 8941 §3.1 requires dictionary parameter keys to be unique within a member; repeating a parameter key makes the Structured Fields value invalid. RFC 9218 uses this grammar for priority values ([RFC 8941 §3.1](https://www.rfc-editor.org/rfc/rfc8941.html#section-3.1), [RFC 9218 §4](https://www.rfc-editor.org/rfc/rfc9218.html#section-4)).

The priority parser checks parameter-key characters and parses each parameter value, but it keeps no set of keys already seen. The `.pp_params` loop therefore accepts repeated keys such as `u=7;x=1;x=2` and `u=7;foo=1;foo=2` without triggering the whole-value parse-failure path ([src/lib/linnea_quic.asm:2388](/home/linnea/linnea/src/lib/linnea_quic.asm:2388) through [src/lib/linnea_quic.asm:2460](/home/linnea/linnea/src/lib/linnea_quic.asm:2460)).

### Reproduction

Send an in-limit HTTP/3 `PRIORITY_UPDATE` with value `u=7;foo=1;foo=2`. The server accepts the value and applies urgency 7; a strict Structured Fields parser treats the duplicate parameter key as malformed and ignores the complete priority value (or uses the permitted HTTP/3 protocol error).

### Impact

This is a low-severity interoperability issue. The priority signal is malformed, yet its recognized member still affects scheduling, and different implementations may disagree about whether to accept the update.

### Recommended fix

Track parameter keys while parsing a member and fail the complete value when a duplicate is encountered, restoring the default priority before returning.


## Resolution (2026-08-27) — REJECTED: a repeated parameter key is legal

RFC 8941 4.2.3.2, "Parsing Parameters", step 7, verbatim:

> If parameters already contains a key param_key (comparing character for
> character), **overwrite its value** with param_value.

And 4.2.2, for a repeated dictionary member:

> If dictionary already contains a key this_key (comparing character for
> character), overwrite its value with member.

A repeated key is not malformed in Structured Fields. It is *defined*, with the
last occurrence winning — the same rule audit-report-82 confirmed for
`u=1,u=5`, where linnea already answers 5. There is no uniqueness requirement in
8941 to violate; the finding cites 3.1, which is the Lists section and contains
no such rule.

Measured on the audited binary — and this is the correct answer, not a defect:

```
u=7;foo=1;foo=2         7 0
u=7;foo=1;bar=2;foo=3   7 0
u=7;x=1;x=2             7 0
```

Implementing the recommended fix — "fail the complete value on duplicates" —
would newly refuse values that every conforming sender may produce. That is the
same shape as audit-report-82's recommendation to treat HTAB as a syntax error,
and it is declined for the same reason.

Two rows are added to `test/quic/linnea_rtxtest.asm` as **controls against this
finding**, so that a later attempt to implement it fails a test rather than
shipping: `u=7;foo=1;foo=2` and `u=7;foo=1;bar=2;foo=3` must both keep urgency
7.

No production change. Its Finding 1 is repeated as audit-report-86's Finding 1
and is rejected there for the same reason; 86's Finding 2 is real and is fixed
in that report's resolution.
