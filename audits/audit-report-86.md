# Audit Report 86

Audited at `5b43731` (`h3: a priority parameter's value is a bare-item, so parse one`), 2026-08-27.

This is a broader pre-fix audit of the HTTP/3 priority parser. The recent fixes correctly handle truncated element IDs, stream-limit checks, whole-value parse failures, and bare-item parameter values. Two independent Structured Fields acceptance gaps remain:

1. **Low: duplicate parameter names are accepted.**
2. **Low: malformed unknown members are skipped instead of invalidating the value.**

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — duplicate parameters are not detected

Severity: **Low (P3, malformed priority input is accepted with implementation-dependent semantics)**  
Confidence: **High**

RFC 8941 requires parameter keys within a member to be unique. A repeated key makes the Structured Fields value invalid; RFC 9218 uses this grammar for HTTP priority values ([RFC 8941 §3.1](https://www.rfc-editor.org/rfc/rfc8941.html#section-3.1), [RFC 9218 §4](https://www.rfc-editor.org/rfc/rfc9218.html#section-4)).

The `.pp_params` scanner validates the shape and value of each parameter but keeps no set of names already seen ([src/lib/linnea_quic.asm:2388](/home/linnea/linnea/src/lib/linnea_quic.asm:2388) through [src/lib/linnea_quic.asm:2460](/home/linnea/linnea/src/lib/linnea_quic.asm:2460)). Values such as `u=7;foo=1;foo=2` and `u=7;foo=1;bar=2;foo=3` therefore return success and leave urgency 7 applied.

Reproduction: send an in-limit `PRIORITY_UPDATE` with `u=7;foo=1;foo=2`. The server acknowledges it and applies urgency 7 instead of treating the complete value as malformed or using the permitted HTTP/3 protocol error.

## Finding 2 — syntactically invalid unknown members are ignored

Severity: **Low (malformed control data can still carry a recognized priority decision)**  
Confidence: **Medium**

RFC 8941's dictionary grammar requires every member, including an unknown one, to be syntactically valid. RFC 9218 says unknown *priority parameters* are ignored, but that does not turn an invalid dictionary member into valid syntax ([RFC 8941 §4.2](https://www.rfc-editor.org/rfc/rfc8941.html#section-4.2), [RFC 9218 §4.1](https://www.rfc-editor.org/rfc/rfc9218.html#section-4.1)).

For an unknown key, the parser jumps to `.pp_adv`, which scans to the next comma without validating the member's `=` form or bare-item value ([src/lib/linnea_quic.asm:2230](/home/linnea/linnea/src/lib/linnea_quic.asm:2230) through [src/lib/linnea_quic.asm:2265](/home/linnea/linnea/src/lib/linnea_quic.asm:2265)). A value such as `u=7,unknown=\"unterminated` or `u=7,?bad` can therefore retain the already-applied urgency 7 and return success, even though the complete dictionary is not parseable.

Reproduction: send a `PRIORITY_UPDATE` value `u=7,unknown=\"unterminated`. The server accepts urgency 7 and continues; a strict parser would ignore the whole value (or use the permitted HTTP/3 error path).

## Combined impact

These are low-severity interoperability and parser-consistency issues rather than transport or memory-safety flaws. A malformed priority signal can nevertheless influence scheduling and consume one of the bounded pending-priority entries. Different HTTP/3 implementations may derive different priorities from the same malformed bytes.

## Recommended remediation

Maintain a bounded set of parameter keys for each member and fail the complete value on duplicates. Validate unknown members with the same member/value grammar as recognized members; only a syntactically valid unknown parameter should be ignored. Preserve the existing whole-value reset on parse failure.


## Resolution (2026-08-27) — Finding 1 REJECTED, Finding 2 CONFIRMED and fixed

### Finding 1 — rejected: a repeated parameter key is legal

RFC 8941 4.2.3.2 step 7, verbatim: "If parameters already contains a key
param_key (comparing character for character), **overwrite its value** with
param_value" — and 4.2.2 says the same for a repeated dictionary member. A
repeated key is not malformed; it is defined, last one winning, which is the
rule audit-report-82 already confirmed for `u=1,u=5`. Neither report points at
a uniqueness requirement because 8941 does not have one; both cite 3.1, the
Lists section.

Measured, and correct as it stands:

```
u=7;foo=1;foo=2         7 0
u=7;foo=1;bar=2;foo=3   7 0
```

The recommendation — "fail the complete value on duplicates" — would refuse
values a conforming sender may produce. Declined, and two rows are added as
controls so a later attempt to implement it fails a test.

This finding is also audit-report-85's only finding, rejected there identically.

### Finding 2 — confirmed, and it is the caveat audit-report-84 left

84's resolution named this one: "What remains is an unknown MEMBER's value,
which may be an inner list and brings its own grammar." The finding is right
that the reasoning does not hold — 9218 4 says to IGNORE an unknown member, and
8941 4.2 says the value it sits in must still PARSE. Two rules, and skipping to
the next comma honoured only the first. Measured:

```
u=7,unknown="unterminated   7 0     the urgency survived a value that fails
u=7,zz=1a                   7 0     ...and this one, which the report omits
u=7,zz=                     7 0
u=7,?bad                    3 0     already correct: "?" is not a key
```

`.pp_unk` now walks the member — key, optional `= member-value`, then the same
parameter walk and the same `.pp_after_value` check every other member gets.
The value reuses the bare-item parser from audit-report-84 rather than a second
copy of it.

**One construct is deliberately left unvalidated**, and it is the one the report
recommends validating: an unknown member whose value is an INNER LIST is still
skipped to the next comma. Each of an inner list's items carries its own
parameters, so checking one needs a nested walk that nothing here would use —
and the cost of getting it wrong is refusing `zz=(1 2)`, which is legal. Skipped
rather than refused keeps a legal inner list free; the function header now says
this is the single remaining gap, in place of the three it used to list.

### Coverage

Eleven cases (22 assertions) in `test/quic/linnea_rtxtest.asm`: **243/243**
after, **239/243** on the audited source — the four malformed unknown members.
Seven of the eleven are controls and pass on both sides: the two duplicate-key
rows above, plus a bare unknown member, one with parameters, one whose string
holds a comma, an inner list with parameters, and a value where the member
*after* an unknown one still applies (`u=7,zz=?1,i` → 7, incremental).

All cases from audit-reports 81 through 84 are unchanged, before and after.

## Verification (resolution)

Measured on a binary built from the audited source and again after the change;
the parser is a pure function, so each row is the pair it actually returned. The
RFC quotations are verbatim from RFC 8941 4.2.2 and 4.2.3.2.

The full suite has NOT been re-run for this pair — the change is confined to
this one function, the unit harness covers it exhaustively, and the suite is
queued for the next batch. `bin/linnea-rtxtest` 243/243.
