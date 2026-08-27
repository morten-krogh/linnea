# Audit Report 83

Audited at `33e57e4` (`h3: a priority value that does not parse is ignored whole, and HTAB is OWS`), 2026-08-27.

Audit report 82's whole-value parse handling is present. The remaining priority parser gap is validation of Structured-Fields parameters:

1. **Low: malformed priority parameters are skipped after applying the member.**

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — malformed parameters can leave a partially applied priority

Severity: **Low (P3, malformed HTTP/3 priority input can still alter scheduling state)**  
Confidence: **Medium**  
Status: **Confirmed by source trace.**

RFC 8941 Structured Fields requires parameters following a member to use the parameter grammar; malformed parameter syntax makes the field value invalid. RFC 9218 permits a recipient to treat a priority parse failure as a connection error, but it must not treat malformed syntax as a valid complete signal ([RFC 8941 §3.2](https://www.rfc-editor.org/rfc/rfc8941.html#section-3.2), [RFC 9218 §7.2](https://www.rfc-editor.org/rfc/rfc9218.html#section-7.2)).

`linnea_quic_parse_priority` applies a recognized `u` or `i` member, then treats `;` as an unconditional boundary and skips the remainder without checking that a valid parameter name and value follow ([src/lib/linnea_quic.asm:2290](/home/linnea/linnea/src/lib/linnea_quic.asm:2290) through [src/lib/linnea_quic.asm:2348](/home/linnea/linnea/src/lib/linnea_quic.asm:2348)). Thus values such as `u=7;=`, `i;"`, or `u=7;bad space` can leave urgency/incremental state applied even though the complete Structured-Fields value is malformed.

### Reproduction

Send an in-limit request-stream `PRIORITY_UPDATE` with a value such as `u=7;=`. The parser records urgency 7 and returns success; a strict Structured-Fields parser would reject the value or ignore the entire update.

### Impact

This is a low-severity interoperability and parser-consistency issue. Different HTTP/3 implementations can derive different scheduling decisions from malformed control data, and malformed updates can consume pending-priority entries.

### Recommended fix

Either validate and skip Structured-Fields parameters syntactically, or treat any malformed parameter after a recognized member as a whole-value parse failure and restore the defaults before returning.


## Resolution (2026-08-27) — CONFIRMED, and it is the door audit-report-82 left open

### Reproduced

`linnea_quic_parse_priority` is a pure function, so the report's three examples
were measured on the audited binary rather than traced (urgency, incremental):

```
u=7;=           7 0     the urgency applied
i;"             3 1     the incremental applied
u=7;bad space   7 0
```

Two more of the same shape, which the report does not list, behaved the same
way:

```
u=7;            7 0     a ";" with no parameter behind it at all
u=7;;q=1        7 0     an empty parameter
```

### This is not a new class — it is the exemption I wrote

audit-report-82 established the rule (RFC 8941 4.2: "If parsing fails ... the
entire field value MUST be ignored") and implemented it for every way a member
can fail — except one. `.pp_after_value` treated `;` as an unconditional
boundary and sent the rest of the member to the skip-to-the-next-comma path,
with the comment "parameters: legal, and not ours to read". Legal they may be;
*present and well formed* is a different claim, and it was never checked. The
finding is the direct consequence, and it is fair.

### The fix

A parameter walk that follows the grammar it was previously assuming:
`*( ";" *SP parameter )` with `parameter = param-key [ "=" param-value ]` and
`param-key = key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." /
"*" )`. The key is validated; the value is a bare-item this parser never
interprets, so it is skipped to the next delimiter rather than typed. Ending a
parameter hands control back to the same `.pp_after_value` check as any other
member, so `;` now composes with the comma/OWS/end rule instead of bypassing it.

Falling out of that grammar is `.pp_fail` — the whole value, defaults restored —
exactly as for every other parse failure.

### What still is not validated, stated rather than discovered

A parameter's *value* is skipped, not typed: `;q=@` and `;q=?9` are not
rejected. An unknown member's value is likewise skipped. A comma or semicolon
inside a quoted string still reads as a delimiter. The function header now says
all three in one place. None of them can move scheduling — which is the only
thing the ignore-the-whole-value rule protects here — and a full Structured
Fields parser for two keys would be a larger and more fragile thing than the
problem deserves.

The MAY in RFC 9218 7.2 (a connection error on a parse failure) stays declined,
as in reports 81 and 82.

### Coverage

Thirteen new cases (26 assertions) in `test/quic/linnea_rtxtest.asm`. The
harness goes from **181/181 to 174/181** on a binary built from the audited
source: seven malformed forms fail, and every one of the twelve legal ones
passes on both sides.

The controls outnumber the failures, deliberately, because this fix's failure
mode is refusing parameters that are perfectly well formed — and there are more
legal shapes here than illegal ones worth testing:

```
u=5;q=1        u=5; q=1        u=5;q=1;r=2      u=5;*k=1
u=5;a;b        u=5;q="x"       i;q              u=5;q=1, i
```

`u=5;*k=1` and `u=5;q-1.a_b=2` are there because a key is not just lcalpha —
getting the key grammar too narrow is the easiest way to break this — and
`u=5;q="x"` because a value we do not interpret must still be skipped rather
than judged. `u=5;Q=1` is the other edge: 8941 keys are lowercase, so an
uppercase one is a failure, not an unknown parameter to ignore.

All cases from audit-reports 81 and 82 are unchanged, before and after.

`bin/linnea-rtxtest` **181/181** (174/181 on the audited source); full suite
**1184 passed, 0 failed**.

## Verification (resolution)

Measured, not traced: `linnea_quic_parse_priority` is a pure function, so each
value above is the pair it actually returned, on a binary built from the audited
source and again after the change. The report's three examples were run first —
they reproduce — and two more of the same shape were found by asking what else
the `;` exemption let through.
