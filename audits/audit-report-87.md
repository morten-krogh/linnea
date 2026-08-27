# Audit Report 87

Audited at `34f9b51` (`h3: an unknown priority member must parse; a repeated parameter key is legal`), 2026-08-27.

The recent parser fixes correctly handle malformed unknown members, parameter values, and repeated parameter keys. One remaining Structured Fields gap is intentionally documented in the implementation:

1. **Low: malformed unknown inner-list members are skipped without validation.**

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — an invalid inner list can preserve a preceding priority decision

Severity: **Low (P3, malformed HTTP/3 priority input can still affect scheduling)**  
Confidence: **High**  
Status: **Confirmed by source trace.**

RFC 8941 §3.1 defines an inner list as a structured value whose items and item parameters each have their own grammar. Even when an application ignores an unknown dictionary member, the member must still be syntactically parseable; RFC 8941 §4.2 requires the entire field value to be ignored when parsing fails ([RFC 8941 §3.1](https://www.rfc-editor.org/rfc/rfc8941.html#section-3.1), [RFC 8941 §4.2](https://www.rfc-editor.org/rfc/rfc8941.html#section-4.2)). RFC 9218 permits unknown priority parameters to be ignored, not malformed Structured Fields values to be partially applied ([RFC 9218 §4](https://www.rfc-editor.org/rfc/rfc9218.html#section-4)).

The unknown-member path recognizes an `=` followed by `(` and jumps directly to `.pp_adv`, which advances to the next comma without walking the inner-list items, closing parenthesis, or item parameters ([src/lib/linnea_quic.asm:2420](/home/linnea/linnea/src/lib/linnea_quic.asm:2420) through [src/lib/linnea_quic.asm:2450](/home/linnea/linnea/src/lib/linnea_quic.asm:2450)). The parser therefore deliberately accepts malformed inner lists, retaining any recognized members parsed before them.

### Reproduction

Send an in-limit HTTP/3 `PRIORITY_UPDATE` with value:

```text
u=7,zz=(1 "unterminated
```

The server applies urgency 7 and returns success. The unknown `zz` member is not valid because its inner list has no closing parenthesis and an unterminated string; a strict parser must ignore the complete value (or use the permitted HTTP/3 protocol error), leaving the default urgency.

A syntactically valid control case such as `u=7,zz=(1 2)` should continue to be accepted and should still apply urgency 7; only malformed inner-list syntax must reset the whole value.

### Impact

This is low severity because priority is advisory and the malformed member is unknown. It nevertheless creates parser differentials between HTTP/3 implementations and allows malformed control input to influence scheduling and consume a pending-priority entry.

### Recommended fix

Add a bounded inner-list validator for unknown members (including item and parameter grammar), or conservatively treat an unknown inner-list value as a whole-value parse failure. Preserve the current acceptance of valid inner lists so legal extension parameters remain interoperable.


## Resolution (2026-08-27) — CONFIRMED; the last skipped construct is now parsed

### Reproduced

The report's own case, measured on the audited binary (urgency, incremental):

```
u=7,zz=(1 "unterminated   7 0     the urgency survived a value that fails
u=7,zz=((1))              7 0     8941 has no list inside a list
u=7,zz=(1;a=?2)           7 0     an item parameter that is not a bare-item
u=7,zz=(1 2)              7 0     correct: a legal list costs nothing
```

The finding is accurate, including its insistence that the conservative option
— failing any inner list — is not acceptable, because `zz=(1 2)` is legal and
refusing it would be a worse defect than the one being fixed. That rules out the
cheap fix and leaves the real one.

### The fix

`inner-list = "(" *SP [ sf-item *( 1*SP sf-item ) *SP ] ")" parameters`, with
`sf-item = bare-item parameters`. The walk is small because the pieces already
existed: audit-report-84 built the bare-item parser and audit-report-83 the
parameter walk, and both are now shared rather than copied.

Sharing them needed one piece of state. A bare-item at member level continues to
`.pp_after_value`; the same bare-item *inside* a list belongs to the list and
must come back to it. `r11` says which, and `.pp_cont` / `.pp_cont_end` are the
two places that ask — the latter for "the input just ended", which finishes the
value at member level and means an unterminated list inside one. One flag is
enough because 8941 has no inner list inside an inner list, and a `(` reaching
the bare-item parser is rejected as a token, which is the right answer.

### What is left

Nothing, for parsing. Every part of the dictionary is now walked — both keys,
every member known or unknown, every parameter, every bare-item and an inner
list with parameters on its items and on itself — and a value that does not
parse is ignored whole. The header's caveat list, three entries in
audit-report-83 and one after 86, is now a statement of what the parser
deliberately does not do: *interpret*. An unknown member's meaning and every
parameter's are discarded once the syntax is checked, which is what RFC 9218 4
asks for.

### Coverage

Fourteen new cases (28 assertions) in `test/quic/linnea_rtxtest.asm`:
**271/271** after, **266/271** on the audited source. Five of the six malformed
lists leaked; the sixth, `zz=(1,2)`, already failed — the old skip-to-the-next-
comma landed *inside* the parens and tripped over `2)` as a member. Passing for
the wrong reason, and it is now checked for the right one.

Eight of the fourteen are controls, and they carry the risk, since this fix
fails by refusing a legal list:

```
(1 2)   ()   ( 1 2 )   (1  2)   (1;a=2 3)   ("a b" 2)   (1 2);p=3   (1 2),i
```

— a plain list, an empty one, padding inside the parens, more than one space
between items, an item carrying parameters, a string item containing a space,
parameters on the list itself, and a value where the member *after* the list
still applies.

All cases from audit-reports 81 through 86 are unchanged, before and after.
