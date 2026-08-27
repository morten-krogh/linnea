# Audit Report 84

Audited at `33e57e4` (`h3: a priority value that does not parse is ignored whole, and HTAB is OWS`), 2026-08-27 (with the uncommitted parameter-name hardening present in the working tree).

Audit report 83's parameter-key check is present in the working tree. The next residual parser gap is validation of parameter values:

1. **Low: arbitrary bytes in a priority parameter value are accepted as a valid bare item.**

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — malformed Structured-Fields parameter values are not rejected

Severity: **Low (P3, malformed HTTP/3 priority control input can still influence scheduling)**  
Confidence: **High**  
Status: **Confirmed by source trace.**

RFC 8941 §3.3 restricts a parameter's bare-item value to the Structured Fields bare-item grammar. Characters such as a quote, backslash, or control byte cannot occur arbitrarily in that value. RFC 9218 uses this syntax for HTTP priority values; a parse failure may be rejected or ignored as a whole ([RFC 8941 §3.3](https://www.rfc-editor.org/rfc/rfc8941.html#section-3.3), [RFC 9218 §4](https://www.rfc-editor.org/rfc/rfc9218.html#section-4)).

The working-tree parser validates the parameter key, but `.pp_par_vskip` advances until `;`, comma, or whitespace without checking the bytes it skips ([src/lib/linnea_quic.asm:2405](/home/linnea/linnea/src/lib/linnea_quic.asm:2405) through [src/lib/linnea_quic.asm:2422](/home/linnea/linnea/src/lib/linnea_quic.asm:2422)). Consequently, values such as `u=7;foo="unterminated` or `u=7;foo=\\` are accepted and urgency 7 remains applied, even though the parameter value is not a valid bare item.

### Reproduction

Send an in-limit HTTP/3 `PRIORITY_UPDATE` with priority value `u=7;foo="unterminated`. The parser applies urgency 7 and returns success. A strict Structured-Fields parser would treat the complete value as malformed and ignore it (or use the permitted HTTP/3 protocol error).

### Impact

This is a low-severity interoperability and parser-consistency issue. Different HTTP/3 implementations can derive different scheduling decisions from the same malformed control value.

### Recommended fix

Validate each parameter value against the RFC 8941 bare-item grammar (or reject unsupported parameter forms), and restore the whole-value defaults whenever validation fails.


## Resolution (2026-08-27) — CONFIRMED, and it also found a regression audit-report-83 introduced

### The report is right, and it is right about something I declined

audit-report-83's resolution named this exact gap as a deliberate limitation:
"a parameter's key is checked but its value is likewise skipped rather than
typed (`;q=@`)". The reason given was that none of the undetected cases "can
change scheduling". **That reason does not survive contact with this finding.**
An undetected syntax error means the value is applied where RFC 8941 4.2 says
the entire field MUST be ignored — which is a change in scheduling, and is
precisely the argument reports 82 and 83 made and I accepted twice. The
stopping point I claimed was self-serving; the rule does not have an exception
for the last sliver.

Measured on the audited binary (urgency, incremental):

```
u=7;foo="unterminated   7 0
u=7;foo=\               7 0
u=7;q=?2                7 0
u=7;q=1.                7 0
u=7;q=1a                7 0
```

### ...and the skip was refusing values that are perfectly legal

The finding looks only at what gets through. The same measurement in the other
direction is worse:

```
u=5;q="a b"    3 0    a string containing a SPACE -- rejected outright
u=5;q="a;b"    3 0    a string containing a semicolon -- likewise
```

An RFC 8941 string may hold a space, a comma or a semicolon; those are the very
characters `.pp_par_vskip` stopped at, so the value was torn in half and the
remainder failed the member check. Both of these worked before audit-report-83
— its `;`-skips-to-the-next-comma path swallowed them by luck — so that fix
traded a leak for a refusal. Its controls used `q="x"`, a string with no
interesting character in it, which is why nothing caught it.

**That is the lesson worth keeping from this one.** A control that exercises a
construct without exercising what makes the construct hard is not a control. The
new cases use strings containing a space, a comma, a semicolon and an escaped
quote.

### The fix

`.pp_par_val` now parses an RFC 8941 bare-item instead of skipping to a
delimiter — all six forms, each rejoining `.pp_after_value` with `rdi` one past
the item, or failing the whole value:

```
sf-string    DQUOTE *( unescaped / "\" ( DQUOTE / "\" ) ) DQUOTE
sf-integer   ["-"] 1*15DIGIT
sf-decimal   ["-"] 1*12DIGIT "." 1*3DIGIT
sf-token     ( ALPHA / "*" ) *( tchar / ":" / "/" )
sf-binary    ":" *( ALPHA / DIGIT / "+" / "/" / "=" ) ":"
sf-boolean   "?" ( "0" / "1" )
```

The two digit limits differ (15 for an integer, 12 before the point for a
decimal, 3 after) and both are enforced, as is the rule that a string's
unescaped characters are %x20-21 / %x23-5B / %x5D-7E — so a control byte inside
a string fails, and `\` escapes only `"` and itself.

Because a string is now parsed rather than scanned past, a comma or semicolon
inside one is no longer read as a delimiter. That was the last of the three
caveats in the function header; the remaining one is an unknown *member's*
value, which may be an inner list and brings its own grammar with parameters on
each element.

### Coverage

Twenty new cases (40 assertions) in `test/quic/linnea_rtxtest.asm`. The harness
goes from **221/221 to 210/221** on a binary built from the audited source: nine
malformed values leaked, and two legal ones were refused.

Half the cases are legal items — one of every form, plus the awkward corners:

```
"a b"   "a,b",i   "a;b"   "a\"b"   ""        strings, including the three
                                              characters the old skip stopped at
-0.5    123456789012345                       a negative decimal, and exactly
                                              the integer digit limit
a:b/c   :aGVsbG8=:   ::                       a token with ":" and "/", a byte
                                              sequence, and an empty one
```

and half are values that are not items at all, chosen to sit one character
outside each grammar rather than far away from it: 16 digits where 15 are
allowed, 13 before a decimal point where 12 are, four digits after one where
three are, `1.` and `.5`, `?2`, `1a`, a lone backslash, an unterminated string,
and a control byte inside a terminated one.

All cases from audit-reports 81, 82 and 83 are unchanged, before and after.

`bin/linnea-rtxtest` **221/221** (210/221 on the audited source); full suite
**1184 passed, 0 failed**.

## Verification (resolution)

Measured, not traced: the parser is a pure function, so each value above is the
pair it actually returned, on a binary built from the audited source and again
after the change. The report's five examples were run first and reproduce; the
two legal values it does not mention were found by asking what the same skip
does to a string that contains the characters it stops at.
