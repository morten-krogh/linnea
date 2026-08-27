# Audit Report 82

Audited at `a4ed68d` (`h3: an invalid priority "i" member must be ignored, not read as true`), 2026-08-27.

Audit report 81's invalid-boolean handling is present. The remaining priority parser edge is invalid whitespace in Structured Fields values:

1. **Low: horizontal-tab separators are tolerated while applying later priority members.**

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — malformed tab-separated priority members are partially applied

Severity: **Low (P3, a malformed HTTP/3 priority signal can still change scheduling state)**  
Confidence: **Medium**  
Status: **Confirmed by source trace.**

RFC 8941 Structured Fields permits a space around list separators, but not an HTTP tab as a member separator. RFC 9218 uses that syntax for the `Priority` field and for HTTP/3 `PRIORITY_UPDATE` values; a malformed value may be rejected or ignored as a whole ([RFC 8941 §3.1](https://www.rfc-editor.org/rfc/rfc8941.html#section-3.1), [RFC 9218 §4](https://www.rfc-editor.org/rfc/rfc9218.html#section-4)).

`linnea_quic_parse_priority` skips only literal space and comma at the member boundary. It does not recognize tab as whitespace, but then continues scanning until the next comma; a later valid member is still parsed and applied ([src/lib/linnea_quic.asm:2177](/home/linnea/linnea/src/lib/linnea_quic.asm:2177) through [src/lib/linnea_quic.asm:2265](/home/linnea/linnea/src/lib/linnea_quic.asm:2265)). Thus a value such as `u=7\ti` is malformed as a single Structured Fields value, yet its `u=7` member is applied and the trailing `i` may be interpreted after the scanner advances.

### Reproduction

Send a valid control-stream `PRIORITY_UPDATE` whose priority field value is `u=7<TAB>i`. The parser accepts urgency 7 and may enable incremental scheduling, rather than treating the malformed field as ignored or returning the permitted HTTP/3 general protocol error.

### Impact

This is a low-severity parser-consistency issue. Different HTTP/3 implementations can derive different priority decisions from the same malformed control value, and malformed control traffic can still consume a pending-priority entry.

### Recommended fix

Treat HTAB and other disallowed control whitespace as a syntax failure for the complete priority value, or stop applying subsequent members once malformed syntax is detected. Preserve the current behavior for valid space-separated Structured Fields.


## Resolution (2026-08-27) — the finding's fact is FALSE and its RFC premise is BACKWARDS; a different, real defect sits underneath

### The reproduction does not reproduce

`linnea_quic_parse_priority` is a pure function, so the report's own example was
measured on the audited binary rather than argued (results are urgency,
incremental):

```
u=7<TAB>i    ->  3 0
```

The defaults. Not "accepts urgency 7 and may enable incremental scheduling".
The urgency branch already required its digits to end the member at end-of-value,
a comma, a space or a `;`, and a tab is none of those, so the member was dropped
— and with no comma anywhere, the trailing `i` was never reached either. The
finding's "Confidence: Medium" and its "may" were doing a lot of work; nothing
was run.

### And HTAB is not the syntax error the finding says it is

RFC 8941 3.2, verbatim:

```
sf-dictionary  = dict-member *( OWS "," OWS dict-member )
```

with 1.2: "It also includes the tchar and OWS rules from [RFC7230]" — and
RFC 7230's `OWS = *( SP / HTAB )`. So a tab beside a comma is **ordinary legal
whitespace**, not a syntax failure. The recommended fix — "treat HTAB and other
disallowed control whitespace as a syntax failure" — would have introduced a
bug: refusing values that are perfectly well formed.

Measured on the audited binary, that bug was already half present:

```
u=7<TAB>,i   ->  3 1     legal OWS before the comma; the u=7 was thrown away
u=7,<TAB>i   ->  7 0     legal OWS after the comma; the i was thrown away
```

### What IS wrong is the finding's other sentence

"Stop applying subsequent members once malformed syntax is detected" points at a
real rule, and understates it. RFC 8941 4.2:

> If parsing fails — including when calling another algorithm — the entire field
> value **MUST** be ignored (i.e., treated as if the field were not present in
> the section).

The entire value, not the subsequent members. Measured:

```
u=1,u=7x     ->  1 0     the u=1 survived a value that does not parse
u=1,i=?2     ->  1 0     likewise
u=1,u=       ->  1 0     likewise
u=7 i        ->  7 0     two members with no separator between them
```

The report's example could never show this, because there the failing member is
the FIRST one and there is nothing earlier to leak.

### Three rules that are not the same rule

The fix turns the scanner into a small dictionary walk that keeps them apart,
because conflating any two of them is how it was wrong in both directions at
once:

| input | rule | result |
|---|---|---|
| `u=1,zz=3` | 9218 4: an unknown member MUST be ignored | `u=1` stands |
| `u=1,u=9` | 8941: a repeated key takes the LAST value; 9218 4.1 then ignores the out-of-range one | the **default**, not the earlier 1 |
| `u=1,u=7x` | 8941 4.2: the value does not parse | the whole value ignored |

`u=1,u=9` is worth spelling out: the second member *replaced* the first, so
there is no earlier value to fall back to — the parsed dictionary is `{u:9}`,
and ignoring that 9 leaves the default. It used to answer 1.

Whitespace now follows the ABNF exactly, which means it is deliberately
asymmetric: OWS (SP **or HTAB**) beside a comma, and 4.2 step 2's leading *SP*
only at the value's edge. So `u=7<TAB>,i` and `u=7,<TAB>i` are both accepted in
full, while a leading tab still fails the value.

### What this is not

It is still a two-key scanner, not a Structured Fields parser: an unknown
member's value is skipped rather than validated, so a syntax error inside one
(`zz=?9`) goes undetected, and a comma inside a quoted string reads as a
separator. Both are now stated in the function's header rather than left to be
discovered. Neither can move scheduling, which is the only thing the
ignore-the-whole-value rule exists to protect here, and priority is advisory
(RFC 9218 2). A full sf parser for two keys would be a much larger and more
fragile thing than the problem deserves.

The MAY in 9218 7.2 — treating a parse failure as a connection error — is still
declined, as in audit-report-81. Ignoring the value is the other half of that
MAY and costs no interoperability.

### Coverage

Eleven new cases (22 assertions) in `test/quic/linnea_rtxtest.asm`, which
already exercised this parser and can assert the exact pair it returns. The
harness goes from **155/155 to 148/155** on a binary built from the audited
source.

Four of the eleven are controls, and they are the ones that matter, because this
fix fails by refusing legal values: `u=7<TAB>,i` and `u=7,<TAB>i` (HTAB beside a
comma must cost nothing), `" u=7"` (a leading SP is discarded), and `u=1,zz=3`
(an unknown member must still leave the rest alone). All thirteen cases from
audit-report-81 are unchanged, before and after.

`bin/linnea-rtxtest` **155/155** (148/155 on the audited source); full suite
**1184 passed, 0 failed**.

## Verification (resolution)

`linnea_quic_parse_priority` is a pure function, so every table above is a
direct measurement of the pair it returns for a given value, taken on a binary
built from the audited source and again after the change. The RFC quotations are
verbatim from RFC 8941 sections 1.2, 3.2 and 4.2. The finding's own example was
measured first, which is what showed the reproduction does not reproduce; the
defect that IS there was found by asking what its second sentence would mean if
taken seriously.
