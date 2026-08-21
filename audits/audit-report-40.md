# Audit Report 40

Audited at `57e7c70`, 2026-08-21.

The previous upstream-capacity finding is fixed in the current tree. One
configuration-parser inconsistency remains:

1. **Low: a multi-backend `proxy` array accepts a trailing comma.** The parser
   documents and tests a strict JSON subset, but this one array silently
   accepts syntax rejected everywhere else.

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — `proxy: [ ... ]` accepts invalid trailing-comma syntax

Severity: **Low (P3, configuration grammar inconsistency)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

The parser states that its accepted grammar is JSON-like with comma-separated
members and no trailing-comma production
([src/server/linnea_config_parse.asm:1](/home/linnea/linnea/src/server/linnea_config_parse.asm:1)
through [:25](/home/linnea/linnea/src/server/linnea_config_parse.asm:25)). The
top-level `servers` array and each server's `locations` array enforce that
grammar: after consuming a comma they immediately parse another element, so a
closing bracket is rejected.

The multi-backend proxy parser differs. After parsing an element, it consumes a
comma and jumps back to `.proxy_elem`; that label treats `]` as a successful
end before requiring another element
([src/server/linnea_config_parse.asm:1228](/home/linnea/linnea/src/server/linnea_config_parse.asm:1228)
through [:1245](/home/linnea/linnea/src/server/linnea_config_parse.asm:1245)).
Consequently this invalid configuration is accepted:

```json
"proxy": ["127.0.0.1:8080",]
```

The same trailing comma in `servers` or `locations` is rejected. Existing
configuration tests explicitly assert that a top-level trailing comma fails
([test/configs/doc_claims_test.py:80](/home/linnea/linnea/test/configs/doc_claims_test.py:80)),
but have no equivalent multi-backend case.

This is not a request-path vulnerability: it requires local configuration
input and the resulting backend list is otherwise the intended one. It does,
however, make syntax validation depend on the selected location shape and can
let a generated or hand-edited invalid configuration pass `--test` while the
same comma is rejected in neighboring arrays.

### Recommended fix

After consuming the comma in `.proxy_elem`, require another element before
accepting `]` (or split the initial-empty check from the post-comma loop, as the
`servers` and `locations` parsers do). Add malformed cases for one and several
backends with a trailing comma, and retain the valid empty-array rejection.

## Resolution — FIXED (2026-08-21)

Confirmed exactly as filed. Before the fix, side by side:

```
"proxy": ["127.0.0.1:8080",]   accepted
"locations": [ {...}, ]        parse error: expected '{'
```

The loop consumed a comma and jumped back ABOVE the `]` test, so a closing
bracket after a comma read as a successful end rather than a missing element.

The `]` test now happens once, before any element — that is the empty list,
still refused with its own message — and past it a comma obliges another
element, the way `servers` and `locations` oblige another object. The diagnostic
matches theirs in shape: `expected '"'` against their `expected '{'`.

The count check at the end of the array went with it. With the empty case caught
up front it could no longer fire, and a guard that cannot fire looks like a
guard that passes.

### Coverage, stated honestly

Nine rows in `test/configs/doc_claims_test.py` — but only **two** fail on a
pre-fix binary, both trailing commas:

```
pre-fix, trailing comma                   ACCEPTED (bug)
pre-fix, trailing comma after several     ACCEPTED (bug)
pre-fix, leading comma                    rejected
pre-fix, doubled comma                    rejected
pre-fix, empty list                       rejected
```

The other three malformed rows were already rejected, and the four valid
spellings must keep parsing. They are controls, not new coverage — which is
worth saying, because "nine new rows" would overstate what this adds.

Full suite: **786 passed, 0 failed**.

## Verification (resolution)

Reproduced against the built binary before the change and re-run after, with a
pre-fix control that identifies precisely which rows the fix is responsible for.

## Verification (as filed)

`make -j4` completed successfully. This finding is a source trace; no runtime
server test was needed because it concerns config acceptance before the server
starts.
