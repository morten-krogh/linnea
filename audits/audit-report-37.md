# Audit Report 37

Audited at `b2173c1`, 2026-08-20.

## Review result

Audit-report-36 is fixed in `2c342c6`. Content-coding selection now evaluates a
specific coding first, then the wildcard, then the identity default. The same
shared helpers are used by HTTP/1, HTTP/2, and HTTP/3, so wildcard handling is
not a protocol-specific copy.

I found no additional source-verifiable defect in the reviewed
`Accept-Encoding` negotiation path. In particular:

* `*;q=0` excludes identity when no explicit identity allowance exists.
* An explicit coding overrides the wildcard in either direction.
* A positive wildcard permits the server’s existing Brotli-then-gzip preference.
* Fourth list lines are refused rather than silently ignored.

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Suggested ongoing coverage

Keep a compact cross-protocol matrix for these boundary cases:

* `br;q=0, *;q=1` — gzip may be selected, Brotli may not.
* `*;q=0, identity;q=1` — plain is permitted.
* `*;q=0, br;q=1` — Brotli is permitted while gzip and identity are not.
* A fourth Accept-Encoding field line — explicit 431 on H1/H2/H3.

## Resolution — CONFIRMED, with two coverage gaps and one defect beside it (2026-08-20)

The review's conclusion holds: re-running the cross-protocol matrix against the
current binary reproduces all four properties it lists, and each is backed by a
row that fails on a pre-fix binary.

### The suggested coverage was not all covered — and one row could not fail

Three of the four suggested cases were already in
`test/tls/conditional_field_dups.py`. Checking the fourth is what mattered:

* **`*;q=0, br;q=1` — "Brotli is permitted while gzip and identity are not."**
  Only the first half was asserted. The row runs against the resource holding
  both variants, where br wins on this server's preference anyway — so it
  answers `200/br` whether or not the wildcard excludes gzip and identity, which
  is also what a build that ignores the wildcard answers. **A control wearing a
  test's clothes.** The same request against a gzip-only resource has nowhere to
  go and must be 406; that row fails pre-fix at `200/plain`, and is now in.
* **`br;q=0, *;q=1`** was covered only as `br;q=0, *`. Added in the spelling the
  report names, which is the one a client is likelier to write.
* `*;q=0, identity;q=1` is inherently a control: with identity named and allowed
  and no coding named, no resource makes the wildcard change the answer. Kept,
  and now labelled as a control so it is not read as evidence it cannot give.

### Found beside it — the 406 did not say it varies

A response selected by Accept-Encoding needs `Vary: Accept-Encoding`, or a
shared cache stores it under the bare URL and serves it to a client that sent a
different one. Measured on the current binary, over all three protocols:

```
200  Vary: Accept-Encoding      206  Vary: Accept-Encoding
304  Vary: Accept-Encoding      404  Vary: Accept-Encoding   (static path)
406  — absent —
```

The 406 is **the one status that exists only because of Accept-Encoding**, and
it was the only one missing the header. It is mine: I added the status in
`4185ddf` and did not re-ask a question the code around it had already answered.
`resp_404_vary` sits three lines above `resp_406` in the same file. Both binary
protocols already gate the header on a status number — h3's gate even carries a
comment enumerating the statuses that do *not* depend on Accept-Encoding, a list
that went stale the moment a new status did. All three now emit it for 406;
unconditionally, since unlike the 404 a 406 is never reached except by
negotiation.

**Severity: low, and worth saying plainly.** 406 is not in RFC 9110 15.5's
heuristically-cacheable list, and linnea's canned 406 carries no explicit
freshness information, so no conforming cache stores it today. The fix closes a
trap rather than an open hole: it costs one status test, and it means a later
change that gives canned errors a `Cache-Control` cannot quietly turn this into
a real one.

### Coverage

Six new rows over h1, h2 and h3: the two negotiation rows above, and four
asserting Vary — on the 406 in both its spellings (`identity;q=0` and `*;q=0`),
and on the negotiated 200 and the static 404, so the rule is pinned for the
whole set rather than only where it was found broken. Four of the six fail on a
pre-fix binary; the 200 and 404 pass both ways as controls. The Vary value is
compared case-insensitively: h1 and h2 send the literal `Accept-Encoding` while
h3 sends QPACK static entry 59, whose built-in value is lowercase, and freezing
that cosmetic difference into a requirement would be wrong.

Full suite: **781 passed, 0 failed**.

## Verification (resolution)

The four properties were re-measured rather than read. The Vary gap was found by
asking what the *other* responses on this path do, then measuring 200/206/304/
404/406 side by side on all three protocols — not by reading the negotiation
code again, which is where the report had already looked.

## Verification (as filed)

No executable tests were run: this report makes no source change. The review
traced `ae_verdict`, `linnea_http_coding_ok`, and
`linnea_http_identity_refused` in the current shared static-serving code.

## Conclusion

The wildcard negotiation defect is closed, and the review is correct that the
coding-selection logic itself holds no further defect. Acting on its coverage
suggestions found one assertion that could not fail, and looking one step
outward — at what the negotiated response says about itself rather than at how
it was chosen — found the 406 missing Vary.
