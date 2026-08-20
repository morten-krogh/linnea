# Audit Report 36

Audited at `4185ddf`, 2026-08-20.

One content-coding negotiation gap remains open:

1. **Medium: wildcard `Accept-Encoding` values are ignored.** In particular,
   `*;q=0` is treated as permitting identity and produces 200 instead of 406.

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — Wildcard coding exclusions do not participate in negotiation

Severity: **Medium (P2, representation-negotiation mismatch)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

`linnea_http_ae_accepts` documents that it does not honor `*`:
[src/server/linnea_static.asm:465](/home/linnea/linnea/src/server/linnea_static.asm:465)
through [:477](/home/linnea/linnea/src/server/linnea_static.asm:477). It only
matches the concrete coding supplied by its caller (`br`, `gzip`, or
`identity`).

The identity fallback helper likewise checks only an explicitly named
`identity;q=0`. Its own comment states that `*;q=0` should exclude identity but
is deliberately unhandled at
[src/server/linnea_static.asm:646](/home/linnea/linnea/src/server/linnea_static.asm:646)
through [:657](/home/linnea/linnea/src/server/linnea_static.asm:657). The
static serving path consults this incomplete identity check immediately before
opening the plain representation at
[src/server/linnea_http.asm:2100](/home/linnea/linnea/src/server/linnea_http.asm:2100)
through [:2117](/home/linnea/linnea/src/server/linnea_http.asm:2117).

### Reproduction

Request a resource with a plain form and optional `.br`/`.gz` variants:

```text
GET /enc.txt HTTP/1.1\r\n
Host: one.test\r\n
Accept-Encoding: *;q=0\r\n
\r\n
```

The wildcard excludes all codings. With no explicitly permitted alternative,
there is no acceptable representation and the response must be `406 Not
Acceptable`. Linnea ignores the wildcard, finds neither a named `br` nor gzip
acceptance, does not see an explicit `identity;q=0`, and serves the unencoded
representation as `200`.

The opposite wildcard is also wrong for representation selection:
`Accept-Encoding: *` permits available content codings, but Linnea needlessly
falls back to identity because neither `br` nor gzip is named directly.

### Impact

Clients cannot reliably prohibit an unencoded response or use the standard
wildcard spelling to accept available codings. This breaks content-negotiation
contracts, can defeat bandwidth/privacy policies that depend on refusing a
representation, and creates cache variants that do not correspond to the
request’s complete `Accept-Encoding` semantics.

### Recommendation

Extend the coding matcher to apply wildcard entries when a concrete coding is
not named explicitly, including their q values. For identity, implement RFC
9110’s default rule: it is acceptable unless explicitly excluded by
`identity;q=0` or by `*;q=0` without a more specific identity allowance. Keep a
specific coding value authoritative over the wildcard.

Suggested tests:

* `*;q=0` returns 406 when no specifically allowed coding remains.
* `*` selects the server’s preferred available variant (Brotli before gzip).
* `*;q=0, identity;q=1` serves plain, while `*;q=0, br;q=1` serves Brotli.
* Run each case across H1/H2/H3 and with resources that have plain-only,
  gzip-only, and Brotli variants.

### Resolution — FIXED (2026-08-20)

Confirmed exactly as reported, on all three protocols, against a binary built
at `4185ddf`:

```
AE=*;q=0        /aetest.txt (plain+.br+.gz)   want 406      got 200/plain  h1 h2 h3
AE=*            /aetest.txt                   want 200/br   got 200/plain  h1 h2 h3
AE=*            /gztest.txt (plain+.gz)       want 200/gzip got 200/plain  h1 h2 h3
AE=br;q=0, *    /aetest.txt                   want 200/gzip got 200/plain  h1 h2 h3
```

RFC 9110 12.5.3 decides a coding in three steps, in order: an explicitly named
coding is governed by its own q; otherwise `*` governs; otherwise the coding is
unacceptable — except identity, which is acceptable by default. Only the first
and last steps existed, so `*` was read as though it were absent.

The fix puts all three steps in one place. A new `ae_verdict` answers **three**
ways for a token across the request's Accept-Encoding spans — named and allowed,
named but always refused, or never named — and two callers sit on top of it:

* `linnea_http_coding_ok` for br and gzip: named wins, else the wildcard, else no.
* `linnea_http_identity_refused` for the unencoded form: named wins, else the
  wildcard, else **yes** — the default that makes identity different from every
  other coding, and the reason the middle answer had to exist. Collapsing "never
  named" into "named with q=0" is the same collapse report 35 fixed one level
  down; here it would have made `*;q=0` and a bare `*` indistinguishable.

HTTP/1 had been walking the spans with its own copy of the loop while HTTP/2 and
HTTP/3 reached the rule through `linnea_static_open_enc`; that copy is deleted
and h1 now calls the shared helper, so there is one implementation of the rule
rather than a shared one plus an h1 duplicate that could drift from it.

### The reasoning it corrects was mine, again

One commit earlier, in report 35, I wrote that `*;q=0` was "deliberately
unhandled — for the reason the helper already gives for `*` generally, that
honouring it means guessing which coding the client meant," and called that
limit written down rather than left implied. Writing a limit down is not the
same as checking it is real, and this one was not:

* The guess it feared exists only for `*` as a **positive** selector. Even there
  it is not a guess: this server holds two variants and prefers br to gzip, and
  choosing among codings the client has called equally acceptable is precisely
  what a server is entitled to do.
* `*;q=0` is **negative** and needed no guess at all. It says every coding not
  named is unacceptable — a statement with one meaning.

So one sentence of reasoning, correct about a positive wildcard in a
hypothetical server with many variants, was applied to a negative wildcard in
this one. That is the second time in two reports that a rule of mine was too
broad for the case it excluded — the same shape as report 32's "a fourth line
can only narrow what is served", and worth the same suspicion next time: when a
rule is justified by what it *would* cost to honour, price it.

### Coverage

`test/tls/conditional_field_dups.py` gains 13 rows, each run over h1, h2 and h3.
The shard now also lays down `aetest.txt.gz` and a gzip-only `gztest.txt`,
because with br the only variant a wildcard row cannot tell "the wildcard chose
br" from "the wildcard was ignored and br was tried first".

Seven of the 13 fail on a pre-fix binary: `*` selecting br, `*` reaching gzip,
`*;q=0` as a 406 both with and without variants present, a named coding beating
the wildcard in both directions, and the two-line pair still refusing. The other
six pass before and after — an empty field value, a wildcard overridden by a
later line, `identity;q=0, *` where a coding remains — and are there to stop the
new rule over-applying, which is the failure mode a negotiation change has.

An eleven-row edge sweep beside them (multi-line wildcards, `q=0.001`, an empty
value, contradictory pairs) agreed on all three protocols with no disagreement
between them.

Full suite: **781 passed, 0 failed**.

## Verification

The finding as filed was traced from the code; it was then reproduced against a
running server on all three protocols before anything was changed, and the same
matrix re-run against the fixed build. The pre-fix control run is what makes the
new rows evidence rather than decoration.

## Conclusion

The recent `identity;q=0` fix handled one explicit exclusion and left the
general wildcard rule unimplemented. All three of RFC 9110 12.5.3's steps are
now in one helper that h1, h2 and h3 share, and the limit report 35 wrote down
is gone rather than merely documented.
