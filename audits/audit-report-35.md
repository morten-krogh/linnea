# Audit Report 35

Audited at `b499ec1`, 2026-08-20.

**Fixed in `8d81001`.** The report is right, and it is right against a
reason I gave in report 32 for keeping the cap: that dropping a coding "can only
narrow what is served, never answer wrongly". A list member can be a
*prohibition*, so that is false. A second gap was found beside it and is **not**
fixed here — `identity;q=0` is never consulted at all — set out below for a
decision.

One representation-negotiation gap remains open:

1. **Medium: `Accept-Encoding` silently ignores the fourth and later field
   lines.** It is list-valued, so every accepted occurrence is part of the
   request’s combined coding preference.

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — Accept-Encoding is truncated after three field lines

Severity: **Medium (P2, representation and cache-integrity mismatch)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

The HTTP/1 collector has room for three spans and skips later occurrences:

```asm
    mov rcx, [rsp + 208]
    cmp rcx, 3
    jae .header_next
```

at [src/server/linnea_http.asm:1425](/home/linnea/linnea/src/server/linnea_http.asm:1425)
through [:1445](/home/linnea/linnea/src/server/linnea_http.asm:1445). The
comment explicitly says further lines are ignored.

HTTP/2 and HTTP/3 share the same three-span cap in the HPACK/QPACK collector:
[src/server/linnea_hpack.asm:985](/home/linnea/linnea/src/server/linnea_hpack.asm:985)
through [:1004](/home/linnea/linnea/src/server/linnea_hpack.asm:1004). Its
`.ae_full` branch treats the fourth occurrence as successful decoding rather
than a malformed/over-limit request.

`Accept-Encoding` is a list-valued field. Repeated field lines are equivalent
to a comma-joined list; the existing header-size limits already bound the total
request, so silently discarding a list member changes its semantics.

### Reproduction

For a resource that has a Brotli variant, send these legal combined preferences:

```text
Accept-Encoding: identity\r\n
Accept-Encoding: gzip\r\n
Accept-Encoding: deflate\r\n
Accept-Encoding: br\r\n
```

The combined value accepts `br`, but Linnea ignores the fourth line and serves
the non-Brotli representation. Moving `br` to one of the first three lines
changes the response, even though only field-line serialization changed.

### Impact

Representation selection and cache behavior depend on how a client or
intermediary splits a legal list. A cache that keys on the complete request
header can expect a compressed variant while Linnea serves plain content; a
client can also be given a representation it did not intend after a later
`identity;q=0` or coding preference is dropped. Agreement across H1/H2/H3 does
not make this correct: all three share the same truncation.

### Recommendation

Do not silently drop accepted occurrences. As with report 31’s ETag collectors,
either reject a fourth `Accept-Encoding` line explicitly (431 is consistent
with the existing bounded request collectors) or implement a complete bounded
header walk for negotiation. Apply the same policy across H1, H2, and H3.

Suggested tests:

* Put `br` and `identity;q=0` on each of lines 1 through 5 and require the same
  negotiated result for every legal split.
* Test a four-line request against resources with and without a Brotli variant.
* Assert a deliberate excess policy identically over HTTP/1, HTTP/2, and HTTP/3.

### Resolution — FIXED (2026-08-20)

Confirmed exactly as filed, on a file with a Brotli variant:

```
  br on line 1 of 4    br     br     br
  br on line 4 of 4    plain  plain  plain
```

Same legal request, different representation, decided by nothing but where the
client put the line break.

A fourth line is now **refused** — 431 on all three, the policy report 31 set
for the entity-tag lists — rather than dropped. The over-limit flag the ETag
collectors set is now shared and named for what it means: a list arrived with
more members than can be combined.

### The reasoning it corrects was mine

Report 32 fixed `Accept-Encoding` on h2/h3 and deliberately kept the cap, on
this argument:

> A fourth line is ignored rather than refused, unlike the entity-tag case:
> dropping a coding can only narrow what is served, never answer wrongly.

That is false, and the report says why in one clause: **a list member can be a
prohibition.** `identity;q=0` does not express a preference for something else,
it forbids the unencoded form — so dropping it turns a refusal into permission,
which is not narrowing. The distinction I drew between this field and the ETag
lists never existed.

### Found beside it, and now fixed too — `identity;q=0` was never consulted

The negotiator asks only "is `br` acceptable?" and "is `gzip` acceptable?". It
never asks whether *identity* is acceptable, so the prohibition is ignored
wherever it appears:

```
  Accept-Encoding: identity;q=0, file has a .br variant   -> 200, plain
  Accept-Encoding: identity;q=0, file has no variant      -> 200, plain
```

The client said it cannot accept the unencoded representation and was given it,
on all three protocols. RFC 9110 12.5.3 makes an unlisted coding unacceptable
and says the origin SHOULD answer **406** when no available representation is
acceptable — which is both rows, since `identity;q=0` names no coding it will
take.

Taken as a separate decision, since it changes what the *serving* path returns
rather than proxy hygiene and its failure mode is refusing a client that would
have been served. Now, on all three:

```
  identity;q=0        (a .br variant exists, br not offered)   406
  identity;q=0        (no variant at all)                      406
  identity;q=0, br    (a .br variant exists)                   200, br
  identity;q=0.5                                               200, plain
  no Accept-Encoding                                           200, plain
```

The third row is the one that keeps the rule honest: **refusing identity is not
refusing everything.** A client that excludes the unencoded form and names a
coding we hold gets that coding, and only a request with nothing left to send
becomes a 406.

`linnea_http_ae_accepts` had to learn a distinction it did not carry: it
returned "may I send this?", which is `0` both for a coding never mentioned and
for one mentioned with `q=0`. Those are **opposite** answers for identity —
absent, it is acceptable by default; named with `q=0`, it is forbidden. It now
returns "was it named at all" beside the verdict, and collapsing the two is
exactly why this went unnoticed.

`*;q=0` would also exclude identity and is deliberately still not handled, for
the reason the helper already gives for `*` generally: honouring it would mean
guessing which coding the client meant. That limit is written into the code
rather than left implied.

### Coverage

`test/tls/conditional_field_dups.py` gains five rows: three lines all honoured
(`br` still served) and a fourth refused; then `identity;q=0` as a 406, the same
with `br` still serving br, and `identity;q=0.5` still serving plain. Two fail on
a pre-fix binary — the fourth-line refusal and the 406 — and the three controls
pass before and after, which is what stops either rule from over-applying.

Full suite: **781 passed, 0 failed**.

## Verification

No executable tests were run: this report makes no source change. The finding
is traced from the identical three-span collectors and their silent excess
branches.

## Conclusion

Repeated Accept-Encoding fields are now combined only up to an undocumented
three-line boundary. The collector must either consider every accepted list
member or refuse the request once its supported representation is exhausted.
