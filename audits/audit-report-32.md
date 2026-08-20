# Audit Report 32

Audited at `e2b4596`, 2026-08-20.

**Fixed in `2d1d3d0`**, verified against a pre-fix binary on all three
protocols. A second field was found beside it and fixed too — `Accept-Encoding`,
which divides the *other* way: it is a list, and there h2 and h3 kept only the
last line while HTTP/1 combined them, so `Accept-Encoding: br` then
`Accept-Encoding: identity` served the compressed variant on one protocol and
the plain file on the others.

One cross-protocol conditional-field gap remains open:

1. **Medium: duplicate singleton conditional/range fields choose different
   values by protocol.** HTTP/1 keeps the first occurrence; HTTP/2 and HTTP/3
   overwrite it with the last.

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — Repeated singleton fields select first on H1 and last on H2/H3

Severity: **Medium (P2, cache and response-integrity differential)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

HTTP/1 treats `Range` and `If-Range` as “first occurrence wins” at
[src/server/linnea_http.asm:1361](/home/linnea/linnea/src/server/linnea_http.asm:1361)
through [:1376](/home/linnea/linnea/src/server/linnea_http.asm:1376). It does
the same for `If-Modified-Since` and `If-Unmodified-Since` at
[:1303](/home/linnea/linnea/src/server/linnea_http.asm:1303) through
[:1330](/home/linnea/linnea/src/server/linnea_http.asm:1330).

The HPACK/QPACK request collector instead overwrites the stored span on every
occurrence. For example, `If-Modified-Since` is assigned unconditionally at
[src/server/linnea_hpack.asm:841](/home/linnea/linnea/src/server/linnea_hpack.asm:841)
through [:854](/home/linnea/linnea/src/server/linnea_hpack.asm:854), and the
same last-occurrence assignment is used for `If-Unmodified-Since`, `Range`, and
`If-Range` at [:879](/home/linnea/linnea/src/server/linnea_hpack.asm:879)
through [:917](/home/linnea/linnea/src/server/linnea_hpack.asm:917).

These fields each define one date, validator, or range specification—not a
combined list of independent field values. Multiple occurrences must not be
silently made meaningful by picking an arbitrary endpoint; at minimum, all
protocols need one explicit and identical rejection/ignore policy.

### Reproduction

For a resource whose modification time lies between the two dates, send:

```text
If-Modified-Since: Wed, 01 Jan 2020 00:00:00 GMT\r\n
If-Modified-Since: Wed, 01 Jan 2100 00:00:00 GMT\r\n
```

HTTP/1 evaluates the first date and returns `200`; HTTP/2 and HTTP/3 evaluate
the second and return `304`. Reversing the lines reverses the answers.

Likewise, two `Range` lines such as `bytes=0-0` and `bytes=10-10` select
different `206` slices depending on the downstream protocol. A mismatching
then matching `If-Range` pair determines whether the response is a full `200`
or a partial `206` by the same first-versus-last accident.

### Impact

One request can expose different cache-validation decisions and representation
bytes over H1, H2, and H3. An intermediary that normalizes, rejects, or selects
one occurrence can disagree with Linnea about whether a cached object is fresh
or which range is authorized. This is especially troublesome for range caches
and conditional-update workflows, where correct field interpretation is part of
the response integrity boundary.

### Recommendation

Track duplicate occurrences for these singleton fields in every request
collector and apply one policy before routing. Rejecting duplicate occurrences
with a client error is the clearest choice; alternatively, ignore the field
entirely, but do so identically on all protocols. Do not retain a first or last
value without recording the duplicate.

Suggested tests:

* Opposed past/future `If-Modified-Since` and `If-Unmodified-Since` pairs in
  both orders must have one identical result on H1/H2/H3.
* Two distinct Range values and mismatching/matching If-Range values must not
  select a protocol-dependent slice.
* Keep the corresponding single-field requests as 200/304/412/206 controls.

### Resolution — FIXED (2026-08-20)

Confirmed exactly as filed, including the second half of the reproduction that
the report reasons about rather than shows — which slice a doubled `Range`
returns:

```
  If-Modified-Since: past, then future     h1 200   h2 304   h3 304
  If-Modified-Since: future, then past     h1 304   h2 200   h3 200
  Range: bytes=0-0, then bytes=10-10       h1 serves byte 0 ("h")
                                           h2 and h3 serve byte 10 (" ")
```

Same request, three listeners, different representation bytes.

These four fields each define one date, validator or range. Two of them are a
request that says two different things, and picking an endpoint resolves a
contradiction the client created — silently, and in opposite directions per
protocol. All three now refuse a repeat, which is what `Host` and
`Content-Length` have always done and for the reason already written at the
duplicate-`Content-Length` check: *"two lengths cannot both equal the body
whether or not they agree with each other"*.

The refusal takes each protocol's own shape, deliberately and by precedent:
`400` on HTTP/1, a stream error on HTTP/2 and HTTP/3, exactly as a duplicate
`Content-Length` is handled there today (RFC 9113 8.1.1 makes a malformed
request a stream error). Giving these four a *different* shape from the
duplicate-`Content-Length` beside them would have been a worse inconsistency
than the one between protocols.

### Found beside it — Accept-Encoding, and the irony is instructive

The collector that overwrites these four sits three fields away from
`accept-encoding`, which overwrites too. That one is **list**-valued, so the
correct treatment is the opposite — combine, do not choose:

```
  Accept-Encoding: br
  Accept-Encoding: identity        h1 -> .br served    h2, h3 -> plain file
```

HTTP/1 has recorded one span per line since h1-14. HTTP/2 and HTTP/3 never did,
**on the very field whose treatment report 30 cited as the precedent for fixing
the entity-tag lists**. `linnea_static_open_enc` now takes a span array and asks
each line in turn, so a coding is served when any line accepts it. A fourth line
is ignored rather than refused, unlike the entity-tag case: dropping a coding
can only narrow what is served, never answer wrongly — and that is HTTP/1's
existing behaviour, which there was no reason to change.

### Coverage

`test/tls/conditional_field_dups.py` drives sixteen rows across h1, h2 and h3:
each singleton repeated in both orders, one of each still working so the rule
cannot become "refuse the field", and the Accept-Encoding combinations. Nine
fail on a pre-fix binary.

Full suite: **780 passed, 0 failed**.

## Verification

No executable tests were run: this report makes no source change. The finding
is a source trace of the H1 first-value guards and the H2/H3 overwrite paths.

## Conclusion

The ETag collectors now agree across protocols, but the adjacent singleton
conditional fields still have opposite duplicate policies. Making duplicates
explicit restores one HTTP semantics surface across all listeners.

Five reports have now come from one collector loop, and the reason they arrived
one field at a time is that each fix was made to the field that was reported.
The h1 and h2/h3 collectors are lists of per-field cases, and **whether a field
is a list or a singleton is a property of the field, not of the protocol** —
yet it was decided independently in each collector, and the two disagreed on
every field either had an opinion about. Both collectors are now consistent for
every field they name; what would prevent a sixth report is not another fix but
a way to state that property once.
