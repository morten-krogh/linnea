# Audit Report 31

Audited at `ee1c900`, 2026-08-20.

**Fixed in `41fe213`.** The cap was mine, from report 30, and documented
there as conservative — which it was, and which is not the same as correct. A
legal list member is now refused rather than dropped: **431 on all three
protocols**, decided before routing.

One conditional-request gap remains open:

1. **Medium: entity-tag lists are silently truncated after three field lines.**
   A valid matching tag on the fourth or later `If-Match`/`If-None-Match` line
   is ignored on all three protocols.

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — The new ETag collectors discard legal list members

Severity: **Medium (P2, cache and precondition integrity)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

The report-30 collectors preserve three spans and silently skip every later
field line. HTTP/1 does so for `If-Match` at
[src/server/linnea_http.asm:1291](/home/linnea/linnea/src/server/linnea_http.asm:1291)
through [:1302](/home/linnea/linnea/src/server/linnea_http.asm:1302), and for
`If-None-Match` at [:1311](/home/linnea/linnea/src/server/linnea_http.asm:1311)
through [:1323](/home/linnea/linnea/src/server/linnea_http.asm:1323):

```asm
    mov rcx, [rsp + 176]
    cmp rcx, 3
    jae .header_next
```

The shared HTTP/2/HTTP/3 collector has the same cap for both fields at
[src/server/linnea_hpack.asm:826](/home/linnea/linnea/src/server/linnea_hpack.asm:826)
through [:870](/home/linnea/linnea/src/server/linnea_hpack.asm:870). Its layout
comment explicitly confirms that later lines are ignored:
[include/linnea_hpack.inc:97](/home/linnea/linnea/include/linnea_hpack.inc:97)
through [:99](/home/linnea/linnea/include/linnea_hpack.inc:99).

Repeated field lines form one combined entity-tag list; no three-line limit is
part of that grammar. The existing header-size limits already bound total input,
so a fixed three-line collector changes semantics rather than providing an
essential safety bound.

### Reproduction

For a representation with ETag `"E"`, send:

```text
If-None-Match: "miss-1"\r\n
If-None-Match: "miss-2"\r\n
If-None-Match: "miss-3"\r\n
If-None-Match: "E"\r\n
```

The combined list matches and must result in `304 Not Modified`. Linnea stores
only the first three misses and returns `200`. With `If-Match`, placing `"E"`
on the fourth line must permit the request but instead yields `412`.

### Impact

The result of a conditional request depends on arbitrary field-line splitting,
not just list content. Caches can be forced to receive a full representation
despite a matching validator, and a valid optimistic-concurrency precondition
can be rejected. Because the same cap exists on H1, H2, and H3, current
cross-protocol agreement masks the standards violation.

### Recommendation

Do not silently discard field occurrences. Either reject an excess count with
a clear client error, or—preferably—walk the complete bounded header block when
evaluating the ETag list so every legal member participates without requiring a
larger per-request span array. Apply the same policy consistently across all
three protocols.

Suggested tests:

* Put the matching tag on lines 1 through 5 for both fields, expecting the same
  304/200 and pass/412 results each time.
* Use a matching tag after several long but legal field values to exercise the
  normal header-size boundary.
* Assert the same result over HTTP/1, HTTP/2, and HTTP/3.

### Resolution — FIXED (2026-08-20)

Confirmed. The cap came from report 30's own fix, where I wrote that a fourth
line "can only cost a 304 or earn a 412, never serve a stale representation".
That is true and it is not a defence: a 412 on a request that must pass is a
wrong answer, and it is given silently.

Of the two remedies the report offers, the second — walk the complete header
block — is available on HTTP/1 alone. **Neither binary protocol can re-walk a
decoded field section**: the HPACK and QPACK dynamic tables have moved on by
then, and re-decoding is not a read-only operation. Taking it on h1 only would
have reintroduced exactly what report 30 closed, the three protocols answering
one request differently, so the policy is set by the two that cannot walk:

```
                     1 line   3 lines   4 lines   6 lines
  http/1.1             304      304       431       431
  http/2               304      304       431       431
  http/3               304      304       431       431
```

Three spans still hold every list any real client sends; a fourth is **refused,
not shortened**. On h1 the refusal happens in the header parse, on h2 and h3 a
flag on the request is read at the top of the serve path — before routing, so a
proxy location cannot forward a list with a member missing either.

### Why the h2 refusal is not the decoder's own limit exit

The first attempt sent the fourth occurrence to `.ef_limit`, the decoder's
existing resource-limit error. It is the wrong exit here and h2 said so
immediately: the request came back as a killed connection rather than a status,
because a decode that stops mid-block leaves our dynamic table behind the
peer's, and ending the connection is the only safe answer to that. The block is
now decoded in full — the table stays in sync — and only the *answer* changes.
**The limit that was hit is ours, not the peer's, and it must not be reported
through a path that assumes the message is unreadable.**

### And a fall-through, again

Rewriting the collector's tail left `inc` falling straight into the new
too-many label, so **every** request with an entity-tag list was refused —
including the three-line case that had just been made to work:

```
  curl --http2   3 lines -> 000      (the connection, killed)
  curl --http3   3 lines -> 431
```

Caught on the first run because the table above is driven at every count rather
than only at the boundary. `A moved block leaves a fall-through` is a note this
tree already carries; it is worth adding that **a boundary test that only tries
the boundary cannot see it.**

### Coverage

`test/tls/etag_list_lines.py` grows from nine rows to twelve, driven across all
three protocols at one, three, four and six lines. Against the build before
report 30 it reports **8 failures**; against report 30's own build the three new
rows fail alone.

Full suite: **779 passed, 0 failed**.

## Verification

No executable tests were run: this report makes no source change. The finding
is traced from the shared three-span cap and the HTTP/1 equivalent.

## Conclusion

Report 30 fixed first-versus-last disagreement, but only for the first three
lines. Conditional ETag handling must account for every accepted list member
or reject the request explicitly.

It rejects explicitly now. The lesson is about the previous fix rather than the
code: I wrote the limitation down, in the commit and in the report, and treated
having documented it as having justified it. **A caveat recorded honestly is
still a defect if the behaviour it describes is wrong** — the note tells the
next reader where to look, which is what happened here, and that is its whole
value.
