# Audit Report 24

Audited at `09ad923` (`audit-report-23: FIXED`), 2026-08-19.

**Fixed in `58cc9e4`**, verified against a pre-fix binary across the
whole 61-variant corpus. The report asks for one invariant to be chosen and
documented; the one chosen is stated under Resolution, and it is the rule this
tree already applies everywhere else: *a malformed body must never become a
clean, complete response.*

One protocol-direction gap remains open:

1. **Medium: HTTP/1 upstream chunked responses are relayed without grammar
   validation, while HTTP/2 and HTTP/3 decode and reject malformed chunks.**

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — HTTP/1 response relay does not apply the chunk grammar

Severity: **Medium (P2, cross-protocol response differential)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

The chunk grammar fixes are applied to the HTTP/1 request decoder and to the
captured HTTP/3 and HTTP/2 response decoders. The HTTP/1 response path is
different: it forwards the upstream response body after the headers have been
sent, preserving the upstream chunk framing rather than running it through a
chunk parser. The differential driver documents this boundary explicitly:
[test/chunkfuzz/variants.py:5](/home/linnea/linnea/test/chunkfuzz/variants.py:9)
says H1 “relays a chunked body byte for byte”, and
[test/chunkfuzz/drive.py:24](/home/linnea/linnea/test/chunkfuzz/drive.py:24)
through [:33](/home/linnea/linnea/test/chunkfuzz/drive.py:33) asserts malformed
results only for HTTP/2 and HTTP/3.

Consequently, an upstream response containing a malformed chunk extension such
as `4;=bad\r\nbody\r\n0\r\n\r\n`, an invalid trailer field, or a bad chunk-data CRLF is forwarded on
HTTP/1, while the same upstream bytes are rejected by the binary response
decoders after the fixes in `9036b39` and earlier reports.

### Impact

Clients observing the same upstream response through different protocol
listeners receive different validation and framing behavior. An intermediary
that relies on the proxy to normalize or reject malformed chunked responses can
instead receive the raw malformed stream on HTTP/1. If a downstream component
parses the forwarded bytes differently, this preserves a response-smuggling or
cache-poisoning differential across protocol versions.

### Recommendation

Choose and document one invariant for upstream chunked responses: either parse
and validate HTTP/1 chunked bodies before forwarding (using the same shared
chunk state machine), or explicitly dechunk and reframe them identically on all
protocols. Extend `test/chunkfuzz/drive.py` with an asserted HTTP/1 response
policy; malformed extensions, trailers, and data delimiters must not remain an
unasserted relay path.

### Resolution — FIXED (2026-08-19)

Confirmed, and wider than the three examples given. Driving all 61
`test/chunkfuzz/variants.py` cases at the HTTP/1 listener and asserting it the
way HTTP/2 and HTTP/3 are asserted:

```
=== 61 variants driven ===
malformed served as a clean 200, or valid rejected: 23
    ('size-trailing-sp',  'http1.1', '200', 4, 0)
    ('size-nonhex',       'http1.1', '200', 4, 0)
    ('ext-unterminated',  'http1.1', '200', 4, 0)
    ('data-lf-only',      'http1.1', '200', 4, 0)
    ('trailer-bad-name',  'http1.1', '200', 4, 0)
    ... 23 rows, every part of the grammar
```

Every one of those reached the client as a **clean, complete 200** carrying the
upstream's framing verbatim — `Transfer-Encoding: chunked`, then `4;=bad\r\n`,
then the body and the terminator — while the same upstream bytes were `502` on
both binary protocols.

### The invariant

Not "h1 must answer 502": it cannot, and the reason is real. h1 relays the body
as it streams and has already sent the head by the time a chunk line is read.
That is why the matrix exempted h1 from these rows, and the exemption was
honest about the constraint.

What the constraint never justified is **forwarding** the malformed framing.
The rule that already governs every other decoder here is the one that applies:

> A malformed chunked body must never become a clean, complete response.

So h1 keeps relaying verbatim — the upstream's framing is preserved rather than
rewritten — but it now decodes what it is about to forward, and the outcome
depends on *when* the malformation becomes readable rather than on which
protocol the client picked:

* **it arrives with the head** — the common case, since a backend writes head
  and body in one go — the head is still sitting unsent in `out_buf`, so h1
  answers **502**, exactly as h2 and h3 do;
* **it arrives in a later read** — the head is gone, so h1 declines to *finish*:
  the offending bytes are never forwarded and the connection closes, leaving
  the client a `200` whose chunked body has no terminator. An incomplete
  message, which is what it is.

### One decoder, two directions

The grammar is not transcribed a fourth time. `linnea_spill_chunked` — the
decoder h3's capture path already uses — gained two parameters:

* `rcx`, the decode state, so the state is the caller's rather than the
  connection's one hardcoded block. The connection now carries two: the request
  capture's and the response relay's, because a chunked upload and a chunked
  response can be in flight on the same connection.
* `r8d`, `LINNEA_CHUNK_CAPTURE` or `LINNEA_CHUNK_VALIDATE`. Validate mode judges
  and nothing else: no spill file, no `max_body` (that bounds a request — capping
  a relayed response here would have turned every download past `max_body` into
  a dropped connection), no pipelined-suffix stash.

Three `%if` blocks per block assert at assembly time that the connection's two
field runs still match `struc linnea_chunk`. The assertion was checked by
breaking the layout on purpose:

```
include/linnea_connection.inc:360: error: linnea_connection.chunk_* has drifted
```

### Found beside it — `body_rem == -1` can finally be told apart

`-1` has always meant two different things: *close-delimited*, where the close
IS the end, and *chunked*, where the terminal chunk is and the close is not.
The relay could not distinguish them, so a chunked response that stopped early
was recorded as a completed relay. It decodes now, so it can: a chunked body
that reaches EOF before `LINNEA_CHUNK_DONE` closes with `upstream chunked body
ended early` instead of finishing. The client sees the same FIN either way — a
chunked relay never keeps the connection alive — but the log stops calling a
truncated relay a complete one.

### Coverage

* `test/chunkfuzz/drive.py` now asserts **all three** protocols against the
  malformed rule, not h2 and h3 only, which is what the report recommends.
  Pre-fix that line reads `23`; after, `0`.
* `STREAMED_BODY` in `test/proxy_upstream_head.py` — h1's exemption from every
  chunk-framing row — **is now an empty set**. All three protocols answer `502`
  identically on `chunksizejunk`, `chunkextnul`, `chunktrailnocolon`,
  `chunkextunterm`, `chunkbig` and the rest. 271 matrix checks.
* `test/h1_chunk_relay.py` plus two split-write backend routes cover the other
  half — the malformation that arrives after the head. On a pre-fix binary it
  reports `relayed as a complete message: b'4;=bad\r\nbody\r\n0\r\n\r\n'`;
  after, `OK`. `/api/chunklategood` is its control: the same split write with a
  valid body must still be relayed whole.

Full suite: **770 passed, 0 failed**.

## Verification

No executable tests were run: this report makes no source change. The finding
is traced from the response-direction test boundary and the differing protocol
handling documented in the current source and fixtures.

## Conclusion

The chunk grammar is now shared across the HTTP/1 request decoders and binary
response decoders, but HTTP/1 upstream responses still bypass that grammar.
That leaves a protocol-version-dependent validation boundary for malformed
chunked responses.

They do not bypass it now, and the boundary is gone: the last direction that
had its own answer runs the same decoder as the rest. Worth recording is what
the exemption was: a true statement about what h1 *cannot* do — answer 502
mid-body — that had quietly come to license something else entirely, forwarding
the bytes. **An exemption states a constraint; it is not a permission, and the
gap between the two is where this defect lived for as long as the note
explaining it did.**
