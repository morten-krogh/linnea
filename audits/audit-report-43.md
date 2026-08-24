# Audit Report 43

Audited at `69f057e`, 2026-08-24.

Audit report 42's trailer-leak defect is fixed in the current tree: the first
response header block is preserved, later blocks are decoded only for HPACK
state, and trailer fields are not relayed. One related backend HTTP/2 protocol
gap remains:

1. **Low: a response trailer HEADERS block without END_STREAM is accepted, and
   later DATA can still complete and be relayed.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — malformed backend trailers are accepted without END_STREAM

Severity: **Low (P3, malformed-upstream acceptance and RFC conformance)**  
Confidence: **High**  
Status: **Confirmed as filed** (see Resolution). Fixed — together with a 1xx
regression that audit-report-42's fix introduced and this report's own
recommended fixture exposed.

HTTP/2 requires a response trailer section to be a later HEADERS block that
carries END_STREAM ([RFC 9113 §8.1](https://www.rfc-editor.org/rfc/rfc9113#section-8.1)).
The backend-H2 driver now recognizes a later completed header block as a
trailer, but it does not enforce that requirement.

In the production resumable driver, every completed HEADERS or CONTINUATION
block is decoded and then accepted. The code records the current HEADERS
frame's END_STREAM bit in `hdr_es`, but after trailer decoding it only checks
the bit to decide whether to finish; a zero value simply returns to the normal
receive loop
([src/server/linnea_h2_client.asm:2365](/home/linnea/linnea/src/server/linnea_h2_client.asm:2365)
through [:2418](/home/linnea/linnea/src/server/linnea_h2_client.asm:2418)).
There is no branch that rejects a completed later block when `hdr_es == 0`.

The next DATA frame is still accepted and appended to the response body
([src/server/linnea_h2_client.asm:2419](/home/linnea/linnea/src/server/linnea_h2_client.asm:2419)
through [:2449](/home/linnea/linnea/src/server/linnea_h2_client.asm:2449)). If
that DATA carries END_STREAM, the driver completes the exchange and the proxy
relays a 200 response and body despite the backend having sent an invalid
trailer section. If the backend sends no later DATA, the driver waits for a
stream terminator and eventually fails on the upstream timeout instead of
rejecting the malformed trailer at the point it is received.

The blocking/reference helper has the same behavior. Its trailer branches call
`h2c_decode_trailer`, then loop when `h2c_hdr_es` is zero rather than returning
an error
([src/server/linnea_h2_client.asm:1205](/home/linnea/linnea/src/server/linnea_h2_client.asm:1205)
through [:1222](/home/linnea/linnea/src/server/linnea_h2_client.asm:1222) and
[src/server/linnea_h2_client.asm:1234](/home/linnea/linnea/src/server/linnea_h2_client.asm:1234)
through [:1251](/home/linnea/linnea/src/server/linnea_h2_client.asm:1251)).
This leaves the test oracle and production driver consistent, but both accept
the malformed response.

### Reproduction

Have a `proxy_h2` backend send this sequence on stream 1:

```text
HEADERS  :status = 200, END_HEADERS
DATA     "body", no END_STREAM
HEADERS  x-checksum = abc, END_HEADERS, no END_STREAM   # malformed trailer
DATA     "more", END_STREAM
```

The current driver decodes and drops `x-checksum`, accepts the following DATA,
then completes from that DATA's END_STREAM. The frontend receives a successful
response containing `bodymore`; the malformed trailer section is never
reported. A legal response would put END_STREAM on the trailer HEADERS block
(on the first HEADERS frame when the trailer block is fragmented across
CONTINUATION frames) and would not send DATA afterward.

This is not a client-controlled cross-request disclosure: the backend leg is
single-stream and the body remains framed by HTTP/2 DATA lengths. It is still a
protocol-validation defect, and it conflicts with the project's stated policy
that malformed upstream responses are refused rather than relayed
([docs/security.md:24](/home/linnea/linnea/docs/security.md:24)
through [:30](/home/linnea/linnea/docs/security.md:30)). It can also turn a
backend protocol bug into a response that downstream clients believe was
properly completed.

### Recommended fix

When a later header block completes, require the END_STREAM bit captured from
its HEADERS frame. Return a stream failure if it is absent, before accepting
any following DATA. Preserve the same check in the blocking helper. The
fragmented-trailer case must inspect the END_STREAM bit on the initial HEADERS
frame, because CONTINUATION carries END_HEADERS but not END_STREAM.

Add a backend-fixture route that sends a trailer block without END_STREAM and
then a DATA frame with END_STREAM. Assert that H1, H2, and H3 frontend clients
receive a gateway failure, and that a subsequent independent request still
works. Keep the existing legal `/trailers` and `/trailers-frag` cases as
controls.

## Verification

The finding is a source-level trace through both the production resumable
driver and its blocking reference implementation. `make -j4` completed with
no work required. The current trailer fixture covers only legal trailer blocks
([test/h2/h2c_server.py:286](/home/linnea/linnea/test/h2/h2c_server.py:286)
through [:309](/home/linnea/linnea/test/h2/h2c_server.py:309)); it has no
no-END_STREAM backend case. Runtime socket reproduction was not available in
this restricted environment, and no source change was made that required
executable verification.

## Resolution (2026-08-24) — CONFIRMED as filed, and it was half the problem

### The finding reproduces exactly

On the audited binary (`69f057e`), the report's own frame sequence:

```
/trailers-noes   HEADERS :status=200, END_HEADERS
                 DATA "hello with trailers\n", no END_STREAM
                 HEADERS x-checksum: abc, END_HEADERS, NO END_STREAM
                 DATA "more", END_STREAM

HTTP/1.1 200 OK
content-length: 24
hello with trailers
more
```

The malformed trailer is accepted, the DATA after it is appended to the body,
and its END_STREAM completes the exchange. The client gets a 200 and a body the
backend never framed as one message. Confirmed on both the resumable driver and
the blocking oracle, and end to end through a `proxy_h2` front.

### The other half: audit-report-42's fix broke informational responses

The same fixture run that confirmed the above also showed this, which the report
does not mention:

```
/interim         HEADERS :status=103, link: </s.css>, END_HEADERS
                 HEADERS :status=200, content-type, content-length, END_HEADERS
                 DATA "final after interim\n", END_STREAM

at 69f057e:   H2C-FAIL  ->  502
at e514202:   HTTP/1.1 200 OK ... final after interim   (with the 103's `link:`
                                   leaked into the final response head)
```

RFC 9113 8.1 admits **three** kinds of completed header block, not two: zero or
more 1xx informational blocks, then the single final response, then optionally a
trailer section. Report 42's fix made "the first completed block is the response
and every later one is a trailer" the rule — so for a backend sending `103 Early
Hints` or `100 Continue`, the *real* response was classified as a trailer, its
`:status` tripped the new pseudo-header check, and the exchange failed outright.
A regression introduced one commit ago, found by writing the fixture this report
asked for.

Before that it "worked" by accident, the same accident report 42 documents: the
concatenated decode let the last `:status` win. It also relayed the 1xx block's
`link:` header as a field of the final response — the leak of report 42, from
the other direction.

### The fix

`h2c_decode_trailer` becomes `h2c_classify_block`, which decides what a
completed block **is** rather than counting how many came before it:

* a `:status` of 1xx → an informational response: dropped, and the driver keeps
  reading for the final head. It may not carry END_STREAM;
* no final head yet → this block is the response header section;
* a final head already in → a trailer section, which must carry **no
  pseudo-header** and **must carry END_STREAM** — the bit that makes it the end
  of the response rather than a stray header block. Absent, the exchange fails
  where the block is received, instead of the following DATA being appended and
  completing it.

Every block is still decoded whatever the verdict, because HPACK is stateful and
a block left undecoded desynchronizes the per-leg dynamic table permanently. The
status and header lines belonging to the response head are restored after any
block that turns out not to be it, so a dropped block leaves no trace. The
fragmented case reads the END_STREAM bit from the frame that OPENED the block,
as the report notes it must — CONTINUATION carries END_HEADERS, never
END_STREAM. The blocking oracle takes the same three-way verdict.

Informational responses are **dropped** rather than relayed: the driver
synthesizes one HTTP/1 head from a fully buffered response, so there is no
second head to relay. That is a v1 limitation, not a claim that 1xx is
meaningless — but silently dropping it is what a translating gateway may do,
where failing the exchange is not.

### Coverage

`test/h2/h2c_server.py` gains `/trailers-noes` (the report's sequence),
`/interim` and `/interim-two`. Five new checks in the tls shard, against a
binary built from the audited source:

```
pre-fix: a trailer with no END_STREAM is refused (h1 client)          FAIL
pre-fix: a trailer with no END_STREAM is refused (h2 client)          FAIL
pre-fix: a refused trailer leaves the next request working            FAIL  (200 then 200)
pre-fix: a 1xx block is dropped and the final response is served      FAIL
pre-fix: two informational blocks before the final response           FAIL
```

All five fail at `69f057e` and pass after. tls shard: **241 passed, 0 failed**. The legal `/trailers` and
`/trailers-frag` cases stay as controls, as the report asks, and the follow-up
request after a refused trailer is asserted so that refusing cannot wedge the
front.

### One unrelated failure in the full run

The full suite came back **826 passed, 1 failed**, and the failure is not this
work:

```
job 1 (h1): FAIL: the /api backend
  api: two pipelined GETs are both answered  the second was lost
```

`bin/linnea-api` is the demo API backend. It links four objects — none of them
the file this fix touches — and the binary predates this session; its source
last changed in `bf40a07`. Standalone, on a fresh port per run, it fails **2 in
8**: two pipelined GETs sent in one `sendall` are sometimes answered once. It
passed in the two full runs earlier in this series, which is consistent with an
intermittent, not with something introduced here.

So: a real, pre-existing, intermittent defect in a shipped binary
(`/usr/local/bin/linnea-api`, two instances live in production), surfaced by
this run rather than caused by it. It is left alone deliberately — it is not
this report's finding, and folding an unrelated backend fix into a trailer
commit would make both harder to review. It does mean the suite is not green on
`the /api backend` until it is dealt with.

## Verification (resolution)

Both behaviours were reproduced on a binary built from the audited source and
re-run after the change, on the resumable driver, on the blocking oracle, and
end to end through a real `proxy_h2` front from HTTP/1.1, HTTP/2 and HTTP/3
clients. The 1xx regression was confirmed as a regression by building
`e514202`'s driver and running the same fixture against it — it answers 200
there and fails at `69f057e`, which is what makes it this series' doing rather
than a pre-existing gap.
