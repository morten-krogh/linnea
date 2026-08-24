# Audit Report 42

Audited at `e514202`, 2026-08-24.

The previous report's filed pooling scenario remains resolved. One backend
HTTP/2 response-compatibility defect remains open:

1. **Medium: a valid response trailer block overwrites the initial `:status`,
   so `proxy_h2` returns 502 for responses that use HTTP/2 trailers.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — backend HTTP/2 trailers erase the response status

Severity: **Medium (P2, valid backend response becomes a gateway error)**  
Confidence: **High**  
Status: **Confirmed in substance, not in symptom** (see Resolution) — no 502
and no lost status for a legal trailer; the trailer fields are relayed as
response header fields instead. Fixed.

The resumable backend H2 driver correctly records the initial response
HEADERS block, but does not retain the distinction between that block and a
trailer section. It initializes the per-leg status, header-block state, and
`hdr_done` flag when a request starts
([src/server/linnea_h2_client.asm:1988](/home/linnea/linnea/src/server/linnea_h2_client.asm:1988)
through [:2009](/home/linnea/linnea/src/server/linnea_h2_client.asm:2009)). On
the first complete HEADERS block, `d_dispatch` decodes the block and marks
`hdr_done`
([src/server/linnea_h2_client.asm:2288](/home/linnea/linnea/src/server/linnea_h2_client.asm:2288)
through [:2322](/home/linnea/linnea/src/server/linnea_h2_client.asm:2322)).

That flag is never consulted on a later HEADERS or CONTINUATION block. The
same decode path runs again for every completed block
([src/server/linnea_h2_client.asm:2323](/home/linnea/linnea/src/server/linnea_h2_client.asm:2323)
through [:2341](/home/linnea/linnea/src/server/linnea_h2_client.asm:2341)).
`d_decode_block` clears the decoded status and synthesized header lines before
each decode, then copies the result back into the leg context
([src/server/linnea_h2_client.asm:1883](/home/linnea/linnea/src/server/linnea_h2_client.asm:1883)
through [:1908](/home/linnea/linnea/src/server/linnea_h2_client.asm:1908)).

Consider a valid single-stream response with this frame sequence:

```text
HEADERS  :status = 200, END_HEADERS
DATA     "hello", no END_STREAM
HEADERS  x-checksum = abc, END_HEADERS | END_STREAM
```

The final HEADERS block is a response trailer section. It has no `:status`, so
the second `d_decode_block` leaves `h2c_status` at zero and replaces the
initial response header lines with the trailer lines. The driver then marks
the response done from the trailer's END_STREAM
([src/server/linnea_h2_client.asm:2342](/home/linnea/linnea/src/server/linnea_h2_client.asm:2342)
through [:2375](/home/linnea/linnea/src/server/linnea_h2_client.asm:2375)).

When the proxy turns the completed driver context into its internal HTTP/1
response, it prints the overwritten status
([src/server/linnea_h2_client.asm:2484](/home/linnea/linnea/src/server/linnea_h2_client.asm:2484)
through [:2512](/home/linnea/linnea/src/server/linnea_h2_client.asm:2512)).
That produces `HTTP/1.1 000 Status` (and relays the trailer as though it were an
initial response field). `h2p_resp_begin` immediately reparses this generated
head
([src/server/linnea_http2.asm:4009](/home/linnea/linnea/src/server/linnea_http2.asm:4009)
through [:4026](/home/linnea/linnea/src/server/linnea_http2.asm:4026)); the
shared upstream-head validator rejects status codes below 100
([src/server/linnea_http.asm:3981](/home/linnea/linnea/src/server/linnea_http.asm:3981)
through [:3989](/home/linnea/linnea/src/server/linnea_http.asm:3989),
called by [src/server/linnea_http2.asm:4715](/home/linnea/linnea/src/server/linnea_http2.asm:4715)
through [:4723](/home/linnea/linnea/src/server/linnea_http2.asm:4723)). The
frontend therefore surfaces a 502 instead of the backend's 200 and body.

The older blocking H2 helper has the same repeated-decode shape: it decodes
both HEADERS and CONTINUATION completion without checking whether the initial
response headers have already been accepted
([src/server/linnea_h2_client.asm:1171](/home/linnea/linnea/src/server/linnea_h2_client.asm:1171)
through [:1222](/home/linnea/linnea/src/server/linnea_h2_client.asm:1222)). The
production proxy path uses the resumable driver, so the async path alone is
enough to make this a production defect.

This is not an invalid-backend corner case. HTTP/2 permits response trailers;
the trailer section is a later HEADERS block and, when it ends the stream,
carries END_STREAM. The existing backend fixture does not exercise it: it
sends one initial HEADERS block followed by DATA whose final frame itself has
END_STREAM
([test/h2/h2c_server.py:257](/home/linnea/linnea/test/h2/h2c_server.py:257)
through [:276](/home/linnea/linnea/test/h2/h2c_server.py:276)). Existing trailer
coverage is for trailers received from frontend HTTP/2 clients, not trailers
returned by a backend H2 server.

### Reproduction

Put an HTTP/2 backend behind a `proxy_h2` location and have it return a 200
response whose body DATA does not carry END_STREAM, followed by a trailer
HEADERS block such as `grpc-status: 0` with END_HEADERS | END_STREAM. Request
that resource through any supported frontend protocol. The expected result is
200 with the body; the current proxy synthesizes status 000, fails its
upstream-head validation, and returns 502.

### Recommended fix

Treat the first completed response header block as the only source of status
and relayed response headers. For later HEADERS/CONTINUATION blocks, continue
decoding into the per-leg HPACK table so compression state remains synchronized,
but do not overwrite the initial status or header buffer. Validate trailer
rules (including no pseudo-headers and END_STREAM on the trailer section), and
either explicitly discard trailers or implement a separate trailer-forwarding
policy.

Add a backend-fixture response with DATA followed by a trailing HEADERS block,
including a fragmented trailer block, and assert status and body through H1,
H2, and H3 frontend clients. Keep a no-trailer response as a control.

## Verification

The finding is a source-level protocol trace through the production resumable
backend-H2 driver, response synthesis, and shared upstream validation.
`make -j4` completed with no work required. The existing backend H2 fixture and
the current runtime test suite contain no backend-response-trailer case, and
runtime socket reproduction was not available in this restricted environment;
no source change was made that required executable verification.

## Resolution (2026-08-24) — the defect is real, the symptom is not: no 502, a silent trailer leak

### What actually happens

Reproduced on the audited binary (`e514202`) with a real HTTP/2 backend that
returns trailers, through a `proxy_h2` front, to an HTTP/1.1 client:

```
GET /trailers                 (200, DATA without END_STREAM, then a trailer
                               section: x-checksum: abc, grpc-status: 0)

HTTP/1.1 200 OK               <- NOT 502, and not status 000
content-type: text/plain
x-h2c-server: linnea-fixture
x-checksum: abc               <- the TRAILER, relayed as a response header field
grpc-status: 0                <- likewise
content-length: 20

hello with trailers           <- body intact
```

The status is not lost and no gateway error is produced. The finding's mechanism
misses one line: `ctx.hdrblk_len` is **never reset between blocks** (it is
cleared only at `linnea_h2c_drv_start`, and `d_hdrblk_append` only ever adds to
it). So the second `d_decode_block` does not decode the trailer — it decodes the
**concatenation** of the initial block and the trailer. Re-running the initial
block's bytes re-emits its `:status`, which is why the status survives as 200,
and re-emits its fields, which is why the trailer's fields land *after* them in
`hdrlines` rather than replacing them.

That is worse than the filed symptom in one way and better in another. Better:
a valid trailered response is not a gateway error, so no working backend is
broken today. Worse: it fails **silently**, and what leaks is attacker-adjacent
— a backend trailer becomes a response header field the client sees as part of
the header section. `grpc-status: 0`, a field whose whole meaning is "this is a
trailer", is delivered as a header.

The concatenation has two further consequences the report does not reach: every
block re-runs every block before it (quadratic, against a `hdrblk` with a fixed
cap that a third block can overrun), and each re-decode re-inserts the initial
block's incrementally-indexed fields into the per-leg HPACK dynamic table, so
the table diverges from the backend's copy of it.

### The one case that does lose the status needs an ILLEGAL trailer

```
GET /trailers-status          (trailer section containing :status = 500)
HTTP/1.1 500 Internal Server Error     <- the backend answered 200
```

A pseudo-header in a trailer is malformed (RFC 9113 8.1: trailers MUST NOT
contain pseudo-header fields). Decoded last in the concatenation, it overwrote
the status the initial block had set. So the status CAN be rewritten — by a
backend response that is already illegal, and in a direction the report did not
consider: not zeroed into a 502, but replaced with a status of the trailer's
choosing.

### The fix

`d_decode_block` now resets `ctx.hdrblk_len` after staging each block, so a
block is decoded once and alone, and it consults `ctx.hdr_done` to decide what
the block *is*. The first completed block is the response header section and is
the only source of `:status` and of relayed fields. Any later one is a trailer
section and goes to a new `h2c_decode_trailer`, which:

* decodes it, because HPACK is stateful and a block left undecoded
  desynchronizes the per-leg dynamic table for every block after it;
* then restores the status and header lines the initial block produced, so the
  trailer contributes neither — an intermediary may drop trailers, and this one
  does;
* fails the exchange if the trailer carried a pseudo-header (a new
  `h2c_saw_pseudo`, set by `h2c_emit` for any field name beginning with `:`),
  so the malformed case above is a 502 rather than a status of the backend's
  choosing.

The blocking helper (`h2c_run_response`) gets the same rule, keeping it a
faithful oracle for the driver — the harness exists to prove the two agree, so a
fix to one and not the other quietly retires it.

### Coverage

`test/h2/h2c_server.py` gains `/trailers` and `/trailers-frag` (the trailer split
across HEADERS + CONTINUATION, END_STREAM on the HEADERS frame and END_HEADERS
on the CONTINUATION), `/trailers-cl`, `/trailers-status`, and a **`tls` mode**:
the same server behind TLS 1.3 with ALPN `h2`, so it can stand where the linnea
backend cannot — `proxy_h2` requires `proxy_tls`, and a linnea backend cannot
produce a trailer section at all (its last DATA frame carries END_STREAM). It
sends NewSessionTickets too, so it is a second ticket-sending backend for free.

Six new checks in the tls shard, against a binary built from the audited source:

```
pre-fix: the python h2 fixture answers through proxy_h2 (control)         PASS
pre-fix: trailer NOT relayed as a header field (H1 client)                FAIL
pre-fix: trailer NOT relayed as a header field (H2 client)                FAIL
pre-fix: a trailer split across HEADERS + CONTINUATION, same              FAIL
pre-fix: a pseudo-header in a trailer is refused, not honoured            FAIL
pre-fix: trailer not relayed (h3 client)                                  FAIL
```

`test/shards/lib/common.sh` gains `P61724`/`P61725`.

Full suite: **822 passed, 0 failed** (816 before; the six are the difference).

Worth stating: the report's recommended test — "assert status and body through
H1, H2, and H3 frontend clients" — would have passed **before** the fix on both
counts it names. Status and body were always right; it is the header section
that was wrong. The assertion that finds this is the absence of the trailer
fields, so that is what the new checks assert.

## Verification (resolution)

Each behaviour was reproduced on a binary built from the audited source and
re-run after the change, at two levels: the driver alone (`bin/linnea-h2client`,
both the resumable driver and the blocking oracle, against the plaintext h2c
fixture) and end to end through a real `proxy_h2` front to a TLS+ALPN backend,
from HTTP/1.1, HTTP/2 and HTTP/3 clients. The pre-fix control identifies which
rows the fix is responsible for.
