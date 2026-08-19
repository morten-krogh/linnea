# Linnea server audit report 7

Date: 2026-08-18  
Audit baseline: commit `c3435ef` (`certbot: serve the shorter chain from the deploy hook, when it verifies`)  
Scope: read-only review and targeted live verification of the current proxy
response paths for HTTP/1.1, HTTP/2, and HTTP/3, including the existing proxy
fixtures and regression coverage.

## Executive summary

Two further, reproducible proxy issues remain:

1. **Medium: the HTTP/3 proxy treats an upstream informational response as the
   final response.** A normal `103 Early Hints` followed by `200 OK` is sent to
   the H3 client as a lone `103`; the final response is never delivered.
2. **Medium: HTTP/2 and HTTP/3 proxy framing rejects legal tab-padded
   `Content-Length` values.** The shared validator correctly accepts HTTP
   optional whitespace, but the two later framing lookups trim only spaces.
   HTTP/1.1 serves the same response successfully while H2 and H3 return 502.

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — HTTP/3 proxy treats an interim response as final

Severity: **Medium (P2, HTTP/3 proxy availability and semantic correctness)**  
Confidence: **High**  
Status: **FIXED** (see Resolution)

### Evidence

The HTTP/3 proxy parses an HTTP/1 response status into `up_status`, validates
the head, and immediately chooses body handling:

- [`src/server/linnea_h3_proxy.asm:535`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:535)
  through [`:591`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:591)
  accept any three-digit status and validate only the field section.
- [`:651`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:651) through
  [`:688`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:688) classify
  every status below 200 as bodiless, open the response capture, and return
  `LINNEA_HTTP_HEAD_READY`. There is no “interim; parse another head” result.
- Delivery passes that first `up_status` straight to the QPACK response encoder
  at [`:971`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:971) through
  [`:980`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:980).

The HTTP/2 path has the missing state distinction. Its parser recognizes a
100–199 status other than 101, returns its separate interim result, and keeps
reading for the final response:

- [`src/server/linnea_http2.asm:4041`](/home/linnea/linnea/src/server/linnea_http2.asm:4041)
  through [`:4053`](/home/linnea/linnea/src/server/linnea_http2.asm:4053).

The repository's own upstream fixture sends the normal sequence at
[`test/proxy_backend.py:200`](/home/linnea/linnea/test/proxy_backend.py:200)
through [`:208`](/home/linnea/linnea/test/proxy_backend.py:208): `103 Early
Hints`, then `200 OK` and `final-reply`. The HTTP/2 suite explicitly asserts
that sequence at
[`test/shards/tls/40-http2.sh:431`](/home/linnea/linnea/test/shards/tls/40-http2.sh:431)
through [`:452`](/home/linnea/linnea/test/shards/tls/40-http2.sh:452). The H3
proxy test has no equivalent case; its ordinary successful-response coverage
starts at
[`test/quic/h3_proxy_test.py:102`](/home/linnea/linnea/test/quic/h3_proxy_test.py:102).

This is required protocol behavior: HTTP/3 permits zero or more interim
responses before exactly one final response (RFC 9114 section 4.1), just as the
HTTP/2 mapping sends an informational response without `END_STREAM` (RFC 9113
section 8.8.5).

### Reproduction

Against a temporary instance of the current binary and the existing TLS H3
proxy fixture (with no repository files modified):

```text
HTTP/2 GET /api/early: 200, body "final-reply"
HTTP/3 GET /api/early: :status 103, empty body, no final 200
```

The H3 client was the repository's `h3_proxy_test.py` request helper, with only
its first in-memory request target changed from `/api/simple` to `/api/early`.
It reported:

```text
simple status: 103 ''
simple body: ''
simple content-length: None
```

Thus a valid, currently covered HTTP/2 upstream exchange is not merely
uncovered on H3; it is observably terminated at the interim response.

### Impact

Any H3 request proxied to an application or upstream intermediary that emits
`100`, `102`, `103`, or another supported interim response loses its final
answer. This is particularly visible for `103 Early Hints`: the client sees
the hint status but not the resource it requested. Multiple interim responses
and an interim/final pair received in one read have the same missing state
transition.

### Resolution — FIXED (2026-08-18, `a81098e`)

Confirmed exactly as described, on all three interim fixtures: h1 and h2
delivered `final-reply`, h3 returned a lone `103` with an empty body.

Interim heads now stay where they are in `up_buf`, and a new
`.h3_hoff` steps past each so the next parse sees the head behind it. Nothing is
shifted: delivery walks `[0, .h3_hoff)` and re-encodes each as its own HEADERS
frame ahead of the final one. They are all frames on one stream and the FIN
rides the stream rather than any frame, so the client sees the sequence RFC 9114
4.1 describes. Verified on the wire:

| route | frames the h3 client receives |
|---|---|
| `early` | `103 -> 200`, body `final-reply` |
| `early-atonce` | `103 -> 200` (both heads in ONE upstream write) |
| `multi-early` | `103 -> 103 -> 100 -> 200` |
| `upgrade101` | `502` — a 101 has no meaning here, as h2 also refuses |

The parse **loops** rather than returning to wait for a read, since an upstream
may write the interim and the final together.

**One limit, stated rather than buried:** the interims reach the client *with*
the final response, not ahead of it. An h3 leg captures the whole body before it
sends anything, so `103 Early Hints` is forwarded as RFC 9110 15.2 requires but
without the head start that is its point. Delivering it genuinely early means
writing to the request stream before the response slot exists, which the
one-slot-per-response model does not support — a larger change than this one.

Delivery's head assembly is now unified behind one bounded helper, which also
repaired a latent overflow: the size check ran *after* the copy, and a field
section may be as large as the whole reserve, so type byte + varint + section
could run a few bytes past `h3p_head`. Harmless with exactly one HEADERS frame
per response; not once interims can add more.

### Recommendation

Give the H3 proxy the same explicit interim-head state as HTTP/2. For a valid
100–199 response other than unsupported `101`, QPACK-encode a HEADERS frame
without ending the request stream, retain the upstream leg, reset head parsing,
and read the next head. Only the first final response may select body framing,
open capture, and close the response stream. Reject malformed interim heads
and `101` with the existing 502 path.

Add H3 regressions alongside the existing H2 cases for `/api/early`,
`/api/early-atonce`, and `/api/multi-early`; each must expose the interim
headers in order and finish with `200` plus `final-reply`.

## Finding 2 — HTTP/2 and HTTP/3 fail legal HTAB optional whitespace in an upstream `Content-Length`

Severity: **Medium (P2, avoidable proxy failures for valid responses)**  
Confidence: **High**  
Status: **FIXED** (see Resolution)

### Evidence

HTTP optional whitespace is zero or more SP or HTAB, and a field parser must
exclude leading and trailing whitespace before evaluating a field value (RFC
9110 sections 5.5 and 5.6.3).

The shared upstream-head validator already implements that rule:

- [`src/server/linnea_http.asm:3484`](/home/linnea/linnea/src/server/linnea_http.asm:3484)
  through [`:3497`](/home/linnea/linnea/src/server/linnea_http.asm:3497)
  skips both SP and HTAB before a field value.
- Its repeated-`Content-Length` check trims trailing SP and HTAB at
  [`:3545`](/home/linnea/linnea/src/server/linnea_http.asm:3545) through
  [`:3558`](/home/linnea/linnea/src/server/linnea_http.asm:3558), so the head
  itself is accepted.

But the two paths that later locate the framing value drift from that rule:

- HTTP/2's `h2p_head_find` skips and trims only ASCII space at
  [`src/server/linnea_http2.asm:4297`](/home/linnea/linnea/src/server/linnea_http2.asm:4297)
  through [`:4317`](/home/linnea/linnea/src/server/linnea_http2.asm:4317).
  Its untrimmed `\t5\t` reaches `linnea_string_to_u64`, which takes the
  existing bad-upstream/502 path.
- HTTP/3's `.ph_find` has the same leading-space-only scan at
  [`src/server/linnea_h3_proxy.asm:762`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:762)
  through [`:778`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:778),
  before its `Content-Length` caller at
  [`:629`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:629) through
  [`:641`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:641).

HTTP/1 does not have the defect: its framing scan explicitly accepts both
forms at [`src/server/linnea_http.asm:3790`](/home/linnea/linnea/src/server/linnea_http.asm:3790)
through [`:3814`](/home/linnea/linnea/src/server/linnea_http.asm:3814).

Report 6 documented this exact residual at the end of its resolution, but the
test matrix still covers only SP padding. The current fixture and test call
`Content-Length:   5  ` legal at
[`test/proxy_backend.py:258`](/home/linnea/linnea/test/proxy_backend.py:258)
through [`:260`](/home/linnea/linnea/test/proxy_backend.py:260), and the
matrix asserts that spelling only at
[`test/proxy_upstream_head.py:48`](/home/linnea/linnea/test/proxy_upstream_head.py:48)
through [`:55`](/home/linnea/linnea/test/proxy_upstream_head.py:55).

### Reproduction

I ran the existing backend in-memory with its `/api/clpad` response changed
only for that process to:

```http
HTTP/1.1 200 OK
Content-Length:\t5\t

valid
```

The current binary produced:

```text
HTTP/1.1 /api/clpad: 200, body "valid"
HTTP/2   /api/clpad: 502, body "502 Bad Gateway\n"
HTTP/3   /api/clpad: 502, body "502 Bad Gateway\n"
```

The HTTP/3 observation used the repository's H3 proxy client helper; it
reported status 502 and the generated bad-gateway body. The temporary backend
and server were stopped after the check.

### Impact

A conforming upstream response can fail only for clients that negotiated HTTP/2
or HTTP/3, while HTTP/1.1 clients receive the intended response. This produces
unnecessary 502s, protocol-dependent availability, and a second parser
differential immediately after the response-head validation was consolidated.

### Resolution — FIXED (2026-08-18, `a81098e`)

This is the residual `978c077` recorded and deliberately left; the report is
right that leaving it meant a second parser differential immediately after the
head validation was consolidated. Measured before the fix, it was finer-grained
than the report states — h3 already handled the trailing half, from the HTAB
added in `978c077`:

| route | h1 | h2 | h3 |
|---|---|---|---|
| `clpad` (SP both sides) | 200 | 200 | 200 |
| `cltab` (HTAB both) | 200 | **502** | **502** |
| `cltablead` (HTAB leading) | 200 | **502** | **502** |
| `cltabtrail` (HTAB trailing) | 200 | **502** | 200 |

`h2p_head_find` now takes HTAB at both ends and h3's `.ph_find` at the leading
one. All three serve every variant, and `cljunk` (`12 34`) still returns 502, so
the trim did not drift into permissiveness.

### Recommendation

Use one OWS-trimming helper for every upstream framing lookup, or change both
`h2p_head_find` and the H3 `.ph_find` to trim SP **and** HTAB on both sides.
Do the same for the response-field emitters that consume their value slices, so
a later refactor cannot reintroduce untrimmed field bytes downstream.

Extend `proxy_upstream_head.py` with a `cltab` fixture (leading, trailing, and
both-side HTAB variants) and require the same `200`/`valid` result on HTTP/1,
HTTP/2, and HTTP/3. Keep `cljunk` as the paired negative control, proving that
internal whitespace remains invalid.

## Conclusion

Both are fixed and pinned in the cross-protocol matrix, which now covers the
tab-padded variants, the three interim shapes and the unrequested 101 — and
asserts the interim *sequence* on HTTP/3, not merely the final status, since
dropping the interims silently would deliver the right body while violating
RFC 9110 15.2. **27 of its checks fail against a pre-fix binary.** Full suite
**762 passed, 0 failed**.

Two faults of my own during the work, recorded because they cost real time. A
worker took a SIGSEGV whose fault address (`0x47`) was a *length* being
dereferenced as a pointer — an `xchg` had swapped the head pointer and length
that the comments beside it already had right. And the first matrix run reported
HTTP/1 failures that were a bug in the *test client*: it split on the first
`CRLF CRLF` and read the 103's head as the response, where a real HTTP/1 client
skips 1xx. curl had been right about that path all along.
