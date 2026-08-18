# Linnea server audit report 5

Date: 2026-08-18  
Audit baseline: commit `7ef7fa4` (`quic: refuse a non-idempotent 0-RTT early request with 425 Too Early`)  
Scope: `src/server`, `src/lib`, `include`, HTTP/1, HTTP/2, HTTP/3, TLS, QUIC,
proxying, listener/lifecycle paths, and the complete available test suite.

## Executive summary

This was a read-only follow-up audit. The report-4 CID-steering correction and
the current 0-RTT method gate were rechecked. I found one new high-confidence
issue:

1. **Medium: HTTP/2 and HTTP/3 accept overflowing or conflicting
   `Content-Length` fields.** Decimal parsing wraps a value at `2^64` to zero,
   so an empty request is accepted and reaches a proxy backend. The shared
   field collector also retains only the last of multiple values.

No source code, tests, configuration, or previous report was changed by the
audit itself. Only this report was added. The finding has since been fixed; see
its Resolution below.

## Finding 1 — HTTP/2 and HTTP/3 `Content-Length` validation wraps and loses duplicates

Severity: **Medium (P2, HTTP message integrity and proxy-side effects)**  
Confidence: **High**  
Status: **FIXED** (see Resolution)

### Evidence

The HTTP/3 reconciliation loop parses decimal digits but has no overflow check:

- [`src/server/linnea_quic_server.asm:3799`](/home/linnea/linnea/src/server/linnea_quic_server.asm:3799)
  through [`:3820`](/home/linnea/linnea/src/server/linnea_quic_server.asm:3820)
  compare the parsed field with the DATA-byte count.
- At [`:3814`](/home/linnea/linnea/src/server/linnea_quic_server.asm:3814) and
  [`:3815`](/home/linnea/linnea/src/server/linnea_quic_server.asm:3815),
  `imul rax, 10` and `add rax, rdx` may wrap. `18446744073709551616` (`2^64`)
  becomes zero, matching an empty DATA payload. The nearby comment claiming an
  overflowing value cannot match is therefore incorrect.

HTTP/2's proxy helper misses overflow in its final addition too:

- [`src/server/linnea_http2.asm:4520`](/home/linnea/linnea/src/server/linnea_http2.asm:4520)
  through [`:4545`](/home/linnea/linnea/src/server/linnea_http2.asm:4545)
  check only whether the multiply result decreases. The add at line 4538 has
  no carry check, so the final digit of `2^64` wraps to zero.
- The terminal-HEADERS path treats that zero as a valid bodiless request at
  [`src/server/linnea_http2.asm:2174`](/home/linnea/linnea/src/server/linnea_http2.asm:2174)
  through [`:2182`](/home/linnea/linnea/src/server/linnea_http2.asm:2182).

The shared field collector overwrites prior values instead of comparing them:

- Every recognised `content-length` sets `cl_ptr` and `cl_len` at
  [`src/server/linnea_hpack.asm:634`](/home/linnea/linnea/src/server/linnea_hpack.asm:634)
  through [`:644`](/home/linnea/linnea/src/server/linnea_hpack.asm:644). No
  earlier value is retained or checked, so HTTP/3 considers only the final one.

HTTP/1 already has the intended defensive pattern: it bounds the value before
multiplying and checks the addition carry at
[`src/server/linnea_http.asm:1422`](/home/linnea/linnea/src/server/linnea_http.asm:1422)
through [`:1440`](/home/linnea/linnea/src/server/linnea_http.asm:1440).

### Reproduction

I used a temporary single-worker TLS/H3 proxy and the repository's test backend;
the helpers and configuration lived only under `/tmp`.

- HTTP/3 `POST /api/echo` with `content-length: 18446744073709551616` and no
  DATA returned **200**. The backend recorded `POST /api/echo 0`.
- HTTP/2 `POST /api/echo` with the same field in END_STREAM `HEADERS` returned
  **200** and the backend again recorded a zero-byte `POST`.
- HTTP/3 `POST /api/headers` with `content-length: 0`, then
  `content-length: 1`, and one DATA byte returned **200**. The backend recorded
  `POST /api/headers 1`: the final declaration won and the first was ignored.

All three requests should be rejected as malformed before routing. An
unrepresentable length cannot equal the DATA count, and contradictory values
cannot both equal it.

### Impact

An HTTP/2 or HTTP/3 client can convert malformed, unrepresentable framing into
a normal zero- or modulo-`2^64` request. On a proxy location it reaches the
backend, so a malformed `POST` can invoke an application endpoint rather than
being rejected at the edge.

The proxy rebuilds forwarded framing from the measured body; this audit did not
demonstrate cross-client request smuggling or memory corruption. The confirmed
impact is message-integrity failure and an avoidable backend side effect, which
warrants P2 rather than a higher rating.

### Recommendation

Use one checked decimal parser for inbound HTTP/2 and HTTP/3 `Content-Length`.
Before a digit, reject when `value > UINT64_MAX / 10`, or when equal and the
digit exceeds `UINT64_MAX % 10`; alternatively check both multiply and addition
overflow. Treat an overflow as malformed before routing or connecting upstream.

Track prior `Content-Length` fields during field-section decoding. Reject
conflicting values; if identical duplicates are intentionally supported, compare
their checked numeric values and emit one canonical value only after validation.

Add HTTP/2 and HTTP/3 regressions for `2^64`, `2^64 + 1`, long all-digit
values, both orders of conflicting duplicates, and a unit-level
`UINT64_MAX` boundary parse.

### Resolution — FIXED (2026-08-18, `e7895b0`)

The report is right on every point, and the shape of the defect is worse than
the three reproductions show: there were **five hand-rolled decimal parsers**
for the same field — HTTP/1's request and response heads, HTTP/2's (shared
between request and response), HTTP/3's request, HTTP/3's proxy response — and
**three of them were wrong, each at a different instruction**. There is now one,
`linnea_string_to_u64` in
[`src/lib/linnea_string.asm`](/home/linnea/linnea/src/lib/linnea_string.asm),
and all five sites call it.

**The parser.** `linnea_string_to_u64(ptr, len) -> rax = value, edx = verdict`
— `0` in range, `1` empty or not all digits, `2` all digits but past `2^64-1`.
It applies the bound *before* the multiply (`value > (2^64-1)/10` rejects) and
checks the digit's carry after it, which is the pattern HTTP/1 already had.

Two things the report's recommendation implies and that turned out to matter:

- **The verdict is returned apart from the value.** `18446744073709551615` is a
  legal `Content-Length`, so a parser that reports failure by returning `-1`
  cannot tell it from a fault — and HTTP/2's did not. A body declaring
  `UINT64_MAX` took the *"unparseable: collect and re-derive"* branch and was
  forwarded to the backend under **our** measured count instead of the client's:
  the exact substitution the RFC 9113 8.1.1 reconciliation exists to prevent.
  That request answered **200** before the fix. `linnea_h2p.rq_declared` had the
  same collision (`-1` also meant "none declared"), so a new
  `LINNEA_H2P_F_HAS_CL` flag now says which of the two it is.
- **"The product got smaller" is not an overflow test.** `(2^61+1) * 10` wraps
  to `2^62 + 10`, which is larger. HTTP/2's guard tested exactly that. HTTP/3's
  proxy tested `jc` after an `lea`, which sets no flags at all — the carry it
  read was the one the preceding `shl rax, 3` had left, i.e. bit 61 of the value
  and nothing about the `*2` or the add. Both accepted `46116860184273879040`
  as `2^63`.

**Where the check now happens.** Once, in the field collector both protocols
share — `emit_field` in
[`src/server/linnea_hpack.asm`](/home/linnea/linnea/src/server/linnea_hpack.asm),
which is where `cl_ptr`/`cl_len` were already captured. The parsed value lands
in a new `linnea_h2_req.cl_val`. An empty, non-decimal or out-of-range value, or
a **second** `content-length` line, sets `.malformed` — the existing route both
protocols use for a stream error (RFC 9113 8.1.1 / RFC 9114 4.1.2), so the fault
is caught **before routing and before any upstream socket is opened**, and the
connection and its compression context are untouched. Duplicates are refused
whether or not they agree, which is what HTTP/1 has always done: two lengths
cannot both equal the body.

The reconciliations downstream now only compare. HTTP/3
([`linnea_quic_server.asm`](/home/linnea/linnea/src/server/linnea_quic_server.asm))
reads `cl_val` against the DATA sum; HTTP/2
([`linnea_http2.asm`](/home/linnea/linnea/src/server/linnea_http2.asm)) reads it
into `rq_declared`. The comment the report quotes — that an overflowing value
"simply will not equal" the body count — is gone: it was backwards, since `2^64`
wraps to zero and zero is exactly the DATA sum of a request that sends no body.

**One thing beyond the report's scope, same defect, response side.** Two of the
three broken parsers were reading an *upstream's* `Content-Length`, and on
HTTP/2 that was live: a backend answering
`Content-Length: 18446744073709551616` or `46116860184273879040` had its
response **relayed as 200** under framing we invented, rather than refused. Both
now go through the shared parser and answer 502, as HTTP/1 already did. HTTP/1's
own upstream parser was correct and is converted for uniformity; the one
behaviour change there is that an upstream declaring exactly `2^64-1` is now a
502 rather than being read as close-delimited, which is the same `-1` sentinel
collision, fixed the same way on all three protocols.

### Verification

Every claim below is an A/B against a pre-fix binary built from `7ef7fa4`, both
run against the same config and backend.

Requests (`POST /api/echo`, a proxy location), pre-fix → post-fix:

| request | h2 before | h2 after | h3 before | h3 after |
|---|---|---|---|---|
| `content-length: 2^64`, no body | 200 | RST | 200 | RESET |
| `content-length: 2^64 + 5`, 5 bytes | 200 | RST | 200 | RESET |
| `content-length: UINT64_MAX`, 5 bytes | 200 | 413 | RESET | RESET |
| `content-length: 0` then `1`, 1 byte | 200 | RST | 200 | RESET |
| `content-length: 1` then `0`, 1 byte | 200 | RST | RESET | RESET |
| `content-length: 5` twice, 5 bytes | 200 | RST | 200 | RESET |
| **control** `content-length: 5`, 5 bytes | 200 | 200 | 200 | 200 |
| **control** no `content-length`, 5 bytes | — | — | 200 | 200 |

The backend's own record is the second half of the A/B: over the h2 case list
the pre-fix binary let **9** requests reach it and the post-fix binary **1** (the
control); over the h3 list, **6** before and **2** after (both controls).

Upstream responses (a backend that echoes a chosen `Content-Length`):
`18446744073709551616` and `46116860184273879040` were **200** on h2 before and
are **502** after; h3 answered 502 either way, but for the wrong reason before
(it waited for `2^63` bytes and hit the backend's close, rather than refusing
the declaration).

HTTP/1's *behaviour* is unchanged, deliberately: both its parsers already had
the bound right, so they now call the shared one and the request path keeps its
own split of the verdict — 400 for "not a number", 413 for "larger than we could
ever accept". A ten-case A/B over the request path returns byte-identical status
lines on both binaries, and the upstream-response path answers 502 for the same
inputs before and after.

Regressions added:

- [`test/str/linnea_strtest.asm`](/home/linnea/linnea/test/str/linnea_strtest.asm)
  — 25 unit vectors for the parser, on the boundaries the four copies each
  missed somewhere else: `UINT64_MAX` must parse, `2^64` and `2^64+1` must be
  out of range, `(2^64-1)/10*10+5` in and `+6` out, and `2^62*10` (which wraps
  *upward*) caught. Control run: rebuilt with HTTP/2's old monotonicity guard it
  fails **4 of 25**, and passes 25/25 with the fix.
- [`test/tls/h2_content_length.py`](/home/linnea/linnea/test/tls/h2_content_length.py)
  — overflow, duplicates in both orders, the identical pair, the `UINT64_MAX`
  boundary, and two controls. Control run: **7 of 15 checks fail** on the
  pre-fix binary.
- [`test/quic/h3_content_length.py`](/home/linnea/linnea/test/quic/h3_content_length.py)
  — the same set for HTTP/3, failing pre-fix on the first overflow case.

The full suite is green on the fixed tree: **757 passed, 0 failed** across three
concurrent jobs (`LINNEA_SUITE=full ./test/run_shards.sh`, 410s) — one check
more than the audited revision's 756, the new parser vectors.

**Incidental repair, found on the way.** Three test binaries had stopped
linking: `bin/linnea-qpacktest` (missing `linnea_network_parse_ipv6`, since
`a9319b8`), `bin/linnea-h3test` and `bin/linnea-h3resp` (missing `s_is_early`,
since `7ef7fa4`). The shards that run them test `[ -x ./bin/... ]` first, so two
checks had been silently skipping and the third was running a **stale** binary
from before the break — the worse of the two failure modes, since it passes. All
three object lists are fixed, all three build and pass, and they exercise the
very decoder this finding is in. Both shard runners now pre-build them, as they
already did for the other unit-test binaries. A full sweep confirms every other
test target still links.

**Remaining, reported not silently fixed.** HTTP/2's *static* path still does
not reconcile a declared length against the body: a static `GET` carrying
`content-length: 5` and no DATA is served 200, where HTTP/3 refuses it. The
declaration is now parsed and range-checked on that path too, so nothing wraps,
but the comparison is not made — h2 dispatches a static request at HEADERS time
and drops DATA frames for a stream nothing is collecting, so there is no body
count to compare against without new accounting. No backend is involved and the
body is discarded, which is why it is left as a separate, lower-severity item
rather than half-closed here.

## Reviewed behavior with no additional finding

- The report-4 BPF correction is present: the sockarray uses all 256 byte
  indices, hot upgrades partition at 128, and failed map registration is logged.
  The test environment still lacks CAP_BPF for live BPF validation.
- The 0-RTT guard in
  [`src/server/linnea_http3.asm`](/home/linnea/linnea/src/server/linnea_http3.asm)
  returns 425 for early non-GET/HEAD requests before location routing.
  `test/quic/h3_0rtt_test.py` covers an early POST alongside an accepted GET.
- QUIC transport/CID handling, H3 framing and flow control, HTTP/1 proxy
  framing, TLS, path normalization, listener setup, upgrade/drain behavior, and
  resource cleanup were reviewed without another high-confidence finding.

## Verification

The build and complete suite passed on the audited revision:

```text
make -j2
Nothing to be done for 'all'.

LINNEA_SUITE=full ./test/run_tests.sh
756 passed, 0 failed (full run)
```

The worktree was clean before this report was created; the only intended
repository change is `audit-report-5.md`.

## Conclusion

The report-4 steering correction and current 0-RTT safety fix hold under the
full suite. Finding 1 is **FIXED**: `Content-Length` on every protocol, in both
directions, now goes through one checked decimal parser, and an unrepresentable
or repeated declaration is a malformed message refused before routing rather
than a wrapped number the request is then measured against. The audit is
complete.
