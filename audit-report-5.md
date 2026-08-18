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

No source code, tests, configuration, or previous report was changed. Only this
report was added.

## Finding 1 — HTTP/2 and HTTP/3 `Content-Length` validation wraps and loses duplicates

Severity: **Medium (P2, HTTP message integrity and proxy-side effects)**  
Confidence: **High**  
Status: **OPEN**

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
full suite. The new open finding is a checked-integer and duplicate-field
validation gap in HTTP/2 and HTTP/3 `Content-Length` handling: malformed
requests can be accepted and dispatched to a proxy backend. The audit is
complete.
