# Linnea server audit report

Date: 2026-08-16  
Scope: `src/server`, `src/lib`, `include`, configuration handling, and the existing test suite.

## Executive summary

The tree builds cleanly and the lightweight self-tests pass. The existing integration suite is unusually thorough around HTTP/2, HTTP/3, uploads, QUIC loss, and descriptor cleanup. I found two issues worth fixing:

1. **High: large streamed HTTP/1 request bodies can discard a pipelined request.** This affects both counted and chunked uploads and can make the client wait forever for a response to a request the server silently consumed. **— FIXED (see "Resolution" below).**
2. **Medium: several cumulative body counters use add-then-compare arithmetic.** At the documented `2^64-1` configuration boundary, the counters can wrap and pass the body-size check. This is primarily a boundary/resource-accounting defect; reaching it with a real upload would require an impractically large body or disk. **— NOT changed (latent, practically unreachable; left for a later opportunistic cleanup).**

Finding 1 has been fixed and its regression tests added to the suite. Finding 2 was left as-is by decision — it is a real arithmetic defect but not reachable without transferring ~18 EB, so it is a defense-in-depth item rather than an operational one.

## Finding 1 — streamed HTTP/1 bodies lose pipelined suffix bytes

Severity: High (P1 correctness/availability)  
Confidence: High  
Status: **FIXED** — see "Resolution" at the end of this section.

### Evidence

Large counted request bodies are received into `out_buf` by
[`src/server/linnea_uring.asm:1423`](/home/linnea/linnea/src/server/linnea_uring.asm:1423).
When a receive contains more bytes than the remaining body, the code clamps the
amount written to the capture file:

```asm
mov eax, r15d
cmp rax, [r12 + linnea_connection.req_body_rem]
jbe .req_body_have
mov rax, [r12 + linnea_connection.req_body_rem]   ; ignore anything past
```

The suffix is never copied to `in_buf`, queued, or parsed as the next request.
The comment at [`src/server/linnea_uring.asm:1434`](/home/linnea/linnea/src/server/linnea_uring.asm:1434)
describes this as intentional, but it is only safe if the peer never pipelines
after a streamed body. HTTP/1.1 permits a client to send those bytes before the
first response arrives.

The chunked capture path has the same structural problem. The parser advances a
local cursor, but its public result is only `0` (need more), `1` (complete), or an
error; see [`src/server/linnea_spill.asm:135`](/home/linnea/linnea/src/server/linnea_spill.asm:135)
and [`src/server/linnea_spill.asm:315`](/home/linnea/linnea/src/server/linnea_spill.asm:315).
At capture start, the caller resets `in_len` to `head_len` after parsing, without
preserving bytes after the terminal chunk; see
[`src/server/linnea_uring.asm:1291`](/home/linnea/linnea/src/server/linnea_uring.asm:1291)
and [`src/server/linnea_uring.asm:1312`](/home/linnea/linnea/src/server/linnea_uring.asm:1312).
Later capture reads pass the whole `out_buf` to the parser and still receive no
consumed-byte count.

### Observable behavior

Send a large proxied POST followed immediately by a GET on one keep-alive
connection. If the GET lands in the same receive completion as the final body
bytes, the server captures the POST and drops the GET. The client receives one
response and then waits until its own timeout, or reports a missing response.
The same happens with a large chunked POST, including when the second request is
after the terminal chunk and trailers.

This is a request-stream desynchronization/availability problem, not an observed
out-of-bounds write. It is also easy to miss because the current `twice` test
sends the second chunked request only after reading the first response.

### Recommended fix

Make the body-consumption APIs return the number of encoded input bytes consumed.
When a body completes:

- copy the unconsumed suffix into the connection's request buffer (or a bounded
  pending-input area);
- set `in_len` to the head plus that suffix; and
- run the normal keep-alive parser after the current exchange is in a state where
  it can safely accept the next request.

The counted path should calculate `body_bytes = min(received, body_remaining)`
and preserve `received - body_bytes` instead of dropping it. The copy must check
the destination capacity and close/refuse cleanly if the suffix cannot fit.

### Regression tests to add

- `test/h1_stream_pipeline.py`: send a 200–300 KiB `Content-Length` POST and a
  second GET in one `sendall`; assert two responses and one accepted connection.
- Extend `test/upload_chunked.py` with a `pipeline` mode that sends a large
  chunked POST, the terminal chunk, and a GET without waiting for the POST
  response. Test both no trailers and several trailers.
- Repeat the two tests with boundaries deliberately split at: the final body
  byte, the terminal chunk's `0`, the CRLF after it, and the first byte of the
  next request.

### Resolution (fixed)

The two framings are fixed by two different mechanisms, because only one of them
knows the body length ahead of time:

- **Counted** (`src/server/linnea_uring.asm`, `.capture_more`): the tail recv is
  now capped at `min(out_buf, req_body_rem)`, so the read stops exactly at the
  body's end and the pipelined suffix is never pulled out of the kernel. It stays
  in the socket buffer, and keep-alive's ordinary recv into `in_buf` reads it as
  the next request. No new buffer is needed. The old clamp at `.req_body_counted`
  that used to *drop* the overshoot is now unreachable, kept only as a defensive
  bound with an updated comment.
- **Chunked** (`src/server/linnea_spill.asm`, `linnea_spill_chunked`): the encoded
  length is unknown, so the suffix does land in `out_buf`. On completion the
  decoder now copies the bytes past the terminal chunk to `in_buf[head_len]`
  (free during a chunked capture — `head_len` is the pure head) and records the
  count in a new connection field `.pend_len`. `.keep_alive_continue` folds
  `pend_len` back into `in_len` so the existing slide-and-parse path serves the
  pipelined request. A new `-3` return covers the pathological case (a >8 KiB
  head pipelined behind a streamed body, which will not fit after the head): the
  connection is closed cleanly with reason `pipelined request too large to
  buffer` rather than the suffix being lost silently.

New per-connection field `.pend_len` was added to `include/linnea_connection.inc`
and zeroed in `linnea_connection_alloc`.

Regression tests added and wired into `test/run_tests.sh`:

- `test/h1_stream_pipeline.py` — counted and chunked framings across a split
  matrix (`together`, at the body's end, one byte into the next request, mid-body,
  and mid-terminal-chunk for chunked), each checking that BOTH responses arrive
  and BOTH bodies survive byte-exact.
- A `pipeline` mode in `test/upload_chunked.py` — a GET pipelined behind a chunked
  upload in one write, with and without trailers (the audit's specific ask).

Both tests were confirmed to **fail against a pre-fix binary** (`PIPELINED
REQUEST DROPPED`) and pass against the fix, so they genuinely exercise the defect.
The fast suite runs green with them included (494 pass, 0 fail).

## Finding 2 — body-size accounting can wrap at the documented u64 limit

Severity: Medium (P2 boundary/resource accounting)  
Confidence: High for the arithmetic defect; low practical exploitability under
ordinary disk limits

### Evidence

The configuration deliberately accepts the full unsigned 64-bit range:

- [`src/server/linnea_config_parse.asm:591`](/home/linnea/linnea/src/server/linnea_config_parse.asm:591)
  accepts any nonzero `u64`.
- [`docs/config.md:112`](/home/linnea/linnea/docs/config.md:112) documents
  `1–18446744073709551615`.

Several paths add an incoming length before comparing with `max_body`:

- HTTP/2 collected bodies use `lea r9, [r8 + rax]` before the check at
  [`src/server/linnea_http2.asm:514`](/home/linnea/linnea/src/server/linnea_http2.asm:514).
- HTTP/3 QUIC region admission uses `spill_len + frame_len` at
  [`src/server/linnea_quic_server.asm:2910`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2910).
- The QUIC sink repeats the pattern at
  [`src/server/linnea_quic_server.asm:7871`](/home/linnea/linnea/src/server/linnea_quic_server.asm:7871).
- The streaming spill counter is incremented by ordinary `add` instructions in
  [`src/server/linnea_spill.asm:103`](/home/linnea/linnea/src/server/linnea_spill.asm:103)
  and the QUIC staging/direct-write paths at
  [`src/server/linnea_quic_server.asm:7918`](/home/linnea/linnea/src/server/linnea_quic_server.asm:7918)
  and [`src/server/linnea_quic_server.asm:7943`](/home/linnea/linnea/src/server/linnea_quic_server.asm:7943).
- Chunked encoded-byte accounting adds the receive length before comparing at
  [`src/server/linnea_spill.asm:159`](/home/linnea/linnea/src/server/linnea_spill.asm:159).

For example, with `max_body = 2^64-1`, a counter at `2^64-2` plus an incoming
length of 2 wraps to zero. The subsequent unsigned `ja` check accepts the data,
and the wrapped counter is later used as a file size, offset, or content length.

On a normal machine, reaching that counter requires an enormous body or storage
capacity, so this is not comparable to a small-request remote memory exploit.
It is nevertheless a real correctness defect at a configuration value the
documentation explicitly promises to accept, and it makes the limit invariant
depend on an unreachable-in-practice assumption rather than on checked math.

### Recommended fix

Use subtraction-before-addition everywhere a cumulative count is bounded:

```text
if current > max_body: reject
if incoming > max_body - current: reject
current += incoming
```

Centralize this in a small assembly helper if possible, then use it for decoded
body length, encoded chunk length, spill length, and QUIC region lengths. Audit
associated `base + length`, file-offset, `mmap`-length, and content-length
calculations for the same wrap pattern.

### Regression tests to add

- Unit-test the bounded-add helper with `(max-1, 2)`, `(max, 0)`, `(max, 1)`,
  and a normal interior value.
- Add fixture-level tests that initialize the relevant connection/stream counters
  near `u64::MAX` and verify a request is rejected without changing the counter
  or writing to the spill file.
- Keep the existing configuration test that accepts `max_body = 2^64-1`, but
  pair it with these arithmetic tests so the accepted boundary is actually safe.

## Coverage and additional test recommendations

The current suite already covers many important cases: large h1/h2/h3 uploads,
chunked framing errors and trailer floods, two sequential chunked captures,
QUIC loss/reordering, H2 flow-control credit, spill-directory selection, and
some descriptor-leak scenarios. The following additions would improve confidence:

- Add a repeated-aborted-upload soak across h1, h2, and h3 that samples worker
  RSS, open-fd count, and deleted `/proc/<pid>/fd` entries before and after the
  run. Run it with a disk-backed and a tmpfs spill directory separately.
- Add explicit HTTP/2 `HEADERS` + fragmented `CONTINUATION` tests across receive
  boundaries, including trailers. The code appears to assemble continuations
  from the initial HEADERS path; this is a coverage recommendation, not a
  confirmed defect.
- Add QUIC body tests that combine reordered DATA frames, duplicate ranges,
  frame boundaries, and the configured body cap. Verify that the final mapped
  body is byte-exact and that rejected requests never leave an open spill fd.
- Add a randomized HTTP/1 framing matrix for `Content-Length`, chunked bodies,
  trailers, `Expect`, keep-alive, and pipelining. The current tests cover these
  dimensions mostly one at a time.

## Verification performed

Audit (unchanged tree):

- `make -j2`: clean; no rebuild was needed.
- `./bin/linnea-selftest`: all reported crypto/TLS vectors passed.
- `./bin/linnea-rtxtest`: `quic-rtx 112/112`.
- `./bin/linnea-quictest`: `quic-crypto 38/38`.

Finding 1 fix:

- Reproduced the drop against a running server (counted and chunked, sent in one
  write): the backend saw only the POST, never the pipelined GET.
- Built a pre-fix binary and confirmed both new regression tests fail against it
  (`PIPELINED REQUEST DROPPED`) and pass against the fixed binary — an A/B control
  proving the tests catch the defect rather than passing vacuously.
- Post-fix, both responses arrive and both bodies are byte-exact across the full
  split matrix; every existing upload check (big/head/bad/abort/cap/flood/twice,
  counted captures) still passes.
- Fast suite (`./test/run_tests.sh`): 494 pass, 0 fail, 17 skip.
- The full long-running network matrix (`LINNEA_SUITE=full`) was not rerun; the
  change is confined to the HTTP/1 request-capture path, which the fast suite
  exercises directly.
