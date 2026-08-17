# Linnea server audit report

Date: 2026-08-16  
Scope: `src/server`, `src/lib`, `include`, configuration handling, and the existing test suite.

## Executive summary

The tree builds cleanly and the lightweight self-tests pass. The existing integration suite is unusually thorough around HTTP/2, HTTP/3, uploads, QUIC loss, and descriptor cleanup. I found thirty-four issues worth fixing:

1. **High: large streamed HTTP/1 request bodies can discard a pipelined request.** This affects both counted and chunked uploads and can make the client wait forever for a response to a request the server silently consumed. **— FIXED (see "Resolution" below).**
2. **Medium: several cumulative body counters use add-then-compare arithmetic.** At the documented `2^64-1` configuration boundary, the counters can wrap and pass the body-size check. This is primarily a boundary/resource-accounting defect; reaching it with a real upload would require an impractically large body or disk. **— NOT changed (latent, practically unreachable; left for a later opportunistic cleanup).**
3. **Medium: buffered HTTP/1 request bodies bypass `max_body`.** Counted bodies are checked against the limit only when the head plus body no longer fits in `in_buf`; complete chunked bodies take the same unchecked buffered path. A proxy therefore accepts and forwards bodies larger than the configured limit as long as they fit in the request buffer. **— FIXED (commit 13db631).**
4. **Medium: HTTP/2 accepts a trailer `HEADERS` block without `END_STREAM`.** The malformed trailer is consumed without failing the stream or completing the request, leaving the body slot collecting and allowing later `DATA` on the same stream. **— FIXED (commit 97046ff).**
5. **Medium: HTTP/2 silently drops stream frames whose IDs have no live slot.** `DATA` on idle or closed streams and `WINDOW_UPDATE`/`RST_STREAM` on idle streams are consumed without the required state-specific error; dropped `DATA` replenishes only the connection window. **— FIXED (idle-stream case): DATA/WINDOW_UPDATE/RST_STREAM on an idle stream (even id, or above the highest opened) now draw a connection PROTOCOL_ERROR instead of being silently ignored; closed-stream frames keep the RFC-permitted lenient handling. A/B-verified.**
6. **Medium: QUIC connection-level receive credit counts duplicate stream bytes.** Retransmissions under fresh packet numbers increment `fc_recv` even when stream reassembly recognizes every byte as already received, causing premature `MAX_DATA` grants. **— FIXED: connection credit now advances from per-stream receive high-water growth, so fresh-packet-number retransmissions and overlaps do not trigger extra `MAX_DATA`; covered by `test/quic/h3_fc_dedup_test.py`.**
7. **Medium: coalesced QUIC 0-RTT processing stops after the first early packet.** Later 0-RTT packets in the same datagram are neither decrypted nor acknowledged, so multi-packet early requests fall back to retransmission or remain incomplete. **— FIXED: the early walk now advances by each protected packet length, decrypts and acknowledges every valid 0-RTT packet, and replays the combined frame stream through normal reassembly; covered by `test/quic/h3_0rtt_coalesced_test.py`.**
8. **Low: HTTP/3 SETTINGS validation is bounded and partially discarded.** SETTINGS payloads larger than the local capture buffer are skipped without validation, and duplicate detection stops after 32 identifiers; the peer's maximum response field-section size is also not retained. **— OPEN (audit-only pass; no source changes made).**
9. **Low: HTTP/3 critical-stream closure can be missed when closure arrives before stream typing.** Reordered FIN/RESET/STOP_SENDING state is not retained for an as-yet-untyped control or QPACK stream. **— OPEN (audit-only pass; no source changes made).**
10. **Low: HTTP/3 accepts duplicate QPACK encoder or decoder streams.** Unlike the control stream, the QPACK stream handlers overwrite the saved ID instead of raising a stream-creation error. **— FIXED: a second QPACK encoder/decoder stream now draws H3_STREAM_CREATION_ERROR like a second control stream, instead of overwriting the saved id; A/B-verified.**
11. **High: a completed HTTP/3 request stream can be dispatched again.** Duplicate suppression lasts only while a response slot or refusal entry is active; a fresh-packet-number retransmission can reach the application again after an inline reply, or after a response slot is reaped. **— FIXED (`05f0194`): a per-connection watermark plus a small completed-stream ring records every dispatched request for the life of the connection, so a retransmission after an inline reply or a slot reap is acknowledged, not re-routed; A/B-verified (4→1 dispatches).**
12. **Medium: QUIC final-size invariants are not enforced.** A later FIN silently replaces the remembered final size, and RESET_STREAM final sizes are discarded, instead of conflicting sizes or data beyond the final size closing the connection with `FINAL_SIZE_ERROR`. **— FIXED (FIN side): a conflicting FIN size, a FIN below the highest byte received, or data past a fixed final size now close the connection `FINAL_SIZE_ERROR` (0x06); A/B-verified with injected packets. The RESET_STREAM cross-check is documented as scoped out (no residual transport-integrity risk).**
13. **Medium: malformed and forbidden QUIC transport parameters are accepted.** Truncation is treated as end-of-list, duplicate parameters overwrite, integer payloads may carry trailing bytes, and several invalid or client-forbidden values never set `TRANSPORT_PARAMETER_ERROR`. **— FIXED: truncated/duplicate/server-only/trailing-byte and out-of-range transport parameters now close the handshake TRANSPORT_PARAMETER_ERROR instead of completing; A/B-verified and covered by a new quic-shard test.**
14. **Medium: QUIC stream direction and state are not validated.** Frames naming server-initiated or send-only streams are skipped or acted on without the required `STREAM_STATE_ERROR`. **— FIXED: a pre-dispatch validator now enforces initiator, direction, and local stream-opening state for all stream-scoped transport frames; covered by `test/quic/h3_stream_state_test.py`.**
15. **Medium: accepted 0-RTT bypasses normal QUIC frame and stream-limit checks.** Early packets jump directly into the STREAM scanner, so prohibited frame types and over-limit early stream IDs do not receive the errors applied to 1-RTT packets. **— FIXED (early data runs the same validate+scan pipeline as 1-RTT via a buffer pointer `s_scan_buf`, plus a new `frames_0rtt_ok` for RFC 9000 12.5 forbidden frames; forbidden ACK/CRYPTO -> PROTOCOL_VIOLATION, over-limit stream -> STREAM_LIMIT_ERROR; `test/quic/h3_0rtt_validation.py`, A/B-verified).**
16. **Medium: inline HTTP/3 and control packets bypass QUIC congestion accounting and can fall out of loss recovery.** Only bulk response chunks are gated by `cwnd`; the eight-entry small-packet ring silently stops tracking additional replies. **— FIXED: ack-eliciting inline/control packets are now charged to a shared in-flight total (`inline_flight` + `bytes_in_flight`), an inline response is admitted only if it fits `cwnd` and a recovery slot, and the overflow is handed to the congestion-controlled pump rather than sent untracked; quic+tls shards green, burst answered 40/40 even with the ring forced to one slot.**
17. **Medium: HTTP/3 trailer field sections are skipped without QPACK or semantic validation.** Invalid compressed trailers and forbidden trailer pseudo-fields are accepted. **— FIXED: trailer field sections are now decoded into a throwaway request/scratch pair; QPACK failures close with `QPACK_DECOMPRESSION_FAILED`, pseudo-field/semantic failures reset the request stream, and valid trailer fields cannot affect routing; verified with malformed-QPACK, pseudo-field, and valid-trailer cases.**
18. **Medium: HTTP/3 does not reconcile `content-length` with DATA bytes.** A short or long body is routed and proxied instead of being rejected as a malformed message. **— FIXED (commit 514532a).**
19. **Medium: single-frame HTTP/3 request bodies bypass `max_body`.** The copy-free offset-zero-plus-FIN path reaches routing without either of the cap checks used by reassembly. **— FIXED (commit 13db631).**
20. **Medium: the peer's QUIC `max_udp_payload_size` is parsed but not enforced.** Large inline field sections can produce datagrams above a client's advertised receive limit. **— FIXED (a large inline h3 response, e.g. a redirect Location carrying a long client path, is split across STREAM frames at `TX_CHUNK` so no datagram exceeds 1200; `emit_inline_chunked`, `test/quic/h3_redirect_datagram.py`, A/B-verified — pre-fix emitted a 2120-byte datagram the client dropped).**
21. **Medium: QUIC connection-ID retirement and peer CID rotation are ignored.** Incoming `NEW_CONNECTION_ID` and `RETIRE_CONNECTION_ID` frames are structurally skipped without updating either outbound addressing or accepted server CIDs. **— FIXED (bounded per-connection CID tables: validate reuse/`retire_prior_to`/CID-limit with transport errors, rotate `conn.dcid` to a non-retired peer CID, deactivate retired local CIDs in the lookup and announce a replacement; `test/quic/h3_cid_lifecycle.py`).**
22. **Low: HTTP/3 unidirectional stream types are read as one byte instead of a QUIC varint.** Legal multi-byte encodings of control or QPACK stream types are classified as unknown streams. **— FIXED: the uni-stream type is decoded as a varint (its width skipped by the control walk and QPACK scan), so a non-minimal encoding like 40 00 is classified correctly instead of dropped; A/B-verified.**
23. **Low: QUIC PTO ignores the peer's advertised `max_ack_delay`.** RTT adjustment uses the negotiated value, but the application-space probe timer always adds the local 25 ms constant. **— FIXED (application-space `linnea_quic_pto_ms` adds `conn.max_ack_peer`, not the 25 ms constant; Initial/Handshake unchanged; unit-tested in `linnea_quictest.asm`/`linnea_rtxtest.asm`, A/B 41/46 vs 46/46).**
24. **Medium: HTTP/2 does not reconcile `content-length` on HEADERS-only or non-proxy requests.** A request that ends in its initial `HEADERS` can declare a nonzero body length and still be served or forwarded as bodiless; static and local-response paths never perform the DATA-length check. **— FIXED (proxy path, commit 97046ff; the harmless static-GET-with-CL sub-case is left).**
25. **Low: a client-sent HTTP/2 `PUSH_PROMISE` is treated as an unknown extension frame.** The server ignores a frame type clients are forbidden to send instead of closing the connection with `PROTOCOL_ERROR`. **— FIXED: an explicit PUSH_PROMISE case closes the connection PROTOCOL_ERROR; A/B-verified and covered by a new tls-shard test.**
26. **Low: oversized HTTP/2 `CONTINUATION` frames bypass the advertised frame-size limit.** Continuations consumed inside header-block assembly are checked against the input-buffer capacity rather than the protocol's 16,384-byte default. **— FIXED: the CONTINUATION size check now uses the 16,384-byte protocol limit instead of the input-buffer size, so an oversized one is FRAME_SIZE_ERROR; A/B-verified.**
27. **Low: HTTP/2 skips mandatory structural validation for `PRIORITY` and `GOAWAY`.** Arbitrary-length or stream-zero `PRIORITY` frames are ignored, while short or nonzero-stream `GOAWAY` frames put the connection into graceful drain. **— FIXED: a wrong-length or stream-0 PRIORITY and a nonzero-stream or short GOAWAY now draw FRAME_SIZE_ERROR/PROTOCOL_ERROR before being ignored or draining; A/B-verified.**
28. **Medium: HTTP/2 CONNECT requests bypass whole-request validation.** Unsupported CONNECT is answered with 405 even when `:authority` is absent or forbidden `:scheme`/`:path` fields are present. **— FIXED: a CONNECT missing :authority or carrying :scheme/:path (or a contradicting Host) is now a stream reset, not a 405; well-formed CONNECT still gets 405. A/B-verified, tls-shard test.**
29. **Low: the HPACK decoder accepts dynamic-table size updates after header fields.** A malformed field block can mutate compression state and be served instead of causing `COMPRESSION_ERROR`. **— FIXED: a dynamic-table size update after a field is now COMPRESSION_ERROR (a decode-time flag tracks whether a field preceded it); A/B-verified.**
30. **Medium: the HTTP/2 proxy treats an upstream informational response as final.** A `100 Continue` or `103 Early Hints` response is emitted with `END_STREAM`, and the backend's actual final response is discarded. **— FIXED: a 1xx is now relayed as an interim HEADERS block without `END_STREAM` and the final response still follows (101 is rejected 502); A/B-verified and covered by new tls-shard tests.**
31. **Medium: the HTTP/2 proxy cleanly completes truncated or malformed upstream bodies.** Premature EOF and chunk-decoding errors set `BODY_DONE`, causing a normal `END_STREAM` over incomplete data instead of resetting or failing the response. **— FIXED: a premature EOF or a malformed chunk now routes to the bad-gateway handler (502 before the head, RST_STREAM after); A/B-verified and covered by a new tls-shard test.**
32. **Medium: the HTTP/2 proxy does not coalesce split `cookie` fields before HTTP/1 forwarding.** Each field becomes a separate HTTP/1 header line, which can change cookie parsing and authentication semantics at the backend. **— FIXED: split cookie fields are accumulated in wire order and forwarded as one `"; "`-joined `Cookie` line; A/B-verified and covered by a new tls-shard test.**
33. **Medium: HTTP/2 proxied uploads do not honor `Expect: 100-continue`.** Linnea waits for the complete body before either responding or forwarding the request head, leaving a compliant waiting client stalled until its fallback timer or the server's body timeout. **— FIXED: a proxied request carrying `expect: 100-continue` is answered with an immediate local interim `100` before the body is collected (and the field is stripped upstream); A/B-verified and covered by a new tls-shard test.**
34. **Medium: the HTTP/2 proxy translates malformed upstream fields into malformed HTTP/2 responses.** Invalid field names and values are encoded without syntax checks, while conflicting `content-length` lines are forwarded together instead of producing 502. **— FIXED: the upstream head is validated (token names, colon present, no control bytes, no obsolete fold, agreeing Content-Length) before any translation — violations answer 502 — and identical duplicate Content-Length is normalized to one line; A/B-verified and covered by new tls-shard tests.**

**Verification pass (all findings checked against the code):** findings 3–34 were
each verified against the cited source. Every one is a real code gap — no false
positives — with one nuance: #28 (h2 CONNECT skips validation) is partly deliberate. The
findings split into real correctness/policy issues and a tail of conformance-strictness
gaps where the current lenient behavior (ignore-instead-of-error) is often the safer
choice.

**Fix status.** Finding 1 fixed (earlier). Findings 3, 4, 6, 18, 19, 24 fixed and
suite-tested this pass (commits above; each reproduced pre-fix and A/B-verified).
Finding 2 left as-is (unreachable without transferring ~18 EB). Finding 7 is
now fixed and covered by a coalesced-packet regression. Finding 14 is now fixed
and covered by an injected 1-RTT stream-state regression. Findings 8–9, 15,
and 20 remain open: critical-stream and SETTINGS gaps (8–9), 0-RTT
checks (15), and negotiated UDP-size enforcement (20). Finding 3
is reachable with an ordinary small request whenever
an operator sets `max_body` below the
request-buffer capacity.

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

## Finding 3 — buffered HTTP/1 bodies bypass `max_body`

Severity: Medium (P2 resource-policy bypass and protocol inconsistency)
Confidence: High
Status: **FIXED** — commit 13db631. `.not_chunked` now checks the declared/decoded
length against `max_body` before the buffered/streamed split; regression test
`test/max_body_small.py` (counted + chunked, `max_body=64`, A/B-verified).

### Evidence

The documented `max_body` setting is the largest request body accepted on h1,
h2, and h3. The HTTP/1 parser checks it only in the path that is already too
large to keep together with the request head:

- [`src/server/linnea_http.asm:1606`](/home/linnea/linnea/src/server/linnea_http.asm:1606)
  computes `head_len + Content-Length` and jumps directly to `.body_ready` when
  the combined request fits in `LINNEA_CONN_IN_BUF`.
- The only HTTP/1 counted-body comparison with `max_body` is at
  [`src/server/linnea_http.asm:1620`](/home/linnea/linnea/src/server/linnea_http.asm:1620),
  inside `.body_stream`, so it is not reached for a body that fits in memory.

Complete chunked bodies have the same gap. After
[`src/server/linnea_http.asm:1560`](/home/linnea/linnea/src/server/linnea_http.asm:1560)
decodes and compacts the body, the decoded length is stored as the effective
`Content-Length` and control jumps to `.not_chunked`; there is no comparison of
that decoded length with `max_body` before `.body_ready`.

The large-body capture paths do enforce the cap: the incremental chunked
decoder checks its decoded spill length, and the counted streaming path checks
the declared length. The defect is therefore specifically the ordinary
buffered path, not an inability to parse or capture the body.

### Observable behavior

Configure a proxy with `max_body` below the request-buffer capacity, for example
`max_body = 64`. Send a complete `POST /api/echo` with a 65-byte
`Content-Length` body. The request head plus body is far below the roughly
17 KiB `in_buf`, so it bypasses `.body_stream`; the backend receives all 65
bytes and the client receives a successful echo instead of 413.

The same result occurs with a complete chunked request whose decoded body is
larger than 64 bytes but whose encoded request still fits in `in_buf`. This
means the configured limit behaves differently depending on whether the body
happens to cross the in-memory buffering threshold. HTTP/2 and the reassembled
HTTP/3 path reject the body, but HTTP/1 and the single-frame HTTP/3 path described
in Finding 19 can accept it under the same configuration.

This is not an out-of-bounds write: the request remains within `in_buf`. It is a
policy and resource-accounting bypass. It can defeat an operator's intended
per-request limit and makes the backend receive requests the configuration says
the server will refuse. With a deliberately low limit it is directly
reproducible using a tiny request; with the default 64 MiB limit the bypass
extends only through the fixed in-memory request-buffer size.

### Recommended fix

Apply the configured cap before selecting between buffered and streamed HTTP/1
body handling:

- For `Content-Length`, reject when the declared length exceeds `max_body`,
  regardless of whether `head_len + body_len` fits in `in_buf`.
- For chunked requests that complete in the buffer, compare the decoded body
  length returned by `chunked_decode` before compacting it into the ordinary
  counted-body path.
- Preserve the existing incremental decoded-length and encoded-byte checks for
  chunked bodies that transition to spill capture.
- Keep the current 413 response and refusal/linger behavior, and ensure the
  check applies consistently before static-method handling and proxy forwarding.

### Regression tests to add

- Start a proxy fixture with `max_body = 64` and send a 65-byte counted body
  that fits entirely in `in_buf`; assert 413 and verify the backend saw no
  request.
- Send a 64-byte counted body through the same fixture; assert 200 and an
  exact echo, proving the boundary remains inclusive.
- Repeat both cases with chunked framing and decoded bodies of 65 and 64 bytes;
  include a framing split that still keeps the complete request below the input
  buffer limit.
- Add a control with a body larger than `in_buf` and above `max_body`, confirming
  the existing streamed rejection remains covered.

## Finding 4 — HTTP/2 trailers without `END_STREAM` leave the request open

Severity: Medium (P2 protocol conformance/resource retention)
Confidence: High
Status: **FIXED** — commit 97046ff. A trailer without `END_STREAM` now marks the
collecting slot FAILED/400 (later DATA cannot collect); test `test/tls/h2_malformed.py`,
A/B-verified (pre-fix hung to 408).

### Evidence

The HTTP/2 request assembler identifies a `HEADERS` block as a trailer when
`h2p_find_collect` finds an existing request-body slot:

- [`src/server/linnea_http2.asm:1078`](/home/linnea/linnea/src/server/linnea_http2.asm:1078)
  clears the trailer flag for the new block, and
  [`src/server/linnea_http2.asm:1086`](/home/linnea/linnea/src/server/linnea_http2.asm:1086)
  through [`src/server/linnea_http2.asm:1092`](/home/linnea/linnea/src/server/linnea_http2.asm:1092)
  marks it as a trailer when the stream is still collecting a body.
- The current `HEADERS` frame's `END_STREAM` bit is saved at
  [`src/server/linnea_http2.asm:988`](/home/linnea/linnea/src/server/linnea_http2.asm:988)
  through [`src/server/linnea_http2.asm:990`](/home/linnea/linnea/src/server/linnea_http2.asm:990).
- The trailer path explicitly notes that `END_STREAM` is required, but when the
  bit is absent it jumps straight to `.trailer_ret` at
  [`src/server/linnea_http2.asm:1206`](/home/linnea/linnea/src/server/linnea_http2.asm:1206)
  through [`src/server/linnea_http2.asm:1209`](/home/linnea/linnea/src/server/linnea_http2.asm:1209).
  `.trailer_ret` consumes the frame and writes no response; it does not reset
  the stream, mark the slot failed, or finalize the body.

The slot remains in the collecting state because `h2p_find_collect` only returns
slots whose state is `LINNEA_H2P_COLLECT` at
[`src/server/linnea_http2.asm:2510`](/home/linnea/linnea/src/server/linnea_http2.asm:2510)
through [`src/server/linnea_http2.asm:2533`](/home/linnea/linnea/src/server/linnea_http2.asm:2533).
Consequently, a later `DATA` frame on that stream reaches the ordinary body
collector at [`src/server/linnea_http2.asm:502`](/home/linnea/linnea/src/server/linnea_http2.asm:502)
through [`src/server/linnea_http2.asm:504`](/home/linnea/linnea/src/server/linnea_http2.asm:504),
even though the peer has already sent what it presented as a trailer section.

### Observable behavior

Send a request whose body is collected, then send a trailing `HEADERS` block
with `END_HEADERS` but without `END_STREAM`. The server accepts and consumes the
block but sends no completion. If the peer then sends more `DATA`, those bytes
are appended to the body; if no later end marker arrives, the body slot remains
occupied until its timeout produces a 408.

This violates the HTTP/2 trailer framing rule and makes stream lifetime depend
on a later timeout rather than the malformed frame. On a connection with many
concurrent uploads, a peer can use these incomplete trailers to retain body
slots and capture resources, while also sending data after the point where the
message should have ended.

### Recommended fix

When a collecting stream receives a trailer block without `END_STREAM`, fail
that stream with `RST_STREAM(PROTOCOL_ERROR)` after decoding the block enough to
keep HPACK state synchronized. Release or mark failed the request-body slot so
later `DATA` cannot be collected. Preserve the existing successful trailer path
for `END_STREAM` and the existing stream-only handling for pseudo-headers in
trailers.

### Regression tests to add

- Send a POST body followed by a trailer `HEADERS` frame lacking `END_STREAM`;
  assert a stream reset, no upstream request, and no connection-wide GOAWAY.
- After the malformed trailer, send another `DATA` frame on that stream and
  verify it is not captured or forwarded; then prove a new stream still works.
- Keep the existing valid trailer cases, including a trailer with an HPACK
  dynamic-table insertion and `END_STREAM`, as controls.

## Finding 5 — HTTP/2 ignores stream frames whose IDs have no live slot

Severity: Medium (P2 protocol-state and flow-control handling)
Confidence: High
Status: **FIXED (idle-stream case)** — DATA, WINDOW_UPDATE and RST_STREAM now
check the target stream before their slot lookup: an even id, or one above the
highest stream opened (`h2_last_stream`), is an idle stream and draws a
connection `PROTOCOL_ERROR` (RFC 9113 5.1/5.1.1) rather than being silently
consumed. A closed stream (an odd id at or below `h2_last_stream` with no live
slot) keeps the existing lenient handling — DATA is dropped with its window
credited, a late WINDOW_UPDATE or RST_STREAM is ignored — which RFC 9113 5.1
permits for a recently closed stream. A/B-verified: DATA/WINDOW_UPDATE/RST on an
idle or even stream were silently ignored before and now draw
GOAWAY(PROTOCOL_ERROR); a normal POST body, a GET, and a late DATA on a closed
stream are unaffected. Regression cases in `test/tls/h2_frame_validation.py`.

Scoped out (documented): DATA on a *closed* stream is dropped rather than
answered with a `STREAM_CLOSED` stream reset. That is bounded, non-harmful work
(the window is credited back), and the RFC explicitly allows ignoring frames on
a recently closed stream; a per-frame reset would add reset noise for no
security gain.

### Evidence

For every `DATA` frame, the connection looks only for a collecting proxy-body
slot. If none exists, the path jumps directly to `.fd_done` at
[`src/server/linnea_http2.asm:489`](/home/linnea/linnea/src/server/linnea_http2.asm:489)
through [`src/server/linnea_http2.asm:504`](/home/linnea/linnea/src/server/linnea_http2.asm:504).
There is no check that the stream is open, remotely writable, or even a stream
the peer has opened. The frame is therefore discarded without a stream reset or
connection error.

The same state loss affects positive `WINDOW_UPDATE` frames. The handler looks
up only an active response slot at
[`src/server/linnea_http2.asm:358`](/home/linnea/linnea/src/server/linnea_http2.asm:358)
through [`src/server/linnea_http2.asm:372`](/home/linnea/linnea/src/server/linnea_http2.asm:372);
when `h2_slot_find` returns no slot, it jumps to `.f_ignore`. There is no
distinction between an idle stream ID, a previously closed stream, and a stream
whose response slot has already been reaped.

`RST_STREAM` has the same lookup-only behavior after its stream-zero check. A
miss is consumed without distinguishing an idle stream from a closed one at
[`src/server/linnea_http2.asm:373`](/home/linnea/linnea/src/server/linnea_http2.asm:373)
through [`src/server/linnea_http2.asm:413`](/home/linnea/linnea/src/server/linnea_http2.asm:413).
[RFC 9113 section 6.4](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.4)
requires `RST_STREAM` on an idle stream to be a connection error. By contrast,
late `WINDOW_UPDATE` and `RST_STREAM` frames on a closed stream can legitimately
be ignored because they might have been in flight before closure; the defect is
the inability to tell that permitted case from an idle stream.

The `DATA` discard path does issue a connection-level `WINDOW_UPDATE` when the
payload is non-empty, but it never sets `h2_fd_sid` for a nonexistent slot, so
the corresponding stream-level credit is absent. This lets malformed input
consume parser work while keeping the connection window open, without applying
the stream-state errors required by HTTP/2. The existing slot-only lookup also
means the server cannot report the correct difference between an idle-stream
connection error and a closed-stream error.

### Observable behavior

After a request on stream 1 has ended, send `DATA` on stream 1. The server
silently drops the frame instead of returning a `STREAM_CLOSED` stream error.
Send `DATA` on an odd stream ID that has never been opened: the server likewise
keeps the connection alive and replenishes only the connection window. A
positive `WINDOW_UPDATE` or `RST_STREAM` on an idle stream is also silently
ignored. A frame on a reaped stream gets the same behavior even where the RFC's
closed-stream rules differ.

These cases allow a malformed peer to bypass required stream-state validation
and to generate unbounded frame-processing work on a connection that should have
been terminated or reset. They also leave the peer's view of per-stream flow
control inconsistent with the server's handling of the discarded payload.

### Recommended fix

Track request/stream state independently of the response-body slot. Validate
the stream state before consuming `DATA` or applying `WINDOW_UPDATE`:

- reject `DATA` on idle streams with a connection error;
- reset `DATA` on closed or remotely closed streams with `STREAM_CLOSED`; and
- reject `WINDOW_UPDATE` and `RST_STREAM` on idle streams with a connection
  error while retaining the RFC-permitted tolerance for late frames on closed
  streams.

Only issue receive-window credit for a valid open stream whose body was actually
consumed. Add explicit state transitions when a request ends, when a stream is
reset, and when the response slot is reaped so a closed stream remains
distinguishable from an idle one.

### Regression tests to add

- Complete a normal request, then send `DATA` on its closed stream; require a
  `STREAM_CLOSED` reset while keeping a separate stream usable.
- Send `DATA` on a never-opened odd stream ID; require a connection-level
  `PROTOCOL_ERROR` rather than a `WINDOW_UPDATE` and continued service.
- Send positive `WINDOW_UPDATE` and `RST_STREAM` frames on both idle and closed
  stream IDs and assert the protocol-specific error or permitted-ignore
  behavior.

## Finding 6 — QUIC receive flow control counts duplicate stream bytes

Severity: Medium (P2 flow-control/resource-accounting bypass)
Confidence: High
Status: **FIXED** — per-stream high-water accounting and a fresh-packet-number
regression test were added in this pass.

### Evidence

Before the fix, the QUIC receive path incremented the connection-wide byte counter
for every parsed `STREAM` frame before dispatching the frame to HTTP/3 or
reassembly:

- [`src/server/linnea_quic_server.asm:2431`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2431)
  through [`src/server/linnea_quic_server.asm:2436`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2436)
  add the frame length directly to `fc_recv`.
- The packet duplicate filter only identifies a repeated packet number at
  [`src/server/linnea_quic_server.asm:2054`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2054)
  through [`src/server/linnea_quic_server.asm:2062`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2062).
  A valid retransmission carries the same stream bytes under a new packet
  number, so it reaches the counter again.
- The per-stream path then trims bytes below its floor as already consumed at
  [`src/server/linnea_quic_server.asm:2601`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2601)
  through [`src/server/linnea_quic_server.asm:2623`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2623),
  and its arrival bitmap marks received ranges at
  [`src/server/linnea_quic_server.asm:2747`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2747)
  onward. Thus the global counter can grow even when no new stream offset is
  accepted.

The inflated counter drove a new connection-level ceiling and queued
`MAX_DATA` at [`src/server/linnea_quic_server.asm:2437`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2437)
through [`src/server/linnea_quic_server.asm:2445`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2445).
The advertised connection credit is supposed to cover the stream receive
high-water, not repeated copies of the same offsets.

### Observable behavior

Send the same valid `STREAM` offset and payload repeatedly under fresh packet
numbers. The server accepts the first copy, discards or rewrites the later
copies during reassembly, but advances `fc_recv` for every copy and eventually
advertises additional `MAX_DATA`. The peer can then spend that artificial
connection credit on new stream data, exceeding the intended aggregate receive
window while still consuming CPU in the frame and reassembly paths.

The existing duplicate body test repeats identical datagrams, so the packet
number filter drops those copies before this accounting path. It does not cover
the required fresh-packet-number retransmission shape.

### Resolution

`src/server/linnea_quic_server.asm` no longer adds the raw STREAM-frame length to
`fc_recv`. Reassembled request contexts now retain an absolute `.fc_hi`; each
frame charges only the amount by which its end offset advances that high-water,
which remains correct as the request window slides and as body bytes move to the
capture file. The copy-free offset-zero-plus-FIN path charges only after its
active, reset, and already-served checks. Client unidirectional streams use a
bounded per-connection stream-id/high-water table, so control and QPACK
retransmissions are deduplicated as well. A shared helper performs the
`MAX_DATA` grant calculation for all three paths.

### Regression coverage

- `test/quic/h3_fc_dedup_test.py` constructs valid packets with the same stream
  offset and payload under enough distinct packet numbers to cross the grant
  threshold; duplicate copies do not trigger a connection-level credit increase.
- The existing same-datagram duplicate tests remain coverage for packet-number
  deduplication; the new test specifically covers fresh packet numbers.

## Finding 7 — only the first coalesced 0-RTT packet is processed

Severity: Medium (P2 early-data availability and QUIC conformance)
Confidence: High
Status: **FIXED** — the early walk now processes every coalesced 0-RTT packet.

### Evidence

The early-data walk is designed to step through coalesced long-header packets:
[`src/server/linnea_quic_server.asm:1687`](/home/linnea/linnea/src/server/linnea_quic_server.asm:1687)
through [`src/server/linnea_quic_server.asm:1715`](/home/linnea/linnea/src/server/linnea_quic_server.asm:1715)
advance `r15` when skipping an Initial. When the cursor reaches a 0-RTT packet,
however, `.ew_zrtt` decrypts one packet and falls through to `.early_done` at
[`src/server/linnea_quic_server.asm:1716`](/home/linnea/linnea/src/server/linnea_quic_server.asm:1716)
through [`src/server/linnea_quic_server.asm:1748`](/home/linnea/linnea/src/server/linnea_quic_server.asm:1748).
It never advances `r15` to the next packet or returns to `.ew_loop`.

Only that packet's plaintext is copied into the single `early_buf` and its
packet number is recorded for the later ACK. The handshake completion path then
serves that one buffer at [`src/server/linnea_quic_server.asm:1961`](/home/linnea/linnea/src/server/linnea_quic_server.asm:1961)
through [`src/server/linnea_quic_server.asm:1975`](/home/linnea/linnea/src/server/linnea_quic_server.asm:1975).

QUIC permits multiple 0-RTT packets to be coalesced in one datagram. A request
larger than one packet, or multiple early streams in one flight, can therefore
put valid early data after the first packet that this code opens.

### Observable behavior

The first early packet is acknowledged and buffered; later 0-RTT packets in the
same datagram are ignored. A multi-packet request is served only after the
client retransmits the missing bytes in 1-RTT, and a second early request can
remain unanswered until retransmission. The server also fails to acknowledge
the ignored 0-RTT packet numbers, contrary to the early-data packet handling
requirement.

### Recommended fix

Advance through every coalesced packet using each packet's protected length,
decrypt and record every valid 0-RTT packet number, and merge all early stream
frames through the normal per-stream reassembly path. If the implementation
keeps a bounded early-data buffer, reject or defer excess data explicitly rather
than silently ending the walk after the first packet.

### Resolution

The early-data walker now decodes the protected length of each 0-RTT packet,
advances to the next packet in the datagram, and records every successfully
opened packet number in the shared application ACK state. Decrypted frame bytes
are appended to a bounded 16 KiB per-connection buffer instead of replacing the
previous packet. Once 1-RTT keys are available, the combined bytes are replayed
directly through the ordinary stream scanner, so both independent requests and
requests split across early packets use the existing per-stream reassembly.

If the bounded capture would overflow, the walker continues acknowledging valid
packets but marks the early flight refused; handshake completion sends an
explicit `H3_REQUEST_REJECTED` connection close rather than silently dropping a
prefix.

### Regression tests to add

- Build a valid coalesced datagram containing two 0-RTT packets and assert both
  packet numbers are acknowledged.
- Put one complete request in each packet and assert both responses arrive
  without 1-RTT retransmission.
- Put one request across two early packets and assert it is assembled and served
  directly from early data.

`test/quic/h3_0rtt_coalesced_test.py` covers all three cases against the
production server: two complete requests in separate coalesced packets, one
request split across two packets, and ACK coverage for both early packet
numbers.

## Finding 8 — HTTP/3 SETTINGS validation is bounded and partially discarded

Severity: Low (P3 protocol-conformance gap)
Confidence: High
Status: **OPEN** — no source or test changes were made during this audit-only pass.

### Evidence

The control-stream walk captures a SETTINGS payload only when its declared size
fits the 64-byte `LINNEA_QUIC_PU_BUF` at
[`src/server/linnea_quic_server.asm:4304`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4304)
through [`src/server/linnea_quic_server.asm:4314`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4314).
For a larger payload it simply continues skipping the frame, so reserved setting
identifiers, duplicate identifiers, and a truncated final varint are never
checked.

Even within the capture limit, `.settings_apply` records only 32 identifiers.
Once that list is full, [`src/server/linnea_quic_server.asm:4687`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4687)
through [`src/server/linnea_quic_server.asm:4691`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4691)
stop recording new identifiers while continuing to parse, so a duplicate after
32 entries is accepted. The setting values are read but not retained at
[`src/server/linnea_quic_server.asm:4663`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4663)
through [`src/server/linnea_quic_server.asm:4668`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4668);
in particular, the peer's `MAX_FIELD_SECTION_SIZE` is not available when the
server builds response headers, as the nearby comment acknowledges at
[`src/server/linnea_quic_server.asm:4631`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4631)
through [`src/server/linnea_quic_server.asm:4635`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4635).

### Observable behavior

Send a SETTINGS frame longer than the capture buffer whose tail is malformed;
the connection stays open. Send more than 32 unique identifiers followed by a
repeat; the repeat is not rejected. A client that advertises a very small
maximum response field section can also receive a larger response header because
the value is discarded.

### Recommended fix

Validate SETTINGS incrementally while the control stream is walked instead of
skipping payloads that do not fit a fixed buffer. Track duplicate identifiers in
a bounded structure sized for the configured frame limit or reject a frame that
exceeds an explicit policy limit after validating its framing. Retain and apply
the peer's response field-section limit when encoding HTTP/3 response headers.

### Regression tests to add

- Send a SETTINGS payload larger than the current capture buffer with a
  truncated final pair and require `H3_FRAME_ERROR`.
- Send 33 unique identifiers followed by a duplicate and require the selected
  duplicate-setting error.
- Advertise a tiny `MAX_FIELD_SECTION_SIZE` and verify response construction
  stays within it or fails in a defined, stream-safe way.

## Finding 9 — reordered critical-stream closure is forgotten before typing

Severity: Low (P3 HTTP/3 critical-stream enforcement gap)
Confidence: High
Status: **OPEN** — no source or test changes were made during this audit-only pass.

### Evidence

The QUIC receive loop exposes the FIN flag only in the transient `s_sfin` global
at [`src/server/linnea_quic_server.asm:2428`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2428)
through [`src/server/linnea_quic_server.asm:2430`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2430).
When a unidirectional continuation arrives before its offset-zero type frame,
`.uni_cont_untyped` stores only its bytes in `.ctrl_ro_capture` at
[`src/server/linnea_quic_server.asm:4166`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4166)
through [`src/server/linnea_quic_server.asm:4174`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4174);
the capture structure has no final-size/FIN field. When the type later arrives,
the control or QPACK handler checks only that current typing frame's FIN at
[`src/server/linnea_quic_server.asm:4069`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4069)
through [`src/server/linnea_quic_server.asm:4071`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4071)
and [`src/server/linnea_quic_server.asm:4139`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4139)
through [`src/server/linnea_quic_server.asm:4142`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4142).

RESET_STREAM and STOP_SENDING have the same ordering gap. The receive-side reset
scan rejects a critical stream only if its ID has already been recorded at
[`src/server/linnea_quic_server.asm:2226`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2226)
through [`src/server/linnea_quic_server.asm:2250`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2250).
An early reset for an as-yet-untyped stream is treated as an ordinary request
teardown; a later reordered type frame can then register the critical stream
without closing the connection.

### Observable behavior

Deliver a continuation carrying FIN before the packet containing the control
stream's type byte, or deliver RESET_STREAM before that type packet. The server
can continue after the critical stream has already been closed, whereas the same
closure delivered after typing produces `H3_CLOSED_CRITICAL_STREAM`.

This is primarily a protocol-enforcement gap, but it also leaves the connection
with a critical stream that the implementation believes is still available.

### Recommended fix

Track per-unidirectional-stream final-size and reset/stop state even before the
type is known. When the type frame arrives, reconcile that state immediately and
raise `H3_CLOSED_CRITICAL_STREAM` for control or QPACK streams. Preserve the
existing ordered fast path.

### Regression tests to add

- Send a control stream's continuation with FIN, hold the type packet back, then
  deliver the type and require `H3_CLOSED_CRITICAL_STREAM`.
- Repeat with QPACK encoder and decoder streams.
- Deliver RESET_STREAM and STOP_SENDING before the type frame and require the
  same close code after the type is learned.

## Finding 10 — duplicate QPACK streams are accepted

Severity: Low (P3 HTTP/3 stream-creation conformance)
Confidence: High
Status: **FIXED** — the QPACK encoder and decoder handlers now mirror the
control-stream check: a stream id already recorded and different from the new
one draws `H3_STREAM_CREATION_ERROR` (0x0103, RFC 9114 6.2.1) instead of
overwriting the saved id; the same id again is treated as a retransmit of the
type frame. A/B-verified against a pre-fix binary: a second client
unidirectional stream typed `0x02` (QPACK encoder) was accepted before (the id
was silently replaced) and now closes the connection `0x0103`; a normal h3
request is unaffected. Regression test `test/quic/h3_dup_qpack.py`.

### Evidence

The control-stream path explicitly rejects a second control stream by comparing
the existing ID at [`src/server/linnea_quic_server.asm:4143`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4143)
through [`src/server/linnea_quic_server.asm:4151`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4151).
The QPACK path performs no equivalent check: each encoder or decoder stream
simply overwrites the saved ID at
[`src/server/linnea_quic_server.asm:4076`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4076)
through [`src/server/linnea_quic_server.asm:4092`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4092).
After the overwrite, reset handling tracks only the newest ID, so the original
critical stream is no longer recognized either.

### Observable behavior

Open two client unidirectional streams with type `0x02`, or two with type
`0x03`, after the normal control/QPACK setup. The connection remains usable and
the second ID replaces the first instead of producing the required stream
creation error.

### Recommended fix

Before recording a QPACK encoder or decoder ID, check whether that slot is already
nonzero and close with `H3_STREAM_CREATION_ERROR` if so. Keep the original ID
intact on the error path so reset/closure handling cannot lose the first stream.

### Regression tests to add

- Open a valid control stream and two QPACK encoder streams; require
  `H3_STREAM_CREATION_ERROR`.
- Repeat with two decoder streams and verify that a single encoder plus a single
  decoder remains accepted.
- Reset the first stream in a duplicate attempt and verify the connection still
  reports the critical-stream violation rather than silently forgetting it.

## Finding 11 — completed HTTP/3 request streams can be dispatched again

Severity: High (P1 duplicate application execution / request integrity)  
Confidence: High  
Status: **FIXED** (commit `05f0194`) — receive-stream completion is now retained
independently of response ownership. A compact per-connection watermark plus a
small ring of out-of-order completed stream IDs (`req_served_lo`,
`req_served_ids`, `req_served_cursor`) records every dispatched request; at
`.serve_bidi` a stream already known served is acknowledged rather than routed
again (`req_served_known` / `req_served_mark`), so a fresh-packet-number
retransmission after an inline reply, or after a response slot is reaped, no
longer reaches the application a second time. A/B-verified by hand-injecting the
exact same STREAM frame under a fresh packet number (aioquic will not retransmit
a small completed request): pre-fix 4 dispatches, fixed 1. Regression test
`test/quic/h3_dup_served.py`; the existing active-large-response duplicate test
is kept as a control.

### Evidence

The receive path suppresses a retransmitted request only while its stream ID is
present in an active response slot or the small refusal/cancellation ring:

- [`src/server/linnea_quic_server.asm:3236`](/home/linnea/linnea/src/server/linnea_quic_server.asm:3236)
  through [`src/server/linnea_quic_server.asm:3257`](/home/linnea/linnea/src/server/linnea_quic_server.asm:3257)
  scan only active `tx_streams` entries.
- The following check at
  [`src/server/linnea_quic_server.asm:3258`](/home/linnea/linnea/src/server/linnea_quic_server.asm:3258)
  through [`src/server/linnea_quic_server.asm:3269`](/home/linnea/linnea/src/server/linnea_quic_server.asm:3269)
  covers IDs remembered by `rst_remember`, but successful streams are never put
  in that ring. Its two call sites are the no-reassembly-slot refusal at
  [`src/server/linnea_quic_server.asm:3217`](/home/linnea/linnea/src/server/linnea_quic_server.asm:3217)
  and peer cancellation at
  [`src/server/linnea_quic_server.asm:6836`](/home/linnea/linnea/src/server/linnea_quic_server.asm:6836).

An offset-zero STREAM carrying FIN takes the direct path to `.serve_bidi` at
[`src/server/linnea_quic_server.asm:2474`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2474).
An inline response is sent and immediately forgotten at
[`src/server/linnea_quic_server.asm:3827`](/home/linnea/linnea/src/server/linnea_quic_server.asm:3827)
through [`src/server/linnea_quic_server.asm:3841`](/home/linnea/linnea/src/server/linnea_quic_server.asm:3841),
so there is no active slot on the very next receive pass. Large and proxied
responses are protected while their slot is active, but the slot is cleared
after its bytes are acknowledged at
[`src/server/linnea_quic_server.asm:6253`](/home/linnea/linnea/src/server/linnea_quic_server.asm:6253)
through [`src/server/linnea_quic_server.asm:6273`](/home/linnea/linnea/src/server/linnea_quic_server.asm:6273),
again without retaining successful receive-stream state.

QUIC retransmits STREAM data in a new packet number. Packet-number duplicate
filtering therefore cannot substitute for stream-offset deduplication. QUIC is
supposed to expose one reliable ordered byte stream to HTTP/3, not repeated
application messages; see [RFC 9000 section 2.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-2.2).

### Observable behavior

Lose an inline response packet, including its ACK of the request, and let the
client retransmit the same FIN-bearing request bytes under a fresh packet
number. The second copy passes both duplicate checks and invokes routing again.
For a slotted response, a delayed retransmission can likewise arrive after the
client's response ACK has reached the server and reaped the slot. A proxied
non-idempotent request can consequently be sent upstream twice.

The existing `h3_dup_request_test.py` exercises large responses while their
slots remain active. It proves the active-slot guard but not the post-inline or
post-reap state.

### Recommended fix

Retain receive-stream completion state independently of response ownership.
Completed request stream IDs and their final sizes need to remain recognizable
for the life of the connection, including after an inline response or response
slot reap. Because request streams can finish out of order, use a compact
watermark plus sparse completed ranges or another bounded state design that
cannot forget a still-retransmittable stream merely because later requests ran.

### Regression tests to add

- Drop an inline response/ACK, retransmit the exact request stream under a fresh
  packet number, and assert one access-log/application dispatch.
- Delay a retransmitted proxied POST until after its response slot is reaped;
  assert the backend receives the request once.
- Keep the existing active-large-response duplicate test as a control.

## Finding 12 — QUIC final-size invariants are not enforced

Severity: Medium (P2 transport-state integrity and stream availability)  
Confidence: High  
Status: **FIXED (FIN side)** — a stream's final size is now fixed once a FIN
learns it. Both FIN-recording sites (the window path and the direct-to-file body
path) check the size a FIN declares against any already stored: a repeat FIN
must name the same size, and on the window path the size must be at least the
highest byte already received (`base + .hi`). A new byte range whose absolute
extent runs past a fixed final size is also rejected, in the `.hi` update. All
three route to a new `.ra_final_size_error` that releases the context and closes
the connection with transport error `0x06` (`FINAL_SIZE_ERROR`, RFC 9000 4.5),
mirroring the existing `FLOW_CONTROL_ERROR` path. A/B-verified against a pre-fix
binary with hand-injected 1-RTT packets (`test/quic/h3_final_size.py`): two FINs
with a decreasing size, two FINs with an increasing size, and data past a
declared final all silently succeeded before and now close `0x06`.

**Scoped out (documented):** the RESET_STREAM final-size cross-check.
`linnea_quic_reset_scan` still records only the stream id, and `reset_teardown`
releases the reassembly context regardless — so a RESET_STREAM whose final size
contradicts a prior FIN is not itself a `FINAL_SIZE_ERROR`. This leaves no
inconsistent transport state (the stream is torn down either way, and
`rst_remember`/`rst_known` keep a reset stream from being served or re-dispatched
by a later frame), and fully enforcing it would require both widening the shared
frame scanner to carry the final size and a persistent per-stream final-size
table to catch a RESET-then-FIN after teardown — disproportionate to the
residual risk, which is nil for transport integrity.

### Evidence

Each reassembly context has one `fin` flag and one `final` offset at
[`include/linnea_quic_conn.inc:519`](/home/linnea/linnea/include/linnea_quic_conn.inc:519)
through [`include/linnea_quic_conn.inc:522`](/home/linnea/linnea/include/linnea_quic_conn.inc:522).
Every FIN-bearing STREAM frame unconditionally sets the flag and overwrites the
stored final size:

- [`src/server/linnea_quic_server.asm:2669`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2669)
  through [`src/server/linnea_quic_server.asm:2676`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2676)
  on the direct-body path; and
- [`src/server/linnea_quic_server.asm:2804`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2804)
  through [`src/server/linnea_quic_server.asm:2809`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2809)
  on the normal window path.

Completion merely compares the current contiguous end with whichever value was
written most recently at
[`src/server/linnea_quic_server.asm:2821`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2821)
through [`src/server/linnea_quic_server.asm:2854`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2854).
There is no check for a changed final size or for already-seen data extending
beyond it.

RESET_STREAM handling also loses the information needed for this invariant.
`linnea_quic_reset_scan` decodes the final-size field at
[`src/lib/linnea_quic.asm:2727`](/home/linnea/linnea/src/lib/linnea_quic.asm:2727)
through [`src/lib/linnea_quic.asm:2741`](/home/linnea/linnea/src/lib/linnea_quic.asm:2741),
but records only the stream ID. `reset_teardown` therefore cannot compare that
size with a prior FIN, prior RESET_STREAM, or the highest received offset.

[RFC 9000 section 4.5](https://www.rfc-editor.org/rfc/rfc9000.html#section-4.5)
requires a fixed final size once learned and requires `FINAL_SIZE_ERROR` for a
conflict or data beyond it.

### Observable behavior

Send two FIN-bearing STREAM frames for one incomplete request with different
end offsets. The second frame changes the target size instead of closing the
connection. Raising it can leave the reassembly context waiting forever for
bytes the first final size said did not exist; lowering it can change which
prefix is treated as complete. A conflicting RESET_STREAM is accepted and its
final size discarded.

### Recommended fix

Introduce one final-size setter shared by FIN and RESET_STREAM processing. On
the first signal, store the size; afterward require equality, require the size
to be at least the highest received offset, and reject any later byte range
past it with transport error `0x06` (`FINAL_SIZE_ERROR`). Preserve final-size
state after request completion so delayed frames are checked too.

### Regression tests to add

- Send two FINs with increasing and decreasing final offsets; require
  `FINAL_SIZE_ERROR` in both orders.
- Combine FIN then RESET_STREAM, and RESET_STREAM then FIN, with disagreeing
  sizes.
- Send data ending beyond an already declared final size, including a duplicate
  range that straddles the boundary.

## Finding 13 — QUIC transport-parameter validation accepts malformed input

Severity: Medium (P2 handshake validation and protocol conformance)  
Confidence: High  
Status: **FIXED** — `linnea_quic_tp_parse` now treats malformed structure as an
error rather than a clean end of the list: a truncated id, length, or payload,
and an integer value whose varint does not fill its payload exactly, all set
`linnea_quic_tp_error` (the caller closes TRANSPORT_PARAMETER_ERROR). Every
parameter id below 64 is tracked in a bitmap so a duplicate is rejected; the
client-forbidden server-only parameters (`0x00`, `0x02`, `0x0d`, `0x10`) are
rejected; `ack_delay_exponent > 20` and `max_ack_delay >= 2^14` now error rather
than silently keeping the default or storing an illegal value; and the two
`max_streams` parameters (`0x08`, `0x09`) are rejected above `2^60`. A latent bug
was fixed on the way: `max_ack_delay` fell through into the
`initial_source_connection_id` handler, treating its payload as a CID. A/B-verified
against a pre-fix binary via a monkey-patched aioquic client that appends
malformed parameters to its valid ones: a truncated, duplicate, server-only, and
trailing-byte parameter each completed the handshake before and now close it
`0x08`; a normal aioquic client is unaffected. Regression test
`test/quic/tp_validation.py`.

### Evidence

`linnea_quic_tp_parse` treats malformed structure as a successful end of the
list. A truncated parameter ID, length, or payload jumps to `.tp_done` at
[`src/lib/linnea_quic.asm:1965`](/home/linnea/linnea/src/lib/linnea_quic.asm:1965)
through [`src/lib/linnea_quic.asm:1985`](/home/linnea/linnea/src/lib/linnea_quic.asm:1985),
returning values already gathered without setting `linnea_quic_tp_error`.
Recognized integer parameters decode one varint but do not require its encoded
length to equal the parameter payload length at
[`src/lib/linnea_quic.asm:2006`](/home/linnea/linnea/src/lib/linnea_quic.asm:2006)
through [`src/lib/linnea_quic.asm:2015`](/home/linnea/linnea/src/lib/linnea_quic.asm:2015),
so trailing bytes are accepted.

There is no duplicate-ID tracking; later recognized values overwrite earlier
ones and repeated unknown IDs are skipped. Invalid `ack_delay_exponent` values
above 20 silently retain the default at
[`src/lib/linnea_quic.asm:2031`](/home/linnea/linnea/src/lib/linnea_quic.asm:2031)
through [`src/lib/linnea_quic.asm:2037`](/home/linnea/linnea/src/lib/linnea_quic.asm:2037).
`max_ack_delay` is stored without its `< 2^14` check, and
`initial_max_streams_uni` is stored without the `2^60` ceiling. Client-forbidden
server-only parameters are not recognized and are therefore skipped.

The handshake caller closes only when `linnea_quic_tp_error` was explicitly set
at [`src/server/linnea_quic_server.asm:1307`](/home/linnea/linnea/src/server/linnea_quic_server.asm:1307)
through [`src/server/linnea_quic_server.asm:1318`](/home/linnea/linnea/src/server/linnea_quic_server.asm:1318).
Consequently, a valid `initial_source_connection_id` followed by malformed or
forbidden parameters completes the handshake. These cases are rejected by the
rules in [RFC 9000 section 7.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-7.4)
and [section 18.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2).

### Observable behavior

A client can authenticate the required source CID first, append a truncated
parameter, and still receive a ServerHello. It can send duplicate flow-control
parameters and make the last one win, encode an integer plus extra payload
bytes, or include `preferred_address`, `stateless_reset_token`, or another
server-only parameter without receiving `TRANSPORT_PARAMETER_ERROR`.

### Recommended fix

Make parsing return an explicit success/error result, require exact consumption
of each parameter payload, track every received identifier for duplicate
rejection, and validate role and value constraints before committing any
parsed value to the connection. Keep unknown parameters ignorable, but still
enforce their declared lengths and duplicate rule.

### Regression tests to add

- Put a truncated ID, length, and value after a valid source-CID parameter and
  require `TRANSPORT_PARAMETER_ERROR`.
- Test duplicate known and unknown identifiers and integer payloads with extra
  bytes.
- Test client-forbidden server-only parameters, `ack_delay_exponent = 21`,
  `max_ack_delay = 2^14`, and stream limits above `2^60`.

## Finding 14 — QUIC frame stream direction and state are not validated

Severity: Medium (P2 transport-state enforcement)  
Confidence: High  
Status: **FIXED** — stream-scoped transport frames are validated before the
specialized receive scanners.

### Evidence

The stream-limit helper examines stream IDs only to enforce the ordinal limit.
When bits 0–1 identify a server-initiated stream, it skips the frame at
[`src/lib/linnea_quic.asm:3646`](/home/linnea/linnea/src/lib/linnea_quic.asm:3646)
through [`src/lib/linnea_quic.asm:3657`](/home/linnea/linnea/src/lib/linnea_quic.asm:3657)
without asking whether that stream exists or whether the client is allowed to
send on it.

The main STREAM loop repeats that behavior: client bidirectional and
unidirectional IDs are dispatched, while IDs with server initiator bits are
silently ignored at
[`src/server/linnea_quic_server.asm:2447`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2447)
through [`src/server/linnea_quic_server.asm:2452`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2452).
Thus client STREAM data on an unopened server bidirectional stream or a
server-initiated send-only stream is authenticated and ACKed rather than
causing `STREAM_STATE_ERROR`.

The same state distinction is absent from the generic scans for RESET_STREAM,
STOP_SENDING, MAX_STREAM_DATA, and STREAM_DATA_BLOCKED. In particular,
`linnea_quic_reset_scan` records cancellation IDs without direction checks at
[`src/lib/linnea_quic.asm:2715`](/home/linnea/linnea/src/lib/linnea_quic.asm:2715)
through [`src/lib/linnea_quic.asm:2748`](/home/linnea/linnea/src/lib/linnea_quic.asm:2748),
and the server then tears matching state down.

[RFC 9000 section 3.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-3.1)
and the individual frame definitions require stream-state errors when a frame
is impossible for the stream's initiator, direction, or creation state.

### Observable behavior

Send a STREAM frame naming server unidirectional stream 3 or an uncreated
server bidirectional stream. The packet is ACKed and the frame disappears. Send
STOP_SENDING or MAX_STREAM_DATA in an invalid direction and it is likewise
ignored or applied through slot-only state rather than closing the connection.

### Recommended fix

Add one stream-state validator before the specialized scanners. It should
classify stream initiator, direction, whether the stream has been opened, and
which send/receive halves still exist, then validate each frame type's allowed
state. Keep ordinal limit errors separate from state/direction errors.

### Regression tests to add

- Send STREAM on a server unidirectional stream and on an unopened server
  bidirectional stream; assert the required transport error.
- Exercise RESET_STREAM, STOP_SENDING, MAX_STREAM_DATA, and
  STREAM_DATA_BLOCKED in both legal and illegal directions.
- Verify a legal STOP_SENDING for an active server response still cancels only
  that response.

### Resolution

`linnea_quic_stream_state` now runs after structural frame validation and before
ACK, reset, flow-control, and STREAM processing. It classifies the stream ID's
initiator and direction for STREAM, RESET_STREAM, STOP_SENDING,
MAX_STREAM_DATA, and STREAM_DATA_BLOCKED. Server-initiated bidirectional IDs
are rejected because this implementation opens none; the fixed HTTP/3
unidirectional IDs 3, 7, and 11 are accepted only for peer receive-side
controls. Client unidirectional send-side controls are accepted, while
STOP_SENDING and MAX_STREAM_DATA on that send-only direction draw
`STREAM_STATE_ERROR`. Stream ordinal enforcement remains in the separate
`STREAM_LIMIT_ERROR` validator.

`test/quic/h3_stream_state_test.py` hand-injects valid 1-RTT packets for the
invalid STREAM, RESET_STREAM, STOP_SENDING, MAX_STREAM_DATA, and
STREAM_DATA_BLOCKED cases and requires transport error `0x05`.

## Finding 15 — 0-RTT bypasses normal frame and stream-limit validation

Severity: Medium (P2 early-data protocol and resource-limit bypass)  
Confidence: High  
Status: **FIXED** — accepted early data now runs the SAME validate+scan pipeline a
1-RTT packet does, instead of jumping straight into the STREAM scanner. The
pipeline's frame buffer became a pointer (`s_scan_buf`): `plaintext` for a 1-RTT
packet, the connection's `early_buf` for 0-RTT, so the one block validates and
scans either. An `s_is_early` flag adds one 0-RTT-specific step — a new
`linnea_quic_frames_0rtt_ok` that rejects the frames RFC 9000 12.5 forbids in a
0-RTT packet (ACK, CRYPTO, NEW_TOKEN, PATH_RESPONSE, HANDSHAKE_DONE) with
PROTOCOL_VIOLATION. Early data is therefore now subject to frame-encoding
(`frames_check`), 0-RTT-forbidden-frame, stream-state (`stream_state`) and
stream-limit (`stream_limit`) checks, and its legal RESET_STREAM/flow-control/CID
frames are acted on by the same scans. No behaviour change for a normal early GET
(the added scans are no-ops on it); the existing 0-RTT, coalesced-0-RTT and
0-RTT-ack tests still pass, including a multi-packet flight larger than
`plaintext`. A/B-verified against a pre-fix binary on a parallel port with
`test/quic/h3_0rtt_validation.py`, which crafts the early packet by hand and
encrypts it with aioquic's own 0-RTT keys: an ACK or CRYPTO ahead of a valid early
GET now closes PROTOCOL_VIOLATION (was served, no close), and an early STREAM above
the granted limit closes STREAM_LIMIT_ERROR (was served) — three checks that all
failed pre-fix and pass now.

### Evidence

Accepted early frames are copied into `early_buf` at
[`src/server/linnea_quic_server.asm:1717`](/home/linnea/linnea/src/server/linnea_quic_server.asm:1717)
through [`src/server/linnea_quic_server.asm:1747`](/home/linnea/linnea/src/server/linnea_quic_server.asm:1747).
After handshake completion, that buffer is copied to `plaintext` and control
jumps directly to `.stream_scan` at
[`src/server/linnea_quic_server.asm:1961`](/home/linnea/linnea/src/server/linnea_quic_server.asm:1961)
through [`src/server/linnea_quic_server.asm:1975`](/home/linnea/linnea/src/server/linnea_quic_server.asm:1975).

The ordinary 1-RTT path first runs structural/unknown-frame validation and the
advertised stream-limit check at
[`src/server/linnea_quic_server.asm:2097`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2097)
through [`src/server/linnea_quic_server.asm:2127`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2127),
then scans ACK, close, reset, path, and flow-control frames before entering the
same STREAM loop. None of those stages runs for `early_buf`.

This is distinct from Finding 7's one-packet buffering limit. For the first
accepted 0-RTT packet itself, a prohibited ACK, CRYPTO, or other packet-type
invalid frame is silently stepped over by the STREAM scanner instead of causing
`PROTOCOL_VIOLATION`. A STREAM ID above the remembered early-data limit can be
served. Legal early RESET_STREAM and flow-control frames are also never acted
on. [RFC 9000 section 12.5](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.5)
defines the packet-type frame restrictions, while stream concurrency limits
also apply to streams opened in early data.

### Observable behavior

Place an ACK followed by a valid request STREAM in accepted 0-RTT. The request
can be served and the forbidden ACK does not close the connection. Likewise, a
complete early request on a stream ordinal above the server's granted limit
reaches routing instead of producing `STREAM_LIMIT_ERROR`.

### Recommended fix

Route accepted 0-RTT through a common packet-validation pipeline parameterized
by packet type. Perform structural validation, the 0-RTT allowed-frame check,
stream state/direction checks, stream-limit enforcement using remembered
limits, and the relevant reset/flow scans before dispatching STREAM data.

### Regression tests to add

- Put each forbidden frame class before and after a valid 0-RTT request and
  require `PROTOCOL_VIOLATION`.
- Open an early stream beyond the granted limit and require
  `STREAM_LIMIT_ERROR` without application dispatch.
- Send legal early RESET_STREAM and flow-control frames and verify they update
  the same state as their 1-RTT equivalents.

## Finding 16 — inline HTTP/3 packets bypass congestion control and bounded recovery

Severity: Medium (P2 congestion-control and response reliability)  
Confidence: High  
Status: **FIXED** — inline responses now share one congestion budget and one
recovery discipline with the bulk pump. Every ack-eliciting inline/control
packet is charged to a new `inline_flight` counter as it enters the recovery
ring (`linnea_quic_rtx_record`) and un-charged when the ring frees it (on ACK in
`linnea_quic_rtx_ack_range`, on give-up in the sweep); the counter is kept apart
from `bytes_in_flight` so the ring's own lifecycle balances it, and both
admission checks — the pump's and the new inline one — gate on the SUM of the
two against `cwnd`. Before an inline response is emitted, `.inline_admit` checks
that it fits `cwnd` AND that a recovery slot is free; if either is unavailable
the response is handed to the congestion-controlled pump as a head-only response
stream (its bytes become the stream head, no file body), which sends it once ACKs
free the window — so no response is ever emitted untracked or beyond `cwnd`. A
response too large for a slot header, or arriving when every response slot is
busy, falls back to an inline send (a rare, bounded overshoot, documented in the
code). Control frames (MAX_STREAMS, HANDSHAKE_DONE, …) keep their reliable
immediate send but are now counted. Verified: the full quic and tls shards pass;
a 40-request burst is answered in full, and — forcing the ring to a single slot
so all but one response must traverse the deferral path — a 40-request burst is
still answered 40/40, exercising the pump route for 39 of them. Regression test
`test/quic/h3_inline_burst.py`.

### Evidence

`.send_1rtt` emits a packet first and only afterward asks the small-packet loss
ring to remember it at
[`src/server/linnea_quic_server.asm:4999`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4999)
through [`src/server/linnea_quic_server.asm:5015`](/home/linnea/linnea/src/server/linnea_quic_server.asm:5015).
The ring has eight slots
([`include/linnea_quic_conn.inc:103`](/home/linnea/linnea/include/linnea_quic_conn.inc:103)
through [`include/linnea_quic_conn.inc:116`](/home/linnea/linnea/include/linnea_quic_conn.inc:116)),
and `linnea_quic_rtx_record` silently returns when all are occupied at
[`src/server/linnea_quic_rtx.asm:143`](/home/linnea/linnea/src/server/linnea_quic_rtx.asm:143)
through [`src/server/linnea_quic_rtx.asm:169`](/home/linnea/linnea/src/server/linnea_quic_rtx.asm:169).
The already-sent packet then has no retained frames for retransmission.

Inline HTTP/3 responses use this path directly at
[`src/server/linnea_quic_server.asm:3827`](/home/linnea/linnea/src/server/linnea_quic_server.asm:3827)
through [`src/server/linnea_quic_server.asm:3841`](/home/linnea/linnea/src/server/linnea_quic_server.asm:3841).
They are not charged to `bytes_in_flight` and do not check `cwnd`. Those checks
exist only in the bulk response pump at
[`src/server/linnea_quic_server.asm:6347`](/home/linnea/linnea/src/server/linnea_quic_server.asm:6347)
through [`src/server/linnea_quic_server.asm:6364`](/home/linnea/linnea/src/server/linnea_quic_server.asm:6364).

A packet can carry multiple complete request STREAM frames, and multiple
datagrams can arrive before any response ACK. The receive loop sends every
inline response immediately, so the ninth outstanding small response is both
outside the recovery ring and outside congestion accounting. This conflicts
with [RFC 9002 section 7](https://www.rfc-editor.org/rfc/rfc9002.html#section-7),
which exempts ACK-only packets but not ack-eliciting STREAM responses from the
congestion window.

### Observable behavior

Send enough small requests without acknowledging their responses. The server
continues beyond the initial congestion window. Once eight small packets are
outstanding, later inline responses are sent but cannot be recovered if lost;
the client waits for stream data the server no longer has, or retransmits the
request and triggers Finding 11.

### Recommended fix

Unify small and bulk packet admission: reserve recovery metadata and congestion
budget before emission, charge every ack-eliciting packet to bytes in flight,
and queue work when either resource is unavailable. ACK-only and deliberately
untracked challenge responses can remain separately classified.

### Regression tests to add

- Queue more than eight inline responses while withholding ACKs; assert no
  untracked response is emitted and total bytes stay within `cwnd`.
- Drop responses around the old ring boundary and verify every request stream
  eventually completes after ACK/loss processing resumes.
- Mix inline, bulk, and control packets and assert they share one congestion
  budget without starving control traffic.

## Finding 17 — HTTP/3 trailers bypass QPACK and field validation

Severity: Medium (P2 malformed-message and compression-state validation)  
Confidence: High  
Status: **FIXED** — trailer sections are decoded into a throwaway request and
scratch arena; malformed QPACK closes the connection and forbidden pseudo-fields
reset only the request stream.

### Evidence

The first HEADERS frame is decoded by `linnea_qpack_decode` and checked with the
shared HTTP field rules at
[`src/server/linnea_http3.asm:290`](/home/linnea/linnea/src/server/linnea_http3.asm:290)
through [`src/server/linnea_http3.asm:355`](/home/linnea/linnea/src/server/linnea_http3.asm:355).
When a second HEADERS frame is recognized as trailers, however, the state
machine changes directly to `LINNEA_H3_W_SKIP` at
[`src/server/linnea_http3.asm:270`](/home/linnea/linnea/src/server/linnea_http3.asm:270)
through [`src/server/linnea_http3.asm:285`](/home/linnea/linnea/src/server/linnea_http3.asm:285).
The skip phase at
[`src/server/linnea_http3.asm:420`](/home/linnea/linnea/src/server/linnea_http3.asm:420)
through [`src/server/linnea_http3.asm:435`](/home/linnea/linnea/src/server/linnea_http3.asm:435)
consumes bytes without invoking QPACK or any field-semantic checks.

A trailer HEADERS payload is still an encoded field section under
[RFC 9114 section 4.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1)
and [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204.html). It must decode
correctly, obey the negotiated QPACK state, and contain no pseudo-fields. The
HTTP/2 implementation demonstrates the intended model: it decodes discarded
trailers to preserve HPACK state and explicitly rejects pseudo-fields at
[`src/server/linnea_http2.asm:1190`](/home/linnea/linnea/src/server/linnea_http2.asm:1190)
through [`src/server/linnea_http2.asm:1205`](/home/linnea/linnea/src/server/linnea_http2.asm:1205).

The existing `h3_trailer_test.py` verifies only that a valid trailer does not
alter routing. It does not exercise invalid compressed sections or trailer
pseudo-fields.

### Observable behavior

Append a trailer HEADERS frame containing an invalid QPACK prefix/index,
including a dynamic reference that is impossible with the advertised zero
table capacity. The request is still served. A syntactically decodable trailer
containing `:path` or another pseudo-field is likewise accepted rather than
failing the request stream.

### Recommended fix

Decode every trailer field section into a fresh throwaway request structure
using the same QPACK connection state. Preserve compression-state effects, then
reject pseudo-fields and other trailer-forbidden fields without merging any
trailer value into routing or proxy headers. Map decompression failure to the
existing QPACK connection error and semantic failure to `H3_MESSAGE_ERROR`.

### Regression tests to add

- Send malformed/truncated trailer field sections and impossible dynamic
  references; require `QPACK_DECOMPRESSION_FAILED`.
- Send each request pseudo-field in trailers; require a stream-level
  `H3_MESSAGE_ERROR` and no upstream dispatch.
- Keep the valid ignored-routing trailer test and add a valid literal trailer
  as controls.

### Resolution (fixed)

The trailer path now accumulates the encoded field section instead of skipping it,
then decodes it with `linnea_qpack_decode` into a fresh request structure and
Huffman scratch arena. The live request and its routing/proxy-header state are
never touched. QPACK decode failures use the existing connection-level
`QPACK_DECOMPRESSION_FAILED` path; a semantically malformed trailer, including
any pseudo-field, returns `H3_MESSAGE_ERROR` on the request stream. Valid regular
trailers remain consumed and ignored.

`test/quic/h3_trailer_test.py` now covers a valid ignored trailer, a pseudo-field
trailer, and an invalid dynamic-table reference in a trailer. The focused QUIC
run passed 91 checks with 0 failures (10 skipped).

## Finding 18 — HTTP/3 does not validate Content-Length against DATA

Severity: Medium (P2 HTTP message integrity and protocol conformance)  
Confidence: High  
Status: **FIXED** — commit 514532a. `.req_ok` parses the declared length and compares
it with the DATA sum before routing; a mismatch resets the stream H3_MESSAGE_ERROR.
Test `test/quic/h3_content_length.py`, A/B-verified.

### Evidence

QPACK decoding retains the `content-length` value in the shared request
structure at
[`src/server/linnea_hpack.asm:538`](/home/linnea/linnea/src/server/linnea_hpack.asm:538)
through [`src/server/linnea_hpack.asm:548`](/home/linnea/linnea/src/server/linnea_hpack.asm:548).
The HTTP/3 walk independently accumulates the sum of DATA payload bytes in
`body_len` at
[`src/server/linnea_http3.asm:363`](/home/linnea/linnea/src/server/linnea_http3.asm:363)
through [`src/server/linnea_http3.asm:418`](/home/linnea/linnea/src/server/linnea_http3.asm:418).

At FIN, completion checks only frame boundaries and the presence of an initial
HEADERS frame at
[`src/server/linnea_http3.asm:440`](/home/linnea/linnea/src/server/linnea_http3.asm:440)
through [`src/server/linnea_http3.asm:455`](/home/linnea/linnea/src/server/linnea_http3.asm:455).
Neither the inline decode nor deferred `linnea_h3_walk_decode` compares the
stored field with `body_len`, and `.serve_bidi` proceeds to routing after parse
success at
[`src/server/linnea_quic_server.asm:3291`](/home/linnea/linnea/src/server/linnea_quic_server.asm:3291)
through [`src/server/linnea_quic_server.asm:3339`](/home/linnea/linnea/src/server/linnea_quic_server.asm:3339).

HTTP/2 already performs the missing comparison when END_STREAM arrives at
[`src/server/linnea_http2.asm:603`](/home/linnea/linnea/src/server/linnea_http2.asm:603)
through [`src/server/linnea_http2.asm:610`](/home/linnea/linnea/src/server/linnea_http2.asm:610).
[RFC 9114 section 4.1.3](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.3)
classifies a mismatch between Content-Length and the sum of DATA lengths as a
malformed message.

### Observable behavior

Declare `content-length: 100`, send ten DATA bytes, and end the request stream.
Linnea routes the ten-byte body. The inverse case—declaring a smaller length and
sending more DATA—is also accepted. On a proxy route, Linnea rebuilds the
upstream request around the measured body, concealing rather than rejecting the
client's malformed message.

### Recommended fix

Parse a single validated Content-Length into an integer during field checking,
retain an explicit “absent” state, and compare it with the final accumulated
DATA length before any rate limit, routing, or upstream side effect. Reject a
mismatch with `H3_MESSAGE_ERROR`. Apply the same check when trailers terminate
the message.

### Regression tests to add

- Test declared lengths smaller and larger than the DATA sum on inline and
  reassembled request streams.
- Test no DATA with nonzero Content-Length and DATA with zero Content-Length.
- Verify exact equality, absent Content-Length, and multiple DATA frames remain
  valid.

## Finding 19 — single-frame HTTP/3 bodies bypass `max_body`

Severity: Medium (P2 configured resource-policy bypass)  
Confidence: High  
Status: **FIXED** — commit 13db631. `.req_ok` caps the parsed body length (both the
single-frame and reassembled paths) before routing. Test
`test/quic/h3_single_frame_maxbody.py` drives aioquic to send the whole request in one
STREAM frame (curl cannot); A/B-verified.

### Evidence

A request carried by one offset-zero STREAM frame with FIN bypasses reassembly
and jumps directly to `.serve_bidi` at
[`src/server/linnea_quic_server.asm:2474`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2474)
through [`src/server/linnea_quic_server.asm:2482`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2482).
`linnea_h3_read_headers` walks the whole stream and returns the DATA pointer and
length at
[`src/server/linnea_http3.asm:547`](/home/linnea/linnea/src/server/linnea_http3.asm:547)
through [`src/server/linnea_http3.asm:595`](/home/linnea/linnea/src/server/linnea_http3.asm:595),
but the HTTP/3 parser contains no `max_body` comparison. The returned body is
accepted at `.req_ok` and handed to the application.

Both existing HTTP/3 cap checks are reassembly-only:

- direct-to-file region admission checks `spill_len + frame_rem` at
  [`src/server/linnea_quic_server.asm:2905`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2905)
  through [`src/server/linnea_quic_server.asm:2915`](/home/linnea/linnea/src/server/linnea_quic_server.asm:2915); and
- the incremental body sink checks `spill_len + run_len` at
  [`src/server/linnea_quic_server.asm:7871`](/home/linnea/linnea/src/server/linnea_quic_server.asm:7871)
  through [`src/server/linnea_quic_server.asm:7878`](/home/linnea/linnea/src/server/linnea_quic_server.asm:7878).

The gap is therefore reachable whenever an operator configures a body limit
below the amount that fits in one QUIC request packet. It is the HTTP/3 analogue
of Finding 3's HTTP/1 buffered-path bypass.

### Observable behavior

Set `max_body = 64` and send a complete POST containing a 65-byte DATA payload
in one STREAM frame with FIN. The request is routed and can be forwarded to the
backend. Fragment the same logical request so it enters reassembly and the
configured cap is enforced instead.

### Recommended fix

Apply one final body-length cap after HTTP/3 message parsing and before routing,
regardless of whether the bytes are packet-backed or spill-backed. Keep the
early reassembly checks to avoid receiving or writing data already known to be
too large, but make the final common check authoritative.

### Regression tests to add

- With `max_body = 64`, send 64- and 65-byte one-frame bodies and require 200/413
  respectively.
- Repeat with several DATA frames that still share one STREAM/packet.
- Run the same boundary across fragmented/reordered streams to prove all paths
  use an inclusive common limit.

## Finding 20 — `max_udp_payload_size` is parsed but not enforced

Severity: Medium (P2 QUIC interoperability and path reliability)  
Confidence: High  
Status: **FIXED** — a large inline (head-only) h3 response is now split across
STREAM frames so no 1-RTT datagram exceeds the 1200-byte floor every QUIC path
must carry (and so a peer's `max_udp_payload_size`, which #13 rejects below 1200).
The inline emit arm chunks the field section at `LINNEA_QUIC_TX_CHUNK` — the same
per-packet budget the body pump already keeps every datagram under — via a new
`emit_inline_chunked`, instead of `.send_1rtt`ing the whole section in one packet.
Each chunk leads with the current ACK, is a STREAM frame with an explicit offset
(FIN on the last), and is tracked for loss recovery (`linnea_quic_rtx_record`,
which copies the frames and charges `inline_flight`, so the burst shares the
congestion window). Reproduced and fixed empirically: a redirect location with a
2000-byte client request target produced one **2120-byte** datagram that a peer
enforcing its limit drops (the client never saw the 301); it now delivers a
complete 301 with the full 2026-byte Location across datagrams each ≤ 1135 bytes.
A/B-verified against a pre-fix binary on a parallel port with
`test/quic/h3_redirect_datagram.py` (config `tls-h3-redirect.json`): pre-fix fails
three checks (redirect undelivered, 2120-byte datagram), fixed passes.
**A shipped-then-caught crash:** the first `emit_inline_chunked` left `rsp`
8-misaligned at its call sites, so `emit_1rtt`'s AES-GCM seal faulted on an
aligned SSE `movdqa` (SIGSEGV at the `linnea_aesgcm_seal` load) — the class
[[linnea-probe]] records as "any function calling SSE crypto must self-align rsp".
Caught by the readable worker-death log line; fixed with a `sub rsp, 8`.

The doc comment at `src/lib/linnea_quic.asm` (the `max_udp_payload_size` check)
claimed "every datagram we send is at most the padded Initial's 1200 bytes" —
true for the body pump, false for this inline path, which is exactly the gap.

### Evidence

The transport-parameter parser validates and stores the peer's
`max_udp_payload_size` in the global `linnea_quic_tp_max_udp` at
[`src/lib/linnea_quic.asm:2038`](/home/linnea/linnea/src/lib/linnea_quic.asm:2038)
through [`src/lib/linnea_quic.asm:2050`](/home/linnea/linnea/src/lib/linnea_quic.asm:2050).
The handshake copies ACK-delay, idle-timeout, flow-control, and stream-limit
values into the connection, but never copies or consults this one; there is no
server-side reference after parsing.

Inline response payload storage is 4096 bytes at
[`include/linnea_quic_conn.inc:43`](/home/linnea/linnea/include/linnea_quic_conn.inc:43),
and `.send_1rtt` passes its complete payload to `emit_1rtt`, which protects and
sends it as one UDP datagram at
[`src/server/linnea_quic_server.asm:5592`](/home/linnea/linnea/src/server/linnea_quic_server.asm:5592)
through [`src/server/linnea_quic_server.asm:5652`](/home/linnea/linnea/src/server/linnea_quic_server.asm:5652).
Static inline bodies are capped at 1024 bytes, but response field sections can
be much larger. Redirect construction, for example, permits a Location value up
to the 4096-byte local buffer at
[`src/server/linnea_http3.asm:1280`](/home/linnea/linnea/src/server/linnea_http3.asm:1280)
through [`src/server/linnea_http3.asm:1305`](/home/linnea/linnea/src/server/linnea_http3.asm:1305).

[RFC 9000 section 18.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2)
requires an endpoint not to send UDP payloads above its peer's advertised
limit. The existing positive probe advertises 1200 but requests only the small
fixture response, so it does not reach the large-field-section case.

### Observable behavior

Have a client advertise the minimum legal value, 1200, then request a configured
redirect whose encoded Location field pushes the protected response above 1200
but below the 4096-byte local buffer. Linnea emits one oversized datagram. A
client enforcing its advertised limit can drop it; network IP fragmentation can
also turn a valid response into a loss-prone one.

### Recommended fix

Store the negotiated value per connection and derive the maximum protected
packet payload after short-header and AEAD overhead. Split STREAM data across
packets when the response exceeds that budget; do not rely on the inline buffer
size as a transport limit. Apply the same ceiling to every 1-RTT emitter.

### Regression tests to add

- Advertise 1200 and request a long redirect and large response-header cases;
  record every server datagram and assert none exceeds 1200.
- Repeat with a larger legal limit and verify packetization can use, but never
  exceed, it.
- Include MAX_DATA prepending, whose extra frame bytes must remain inside the
  same calculated budget.

## Finding 21 — QUIC connection-ID rotation and retirement are ignored

Severity: Medium (P2 migration/interoperability and CID lifecycle)  
Confidence: High  
Status: **FIXED** — the receive path now keeps bounded per-connection tables of
both sides' connection IDs keyed by sequence (`include/linnea_quic_conn.inc`:
`linnea_quic_pcid` for peer CIDs, `linnea_quic_lcid` for the alternates we issue),
seeded at handshake (the peer's Initial SCID becomes its sequence-0 CID; our
`cid1` becomes local sequence 1). `linnea_quic_cid_frames` walks every 1-RTT
packet's NEW_CONNECTION_ID / RETIRE_CONNECTION_ID frames and:
`retire_prior_to > sequence`, a sequence reused with a different CID, and more
live peer CIDs than our `active_connection_id_limit` (default 2) each close the
connection (`PROTOCOL_VIOLATION` / `CONNECTION_ID_LIMIT_ERROR`); a valid
`retire_prior_to` retires the peer CIDs below it and rotates `conn.dcid` to the
active peer CID with the highest sequence (`cid_rotate_dcid`), so outbound packets
follow the peer's rotation; retiring an id we never issued is `PROTOCOL_VIOLATION`;
a valid RETIRE deactivates that local CID (the lookup at
`linnea_quic_conn_lookup` no longer routes a retired one) and mints a replacement,
announced as a fresh NEW_CONNECTION_ID tracked for loss recovery
(`cid_announce_pending`). A/B-verified against a pre-fix binary on a parallel
port: `test/quic/h3_cid_lifecycle.py` — the four malformed cases drew no close
and the valid retirement drew no replacement before, and all five behave
correctly now. **A shipped-then-caught crash:** the first announce loop clobbered
`r12d` (the socket `emit_1rtt` sends on) and relied on inner calls preserving
callee-saved registers; it respawned the worker on every valid retirement. The
loop now keeps all state in its stack frame and leaves `r12d` alone. Detected only
by watching the worker PID across the injection — no core (AmbientCapabilities),
and the later request that respawned it read as green. See
[[worker-deaths-2026-08-14]].

Two conformance points are deliberately left for a follow-up, neither a stall nor
a security issue: (1) the peer's stateless-reset token in NEW_CONNECTION_ID is
skipped rather than stored, so a stateless reset *from* the client is not matched
(a client resetting a server is not a path we act on); (2) when the peer raises
`retire_prior_to`, we stop using and stop routing the affected peer CIDs but do
not send RETIRE_CONNECTION_ID back to acknowledge the retirement (RFC 9000 5.1.2
MUST) — the rotation still happens, the peer merely holds those ids a little
longer. Both would add a second emission path; the crash above argued for not
doubling that surface in one change.

### Evidence

The peer CID used as every outbound DCID is copied once from the completing
Initial at
[`src/server/linnea_quic_server.asm:1117`](/home/linnea/linnea/src/server/linnea_quic_server.asm:1117)
through [`src/server/linnea_quic_server.asm:1141`](/home/linnea/linnea/src/server/linnea_quic_server.asm:1141).
Short-header emission continues to use only that fixed `conn.dcid` at
[`src/server/linnea_quic_server.asm:5620`](/home/linnea/linnea/src/server/linnea_quic_server.asm:5620)
through [`src/server/linnea_quic_server.asm:5623`](/home/linnea/linnea/src/server/linnea_quic_server.asm:5623).

Incoming NEW_CONNECTION_ID and RETIRE_CONNECTION_ID frames are known only to
generic scanners so later frames can be reached. For example,
`linnea_quic_reset_scan` sends them to skip handlers at
[`src/lib/linnea_quic.asm:2539`](/home/linnea/linnea/src/lib/linnea_quic.asm:2539)
through [`src/lib/linnea_quic.asm:2562`](/home/linnea/linnea/src/lib/linnea_quic.asm:2562),
but no receive path stores peer sequences, CIDs, reset tokens, or retirement
state.

In the other direction, Linnea issues one alternate server CID at
[`src/server/linnea_quic_server.asm:1900`](/home/linnea/linnea/src/server/linnea_quic_server.asm:1900)
through [`src/server/linnea_quic_server.asm:1917`](/home/linnea/linnea/src/server/linnea_quic_server.asm:1917).
The connection lookup accepts it whenever `cid1_active` is set at
[`src/server/linnea_quic_conn.asm:41`](/home/linnea/linnea/src/server/linnea_quic_conn.asm:41)
through [`src/server/linnea_quic_conn.asm:60`](/home/linnea/linnea/src/server/linnea_quic_conn.asm:60),
and RETIRE_CONNECTION_ID never clears that state or causes a replacement CID to
be issued.

[RFC 9000 section 5.1.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.2)
requires endpoints to stop using CIDs below an increased Retire Prior To value
and defines retirement as a request for replacement.

### Observable behavior

If a client sends NEW_CONNECTION_ID with `retire_prior_to = 1`, Linnea keeps
addressing responses to the client's handshake CID. The client is entitled to
stop accepting that CID, so the connection stalls during rotation or migration.
If the client retires Linnea's alternate CID, packets addressed to that retired
ID remain routable and no replacement is supplied.

### Recommended fix

Maintain bounded per-connection tables for peer and local CIDs keyed by sequence
number, including reset token and retirement state. Validate sequence reuse,
Retire Prior To, and active-CID limits; select a non-retired peer CID for each
path; deactivate local CIDs only when retirement is valid; and issue a
replacement within the peer's advertised limit.

### Regression tests to add

- Rotate the peer CID with an increased Retire Prior To value and assert every
  later server packet uses an allowed replacement.
- Retire each server-issued CID and verify it stops routing after the required
  transition and a replacement is sent.
- Add malformed sequence reuse, Retire Prior To greater than sequence, and
  active-CID-limit cases with their required transport errors.

## Finding 22 — HTTP/3 unidirectional stream type is parsed as one byte

Severity: Low (P3 valid-client interoperability)  
Confidence: High  
Status: **FIXED** — the uni-stream type is now decoded as a QUIC varint
(`linnea_quic_varint_decode`), and its width is remembered (`s_uni_wid`) so the
control-stream walk offset and the QPACK encoder scan skip the whole type rather
than a hard-coded one byte. A control stream sent as `40 00` and QPACK streams as
`40 02`/`40 03` are now classified correctly instead of being dropped as unknown.
A type varint SPLIT across STREAM frames (the decode returns width 0) is not
reassembled — the stream is left untyped, as an unknown type already was, so no
crash or misclassification. A/B-verified: two-byte-typed control + duplicate
QPACK encoder streams were dropped before (no error) and now decode, so the
duplicate draws `H3_STREAM_CREATION_ERROR`. Regression test
`test/quic/h3_uni_type.py`.

### Evidence

HTTP/3 defines the leading unidirectional stream type as a QUIC variable-length
integer. The receive path instead loads exactly one byte at
[`src/server/linnea_quic_server.asm:4038`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4038)
through [`src/server/linnea_quic_server.asm:4063`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4063),
then assumes the next byte begins the stream payload. For a recognized control
stream it hard-codes the consumed offset as one at
[`src/server/linnea_quic_server.asm:4152`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4152)
through [`src/server/linnea_quic_server.asm:4157`](/home/linnea/linnea/src/server/linnea_quic_server.asm:4157).

[RFC 9114 section 6.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2)
uses QUIC varints for stream types. Unlike QUIC frame types, ordinary varint
values may legally use a non-minimal width under
[RFC 9000 section 16](https://www.rfc-editor.org/rfc/rfc9000.html#section-16).
Thus control type 0 can legally be encoded as bytes `40 00`, and the type varint
can itself be split across STREAM frames.

### Observable behavior

Open a valid control stream whose type 0 uses the two-byte encoding `40 00`.
Linnea classifies byte `40` as an unknown stream type, discards the stream, and
never processes its SETTINGS. The same happens to multi-byte encodings of QPACK
types, and a fragmented type is prematurely classified from its first byte.

### Recommended fix

Reassemble and decode the leading varint before classifying a unidirectional
stream. Retain both “type incomplete” and “type known” state per stream, advance
the payload offset by the decoder's returned width, and feed any bytes following
the completed type into the appropriate control/QPACK handler.

### Regression tests to add

- Encode control and both QPACK stream types in two-, four-, and eight-byte
  legal forms and require normal recognition.
- Split each encoding at every byte boundary across reordered STREAM frames.
- Verify genuinely unknown multi-byte types remain ignored without affecting
  the required control stream.

## Finding 23 — QUIC PTO uses a fixed rather than negotiated ACK delay

Severity: Low (P3 loss-recovery timing and interoperability)  
Confidence: High  
Status: **FIXED** — `linnea_quic_pto_ms` now adds `conn.max_ack_peer` (the peer's
advertised `max_ack_delay`, in ms) on the application-space path instead of the
compile-time `LINNEA_QUIC_MAX_ACK_DELAY` (25). The field already existed, is set
at handshake from the parsed transport parameter — defaulting to 25 ms when the
peer omits it — and is bounded below 2^14 by the Finding-13 check, so it cannot
overflow the timer. Initial/Handshake PTO (`esi = 0`) is unchanged: it adds no
ack delay. A peer advertising a legal delay above 25 ms no longer draws a
premature probe (spurious retransmit + congestion response); one advertising 0 or
a small value is no longer made to wait the extra 25 ms. Behaviour-neutral for a
peer at the default of 25. Unit-tested in `test/quic/linnea_quictest.asm` (eight
cases: default, 0, 10/100/1000 ms, the largest legal value clamped to the ceiling,
`esi = 0` ignoring the field, and the pre-sample default-RTT path) and in the
loss-recovery selftest `test/quic/linnea_rtxtest.asm`. A/B-verified: reverting only
`linnea_quic.asm` fails exactly the five discriminating checks (`quic-crypto
41/46`) and passes them fixed (`46/46`).

### Evidence

The transport-parameter parser records the peer's `max_ack_delay` at
[`src/lib/linnea_quic.asm:2066`](/home/linnea/linnea/src/lib/linnea_quic.asm:2066)
through [`src/lib/linnea_quic.asm:2067`](/home/linnea/linnea/src/lib/linnea_quic.asm:2067),
and the handshake copies it into `conn.max_ack_peer` at
[`src/server/linnea_quic_server.asm:1346`](/home/linnea/linnea/src/server/linnea_quic_server.asm:1346)
through [`src/server/linnea_quic_server.asm:1350`](/home/linnea/linnea/src/server/linnea_quic_server.asm:1350).
RTT sampling correctly caps the decoded ACK delay by that value at
[`src/server/linnea_quic_server.asm:5717`](/home/linnea/linnea/src/server/linnea_quic_server.asm:5717)
through [`src/server/linnea_quic_server.asm:5733`](/home/linnea/linnea/src/server/linnea_quic_server.asm:5733).

The application-space PTO helper does not use the connection field. When its
caller requests inclusion of peer ACK delay, it always adds the compile-time
`LINNEA_QUIC_MAX_ACK_DELAY` (25 ms) at
[`src/lib/linnea_quic.asm:840`](/home/linnea/linnea/src/lib/linnea_quic.asm:840)
through [`src/lib/linnea_quic.asm:877`](/home/linnea/linnea/src/lib/linnea_quic.asm:877).
[RFC 9002 section 6.2.1](https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.1)
uses the receiver's advertised maximum acknowledgment delay when calculating
the application-data PTO.

### Observable behavior

A peer advertising a legal delay above 25 ms can cause Linnea to probe and
declare loss before the peer's promised ACK deadline, producing spurious
retransmission and congestion response. A peer advertising zero or a small
delay gets an unnecessary extra wait of up to 25 ms before loss recovery.

### Recommended fix

When `esi` requests application-space delay, add
`conn.max_ack_peer` rather than the local default. Retain zero delay for Initial
and Handshake spaces. Validate the transport parameter's upper bound as part of
Finding 13 before the value can reach timer arithmetic.

### Regression tests to add

- Unit-test PTO with peer delays 0, 10, 25, 100, and the largest legal value.
- Exercise an application response with delayed ACKs just below the advertised
  maximum and assert no premature PTO fires.
- Verify Initial and Handshake PTO calculations remain independent of the peer
  value.

## Finding 24 — HTTP/2 does not reconcile `content-length` on HEADERS-only or non-proxy requests

Severity: Medium (P2 message-framing and intermediary correctness)
Confidence: High
Status: **FIXED (proxy path)** — commit 97046ff. A terminal HEADERS (`END_STREAM`)
with a nonzero content-length now fails the stream 400 instead of forwarding it
bodiless; test `test/tls/h2_malformed.py`, A/B-verified. The harmless static-GET-with-
content-length sub-case and duplicate-CL normalization are left for a later pass.

### Evidence

The HPACK decoder records `content-length` only for later use by the proxy path
at [`src/server/linnea_hpack.asm:538`](/home/linnea/linnea/src/server/linnea_hpack.asm:538)
through [`src/server/linnea_hpack.asm:548`](/home/linnea/linnea/src/server/linnea_hpack.asm:548).
Each occurrence simply overwrites the saved pointer; there is no count or
comparison to reject conflicting duplicate values.
That path checks `END_STREAM` before parsing the declaration and jumps directly
to bodiless finalization at
[`src/server/linnea_http2.asm:2040`](/home/linnea/linnea/src/server/linnea_http2.asm:2040)
through [`src/server/linnea_http2.asm:2054`](/home/linnea/linnea/src/server/linnea_http2.asm:2054).
Consequently, `HEADERS(END_STREAM)` plus `content-length: 5` is finalized as a
zero-byte proxied request without comparing the declared and actual lengths.

For requests that do carry DATA, reconciliation occurs only in a collecting
proxy slot at
[`src/server/linnea_http2.asm:603`](/home/linnea/linnea/src/server/linnea_http2.asm:603)
through [`src/server/linnea_http2.asm:613`](/home/linnea/linnea/src/server/linnea_http2.asm:613)
or at the end of proxy trailers. Static-file, redirect, and local-error paths do
not consult the captured length. [RFC 9113 section 8.1.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1.1)
defines a message whose `content-length` differs from the sum of DATA payloads
as malformed and forbids an intermediary from forwarding it.

### Observable behavior

A static GET ending in its initial HEADERS can declare a positive length and
receive a normal response. A proxied POST with the same framing reaches the
backend as a zero-length request instead of being rejected. A pair such as
`content-length: 1` followed by `content-length: 5` is accepted when five DATA
bytes arrive because only the last value is retained, and the proxy rewrites the
message with its measured length. The existing
content-length test always sends a separate DATA frame at
[`test/tls/h2_content_length.py:42`](/home/linnea/linnea/test/tls/h2_content_length.py:42)
through [`test/tls/h2_content_length.py:58`](/home/linnea/linnea/test/tls/h2_content_length.py:58),
so it does not exercise this terminal-HEADERS case.

### Recommended fix

Parse and retain the declared length as part of message validation, independent
of routing. When the initial HEADERS carries `END_STREAM`, require the declared
length to be zero before serving or opening an upstream. Apply the same final
byte-count check to every request path, not only proxy body collection. Reject
conflicting duplicate or comma-list values; if identical duplicates are
accepted, normalize them to one decimal value before forwarding.

### Regression tests to add

- Send `HEADERS(END_STREAM)` with `content-length: 1` to static and proxy routes;
  require a stream-level protocol error and no backend request.
- Keep zero-length declarations as controls on GET and POST.
- Send mismatched DATA lengths to a non-proxy route and require the same
  malformed-message handling as the proxy route.
- Send duplicate and comma-list lengths with both matching and conflicting
  values, and verify only the RFC-permitted identical form can be normalized.

## Finding 25 — HTTP/2 ignores client-sent `PUSH_PROMISE`

Severity: Low (P3 protocol-state enforcement)
Confidence: High
Status: **FIXED** — the frame dispatcher now has an explicit case for type 5
(`PUSH_PROMISE`) that ends the connection with `PROTOCOL_ERROR` (RFC 9113 8.4:
a client MUST NOT push), rather than falling through to the discard-unknown
path. A/B-verified: a client `PUSH_PROMISE` was accepted and ignored before and
now draws GOAWAY(PROTOCOL_ERROR). Covered by `test/tls/h2_frame_validation.py`.

### Evidence

The frame dispatcher has cases for the core frame types but no case for type 5,
`PUSH_PROMISE`, at
[`src/server/linnea_http2.asm:267`](/home/linnea/linnea/src/server/linnea_http2.asm:267)
through [`src/server/linnea_http2.asm:291`](/home/linnea/linnea/src/server/linnea_http2.asm:291).
It therefore reaches the generic unknown-frame path and consumes the complete
frame at
[`src/server/linnea_http2.asm:678`](/home/linnea/linnea/src/server/linnea_http2.asm:678)
through [`src/server/linnea_http2.asm:680`](/home/linnea/linnea/src/server/linnea_http2.asm:680).
[RFC 9113 section 8.4](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.4)
does not permit a client to push; a server receiving `PUSH_PROMISE` must treat it
as a connection error of type `PROTOCOL_ERROR`.

### Observable behavior

A client can send a syntactically complete `PUSH_PROMISE` and then continue
using the connection. The promised stream, field block, and any HPACK table
effects are all ignored rather than the connection being terminated at the
protocol violation.

### Recommended fix

Dispatch `PUSH_PROMISE` explicitly and emit `GOAWAY(PROTOCOL_ERROR)` whenever it
is received from the client. Do not route it through the extension-frame ignore
rule, which applies only to unknown frame types.

### Regression tests to add

- Send a minimal `PUSH_PROMISE` after a valid preface and require
  `GOAWAY(PROTOCOL_ERROR)`.
- Repeat with a field block containing a dynamic-table insertion and verify the
  connection is closed before any later request can depend on that state.

## Finding 26 — oversized HTTP/2 `CONTINUATION` frames bypass the advertised limit

Severity: Low (P3 framing conformance)
Confidence: High
Status: **FIXED** — the per-frame size check inside `h2_build_request` (which
consumes CONTINUATION frames the outer loop never sees) now bounds against
`LINNEA_H2_MAX_FRAME` (16,384) rather than the input-buffer size (~1 KiB
larger), so a CONTINUATION between 16,385 bytes and the buffer bound now takes
the `FRAME_SIZE_ERROR` path. A/B-verified with a 16,385-byte CONTINUATION.
Covered by `test/tls/h2_frame_validation.py`.

### Evidence

The outer frame loop enforces `LINNEA_H2_MAX_FRAME` on the initial frame at
[`src/server/linnea_http2.asm:241`](/home/linnea/linnea/src/server/linnea_http2.asm:241)
through [`src/server/linnea_http2.asm:247`](/home/linnea/linnea/src/server/linnea_http2.asm:247),
but `h2_build_request` consumes following CONTINUATION frames internally. Its
check uses `LINNEA_CONN_IN_BUF - 9` at
[`src/server/linnea_http2.asm:949`](/home/linnea/linnea/src/server/linnea_http2.asm:949)
through [`src/server/linnea_http2.asm:967`](/home/linnea/linnea/src/server/linnea_http2.asm:967),
which is larger than the 16,384-byte protocol default Linnea advertises. Thus a
continuation payload between 16,385 bytes and the local input-buffer bound can
be assembled or routed into the oversized-field-block path.

[RFC 9113 section 4.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-4.2)
requires every frame to respect the receiver's `SETTINGS_MAX_FRAME_SIZE` and
requires an oversized CONTINUATION to produce a connection-level
`FRAME_SIZE_ERROR`.

### Observable behavior

A small HEADERS frame without `END_HEADERS`, followed by a CONTINUATION just
over 16 KiB, does not take the frame-size error path. Depending on field-block
contents and compression state, it is instead assembled, answered as an
oversized request, or rejected for a different reason.

### Recommended fix

Apply `LINNEA_H2_MAX_FRAME` to every frame parsed inside header-block assembly.
Keep the separate input-buffer bound as a memory-safety check, not as the peer's
wire-level frame-size allowance.

### Regression tests to add

- Send 16,384- and 16,385-byte CONTINUATION payloads after a small HEADERS frame;
  require the former to reach normal header processing and the latter to draw
  `GOAWAY(FRAME_SIZE_ERROR)`.
- Fragment the oversized continuation across TLS reads to exercise the resume
  path as well as the one-read path.

## Finding 27 — HTTP/2 skips structural validation for `PRIORITY` and `GOAWAY`

Severity: Low (P3 malformed-control-frame handling)
Confidence: High
Status: **FIXED** — PRIORITY now routes to `.f_priority`, which rejects a length
other than 5 (`FRAME_SIZE_ERROR`) and stream 0 (`PROTOCOL_ERROR`) before the
frame is ignored; `.f_goaway` now rejects a nonzero stream (`PROTOCOL_ERROR`)
and a payload shorter than the mandatory 8 bytes (`FRAME_SIZE_ERROR`) before
entering the drain. A wrong-length PRIORITY is treated as a connection
FRAME_SIZE_ERROR (RFC 9113 4.2 permits this) rather than a per-stream reset,
which is simpler and safe since PRIORITY is not acted on. A/B-verified: all four
cases were silently ignored/drained before and now draw the correct GOAWAY.
Covered by `test/tls/h2_frame_validation.py`.

### Evidence

Every PRIORITY frame is sent directly to `.f_ignore` at
[`src/server/linnea_http2.asm:276`](/home/linnea/linnea/src/server/linnea_http2.asm:276)
through [`src/server/linnea_http2.asm:280`](/home/linnea/linnea/src/server/linnea_http2.asm:280),
without checking its fixed five-byte payload or rejecting stream ID zero.
[RFC 9113 section 6.3](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.3)
requires a wrong-length PRIORITY to cause `FRAME_SIZE_ERROR` and a stream-zero
PRIORITY to cause connection-level `PROTOCOL_ERROR`.

The GOAWAY path likewise consumes any payload and enters draining state at
[`src/server/linnea_http2.asm:782`](/home/linnea/linnea/src/server/linnea_http2.asm:782)
through [`src/server/linnea_http2.asm:793`](/home/linnea/linnea/src/server/linnea_http2.asm:793).
It does not require stream ID zero or the eight mandatory payload bytes specified
by [RFC 9113 section 6.8](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.8).

### Observable behavior

Zero-length PRIORITY, PRIORITY on stream zero, zero-length GOAWAY, and GOAWAY on
a nonzero stream are all accepted. The GOAWAY cases trigger an apparently normal
graceful drain despite not containing a last-stream ID or error code.

### Recommended fix

Add explicit handlers that validate each known frame's stream-ID and mandatory
length rules before applying or ignoring its semantics. Use the RFC-specific
error scope and code for each failure.

### Regression tests to add

- Cover PRIORITY lengths 4, 5, and 6 on a valid stream, plus length 5 on stream
  zero.
- Cover GOAWAY payload lengths 0, 7, and 8 on stream zero, plus a valid-length
  payload on a nonzero stream.

## Finding 28 — HTTP/2 CONNECT bypasses whole-request validation

Severity: Medium (P2 request-semantics validation)
Confidence: High
Status: **FIXED** — CONNECT is still answered 405 (unsupported), but it is now
validated first: the CONNECT branch requires a non-empty `:authority`, rejects a
present `:scheme` or `:path`, and rejects a duplicate or contradicting `Host`
(RFC 9113 8.5). A nonconforming CONNECT takes `.malformed_stream` (a stream
reset) instead of the 405. The shared `linnea_hpack_req_check` is still not run
for CONNECT — it would wrongly reject the mandatory omission of `:scheme`/`:path`
— so the CONNECT-specific rules are checked inline. A/B-verified against a
pre-fix binary: a CONNECT with no `:authority`, an empty `:authority`, a present
`:scheme`, or a present `:path` was answered 405 before and now draws
RST_STREAM; a well-formed CONNECT still gets 405. Regression test
`test/tls/h2_connect.py`.

### Evidence

After HPACK decoding, CONNECT is detected and sent directly to `.serve` at
[`src/server/linnea_http2.asm:1130`](/home/linnea/linnea/src/server/linnea_http2.asm:1130)
through [`src/server/linnea_http2.asm:1143`](/home/linnea/linnea/src/server/linnea_http2.asm:1143).
That bypasses `linnea_hpack_req_check`, which validates authority presence,
duplicates, agreement with Host, and value syntax at
[`src/server/linnea_hpack.asm:1318`](/home/linnea/linnea/src/server/linnea_hpack.asm:1318)
through [`src/server/linnea_hpack.asm:1370`](/home/linnea/linnea/src/server/linnea_hpack.asm:1370).
The request is then answered 405 by the method gate at
[`src/server/linnea_http2.asm:1414`](/home/linnea/linnea/src/server/linnea_http2.asm:1414)
through [`src/server/linnea_http2.asm:1422`](/home/linnea/linnea/src/server/linnea_http2.asm:1422).

[RFC 9113 section 8.5](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.5)
requires a classic CONNECT to include `:authority` and omit `:scheme` and
`:path`; a nonconforming request is malformed even when the method itself is
unsupported by the endpoint.

### Observable behavior

CONNECT without `:authority`, with an empty authority, with conflicting Host,
or with forbidden `:scheme`/`:path` fields receives an ordinary 405 response.
The malformed request is therefore treated as an application-level method
choice rather than a stream protocol error.

### Recommended fix

Split whole-request validation into common authority/method checks and the two
pseudo-header profiles: ordinary requests require scheme/path, while classic
CONNECT requires authority and forbids scheme/path. Run the appropriate profile
before the unsupported-method response.

### Regression tests to add

- Require 405 only for a structurally valid classic CONNECT.
- Require a stream reset for missing/empty authority, duplicate or conflicting
  Host, and present `:scheme` or `:path`.
- Keep ordinary request pseudo-header validation as a control.

## Finding 29 — HPACK accepts dynamic-table size updates after header fields

Severity: Low (P3 compression-state validation)
Confidence: High
Status: **FIXED** — the decoder now records `dec_field_seen` when it decodes any
field representation (indexed or literal), and `.tsize` rejects a dynamic-table
size update once that flag is set (RFC 7541 4.2: updates only at the beginning
of a block), returning the HPACK error the receive path maps to a connection
`COMPRESSION_ERROR`. A/B-verified: a block encoding `:method` then a size update
was applied and served before, and now draws GOAWAY(COMPRESSION_ERROR); a size
update at the block start is unaffected. Covered by
`test/tls/h2_frame_validation.py`.

### Evidence

The decoder dispatches a dynamic-table size update whenever the next
representation has the `0x20` prefix at
[`src/server/linnea_hpack.asm:94`](/home/linnea/linnea/src/server/linnea_hpack.asm:94)
through [`src/server/linnea_hpack.asm:108`](/home/linnea/linnea/src/server/linnea_hpack.asm:108).
The update handler validates only the numeric bound and then mutates the table
at [`src/server/linnea_hpack.asm:239`](/home/linnea/linnea/src/server/linnea_hpack.asm:239)
through [`src/server/linnea_hpack.asm:258`](/home/linnea/linnea/src/server/linnea_hpack.asm:258).
No state records that a normal field representation has already been decoded.

[RFC 7541 section 4.2](https://www.rfc-editor.org/rfc/rfc7541.html#section-4.2)
and [section 6.3](https://www.rfc-editor.org/rfc/rfc7541.html#section-6.3)
permit table-size updates only at the beginning of a header block; an update
after a field representation is a decoding error. HTTP/2 maps HPACK decoding
errors to a connection-level `COMPRESSION_ERROR`.

### Observable behavior

A block can encode `:method`, then shrink the dynamic table, then encode the
remaining pseudo-fields. Linnea applies the update and serves the request. The
current HPACK stress tests put size updates at the start of blocks, so they do
not cover the invalid placement.

### Recommended fix

Track whether any field representation has been encountered in the current
block. Reject a later table-size update as an HPACK decoding error; also enforce
the RFC's constrained sequence when two beginning-of-block updates are needed.

### Regression tests to add

- Put a valid update before all fields and require the request to succeed.
- Put the same update after an indexed or literal field and require
  `GOAWAY(COMPRESSION_ERROR)`.
- Add excessive and incorrectly ordered beginning-of-block update sequences.

## Finding 30 — the HTTP/2 proxy treats informational responses as final

Severity: Medium (P2 proxy response correctness)
Confidence: High
Status: **FIXED** — the upstream head parser now classifies a 1xx response as an
interim head (a new `h2p_parse_head` return of 2) rather than a bodiless final
one, and rejects 101 (and any status below 100) as a bad gateway. The response
scheduler's `.sv_head` gained an interim path: it relays the 1xx as an HEADERS
block without `END_STREAM` (leaving `F_HEAD_SENT` clear so a later upstream
failure can still answer 502), drops the interim head from the buffer, and
resumes parsing the next head — looping over further 1xx responses and, when the
final head is already buffered, decoding its body and emitting it in the same
pass so a backend that writes the interim and the final response in one go
neither hangs nor loses the final response. A/B-verified against a pre-fix
binary: `/api/early` (103 then 200), `/api/early-atonce` (both in one write),
and `/api/multi-early` (103, 103, 100, then 200) all delivered only the 103 with
an empty body before the fix and now relay each interim HEADERS in order ahead
of the final 200; `/api/upgrade101` is now 502. Regression tests added at
[`test/shards/tls/40-http2.sh`](/home/linnea/linnea/test/shards/tls/40-http2.sh)
with four backend routes in
[`test/proxy_backend.py`](/home/linnea/linnea/test/proxy_backend.py).

### Evidence

The upstream parser accepts the first HTTP/1 response head and classifies every
status below 200 as having no body at
[`src/server/linnea_http2.asm:3607`](/home/linnea/linnea/src/server/linnea_http2.asm:3607)
through [`src/server/linnea_http2.asm:3646`](/home/linnea/linnea/src/server/linnea_http2.asm:3646)
and [`src/server/linnea_http2.asm:3720`](/home/linnea/linnea/src/server/linnea_http2.asm:3720)
through [`src/server/linnea_http2.asm:3736`](/home/linnea/linnea/src/server/linnea_http2.asm:3736).
`NO_BODY` makes the service loop emit one HEADERS block and immediately release
the upstream slot at
[`src/server/linnea_http2.asm:3272`](/home/linnea/linnea/src/server/linnea_http2.asm:3272)
through [`src/server/linnea_http2.asm:3290`](/home/linnea/linnea/src/server/linnea_http2.asm:3290),
while the encoder adds `END_STREAM` at
[`src/server/linnea_http2.asm:4282`](/home/linnea/linnea/src/server/linnea_http2.asm:4282)
through [`src/server/linnea_http2.asm:4301`](/home/linnea/linnea/src/server/linnea_http2.asm:4301).

[RFC 9113 section 8.8.5](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.8.5)
represents informational responses, other than the prohibited 101, as interim
HEADERS that do not end the stream; the final response still has to follow.

### Observable behavior

If a backend sends `100 Continue` or `103 Early Hints` before its final 200,
the client receives the informational status as a final HTTP/2 response with
`END_STREAM`. Linnea releases the proxy slot and closes or reuses the upstream
without relaying the actual response.

### Recommended fix

Loop over upstream response heads until a final status is parsed. Translate each
permitted informational response into an interim HEADERS block without
`END_STREAM`, reject 101, and retain the upstream and stream slots for the final
response.

### Regression tests to add

- Proxy backends that send `100` then `200`, and `103` then `200`; require both
  header sections in order and `END_STREAM` only on the final response.
- Send multiple informational responses before the final one.
- Verify an upstream 101 is rejected rather than relayed as HTTP/2.

## Finding 31 — the HTTP/2 proxy cleanly completes truncated or malformed upstream bodies

Severity: Medium (P2 response-integrity failure)
Confidence: High
Status: **FIXED** — the EOF path now distinguishes a legitimate close-delimited
end from a premature one, and a malformed chunk is flagged as a decode error;
both route to the existing bad-gateway handler, which answers 502 before the
response head has reached the client and RST_STREAMs the stream after it. A new
`LINNEA_H2P_F_DEC_ERR` flag carries the malformed-chunk signal out of `.dec_bad`,
and `.ev_eof` treats a chunked body with no terminating 0-chunk, or a
fixed-length body still owed bytes, as a bad gateway rather than a clean
`END_STREAM`. A close-delimited body (`body_rem == -1`, not chunked) still ends
correctly at EOF. Verified by A/B against a pre-fix binary: `/api/chunktrunc`
(a chunked body flushed then cut short) reported success to curl before the fix
(the de-chunked body had no length to check) and is now surfaced as a stream
reset. Regression test added at
[`test/shards/tls/40-http2.sh`](/home/linnea/linnea/test/shards/tls/40-http2.sh),
backed by a new `/chunktrunc` route in
[`test/proxy_backend.py`](/home/linnea/linnea/test/proxy_backend.py); full tls
shard 185/0.

One sub-case in the original recommendation is deliberately left lenient: the
last-chunk path marks the body done at `0\r\n` without requiring the trailer
section's terminating empty line. That case delivers every body byte intact —
only a zero-content terminator is absent — and enforcing it would answer 502 to
well-behaved backends that close immediately after `0\r\n`. The data-integrity
cases (truncated chunk data, an entirely missing 0-chunk, and a malformed
chunk-size line) are all closed.

### Evidence

On any upstream EOF after the response head, the event path calls the body
decoder and then unconditionally sets `BODY_DONE` at
[`src/server/linnea_http2.asm:2984`](/home/linnea/linnea/src/server/linnea_http2.asm:2984)
through [`src/server/linnea_http2.asm:2993`](/home/linnea/linnea/src/server/linnea_http2.asm:2993).
It does not require a fixed-length body to have reached its declared size or a
chunked body to have reached its terminating zero-size chunk.

Malformed chunk syntax takes the same success-shaped path: `.dec_bad` merely
sets `BODY_DONE` at
[`src/server/linnea_http2.asm:3878`](/home/linnea/linnea/src/server/linnea_http2.asm:3878)
through [`src/server/linnea_http2.asm:3889`](/home/linnea/linnea/src/server/linnea_http2.asm:3889).
The nominal last-chunk path also marks completion immediately after the
`0\r\n` size line at
[`src/server/linnea_http2.asm:3832`](/home/linnea/linnea/src/server/linnea_http2.asm:3832)
through [`src/server/linnea_http2.asm:3849`](/home/linnea/linnea/src/server/linnea_http2.asm:3849),
without requiring the trailer section's terminating empty line.
The response scheduler interprets that flag as permission to put `END_STREAM`
on the last DATA frame. For a de-chunked response, the client no longer has the
HTTP/1 chunk terminator as evidence that the backend response was incomplete.

### Observable behavior

A backend can advertise a chunk, send only part of it, and close. Linnea relays
the decoded prefix and ends the HTTP/2 stream normally, so the client sees a
successfully completed but truncated response. A short fixed-length response is
also ended normally; its retained `content-length` may let a strict client
detect the mismatch, but Linnea still emits a malformed HTTP/2 response rather
than signaling upstream failure. The framing requirements are described by
[RFC 9112 section 7.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1)
and [RFC 9113 section 8.1.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1.1).

### Recommended fix

Distinguish close-delimited completion from premature EOF for fixed-length and
chunked bodies. Treat decoder errors and incomplete framing as upstream failure:
send 502 if response headers have not reached the client, otherwise reset the
HTTP/2 stream instead of emitting a clean `END_STREAM`.

### Regression tests to add

- Truncate a chunk data section, omit the terminating zero chunk, omit the final
  trailer-section CRLF, and send a bad chunk-size line; none may yield a normally
  completed 200 response.
- Close a fixed-length response before and exactly at its declared length.
- Exercise failures both before and after the translated response HEADERS have
  been sent.

## Finding 32 — the HTTP/2 proxy does not coalesce split `cookie` fields

Severity: Medium (P2 proxy semantics and authentication correctness)
Confidence: High
Status: **FIXED** — the HPACK proxy rebuild no longer emits a line per `cookie`
field. A length-6 dispatch recognises `cookie` and accumulates each value, in
wire order, into a per-request join buffer (`ck_buf`/`ck_len`, `"; "`-separated);
`.serve_proxy` then appends one `Cookie:` line before the head is bounded, so an
overflowing join is answered 431 by the existing block-overflow check. Only the
HTTP/2-to-HTTP/1 boundary is affected. A/B-verified against a pre-fix binary via
the `/api/headers` echo backend: two and three split cookie fields arrived as two
and three separate lines before the fix and now arrive as one `"; "`-joined line
in order; a single cookie field is unchanged. Regression test
`test/tls/h2_cookie.py`.

### Evidence

The HPACK decoder's proxy rebuild appends every ordinary field independently as
`name: value\r\n` at
[`src/server/linnea_hpack.asm:571`](/home/linnea/linnea/src/server/linnea_hpack.asm:571)
through [`src/server/linnea_hpack.asm:603`](/home/linnea/linnea/src/server/linnea_hpack.asm:603).
There is no cookie-specific aggregation before that rebuilt block is copied into
the HTTP/1.1 upstream request at
[`src/server/linnea_http2.asm:2031`](/home/linnea/linnea/src/server/linnea_http2.asm:2031)
through [`src/server/linnea_http2.asm:2036`](/home/linnea/linnea/src/server/linnea_http2.asm:2036).

[RFC 9113 section 8.2.3](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.3)
allows HTTP/2 clients to split Cookie for compression, but requires an
intermediary to concatenate multiple cookie fields in order with `"; "` before
passing them into a non-HTTP/2 context.

### Observable behavior

An HTTP/2 request carrying `cookie: session=...` and `cookie: prefs=...` reaches
the HTTP/1 backend as two Cookie header lines. Backends differ in how they fold
or select repeated Cookie fields; comma folding in particular is not equivalent
to the required semicolon delimiter. Session, authorization, routing, or
preference cookies can therefore be lost or misparsed only on the proxy path.

### Recommended fix

Collect all decoded cookie values in wire order and emit one HTTP/1 `Cookie`
line joined with `; `. Apply the transformation only at the HTTP/2-to-HTTP/1
boundary; keep the original fields for native HTTP/2 semantics and accounting.

### Regression tests to add

- Send two and three split cookie fields through an HTTP/2 proxy and assert the
  backend receives one semicolon-joined value in order.
- Include empty and whitespace-trimmed values according to the field-value rules.
- Keep a single Cookie field and a large compressed cookie set as controls.

## Finding 33 — HTTP/2 proxied uploads do not honor `Expect: 100-continue`

Severity: Medium (P2 valid-client interoperability and upload latency)
Confidence: High
Status: **FIXED** — the HPACK rebuild now recognises `expect: 100-continue`
(a length-6 dispatch beside `cookie`), sets a per-request flag, and strips the
field from the upstream request. When a proxied request with a body reaches the
collect path, `.proxy_expect_100` emits one interim `100` HEADERS to the client
locally (no `END_STREAM`, via the same `.flags` builder the conditional
responses use) before the body is collected, then leaves the slot COLLECTing.
This is the buffering-preserving strategy the finding recommends: no upstream
connection is held, and because we answer the expectation ourselves the field is
removed so a backend `100` cannot compound with Finding 30. Any other
expectation is forwarded unchanged for the backend to answer. A/B-verified
against a pre-fix binary: with `expect: 100-continue` and the body withheld, the
client received no `100` and stalled before, and now receives a `100` in ~0.04 s,
then one final `200` carrying the backend echo after it releases the body.
Regression test `test/tls/h2_expect.py`.

### Evidence

For a proxied request whose initial HEADERS does not carry `END_STREAM`, the
HTTP/2 path allocates a body slot but deliberately does not finalize or connect
the upstream until the request body has been fully collected at
[`src/server/linnea_http2.asm:2040`](/home/linnea/linnea/src/server/linnea_http2.asm:2040)
through [`src/server/linnea_http2.asm:2087`](/home/linnea/linnea/src/server/linnea_http2.asm:2087).
The ordinary DATA path reaches `h2p_finalize` only at request completion at
[`src/server/linnea_http2.asm:600`](/home/linnea/linnea/src/server/linnea_http2.asm:600)
through [`src/server/linnea_http2.asm:614`](/home/linnea/linnea/src/server/linnea_http2.asm:614).
The generic HPACK rebuild preserves `Expect` as an ordinary field, but there is
no HTTP/2 request-side path that recognizes `100-continue` or emits an interim
HEADERS response.

[RFC 9110 section 10.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.1)
requires an HTTP/1.1-or-later origin server to send either an immediate final
response or an immediate 100 response when content will follow. A proxy must
instead send an immediate final response or forward the request head toward the
origin. Waiting for the content before doing either is explicitly prohibited.

### Observable behavior

An HTTP/2 client sends request HEADERS with a positive `content-length` and
`expect: 100-continue`, then waits before transmitting DATA. Linnea sends no 100,
does not connect to the backend, and cannot produce the backend's final response.
A client with a fallback timer incurs that full delay; one that waits longer can
remain stalled until Linnea's request-body timeout. If the client eventually
sends the body and the backend returns 100, Finding 30 then misclassifies that
upstream interim response as final.

The current large-upload commands explicitly remove Expect at
[`test/shards/tls/40-http2.sh:684`](/home/linnea/linnea/test/shards/tls/40-http2.sh:684)
through [`test/shards/tls/40-http2.sh:688`](/home/linnea/linnea/test/shards/tls/40-http2.sh:688),
so they cannot expose the stall.

### Recommended fix

Choose one RFC-compliant strategy after validating and routing the request head:
emit an HTTP/2 100 HEADERS response locally before collecting the body, or send
the translated upstream request head immediately and relay the backend's interim
or final response. If buffering remains mandatory, local 100 generation avoids
holding an upstream connection while preserving the current buffering policy.

### Regression tests to add

- Send HEADERS with `expect: 100-continue`, wait without sending DATA, and require
  an immediate 100 or final response within a tight deadline.
- After 100, send the body and require one final response with exact backend data.
- Cover an immediate local rejection and a client that sends DATA without
  waiting, ensuring neither path receives a duplicate 100.

## Finding 34 — the HTTP/2 proxy translates malformed upstream fields

Severity: Medium (P2 proxy response correctness and interoperability)
Confidence: High
Status: **FIXED** — a new `h2p_head_validate`, called from `h2p_parse_head` the
moment the head is delimited (before any translation), walks every field line
and requires a token name, a colon, and a value free of control bytes but HTAB;
it rejects an obsolete fold (a line beginning SP/HTAB) and rejects two
Content-Length values that disagree. Any violation makes `h2p_parse_head` return
-1, which the receive path already turns into a 502 — so a malformed head is
never partially translated and the old silent skip of a colon-less or over-long
line is gone. Identical duplicate Content-Length is normalized rather than
rejected: the response emitter now forwards only the first `content-length`, so
the client receives one framing field. A/B-verified against a pre-fix binary
through new backend routes: a field name with a space, a NUL in a value, a
missing colon, and conflicting Content-Length were all relayed before (the
client rejected the block, or the colon-less line was silently dropped) and now
answer 502; identical duplicate Content-Length returned an empty body before and
now serves the body under one length. Regression tests in
[`test/shards/tls/40-http2.sh`](/home/linnea/linnea/test/shards/tls/40-http2.sh)
with five backend routes in
[`test/proxy_backend.py`](/home/linnea/linnea/test/proxy_backend.py).

### Evidence

The upstream response parser validates the rough status-line shape and locates
the first empty line at
[`src/server/linnea_http2.asm:3619`](/home/linnea/linnea/src/server/linnea_http2.asm:3619)
through [`src/server/linnea_http2.asm:3667`](/home/linnea/linnea/src/server/linnea_http2.asm:3667),
but it does not validate each field's syntax. During translation, a line without
a colon or with a name longer than 64 bytes is silently skipped; every other
name is merely lowercased at
[`src/server/linnea_http2.asm:4168`](/home/linnea/linnea/src/server/linnea_http2.asm:4168)
through [`src/server/linnea_http2.asm:4202`](/home/linnea/linnea/src/server/linnea_http2.asm:4202).
The value is trimmed and encoded without rejecting prohibited control bytes at
[`src/server/linnea_http2.asm:4209`](/home/linnea/linnea/src/server/linnea_http2.asm:4209)
through [`src/server/linnea_http2.asm:4230`](/home/linnea/linnea/src/server/linnea_http2.asm:4230).

Framing fields are also only partially validated. `h2p_parse_head` finds and
parses the first `content-length` at
[`src/server/linnea_http2.asm:3703`](/home/linnea/linnea/src/server/linnea_http2.asm:3703)
through [`src/server/linnea_http2.asm:3716`](/home/linnea/linnea/src/server/linnea_http2.asm:3716),
while the response emitter forwards every Content-Length line for a non-chunked
response. Conflicting duplicates therefore survive into the HTTP/2 field block.

[RFC 9113 section 8.2.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.1)
requires field names and values to satisfy the HTTP field rules and classifies
prohibited characters as a malformed message. [RFC 9110 section 8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6)
permits duplicate Content-Length values to be normalized only when every value
is the same. An intermediary must not forward a malformed response.

### Observable behavior

A backend field name containing a space is lowercased and HPACK-encoded, causing
a conforming HTTP/2 client to reject Linnea's response. A NUL in a field value
has the same effect. Two different Content-Length lines are both emitted while
the body decoder follows only the first, so the client receives contradictory
framing generated by Linnea instead of a 502.

### Recommended fix

Fully validate the upstream HTTP/1 response head before exposing any translated
HEADERS: require a supported status-line form and status range, token field
names, valid field values and CRLF structure, no obsolete folding, and
consistent framing fields. Normalize identical Content-Length duplicates to one
value and reject conflicting values as bad gateway. Do not silently drop a
malformed line and continue translating the rest of the response.

### Regression tests to add

- Return a field name containing a space or separator, a NUL/control byte in a
  value, a missing colon, and obsolete folded syntax; require 502 or a reset,
  never a malformed client-facing field block.
- Return identical and conflicting duplicate Content-Length lines; normalize
  the identical pair and reject the conflicting pair.
- Cover out-of-range status values and malformed CRLF boundaries.

## Coverage and additional test recommendations

The current suite already covers many important cases: large h1/h2/h3 uploads,
chunked framing errors and trailer floods, two sequential chunked captures,
QUIC loss/reordering, H2 flow-control credit, spill-directory selection, and
some descriptor-leak scenarios. The following additions would improve confidence:

- Add a repeated-aborted-upload soak across h1, h2, and h3 that samples worker
  RSS, open-fd count, and deleted `/proc/<pid>/fd` entries before and after the
  run. Run it with a disk-backed and a tmpfs spill directory separately.
- Add explicit HTTP/2 `HEADERS` + fragmented `CONTINUATION` tests across receive
  boundaries, including trailers and the 16,384/16,385-byte frame-size boundary
  from Finding 26.
- Add HTTP/2 stream-state tests for post-trailer `DATA`, `DATA` on closed and
  idle streams, and `WINDOW_UPDATE`/`RST_STREAM` on closed and idle streams
  (Findings 4–5).
- Add a malformed HTTP/2 request matrix covering terminal HEADERS with
  `content-length`, client push, PRIORITY/GOAWAY shape, CONNECT pseudo-headers,
  and late HPACK table updates (Findings 24–29).
- Add HTTP/2 proxy translation tests for informational response chains,
  truncated fixed/chunked bodies, split Cookie fields, and request-side
  `100-continue` handling, plus malformed upstream response fields
  (Findings 30–34).
- Add QUIC fresh-packet-number duplicate-range tests, coalesced multi-packet
  0-RTT tests, and reordered critical-stream closure tests (Findings 6–9).
- Add HTTP/3 SETTINGS payloads above the capture limit and duplicate QPACK-stream
  tests (Findings 8 and 10).
- Add request-lifecycle tests for retransmission after an inline response and
  after slot reap, conflicting FIN/RESET final sizes, illegal stream directions,
  and forbidden/over-limit 0-RTT input (Findings 11–15).
- Add a no-ACK burst that crosses the inline loss ring and initial congestion
  window, with packet loss around the boundary (Finding 16).
- Add Content-Length/DATA mismatches and single-packet body-cap boundaries
  (Findings 18–19); malformed QPACK trailers and trailer pseudo-fields are now
  covered by `test/quic/h3_trailer_test.py` (Finding 17).
- Extend transport-parameter fixtures with malformed, duplicate, forbidden, and
  boundary values; then exercise negotiated UDP limits, peer/local CID rotation,
  multi-byte unidirectional stream types, and nondefault ACK delays
  (Findings 13 and 20–23).
- Add QUIC body tests that combine reordered DATA frames, duplicate ranges,
  frame boundaries, and the configured body cap. Verify that the final mapped
  body is byte-exact and that rejected requests never leave an open spill fd.
- Add a randomized HTTP/1 framing matrix for `Content-Length`, chunked bodies,
  trailers, `Expect`, keep-alive, and pipelining. The current tests cover these
  dimensions mostly one at a time.
- Add the small-limit HTTP/1 cases from Finding 3 to the fast suite; the current
  upload-cap test only exercises bodies that are large enough to enter capture.

## Verification performed

Earlier baseline verification (recorded before the later audit-only passes):

- `make -j2`: clean; no rebuild was needed.
- `./bin/linnea-selftest`: all reported crypto/TLS vectors passed.
- `./bin/linnea-rtxtest`: `quic-rtx 112/112`.
- `./bin/linnea-quictest`: `quic-crypto 38/38`.

Finding 3 audit pass:

- Source inspection confirmed that the `max_body` comparison is reachable only
  from `.body_stream`, while buffered counted and completed chunked bodies jump
  through `.body_ready` without a cap check.
- No source, test, or build changes were made in this pass; the regression cases
  above remain pending.

Findings 4–5 audit pass:

- Source inspection confirmed that a trailer `HEADERS` without `END_STREAM`
  returns through `.trailer_ret` while leaving its body slot collecting, and
  that later `DATA` can still reach that slot.
- Source inspection confirmed that `DATA` with no collecting slot and positive
  `WINDOW_UPDATE` or `RST_STREAM` with no active response slot are silently
  discarded/ignored rather than classified by idle, open, half-closed, or
  closed stream state. The finding now distinguishes permitted late closed-stream
  control frames from forbidden frames on an idle stream.
- No source, test, or build changes were made for these findings; the
  regression cases above remain pending.

Finding 6 implementation pass:

- `fc_recv` now advances from per-stream high-water growth after duplicate/offset
  filtering, and `test/quic/h3_fc_dedup_test.py` confirmed that a fresh-packet-number
  retransmission burst does not raise `MAX_DATA`.

Findings 7–10 audit pass:
- Source inspection confirmed that the coalesced early-data loop stops at the
  first 0-RTT packet, that oversized/overfull SETTINGS validation is skipped or
  truncated, and that critical-stream FIN/reset state is not retained before
  stream typing.
- Source inspection confirmed that QPACK stream IDs are overwritten without the
  duplicate check present for the control stream.
- No source, test, or build changes were made for these findings; the
  regression cases above remain pending.

Findings 11–23 QUIC/HTTP/3 audit pass:

- Traced request-stream ownership from direct and reassembled receive paths
  through inline, bulk, and proxied responses, confirming that successful
  receive completion is forgotten independently of response-slot lifetime.
- Traced FIN and RESET_STREAM final-size handling, transport-parameter parsing,
  stream-direction checks, and the separate 0-RTT/1-RTT entry paths against the
  corresponding RFC 9000 state and packet-type rules.
- Traced inline packet emission through both loss-recovery tables and congestion
  accounting, and checked negotiated UDP size, peer ACK delay, and connection-ID
  lifecycle values through their consumers.
- Traced request HEADERS, DATA, and trailer processing through QPACK decode,
  message completion, body limits, and proxy dispatch; compared the missing
  checks with the existing HTTP/2 equivalents and current QUIC tests.
- This pass was static and audit-only. No source or test files were changed, no
  regression tests were added, and no build or test command was run.

Findings 24–34 HTTP/2 audit pass:

- Traced frame dispatch and header-block assembly, confirming that
  `PUSH_PROMISE` reaches the unknown-frame ignore path, PRIORITY and GOAWAY omit
  mandatory structural checks, and CONTINUATION uses the input-buffer bound
  instead of the advertised frame-size limit.
- Traced HPACK and request validation through routing, confirming that late
  table-size updates are accepted, CONNECT skips whole-request validation, and
  terminal-HEADERS/non-proxy messages do not reconcile `content-length`.
- Traced HTTP/2-to-HTTP/1 request and response translation, confirming that
  split Cookie fields remain separate, upstream informational responses end the
  stream, truncated or malformed upstream bodies set `BODY_DONE`, and proxied
  uploads wait for their body before handling `Expect: 100-continue`. The
  reverse translation also emits upstream field names, values, and duplicate
  Content-Length lines without complete validation.
- Compared these paths with RFC 9113, RFC 7541, RFC 9112, and the existing HTTP/2
  tests. This pass was static and audit-only: no source or test files were
  changed, no regression tests were added, and no build or test command was run.

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

Finding 17 fix:

- The audit's pre-fix observation was confirmed in the affected path: invalid
  QPACK and pseudo-field trailers were skipped without validation, while a valid
  `range` trailer was ignored for routing.
- Added regression cases for a valid ignored trailer, a decodable pseudo-field
  (expected stream reset `H3_MESSAGE_ERROR`), and a dynamic-table reference in a
  trailer (expected connection close `QPACK_DECOMPRESSION_FAILED`).
- The focused QUIC run passed 91 checks with 0 failures and 10 skips; the trailer
  cases ran against the rebuilt binary.
