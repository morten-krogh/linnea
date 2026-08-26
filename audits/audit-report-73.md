# Audit Report 73

Audited at `b1bdfae` (`backend h2: the blocking pump hands an early response
to the parser`), 2026-08-26.

Audit report 72's one-frame pushback is present. The next backend-H2 flow
control gap is in the resumable driver's pending-credit flush:

1. **Low: a partially successful credit flush can grant duplicate connection
   window credit on its retry.**

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — connection credit is appended before stream credit atomically

Severity: **Low (P3, queue pressure can make the driver over-credit the HTTP/2
connection even though it credits the response stream once)**  
Confidence: **High**  
Status: **Confirmed in source — and NOT reproducible from outside.** The
partial state needs 13..25 bytes free at the flush; no arrangement of legal
traffic reached it, on either parser or end to end. Fixed anyway (two lines).

Audit report 70 changed the response path to accumulate DATA credit in
`credit_pend`, then flush one connection-level and one stream-level
`WINDOW_UPDATE` ([include/linnea_h2_client.inc:149](/home/linnea/linnea/include/linnea_h2_client.inc:149)
through [:156](/home/linnea/linnea/include/linnea_h2_client.inc:156)). The flush
does not make the pair atomic:

1. It calls `d_stage_window` for connection stream 0.
2. If that append succeeds, it calls `d_stage_window` for stream 1.
3. If the second append fails, it jumps to `.no_credit` with the original
   `credit_pend` value still intact.

Those operations are visible at
[src/server/linnea_h2_client.asm:3204](/home/linnea/linnea/src/server/linnea_h2_client.asm:3204)
through [:3223](/home/linnea/linnea/src/server/linnea_h2_client.asm:3223).
`d_stage_window` appends a 13-byte frame through the bounded output helper,
which can fail without changing `out_len`
([src/server/linnea_h2_client.asm:2491](/home/linnea/linnea/src/server/linnea_h2_client.asm:2491)
through [:2512](/home/linnea/linnea/src/server/linnea_h2_client.asm:2512)).

When the output queue is subsequently sent, the next receive pass retries the
same pending amount. It appends a second connection-level update before the
stream update and then clears the counter. The peer therefore receives:

```text
WINDOW_UPDATE(stream=0, increment=N)
WINDOW_UPDATE(stream=0, increment=N)  # duplicate credit
WINDOW_UPDATE(stream=1, increment=N)
```

for only `N` bytes of response DATA. The source has no “connection update
already sent” bit or separate pending counters to prevent this.

### Reproduction

The partial state is reachable because a receive chunk can contain legal
control frames whose ACKs occupy nearly the entire 32 KiB output queue, plus a
response HEADERS frame and DATA. For one concrete chunk, stage:

```text
3623 zero-length non-ACK SETTINGS frames: 3623 * 9 = 32607 bytes of ACKs
8 PING frames:                              8 * 17 =   136 bytes of ACKs
                                                     ----------------
                                                     32743 bytes queued
```

Then include a small valid response HEADERS frame and a one-byte DATA frame
without `END_STREAM`; their input framing still fits in the 32 KiB receive
chunk. The DATA handler adds one byte to `credit_pend`
([src/server/linnea_h2_client.asm:3529](/home/linnea/linnea/src/server/linnea_h2_client.asm:3529)
through [:3538](/home/linnea/linnea/src/server/linnea_h2_client.asm:3538)).
At `.compact`, 25 bytes remain in the output queue. The 13-byte connection
update fits, leaving 12 bytes; the 13-byte stream update fails and the pending
credit remains one.

The event loop sends the ACKs and the connection update. Once the queue is
empty, a later receive pass carrying another non-final DATA frame flushes the
still-pending byte: both updates now fit, so a second connection update is sent
for the same byte before the counter is cleared. A later final DATA frame can
then terminate the response. The stream receives one byte of credit; the
connection receives two.

This can be driven while the request body is still being sent: the resumable
dispatcher accepts response frames during `ST_SEND_BODY`, and the post-parse
step attempts to stage the next request DATA
([src/server/linnea_h2_client.asm:3224](/home/linnea/linnea/src/server/linnea_h2_client.asm:3224)
through [:3230](/home/linnea/linnea/src/server/linnea_h2_client.asm:3230)). A
backend may legally send control frames and an independent response before the
request body is complete ([RFC 9113 §8.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1)).

The issue is distinct from audit-report-70: the new accumulator prevents lost
credit, but its two output records are not committed as a pair. It is also
distinct from audit-report-72: the early response pushback is in the blocking
oracle, while this partial flush is in the production resumable driver.
HTTP/2 defines connection and stream flow-control windows separately in
[RFC 9113 §5.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-5.2) and
requires `WINDOW_UPDATE` increments to be applied to the identified window in
[RFC 9113 §6.9](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9).

### Impact

The current backend leg is intentionally single-stream, so the extra
connection credit does not by itself let stream 1 exceed its correctly
credited stream window. It nevertheless violates the driver's flow-control
accounting and inflates the connection window relative to bytes consumed. Any
future multiplexing, connection reuse, or connection-level accounting will
inherit the excess; even now, the result depends on exact queue fragmentation
and is a protocol-visible discrepancy between what the driver records and
what it sends.

### Recommended fix

Make the connection/stream credit pair atomic:

- reserve 26 bytes before staging either update; or use separate
  `conn_credit_pend` and `stream_credit_pend` counters and decrement each only
  after its own frame is successfully staged;
- if only one frame fits, retain both exact counters and do not retry the
  already-staged connection amount;
- add a flush invariant that a successful stream credit of `N` is paired with
  exactly one connection credit of `N`.

Add a direct driver test that preloads `out_len` so exactly one 13-byte update
fits, then exercises the pending flush across two receive/send cycles and
counts stream-0 versus stream-1 increments. Add an end-to-end control burst
that leaves the queue in this partial state, and keep controls where neither
update fits and where both fit.

## Verification

The source trace establishes the accounting error without modifying
production code: `d_stage_window` is a bounded append; the first append is
committed; the second can fail; `.no_credit` preserves the full pending amount;
and the next flush repeats the first append. The concrete ACK burst leaves 25
bytes before the pair, creating exactly the 13-bytes-fit/13-bytes-fail state.
`make -j4` should be run after this report is recorded; no production source,
configuration, or test file was changed in this audit.

References:

- [RFC 9113 §5.2 — Flow Control](https://www.rfc-editor.org/rfc/rfc9113.html#section-5.2)
- [RFC 9113 §6.9 — WINDOW_UPDATE](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9)
- [RFC 9113 §8.1 — HTTP Message Exchanges](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1)

## Resolution (2026-08-26) — CONFIRMED in source, NOT reproducible from outside

### The defect is real, and it is mine

The flush added for audit-report-70 stages the connection update, then the
stream update, and clears `credit_pend` only after both. If the second append
fails, the counter survives **with the first frame already queued**, so the
retry sends a second connection update for the same bytes: the stream is
credited N, the connection 2N. The report reads the code correctly; there is no
"connection already sent" bit and no second counter.

### It could not be reached from outside, and the arithmetic says why

The partial state needs the output queue left with **13 to 25 bytes free** at
the flush — room for one 13-byte WINDOW_UPDATE and not two. Attempts, all
measuring the backend's own view of the credit it received:

- the harness, with and without a 3638-frame ACK flood: `conn == stream`, every
  time. Its reads are capped at 20480 bytes, so the ACKs from one pass can never
  fill more than 20475 of the 32768-byte queue — the pair always fits;
- the production path end to end through `proxy_h2`, with the flood and the
  credit-bearing DATA **coalesced into one write**, swept across 3500, 3600,
  3638, and 3639–3644 frames — the counts whose ACK volume lands in the band:
  `conn=1 stream=1` at every value.

A single read never carries the exact frame count required, because TLS records
and TCP segmentation break the write up and the queue drains between reads. The
state is real in the instruction stream and, as far as I can construct it, not
reachable through the transport.

### Fixed anyway, and why

Two lines: reserve 26 bytes — both updates — before staging either, the same
whole-or-nothing rule audit-report-71 put on request DATA. The reasons not to
leave it: it is a two-line change in a path that has now produced three separate
findings (70, 71, 73), the queue arithmetic that makes it unreachable is
incidental rather than designed, and audit-reports 64 and 67 both showed how
quickly such a margin disappears when a constant moves.

### Coverage, and what it is worth

Two rows, one per parser, asserting that the connection and stream credit the
backend received are **equal**. Against a binary built from the audited source,
**neither fails** — because the defect has no reachable path, exactly as
described above. They are an invariant, not a reproduction, and the shard says
so where the rows are.

This is the second report in the series whose evidence is a source argument
rather than a measurement (the first was audit-report-67's overflow, whose
output stayed byte-correct). Recording that plainly is better than dressing a
green control up as a demonstration.

Full suite **1167 passed, 0 failed**.

## Verification (resolution)

Measured on the backend side — the peer that receives the WINDOW_UPDATEs and
can count them by stream — on both parsers, and end to end through a real
`proxy_h2` front across six flood sizes chosen to bracket the failing band. The
credit path's existing behaviour is unchanged after the fix: 200000/200000 on
the oracle, 198656/200000 on the driver, `conn == stream` throughout, and
audit-report-71's request-side flood case still relays its body intact.
