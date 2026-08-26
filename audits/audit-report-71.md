# Audit Report 71

Audited at `0df189e` (`backend h2: response credit accrues and is staged once
per read`), 2026-08-26.

Audit report 70's response-credit accumulator is present. The next resumable
backend-H2 output-state gap is in request DATA staging:

1. **Medium: a partial output-buffer append can put a truncated request DATA
   frame on the wire, and the retry then sends a duplicate header.**

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — request DATA header is committed before its payload

Severity: **Medium (P2, a legal backend control-frame sequence can corrupt or
desynchronize the forwarded request body)**  
Confidence: **High**  
Status: **Confirmed and reproduced from legal traffic** — 8 runs out of 8 at
2400 flood frames, with the threshold located where the report predicts. Fixed
by preflighting the whole frame.

`d_stage_body` constructs a request DATA frame and appends its nine-byte
header first ([src/server/linnea_h2_client.asm:2920](/home/linnea/linnea/src/server/linnea_h2_client.asm:2920)
through [:2943](/home/linnea/linnea/src/server/linnea_h2_client.asm:2943)). It
then appends the payload as a separate bounded operation
([src/server/linnea_h2_client.asm:2944](/home/linnea/linnea/src/server/linnea_h2_client.asm:2944)
through [:2948](/home/linnea/linnea/src/server/linnea_h2_client.asm:2948)). If
the payload append sets carry, the helper returns the same `blocked` result it
uses for a flow-control wait ([src/server/linnea_h2_client.asm:2960](/home/linnea/linnea/src/server/linnea_h2_client.asm:2962)),
but it does not remove the already-appended header or record that the header
is pending.

The caller treats that result as a reason to send whatever is staged. On a
fully drained send, `linnea_h2c_drv_on_sent` calls `d_stage_body` again while
`body_sent` is unchanged ([src/server/linnea_h2_client.asm:3078](/home/linnea/linnea/src/server/linnea_h2_client.asm:3079)
through [:3103](/home/linnea/linnea/src/server/linnea_h2_client.asm:3103)).
The retry therefore writes a second DATA header before the original header's
declared payload. The peer interprets that second header as the first nine
payload bytes of the first frame, and the remaining bytes are no longer framed
at the intended boundaries.

### Reproduction

Start a request with a body large enough that `d_stage_body` selects a payload
larger than the remaining output capacity. After the initial request preface
has been sent, keep the driver in `ST_SETTLE` and have the backend send one
initial non-ACK SETTINGS frame followed by legal control frames in a single
read. Each zero-length non-ACK SETTINGS frame is nine bytes on the wire and
requires a nine-byte ACK; each PING is 17 bytes on the wire and requires a
17-byte ACK. The driver stages those ACKs as it parses them
([src/server/linnea_h2_client.asm:3331](/home/linnea/linnea/src/server/linnea_h2_client.asm:3331)
through [:3358](/home/linnea/linnea/src/server/linnea_h2_client.asm:3358)
and [src/server/linnea_h2_client.asm:3398](/home/linnea/linnea/src/server/linnea_h2_client.asm:3398)
through [:3419](/home/linnea/linnea/src/server/linnea_h2_client.asm:3419)).

For example, four PINGs plus 3,632 zero-length SETTINGS frames consume

```text
4 * 17 + 3632 * 9 = 32756 bytes
```

of a 32 KiB receive chunk and stage the same 32,756 bytes of ACKs. Twelve
bytes remain in the 32,768-byte output queue. The next request DATA frame can
have a 32-byte payload: its nine-byte header fits, but its payload does not.
The first call leaves a header declaring a 32-byte DATA payload in the queue,
returns blocked, and leaves `body_sent` at zero. The event loop sends the
control ACKs plus that header. The next `on_sent` call resets the queue and
retries the same body position, adding a second header and then the 32 payload
bytes.

The peer consequently sees the first DATA header followed by the second DATA
header and only then body bytes. The first frame consumes header bytes as
payload; the request is malformed or hangs waiting for bytes for a frame whose
boundaries no longer match. The control sequence is legal under HTTP/2: a
SETTINGS payload may contain zero records, SETTINGS frames may be sent more
than once, and PING is a connection-level frame. The bounded output queue is
the implementation limit ([include/linnea_h2_client.inc:132](/home/linnea/linnea/include/linnea_h2_client.inc:132)
through [:136](/home/linnea/linnea/include/linnea_h2_client.inc:136)), not a
peer protocol violation.

This is a different queue failure from audit-report-70. The response-credit
path now retains its counter, but request DATA staging still treats a
two-part append as though it were atomic. HTTP/2 DATA framing and SETTINGS
ACK requirements are specified in [RFC 9113 §6.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.1)
and [RFC 9113 §6.5](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.5).

### Impact

The backend does not need to send an invalid frame or exceed the advertised
request limits. It only needs to fill the client's finite ACK queue with legal
control traffic while the request body is waiting for the server SETTINGS.
The resulting truncated DATA frame can cause the backend to issue a protocol
error, parse the request body incorrectly, or wait indefinitely for payload
bytes. This is a request availability/integrity failure in the deployed
resumable `proxy_h2` path; the blocking oracle's synchronous write path does
not exercise this two-append output-queue state.

### Recommended fix

Make request DATA staging atomic with respect to the output queue:

- preflight that nine header bytes plus the selected payload both fit before
  appending either part; or stage the complete frame in a separate scratch
  area and append it with one bounded operation;
- if it does not fit, return `WANT_SEND` without changing `out_len`,
  `body_sent`, or either send window;
- keep the retry idempotent: a failed staging attempt must never leave a
  partial frame in `out_buf`.

Add a driver test that preloads the output queue to every boundary from eight
through the selected DATA payload's shortfall, then calls `on_sent` and
verifies that the peer receives exactly one complete DATA frame. Add an
end-to-end `proxy_h2` fixture with a large legal SETTINGS/PING control burst
while a request body is pending, and retain controls for a full queue (header
append fails before writing) and a normally empty queue.

## Verification

The source trace establishes the failure without modifying production code: a
successful header append is followed by a failed payload append; the cursor and
windows advance only after the payload call; the caller sends the partial
queue; and the completed send retries the unchanged cursor. The concrete
control burst leaves 12 bytes in the declared 32 KiB queue, enough for the
header but not for a 32-byte body. `make -j4` should be run after this report
is recorded; no production source, configuration, or test file was changed in
this audit.

References:

- [RFC 9113 §6.1 — DATA](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.1)
- [RFC 9113 §6.5 — SETTINGS](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.5)
- [RFC 9113 §6.7 — PING](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.7)

## Resolution (2026-08-26) — CONFIRMED, and reproduced from legal traffic

### Reproduced

A backend whose opening write is thousands of zero-length non-ACK SETTINGS
frames — the first is the required preface, the rest are legal repeats — while a
64 KiB request body is pending. Each one obliges the client to queue a 9-byte
ACK, and the queue is 32 KiB. Sweeping the flood size on the audited binary,
driver path:

```
1600 frames (14400 bytes of ACKs)  ->  body arrives intact
2400 frames (21600 bytes of ACKs)  ->  H2C-FAIL, 8 runs out of 8
3600 frames (32400 bytes of ACKs)  ->  H2C-FAIL
```

The threshold is exactly the band the report predicts: enough staged output that
the 9-byte header fits and the 16384-byte payload does not. Below it the whole
frame fits and nothing goes wrong; above it the header is committed alone,
`body_sent` does not advance, and the retry writes a second header in front of
the first one's declared payload.

The blocking oracle writes synchronously and has no staging queue to overrun, so
it is unaffected at every flood size — driver-only, in the deployed path.

### The fix

`d_stage_body` now preflights the **whole** frame — nine header bytes plus the
selected payload — before appending either part, and returns the existing
blocked result without touching `out_len`, `body_sent`, or either window. The
caller drains and calls back, which it already knew how to do. Post-fix the body
arrives intact at 1600, 2400, 3600 and 6000 frames (54 KB of ACKs), and on the
production path end to end.

The source already suspected this: `.fail` is commented *"treat as blocked
(shouldn't happen)"*. It could happen.

### A neighbour, measured and left alone

`d_stage_settings_ack` and `d_stage_ping_ack` ignore their staging result the
same way. I measured rather than assumed: with 3601 SETTINGS frames, all 3601
ACKs came back, both through the harness and end to end through a real
`proxy_h2` front. Within a single read the ACK volume cannot exceed the queue —
20480 bytes of 9-byte frames is 20475 bytes of ACKs, and of 17-byte PINGs
20468 — so there is nothing to drop. It is reachable in principle at
production's 32 KiB read size combined with other staged output, and it is
recorded here rather than fixed on speculation.

### Coverage

Four rows: the flood and a small-flood control on each parser. Against a binary
built from the audited source, **1 fails and 3 pass as controls**. The rows
assert the request body the backend received, byte for byte — a status check
cannot see debris in the middle of a body.

**The first version of these rows passed on the broken build**, all four. The
helper ran `POST 0 "$@"` with `argv="0 drv"`, so `drv` landed in argv[6] and both
"driver" rows were the oracle. That is the same argv slip as audit-report-54,
in the same file, and the control caught it the same way: a row that cannot fail
is a row that is not testing what it names.

Full suite **1159 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source — eight runs out of eight
at the failing flood size, and a sweep locating the threshold between 1600 and
2400 frames — and re-run after the change at four flood sizes including one well
past the pre-fix breaking point, on both parsers and end to end through a real
`proxy_h2` front. The harness was rebuilt explicitly on both sides of the A/B,
which audit-report-70 established `make -j8` does not do.
