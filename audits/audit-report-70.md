# Audit Report 70

Audited at `05e8d7f` (`backend h2: END_STREAM ends the parse, so the body
cannot change after it`), 2026-08-26.

Audit report 69's terminal response check is present. The next backend-H2
state/resource gap is in the resumable driver's response flow-control path:

1. **Medium: the driver silently drops response `WINDOW_UPDATE` frames when
   its outbound staging buffer fills, eventually stalling a legal response.**

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — ignored staging failure loses flow-control credit

Severity: **Medium (P2, a legal backend response can make the proxy stall
before the configured one-MiB body limit)**  
Confidence: **High**  
Status: **Confirmed as a credit loss, measured: 31.7% of it dropped.** The
predicted STALL does not reproduce — the loss is self-limiting. Fixed by
accruing credit and staging it once per read, with the result checked.

The resumable driver uses a fixed 32 KiB output queue
([include/linnea_h2_client.inc:136](/home/linnea/linnea/include/linnea_h2_client.inc:136)).
`d_out_append` correctly reports an over-capacity append through the carry flag
([src/server/linnea_h2_client.asm:2491](/home/linnea/linnea/src/server/linnea_h2_client.asm:2491)
through [:2512](/home/linnea/linnea/src/server/linnea_h2_client.asm:2512)).
`d_stage_window` builds a 13-byte HTTP/2 `WINDOW_UPDATE` and delegates to that
bounded append ([src/server/linnea_h2_client.asm:2541](/home/linnea/linnea/src/server/linnea_h2_client.asm:2541)
through [:2561](/home/linnea/linnea/src/server/linnea_h2_client.asm:2561)).

For every nonempty response DATA frame, however, the driver calls that helper
twice—once for connection stream 0 and once for response stream 1—and ignores
both carry results ([src/server/linnea_h2_client.asm:3508](/home/linnea/linnea/src/server/linnea_h2_client.asm:3508)
through [:3516](/home/linnea/linnea/src/server/linnea_h2_client.asm:3516)).
The DATA dispatch still returns success, so the parser consumes the frame and
the lost credit is not recorded for a later retry.

The receive path is exposed to this queue behavior in production: io_uring
receives backend bytes into the same `out_buf`-sized 32 KiB region
([src/server/linnea_uring.asm:4693](/home/linnea/linnea/src/server/linnea_uring.asm:4693)
through [:4703](/home/linnea/linnea/src/server/linnea_uring.asm:4703)), and
the HTTP/2 event handler feeds each read to the resumable driver
([src/server/linnea_http2.asm:3929](/home/linnea/linnea/src/server/linnea_http2.asm:3929)
through [:3935](/home/linnea/linnea/src/server/linnea_http2.asm:3935)).
The driver parses every complete frame in that input before returning to the
event loop ([src/server/linnea_h2_client.asm:3168](/home/linnea/linnea/src/server/linnea_h2_client.asm:3168)
through [:3189](/home/linnea/linnea/src/server/linnea_h2_client.asm:3189)).

### Reproduction

Have a backend send a valid response HEADERS frame followed by many legal
stream-1 DATA frames, each with a one-byte payload and no padding. A DATA
frame is 10 bytes on the wire (9-byte header plus one byte), while processing
it attempts to append 26 bytes of flow-control frames (two 13-byte frames).

Starting with an empty output queue, a single 32 KiB read can contain 3,276
complete one-byte DATA frames (32,760 input bytes). The output queue can hold
only 2,520 `WINDOW_UPDATE` frames (32,760 bytes). After roughly 1,260 DATA
frames, both staging calls begin to fail, but the driver continues appending
body bytes and consuming frames. A preceding SETTINGS ACK or other control
frame reduces this threshold further.

The initial connection receive window is the HTTP/2 default 65,535 bytes; the
driver does not send an initial connection-level window enlargement. Repeating
legal small-frame bursts therefore consumes connection credit that the driver
believes it is returning but has silently failed to queue. With the simple
empty-queue arithmetic above, about 32 such bursts can receive approximately
105 KiB of body while losing roughly 64 KiB of connection credit—well below
the one-MiB body cap ([include/linnea_h2_client.inc:65](/home/linnea/linnea/include/linnea_h2_client.inc:65)).
The backend then stops when its connection window is exhausted, while Linnea
waits for the response to finish.

This remains a legal response shape: DATA frames may be fragmented, and the
body is below the driver's configured cap. The problem is not the optional
choice to reject an over-window frame discussed in audit-report-64. The
driver deliberately accepts the DATA and attempts to restore both windows,
then loses that required implementation state when its own queue is full.
HTTP/2 flow-control rules and the connection/stream windows are described in
[RFC 9113 §5.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-5.2) and
[RFC 9113 §6.9](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9).

### Impact

A backend that uses ordinary large DATA frames is unlikely to hit the
expansion ratio, because two 13-byte updates per frame are amortized over the
payload. A backend-controlled or intermediary-controlled response that splits
the same body into many one-byte frames can, however, fill the queue without
exceeding the body cap or sending an invalid frame. Once connection credit is
lost, the response can hang until the proxy's timeout and be surfaced as a
gateway failure. The driver has also already appended the accepted bytes, so
simply returning success from the dispatch does not make the missing credit
recoverable.

### Recommended fix

Make flow-control credit lossless and make queue pressure a parser state:

- check the carry result from each `d_stage_window` call;
- if either update cannot be staged, stop before consuming additional DATA,
  preserve the frame/credit amount as pending state, and return `WANT_SEND`
  so the event loop flushes the queue; or reserve space for both updates
  before appending the body;
- if updates are coalesced, retain separate pending connection and stream
  credit counters and flush them without dropping either counter.

Do not treat a failed append as a successfully processed DATA frame. Add a
direct driver test with a burst of more one-byte DATA frames than the output
queue can service, and assert that every accepted payload byte eventually
produces both connection- and stream-level credit and that the response
completes. Add an end-to-end `proxy_h2` fixture that repeats the burst until
the default connection window would otherwise be exhausted. Keep controls for
large DATA frames and for a burst split across reads with output drained
between reads.

## Verification

The source trace establishes the failure without changing the code: a 13-byte
append can set carry in `d_out_append`; both DATA-side callers ignore it; the
same receive invocation continues parsing complete frames; and the connection
window credit is not represented anywhere else in the driver. The arithmetic
uses the declared 32 KiB queue, 10-byte one-byte DATA frames, and the HTTP/2
default 65,535-byte connection window. `make -j4` completed with no work
required; no production source, configuration, or test file was changed in
this audit.

References:

- [RFC 9113 §5.2 — Flow Control](https://www.rfc-editor.org/rfc/rfc9113.html#section-5.2)
- [RFC 9113 §6.1 — DATA](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.1)
- [RFC 9113 §6.9 — WINDOW_UPDATE](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9)

## Resolution (2026-08-26) — CONFIRMED as a credit loss; the predicted stall is not

### The loss is real, and measured

A backend that splits a legal body into one-byte DATA frames **and obeys its own
windows** — the only kind of backend that can show this — against the audited
binary, 200,000 bytes:

```
                credit returned      WINDOW_UPDATE frames sent to it
driver          136,680 / 200,000    273,360
oracle          200,000 / 200,000    400,000
```

The driver dropped **31.7%** of the credit it had decided to return. The
blocking oracle writes its updates synchronously and loses none, so this is
driver-only — the deployed `proxy_h2` path.

### The stall is not reproducible, and the reason is interesting

The report predicts the connection window is exhausted and the response hangs.
It does not happen — not through the harness, and not end to end through a real
`proxy_h2` front at 120 KB, 400 KB or 900 KB of one-byte frames. The loss is
**self-limiting**: losing credit shrinks the peer's window, a smaller window
makes it send smaller bursts, smaller bursts fit the output queue, and credit
starts flowing again. The system settles just short of exhaustion instead of
crossing it.

So the arithmetic in the report is right about the queue and wrong about the
consequence, because it assumes the backend keeps bursting at full size after
its window has shrunk. A window-respecting backend throttles itself first.

It is still a defect worth fixing: dropping a frame we decided to send is
silent data loss in the flow-control protocol, and the equilibrium that saves it
depends on the queue size, the read size and the frame size — three constants
that reports 64 and 67 have already shown can move.

### The fix removes the expansion rather than patching the symptom

Two 13-byte updates per DATA frame is 26 bytes of output for a frame that may be
10 bytes on the wire. Credit now **accrues** in the context and is staged **once
per read**, and the staging result is *checked*: if the queue is full the credit
stays pending and goes out on the next pass, so it cannot be lost.

```
                credit returned      WINDOW_UPDATE frames
driver, fixed   198,656 / 200,000    196
```

The same body, credited losslessly, with 196 control frames instead of 273,360.
The 1,344-byte remainder is credit still pending when the exchange ends, which
nothing is waiting for.

### Four measurement faults of mine, and what caught each

This report took four attempts to measure honestly, which is worth recording:

1. **The fixture credited both updates to one counter.** The client returns
   credit on stream 0 *and* stream 1; adding both to one window grants double
   credit and hides the loss completely. First run: "no stall, nothing wrong".
2. **I measured without draining.** The fixture stopped reading when it had sent
   everything, leaving credit unread in the socket buffer. That made the
   *oracle* look like it lost 30% too — it loses nothing.
3. **I measured a stale harness.** `make -j8` builds `bin/linnea`, not
   `bin/linnea-h2client`, so a `git stash pop` followed by `make -j8` left the
   pre-fix harness in place and the fix appeared to do nothing. Rebuild the
   harness explicitly, every time.
4. **`set --` in the shard clobbered the runner's own positional parameters**,
   corrupting the suite footer into `run_tests.sh 200000 136680`. Caught by
   reading the control's output rather than only its verdicts.

Only the third of those was a fault in the fix; the other three were faults in
the instrument that would each have produced a confident wrong answer.

### Coverage

Four rows: the credit accounting and the response on each parser. Against a
binary built from the audited source, **1 fails and 3 pass as controls** — the
oracle rows are controls precisely because it never had the defect, and the
pair is what identifies this as driver-only.

Full suite **1155 passed, 0 failed**.

## Verification (resolution)

Measured on binaries built from the audited source and from the fix, with the
harness rebuilt explicitly for each, on both parsers, and end to end through a
real `proxy_h2` front. The backend reports its own credit accounting after
draining to completion, so "not sent" is not confused with "not yet read". The
absence of a stall was checked to 900 KB of one-byte frames rather than assumed.
