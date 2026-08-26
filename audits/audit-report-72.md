# Audit Report 72

Audited at `b44684d` (`backend h2: a request DATA frame is staged whole or
not at all`), 2026-08-26.

Audit report 71's whole-frame request staging is present. The next backend-H2
state-machine gap is in the blocking upload pump:

1. **Medium: the blocking client rejects a legal complete response when the
   server sends it before the request body can be transmitted.**

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — flow-control pumping treats an early response as an error

Severity: **Medium (P2, a legal backend response is turned into a gateway
failure by the blocking backend-H2 client)**  
Confidence: **High**  
Status: **Confirmed as filed and measured: oracle 0/5 pre-fix, 5/5 after;
driver 5/5 throughout.** Fixed with a one-frame pushback. The report's claim
that the driver is unaffected is correct — see the note on how I briefly
convinced myself otherwise.

HTTP/2 permits a server to send a complete response before the client has sent
the entire request, when the response does not depend on the unsent request
portion ([RFC 9113 §8.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1)).
This matters for a client whose request body is flow-control blocked: the
server can finish the response without granting any more request DATA credit.

The blocking exchange sends a request with a body through `h2c_send_body`
([src/server/linnea_h2_client.asm:268](/home/linnea/linnea/src/server/linnea_h2_client.asm:268)
through [:279](/home/linnea/linnea/src/server/linnea_h2_client.asm:279)). After
the server's SETTINGS sets the request stream window to zero, the body sender
calls `h2c_pump_window` while waiting for a WINDOW_UPDATE
([src/server/linnea_h2_client.asm:1506](/home/linnea/linnea/src/server/linnea_h2_client.asm:1506)
through [:1513](/home/linnea/linnea/src/server/linnea_h2_client.asm:1513)).

That pump accepts only WINDOW_UPDATE, SETTINGS, PING, RST_STREAM, and GOAWAY.
Any other frame, including a valid response HEADERS frame, falls directly to
the error result ([src/server/linnea_h2_client.asm:1426](/home/linnea/linnea/src/server/linnea_h2_client.asm:1426)
through [:1451](/home/linnea/linnea/src/server/linnea_h2_client.asm:1451)).
Consequently, a response that is already complete with
`HEADERS(END_HEADERS|END_STREAM)` is refused before the response parser gets a
chance to decode it.

The resumable driver does not have this gap. Its dispatcher accepts response
HEADERS independent of whether the request body is still being sent, decodes
the block, and marks the leg done when `END_STREAM` is present
([src/server/linnea_h2_client.asm:3421](/home/linnea/linnea/src/server/linnea_h2_client.asm:3421)
through [:3479](/home/linnea/linnea/src/server/linnea_h2_client.asm:3479)).
Thus the blocking oracle and the production resumable path disagree on a legal
early-completion response.

### Reproduction

Use a request with a nonempty body and have the backend send:

```text
SETTINGS  stream 0, non-ACK, INITIAL_WINDOW_SIZE = 0
HEADERS   stream 1, END_HEADERS | END_STREAM, :status = 204
```

The client has already sent the request HEADERS without `END_STREAM`, so it
has a body still to send. The initial server SETTINGS is legal and sets the
client's request stream window to zero. `h2c_settle` applies it and returns;
the next `h2c_pump_window` call sees the final response HEADERS. Because that
frame is not one of the pump's five accepted types, the pump returns
`LINNEA_H2C_ERR`, `h2c_send_body` aborts, and the blocking API returns an
error without relaying the valid 204 response.

The same behavior occurs with a final `200` HEADERS block carrying
`content-length: 0` and `END_STREAM`. A final response with DATA can expose
the same first-frame rejection, but the zero-body final HEADERS form isolates
the defect from response-body flow control. The frame ordering is legal: a
server may complete an independent response before receiving all request
DATA, and a response is complete once the `END_STREAM` flag is received.

This is not the missing server-preface case from audit-report-56. The server's
first frame is a valid SETTINGS preface; the rejected HEADERS is a subsequent
stream frame arriving while the client waits for request credit. It is also
not a malformed response: the driver's own response dispatcher accepts the
same HEADERS and completes successfully.

### Impact

Any caller using the blocking `linnea_h2c_exchange` path can receive a 502 or
generic exchange error from a backend that legally short-circuits an upload.
This pattern is useful for endpoints that reject or answer a request based on
its headers, authentication, routing, or an already-known resource state. The
resumable production path currently handles the isolated final HEADERS case,
so the principal defect is oracle/implementation divergence and loss of
interoperability for the blocking API, not a claim that every `proxy_h2`
request currently fails this way.

### Recommended fix

Give the blocking upload pump the same response-frame handling as the normal
response loop:

- either enter the response parser when `HEADERS` or `CONTINUATION` begins a
  response block, preserving the reassembled HPACK state and the current
  request-body cursor;
- or make the pump dispatch all valid response frames into the same response
  state machine and return a distinct “response complete” result;
- on a complete early response, stop sending the unsent request body and
  compose the response, as the resumable driver already does.

Do not solve this by waiting indefinitely for a WINDOW_UPDATE: the server is
permitted to finish without granting request credit. Add paired oracle/driver
tests for a final `HEADERS|END_STREAM` response after
`INITIAL_WINDOW_SIZE=0`, with both `204` and `200`/zero-length controls. Keep
the existing case where a WINDOW_UPDATE arrives first and the complete request
body is still sent, proving that the pump continues to handle ordinary upload
flow control.

## Verification

The source trace establishes the divergence without modifying production code:
the server SETTINGS can set the request stream window to zero; the blocking
sender then enters `h2c_pump_window`; its dispatch table sends every frame
other than control frames to `.err`; and the normal response parser is never
called. The resumable dispatcher has no equivalent request-body-state gate and
can mark the same final HEADERS response done. `make -j4` should be run after
this report is recorded; no production source, configuration, or test file was
changed in this audit.

References:

- [RFC 9113 §8.1 — HTTP Message Exchanges](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1)
- [RFC 9113 §6.9 — WINDOW_UPDATE](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9)
- [RFC 9113 §8.1.1 — Message Exchanges](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1.1)

## Resolution (2026-08-26) — CONFIRMED as filed, oracle-only exactly as stated

### Reproduced

A backend that grants zero request credit and then answers, with a 4 KiB body
pending. Five runs each, on binaries built from the audited source and from the
fix:

```
                 pre-fix     post-fix
oracle           0 / 5       5 / 5
driver           5 / 5       5 / 5
```

The report is right on both halves: the blocking pump refuses a legal early
response, and the resumable driver does not have the gap. End to end through a
real `proxy_h2` front the same request returns **204** on the audited binary,
which is the same statement from the production side.

### The fix

The pump's own comment named the limitation — *"response before END_STREAM:
unsupported in v1"*. The difficulty is that the pump has already **read** the
frame, so it cannot simply defer to the response parser.

It now pushes that one frame back: `h2c_pushback` says the frame in
`h2c_frame_buf` has been read but not consumed, `h2c_next_frame` returns it
instead of reading the wire, and the pump returns a distinct
`LINNEA_H2C_RESP_EARLY`. `h2c_send_body` treats that as "stop sending, the
server has answered" and the exchange falls into the response parser, which
reads the pushed-back frame exactly as if it had read it itself. A one-frame
pushback rather than a second copy of the response state machine.

Not sending the rest of the body is the correct outcome — §8.1 anticipates it,
and a fuller implementation would add `RST_STREAM(NO_ERROR)`, which v1 does not.

### Five wrong conclusions on the way here, four of them one bug

This report cost more wrong turns than any so far, and every one was the
instrument:

1. The fixture sent the zero-window SETTINGS and then **fell through to the
   default SETTINGS block**, which set the window back to 65535. The scenario
   under test never existed; both parsers "passed".
2. The fixture `return`ed immediately after the early response, **closing the
   socket** under a client that was still writing. The EPIPE looked exactly like
   the defect.
3. A startup race produced "NO RESPONSE" readings I briefly took as hangs.
4. **`POST drv` puts `drv` in the chunk-cap slot** — argv[4] — so every "driver"
   run in this report was the oracle. That produced a confident, wrong,
   *published-in-my-own-notes* conclusion that the driver was affected too and
   that the report was wrong about it. It is the third occurrence of this exact
   slip (audit-reports 54, 71, and here).
5. Chasing (4)'s phantom, I instrumented the binary with syscall probes and read
   their silence as evidence about the driver, when the driver was not running.

What finally settled it was not another probe: it was asking the **server** —
the end-to-end path through `proxy_h2` returned 204 and its own log said so,
which is a measurement the harness cannot fake.

### Coverage

Six rows: a 204 answered early, a 200 with `content-length: 0`, and the same
early answer with ordinary credit, on each parser. Against a binary built from
the audited source, **2 fail and 4 pass as controls** — and the four passes are
the point, because they are what makes this oracle-only rather than a claim.

Full suite **1165 passed, 0 failed**.

## Verification (resolution)

Five-run A/B on both parsers with the harness rebuilt explicitly on each side,
plus an end-to-end check through a real `proxy_h2` front on the audited binary.
The pump's ordinary duties — throttled uploads and the PING rules from
audit-report-54 — were re-run afterwards, since the pushback changes the reader
they share.
