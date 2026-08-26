# Audit Report 68

Audited at `3e6368a` (`backend h2: the response buffer must hold a maximum
body PLUS its head`), 2026-08-26.

Audit report 67's response-composition capacity fix is present. The next
backend-H2 frame-validation gap is the still-defined HTTP/2 `PRIORITY` frame:

1. **Low: the backend HTTP/2 client ignores malformed `PRIORITY` frames as if
   they were unknown extension frames.**

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — backend HTTP/2 skips structural validation for PRIORITY frames

Severity: **Low (P3, malformed upstream control-frame handling)**  
Confidence: **High**  
Status: **Confirmed as filed and reproduced.** Fixed in both readers. We refuse
a stream-0 PRIORITY where nghttp2 serves it — the text and our own frontend
agree, and the divergence is named in the source.

HTTP/2 frame type `0x02` is the defined `PRIORITY` frame. Although the priority
signaling scheme is deprecated, RFC 9113 §6.3 retains its frame format and
validation rules: the frame payload must be exactly five octets, and the frame
must identify a nonzero stream. A wrong-length frame is a `FRAME_SIZE_ERROR`
and a stream-zero frame is a connection-level `PROTOCOL_ERROR`. A receiver may
ignore the priority information itself; it may not treat the defined frame as
an unknown type and skip its mandatory structure checks.

The backend-H2 include defines the other frame types, but has no
`LINNEA_H2C_FT_PRIORITY` constant ([include/linnea_h2_client.inc:13](/home/linnea/linnea/include/linnea_h2_client.inc:13)
through [:22](/home/linnea/linnea/include/linnea_h2_client.inc:22)). The
blocking response loop dispatches SETTINGS, WINDOW_UPDATE, PING, HEADERS,
CONTINUATION, DATA, RST_STREAM, and GOAWAY, then falls through to its ordinary
loop for every other type ([src/server/linnea_h2_client.asm:1624](/home/linnea/linnea/src/server/linnea_h2_client.asm:1624)
through [:1643](/home/linnea/linnea/src/server/linnea_h2_client.asm:1643)). A
type-`0x02` frame therefore reaches `jmp .loop` without checking either its
length or stream identifier.

The resumable driver's dispatch table has the same omission. After the known
handlers, it explicitly labels the fall-through as `ignore unknown`
([src/server/linnea_h2_client.asm:3249](/home/linnea/linnea/src/server/linnea_h2_client.asm:3249)
through [:3272](/home/linnea/linnea/src/server/linnea_h2_client.asm:3272)).
Because `0x02` is not routed separately, the driver also accepts a malformed
PRIORITY frame and continues parsing the following response.

This is distinct from the existing `PRIORITY` flag inside a HEADERS frame.
The current HEADERS paths check that the optional five-octet priority section
fits before skipping it ([src/server/linnea_h2_client.asm:1696](/home/linnea/linnea/src/server/linnea_h2_client.asm:1696)
through [:1702](/home/linnea/linnea/src/server/linnea_h2_client.asm:1702), and
[:3386](/home/linnea/linnea/src/server/linnea_h2_client.asm:3386) through
[:3392](/home/linnea/linnea/src/server/linnea_h2_client.asm:3392)). The
standalone frame type is a separate validation path and is currently absent.

### Reproduction

After the required non-ACK SETTINGS preface, have the backend send one of the
following on the connection, followed by an ordinary valid stream-1 `200`
response:

```text
PRIORITY  stream 1, payload length 0  -> must be rejected
PRIORITY  stream 1, payload length 4  -> must be rejected
PRIORITY  stream 1, payload length 6  -> must be rejected
PRIORITY  stream 0, payload length 5  -> must be rejected
```

The current blocking and resumable paths read each complete frame, classify
type `0x02` as the final unknown-frame case, and continue to the valid
response. The caller consequently receives a successful synthesized response
instead of a backend protocol failure.

A legal control should remain accepted:

```text
PRIORITY  stream 1, payload length 5  -> priority may be ignored, response serves
```

The existing `/prio-short` fixture does not cover this finding. It sets the
`PRIORITY` flag on a HEADERS frame and tests the five-octet optional section
inside that frame; it does not send a standalone type-`0x02` PRIORITY frame
([test/h2/h2c_server.py:997](/home/linnea/linnea/test/h2/h2c_server.py:997)
through [:1024](/home/linnea/linnea/test/h2/h2c_server.py:1024)).

### Impact

The bounded frame reader does not overrun memory for these inputs: it reads
the declared payload after applying the global 16,384-byte receive-frame cap.
The defect is nevertheless a protocol-boundary failure. A faulty or
compromised backend can send a known malformed control frame and have Linnea
silently normalize it away, then expose a later response as valid. This makes
the backend leg disagree with strict HTTP/2 peers and leaves malformed-frame
handling dependent on whether the frame happened to be placed between an open
HEADERS block (where the generic CONTINUATION gate rejects it) or elsewhere
(where it is ignored).

The issue affects both the standalone blocking oracle and the resumable driver
used by `proxy_h2`. It is not a claim that legal priority information must be
implemented; the priority tree may continue to be ignored after the frame's
required structure has been validated.

### Recommended fix

Add a `LINNEA_H2C_FT_PRIORITY equ 0x02` constant and route the type through a
small shared validation rule in both frame loops:

- require payload length exactly 5;
- require a nonzero stream identifier; and
- ignore the five priority octets after those checks, since this single-stream
  client does not implement priority scheduling.

For the blocking path, return the existing backend-error sentinel. For the
driver, return its ordinary failure sentinel. If the implementation later
grows precise HTTP/2 error emission, preserve RFC 9113's distinction between
the wrong-length stream error and stream-zero connection error.

Add direct-oracle and driver controls for a legal five-octet frame, wrong
lengths 0/4/6 on stream 1, and length 5 on stream 0. Add an end-to-end refusal
case through `proxy_h2`; retain the existing HEADERS-embedded priority test so
the two five-octet rules cannot be accidentally conflated.

## Verification

The source trace was checked in both backend-H2 readers. `h2c_next_frame` and
the resumable input parser safely retain the frame boundary, but neither
dispatch sequence has a branch for defined type `0x02`; both fall through to
the unknown-frame path. Existing `/prio-short` coverage concerns only the
HEADERS `PRIORITY` flag and therefore cannot detect this omission. `make -j4`
completed with no work required. No production source, configuration, or test
file was changed in this audit.

References:

- [RFC 9113 §4.2 — Frame Size](https://www.rfc-editor.org/rfc/rfc9113.html#section-4.2)
- [RFC 9113 §6.3 — PRIORITY](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.3)

## Resolution (2026-08-26) — CONFIRMED as filed

### Reproduced

Both parsers, at the audited commit, a standalone type-`0x02` frame followed by
an ordinary 200:

```
PRIORITY stream 1, length 0  -> 200 OK
PRIORITY stream 1, length 4  -> 200 OK
PRIORITY stream 1, length 6  -> 200 OK
PRIORITY stream 0, length 5  -> 200 OK
PRIORITY stream 1, length 5  -> 200 OK   <- legal, the control
```

The leg had no constant for `0x02` at all, so every shape fell through the
unknown-frame arm. Deprecated is not undefined.

### The eighth report with the same root

The frontend has enforced both halves for a long time, and its comment says the
same thing this fix says: *"a PRIORITY frame is exactly 5 octets and never on
stream 0. We do not act on it (RFC 9218 carries priority instead), but a
malformed one is still rejected."* The backend leg had never been asked.

### Where the checks live, and one divergence

The blocking rule sits in `h2c_next_frame` — the one reader that settle, the
flow-control pump and the response loop all share — because it depends only on
the frame, not on which loop is running. The driver's twin is an arm in
`d_dispatch`. Same split as the preface gate.

nghttp2 1.66.0 as a client splits on these rows: it refuses the wrong lengths
with `FRAME_SIZE_ERROR` and **serves** a PRIORITY on stream 0, which §6.3 makes
a MUST-level `PROTOCOL_ERROR`. We refuse it, which is the text and also what our
own frontend does — keeping the two directions in agreement is worth more here
than matching the reference's leniency. Named rather than left to be discovered.

### Three mistakes of mine, and what caught each

1. The blocking check was placed after the preface gate, whose `jne .ret` jumps
   **past everything below it** once the preface has been seen. The check was
   dead for every frame after the first. What caught it: the post-fix
   measurement did not move at all — a fix that changes nothing is a fix that
   is not running.
2. Two patch scripts aborted on anchors that matched zero times, and because
   the assert precedes the write, **neither** edit in those scripts landed. The
   driver stayed unfixed twice while I read the oracle's output as progress.
3. I stopped guessing anchors and inserted by line position instead, which
   worked first time.

### Coverage

Twelve rows: four malformed shapes and one legal control on each parser, plus
two end to end. Against a binary built from the audited source, **9 fail and 3
pass as controls**. `/prio-short` — the PRIORITY *flag* on a HEADERS frame —
stays green throughout and is kept deliberately separate: same five octets,
different rule.

Full suite **1141 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the blocking oracle and the resumable driver, and end to end through
a real `proxy_h2` front. The rules were put to nghttp2 as a client, and the
first attempt at that probe sent the PRIORITY frame *before* the server's
SETTINGS preface — so every row failed for the preface rule instead, including
the legal control, which is how the fault was visible.
