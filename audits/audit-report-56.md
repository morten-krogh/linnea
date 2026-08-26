# Audit Report 56

Audited at `cf8040d`, 2026-08-26.

Audit report 55's conclusion was correctly rejected: HTTP/2 processes repeated
SETTINGS values in order. The next backend-H2 connection-establishment gap is
enforcement of the server connection preface:

1. **Low: the backend client does not require the server's first frame to be a
   non-ACK SETTINGS frame.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — the server SETTINGS preface is optional in the client

Severity: **Low (P3, a malformed upstream can send a response before completing
HTTP/2 connection setup)**  
Confidence: **High**  
Status: **Confirmed as filed.** Fixed in both parsers, at the one shared
reader and the one shared dispatcher. The rule was checked against nghttp2
acting as a client before any code was written.

RFC 9113 §3.4 requires the server connection preface to be a SETTINGS frame and
requires that frame to be the first frame the server sends. The client may send
its request immediately after its own preface, but it still must receive and
process the server's connection preface before accepting a server response.

The blocking exchange sends its client preface, SETTINGS, and request HEADERS
as one write ([src/server/linnea_h2_client.asm:156](/home/linnea/linnea/src/server/linnea_h2_client.asm:156)
through [:234](/home/linnea/linnea/src/server/linnea_h2_client.asm:234)).
For a bodyless request it then jumps directly to `h2c_run_response`
([src/server/linnea_h2_client.asm:236](/home/linnea/linnea/src/server/linnea_h2_client.asm:236)
through [:247](/home/linnea/linnea/src/server/linnea_h2_client.asm:247)).
That response loop has no `server_settings_received` requirement, so a valid
stream-1 HEADERS/DATA response can be accepted before any server SETTINGS
frame.

For a request with a body, `h2c_send_body` calls `h2c_settle`, but the settle
loop is not a first-frame gate. It processes a WINDOW_UPDATE, PING, RST_STREAM,
or GOAWAY before a non-ACK SETTINGS frame and continues looping
([src/server/linnea_h2_client.asm:1034](/home/linnea/linnea/src/server/linnea_h2_client.asm:1034)
through [:1057](/home/linnea/linnea/src/server/linnea_h2_client.asm:1057)).
Thus even this path accepts a server connection preface whose first frame is
not SETTINGS. An unknown frame also falls through the loop after it has been
read.

The resumable driver has a `settled` field and enters `ST_SETTLE` for a request
with a body ([src/server/linnea_h2_client.asm:2569](/home/linnea/linnea/src/server/linnea_h2_client.asm:2569)
through [:2577](/home/linnea/linnea/src/server/linnea_h2_client.asm:2577)), but
`d_dispatch` never uses that state to restrict the first received frame. Its
WINDOW_UPDATE, PING, and response-frame arms are available before
`d_apply_settings` sets `settled` ([src/server/linnea_h2_client.asm:2720](/home/linnea/linnea/src/server/linnea_h2_client.asm:2720)
through [:2795](/home/linnea/linnea/src/server/linnea_h2_client.asm:2795)).
For a bodyless request, `linnea_h2c_drv_on_sent` explicitly changes directly
from `SEND_INIT` to `RESP` without waiting for server SETTINGS
([src/server/linnea_h2_client.asm:2562](/home/linnea/linnea/src/server/linnea_h2_client.asm:2562)
through [:2577](/home/linnea/linnea/src/server/linnea_h2_client.asm:2577)).

The result is a malformed-upstream acceptance and an implementation divergence
from the intended state model: `settled` records whether SETTINGS were seen,
but a response can complete while it is still clear. If the server SETTINGS
would have changed how the client must send subsequent frames, the client has
already made its response decision without seeing those settings.

### Reproduction

For a bodyless request, have the backend send the response before its SETTINGS:

```text
HEADERS   stream 1, END_HEADERS, payload = a valid :status 200 block
DATA      stream 1, END_STREAM, payload = "body"
SETTINGS  stream 0, non-ACK, legal payload
```

Both blocking and resumable paths accept the HEADERS and DATA and return a
successful response before reading the trailing SETTINGS. The required first
server frame was never observed. Replacing the first frame with a valid PING
or WINDOW_UPDATE and then sending SETTINGS is accepted on the bodyful blocking
settle path as well; the PING is even acknowledged before the server preface
has been received.

The backend fixture always sends its SETTINGS immediately after consuming the
client preface ([test/h2/h2c_server.py:241](/home/linnea/linnea/test/h2/h2c_server.py:241)
through [:271](/home/linnea/linnea/test/h2/h2c_server.py:271)), so its normal
responses cannot expose this. The frontend HTTP/2 suite has an analogous
first-SETTINGS check for client input, but it does not exercise Linnea's
backend-H2 client as a peer.

### Recommended fix

Track a per-exchange server-preface state and require the first frame received
from the backend to be a non-ACK SETTINGS frame on stream 0 with a valid
payload. Do this before dispatching PING, WINDOW_UPDATE, terminal frames, or
response frames. A malformed or missing first SETTINGS must fail the backend
exchange; do not acknowledge or apply later frames before that gate succeeds.

Use the same rule for the blocking and resumable paths. For bodyless requests,
wait for the server SETTINGS before entering response parsing. For bodyful
requests, make `h2c_settle` and the driver's `ST_SETTLE` state reject every
non-SETTINGS first frame while preserving the existing handling of legal
frames after the preface. Add backend-fixture cases for response-first,
PING-first, WINDOW_UPDATE-first, and SETTINGS-ACK-first sequences, with a
normal response after each to prove the refusal is caused by the missing
server preface. Keep the legal server SETTINGS-first response as a control.

## Verification

This finding is a source-level trace through the blocking exchange, settle loop,
normal response loop, resumable state transition, and resumable dispatcher.
`make -j4` completed with no work required. The backend fixture always emits a
legal SETTINGS frame first and has no negative server-preface cases; the
frontend's corresponding first-SETTINGS test covers the opposite direction.
No production source, configuration, or test file was changed that required
runtime verification.

## Resolution (2026-08-26) — CONFIRMED as filed

### Reproduced

A fixture that puts each offending frame in front of its SETTINGS and then
sends a perfectly good response behind it, so a refusal can only be the missing
preface. On the audited binary, both parsers:

```
prefnone   (the RESPONSE first)      200 OK    200 OK
prefping   (a legal PING first)      200 OK    200 OK
prefwin    (a WINDOW_UPDATE first)   200 OK    200 OK
prefack    (an ACK of ours first)    200 OK    200 OK
prefempty  (an EMPTY SETTINGS)       200 OK    200 OK   <- legal, the control
```

All four malformed orders accepted, on both paths, exactly as filed.

### Checked against the reference client before changing anything

Report 55 was rejected because it borrowed a rule from HTTP/3. This one does
not: RFC 9113 §3.4 makes the server preface a SETTINGS frame that MUST be the
first frame the server sends, and an invalid connection preface a
PROTOCOL_ERROR. Our own frontend has enforced the mirror image since the
beginning — `test/tls/h2_error_codes.py` asserts that a client preface not
followed by SETTINGS is refused. We simply never asked it of a backend.

nghttp2 1.66.0's client, against the same four fixtures:

```
prefnone / prefping / prefack:
  [ERROR] Remote peer returned unexpected data while we expected SETTINGS frame.
  send GOAWAY frame
prefempty:  served normally
```

The reference implementation refuses exactly the rows we now refuse and accepts
exactly the one we still accept.

### The fix, in two places rather than five

- **Blocking:** a `h2c_preface_ok` flag checked inside `h2c_next_frame`, the one
  reader that settle, the flow-control pump and the response loop all share.
  Putting it in each of the three would repeat the mistake of audit-report-54.
  Reset per exchange beside the decoder carrier.
- **Resumable:** a gate at the top of `d_dispatch`, ahead of every other
  decision, keyed on the existing `.settled` field. The report is right that the
  state was already there and simply unused: `.settled` means "a non-ACK
  SETTINGS has been applied", which is precisely what a preface is.

An empty SETTINGS frame stays legal — §3.4 says "potentially empty" — so the
gate checks type, stream and the ACK flag, never the length.

### Coverage

Twelve rows: four malformed orders and the empty-preface control on each
parser, plus two end to end. Against a binary built from the audited source,
**9 fail and 3 pass as controls**:

```
pre-fix: preface (oracle|driver): prefnone prefping prefwin prefack   FAIL x8
pre-fix: preface: a response before SETTINGS is refused e2e           FAIL
pre-fix: preface (oracle|driver): an EMPTY SETTINGS is accepted       PASS <- control
pre-fix: preface: an empty SETTINGS preface serves e2e                PASS <- control
```

`prefempty` is the row a careless gate breaks, and it is not hypothetical: a
length check, or requiring the frame to carry INITIAL_WINDOW_SIZE, would refuse
a legal preface and take out every backend that sends an empty one.

### The regression this could have caused, and why it does not

The preface is per CONNECTION, not per request, so a gate that demands one on
every request would break any reused leg. Backend h2 legs are never pooled —
they are TLS, and a TLS leg is never parked (audit-report-41) — and the suite
already has a `proxy_h2 + proxy_keepalive` fixture asserting exactly that. It
stays green, as does the nginx interop shard: real nginx sends its SETTINGS
first, which is what the RFC requires of it.

Full suite **945 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the blocking oracle and the resumable driver, and end to end through
a real `proxy_h2` front. The rule was checked against nghttp2 1.66.0 acting as a
client on the same fixtures before any code was written, and against live nginx
afterwards. The empty-preface control is named as the row that separates this
fix from an over-strict one.
