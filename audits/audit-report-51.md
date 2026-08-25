# Audit Report 51

Audited at `748139e`, 2026-08-25.

Audit report 50's known SETTINGS value checks are present in both backend-H2
walkers. The next terminal-frame gap is in `RST_STREAM` and `GOAWAY` handling:

1. **Low: backend `RST_STREAM` and `GOAWAY` frames are converted directly into
   terminal outcomes without validating their required length or stream ID, and
   the blocking settle loop ignores `RST_STREAM` altogether.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — terminal backend frames are not structurally validated

Severity: **Low (P3, malformed upstream control can be misclassified and the
blocking path can continue after a stream reset)**  
Confidence: **High**  
Status: **Structurally confirmed** and fixed. The claimed divergence between
the oracle and the driver did NOT reproduce — both stop on a reset that lands
while the sender waits for credit, and both finish a body already in flight.

RFC 9113 §6.4 requires `RST_STREAM` to have exactly a four-octet error-code
payload and a nonzero stream ID. RFC 9113 §6.8 requires `GOAWAY` to be on stream
0 with a payload of at least eight octets. Unused flags may be ignored, but
these length and stream rules are mandatory.

The resumable dispatcher recognizes both frame types and jumps straight to the
terminal sentinels; neither branch checks `r15` or `d_fr_sid`
([src/server/linnea_h2_client.asm:2634](/home/linnea/linnea/src/server/linnea_h2_client.asm:2634),
[src/server/linnea_h2_client.asm:2845](/home/linnea/linnea/src/server/linnea_h2_client.asm:2845)). A
three-byte `RST_STREAM`, an `RST_STREAM` naming stream 0, a zero-length
`GOAWAY`, and a `GOAWAY` naming stream 1 all become ordinary
`LINNEA_H2C_DRV_RST` or `LINNEA_H2C_DRV_GOAWAY` results rather than backend
protocol failures.

The blocking response loop has the same unguarded terminal branches
([src/server/linnea_h2_client.asm:1424](/home/linnea/linnea/src/server/linnea_h2_client.asm:1424),
[src/server/linnea_h2_client.asm:1427](/home/linnea/linnea/src/server/linnea_h2_client.asm:1427)). Its
flow-control wait loop likewise maps any `RST_STREAM` or `GOAWAY` directly to a
sentinel ([src/server/linnea_h2_client.asm:1101](/home/linnea/linnea/src/server/linnea_h2_client.asm:1101),
[src/server/linnea_h2_client.asm:1104](/home/linnea/linnea/src/server/linnea_h2_client.asm:1104)).
Neither path distinguishes a valid terminal frame from malformed terminal
framing before exposing the result to its caller.

There is also a state inconsistency in the blocking oracle. During initial body
settling, `h2c_settle` handles SETTINGS, `WINDOW_UPDATE`, PING, and GOAWAY, but
does not dispatch `RST_STREAM`; every other frame falls through to the loop
([src/server/linnea_h2_client.asm:995](/home/linnea/linnea/src/server/linnea_h2_client.asm:995)). A
backend can therefore send a valid reset for stream 1, then a SETTINGS frame,
and the oracle proceeds to send the request body instead of returning the reset.
The resumable driver returns immediately from the same sequence because its
dispatcher does recognize `RST_STREAM`. The two implementations do not agree on
whether the stream is already terminated.

The frontend HTTP/2 matrix already requires a three-byte `RST_STREAM` to be a
`FRAME_SIZE_ERROR` and an `RST_STREAM` on stream 0 to be a `PROTOCOL_ERROR`
([test/tls/h2_error_codes.py:115](/home/linnea/linnea/test/tls/h2_error_codes.py:115),
[test/tls/h2_error_codes.py:131](/home/linnea/linnea/test/tls/h2_error_codes.py:131)).
There is no equivalent backend validation for either terminal frame type.

### Reproduction

During a backend exchange, send one of these before or instead of a normal
response:

```text
RST_STREAM  stream 1, length 3, payload = 00 00 00
RST_STREAM  stream 0, length 4, payload = 00 00 00 08
GOAWAY      stream 1, length 8, payload = 00 00 00 00 00 00 00 00
GOAWAY      stream 0, length 0, payload = ""
```

The resumable driver and blocking response loop classify each malformed frame as
the corresponding reset or goaway outcome. During blocking settle, a valid
`RST_STREAM stream 1` is ignored if the backend follows it with SETTINGS; the
oracle then sends DATA on a stream the peer has already reset. A valid RST or
GOAWAY in the state where it is handled remains a legitimate terminal control
case and should continue to produce its existing sentinel.

### Recommended fix

Validate terminal frames before returning their sentinels in both paths:

1. Require `RST_STREAM` payload length exactly 4 and stream ID 1 for this
   single-stream backend leg. Treat other stream IDs as backend protocol errors.
2. Require `GOAWAY` stream ID 0 and payload length at least 8. Preserve the
   existing GOAWAY sentinel for a valid frame.
3. Add an explicit `RST_STREAM` branch to `h2c_settle` so a valid reset is
   returned immediately and cannot be followed by request-body transmission.
4. Keep malformed terminal frames distinct from valid backend reset/goaway
   outcomes, without reading or interpreting their payloads before validation.

Add backend-fixture cases for short `RST_STREAM`, stream-0 `RST_STREAM`, short
`GOAWAY`, and stream-1 `GOAWAY`, plus a settle-time valid RST followed by a
SETTINGS frame. Assert gateway failure and no request body after every malformed
or reset case. Retain valid RST/GOAWAY controls in both the blocking oracle and
the resumable driver.

## Verification

This finding is a source-level trace through the resumable dispatcher, the
blocking settle loop, the flow-control wait loop, and the blocking response
loop. `make -j4` completed with no work required. Existing malformed terminal
frame tests cover the frontend HTTP/2 server only; the backend fixture sends
valid terminal frames only. Runtime socket reproduction was not available in
this restricted environment, and no source change was made that required
executable verification.

## Resolution (2026-08-25) — structurally confirmed; the divergence it claims did not reproduce

### The structural half is real and unobservable

At `748139e` a three-octet `RST_STREAM`, an `RST_STREAM` naming stream 0, an
empty `GOAWAY` and a `GOAWAY` naming stream 1 all became ordinary terminal
sentinels. Both paths now require four octets on a nonzero stream, and eight or
more on stream 0.

It changes nothing observable. A **valid** reset already ends the exchange in a
502, so a malformed one did too — measured, all six cases identical before and
after:

```
/term-rstok  /term-rst3  /term-rst0  /term-gook  /term-goshort  /term-gosid
      502         502         502         502           502           502
```

The driver does not distinguish `LINNEA_H2C_RST` from `LINNEA_H2C_ERR` anywhere
downstream either — both reach `.ev_bad_gateway`. So this is classification, for
the code to be able to tell the two apart, not a behavioural fix.

### The claimed divergence did not reproduce

The report says the blocking oracle, lacking an `RST_STREAM` branch in
`h2c_settle`, "proceeds to send the request body instead of returning the
reset", while "the resumable driver returns immediately... The two
implementations do not agree."

I could not construct a case where they disagreed.

* **Reset racing an in-flight body** — fixture resets on END_HEADERS, 40 KB
  body, default window: *both* paths sent all 40000 bytes before the reset was
  parsed. That is not a defect; a body already on the wire cannot be un-sent.
* **Reset landing while the sender waits for credit** — fixture advertises a
  1024-byte window and sends `RST_STREAM` instead of the next credit: *both*
  paths sent **0 bytes** afterwards and failed the exchange.

The `h2c_settle` branch is added regardless, so the two agree by construction
rather than by the timing of when a reset happens to arrive. But the divergence
as described is not something I was able to demonstrate, and the fix should not
be read as having fixed it.

### Coverage

Seven checks. All of them pass on a pre-fix binary — there is nothing here for a
pre-fix control to discriminate, for the reason given above. They are worth
adding anyway because backend terminal frames had **no** coverage at all:
nothing said a backend reset produces a gateway error rather than a hang, or
that the connection recovers for the next request.

tls shard **307 passed, 0 failed**.

### An unrelated failure in the same run, which needs its own look

```
job 1 (h1): FAIL: upgrade under load loses no connection
  (35259 attempts, 2 lost (reset=2 refused=0 empty=0 other=0);
   retry: 31719 attempts, 1 lost (reset=1 refused=0 empty=0 other=0))
```

Two connections RST during a hot upgrade, and one more on the check's own retry.
Two subsequent h1-group runs lost none in ~42000 attempts each — but those were
not under the three-job load the failing run had, which is the same shape as the
h3 stress flake resolved in `b4b4040`.

This one deserves more than that comparison, because the invariant it guards is
the lossless reload — a headline behaviour, not a test's patience. It is not
this change: nothing here touches accept or reload. Recorded here and raised
rather than folded into this commit.

## Verification (resolution)

Every terminal case was run against a binary built from the audited source and
after the change, on the driver and the oracle, and is identical in both — which
is the finding. The two reset-timing scenarios above were built specifically to
separate "sent before the reset arrived" from "sent after a reset was known",
because only the second would be a defect.
