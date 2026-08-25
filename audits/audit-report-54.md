# Audit Report 54

Audited at `ba30604`, 2026-08-25.

Audit report 53's stream-ownership checks are present in both backend-H2
parsers. The next gap is an omitted call site in the blocking upload path:

1. **Medium: the blocking backend oracle still acknowledges malformed or
   already-ACKed PING frames while waiting for request flow-control credit.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — the flow-control pump bypasses PING validation

Severity: **Medium (P2, malformed upstream can cause an out-of-frame payload
read and an invalid ACK)**  
Confidence: **High**  
Status: **Confirmed as filed and reproduced on the wire.** The omission is
mine, from report 46's fix. The three copies of the rule are now one helper.

HTTP/2 PING frames require exactly eight payload octets and stream 0. A PING
with the ACK flag set is a response and must not be answered with another ACK
(RFC 9113 §6.7, [RFC 9113 §6.7](https://www.rfc-editor.org/rfc/rfc9113#section-6.7)).

The blocking oracle validates those rules in `h2c_settle`
([src/server/linnea_h2_client.asm:1056](/home/linnea/linnea/src/server/linnea_h2_client.asm:1056)
through [:1065](/home/linnea/linnea/src/server/linnea_h2_client.asm:1065)) and
again in the normal response loop
([src/server/linnea_h2_client.asm:1331](/home/linnea/linnea/src/server/linnea_h2_client.asm:1331)
through [:1343](/home/linnea/linnea/src/server/linnea_h2_client.asm:1343)).
The resumable driver's `d_dispatch` has the equivalent checks
([src/server/linnea_h2_client.asm:2797](/home/linnea/linnea/src/server/linnea_h2_client.asm:2797)
through [:2819](/home/linnea/linnea/src/server/linnea_h2_client.asm:2819).

The upload path has a third frame-reading loop, `h2c_pump_window`, used when
the request's stream or connection window is exhausted
([src/server/linnea_h2_client.asm:1077](/home/linnea/linnea/src/server/linnea_h2_client.asm:1077)
through [:1102](/home/linnea/linnea/src/server/linnea_h2_client.asm:1102)). Its
PING arm calls `h2c_send_ping_ack` without checking the frame's stream ID,
length, or ACK flag ([src/server/linnea_h2_client.asm:1121](/home/linnea/linnea/src/server/linnea_h2_client.asm:1121)
through [:1123](/home/linnea/linnea/src/server/linnea_h2_client.asm:1123).
Thus the same oracle has two correct PING handlers and one stale handler.

The ACK helper always copies a full qword from the current frame payload
([src/server/linnea_h2_client.asm:857](/home/linnea/linnea/src/server/linnea_h2_client.asm:857)
through [:871](/home/linnea/linnea/src/server/linnea_h2_client.asm:871)).
`h2c_next_frame` reads only the declared payload length, so a seven-byte PING
received by the flow-control pump causes the eighth echoed byte to come from
the following contents of the reusable frame buffer rather than from that
frame. An ACK PING also receives an unsolicited ACK in this path.

This omission matters only in the blocking upload state: `h2c_pump_window` is
called from `h2c_send_body` after the initial SETTINGS have reduced one of the
send windows to zero ([src/server/linnea_h2_client.asm:1155](/home/linnea/linnea/src/server/linnea_h2_client.asm:1155)
through [:1162](/home/linnea/linnea/src/server/linnea_h2_client.asm:1162)).
The normal response PING tests therefore do not exercise it, and the
resumable driver already refuses the malformed cases.

### Reproduction

Have the backend advertise a small `INITIAL_WINDOW_SIZE`, let the client send
one DATA chunk until its request window reaches zero, then send:

```text
PING          stream 0, length 7, payload = "1234567"
WINDOW_UPDATE stream 0, increment = 1024
WINDOW_UPDATE stream 1, increment = 1024
```

The blocking oracle is inside `h2c_pump_window` when it reads the PING. It
constructs and sends a 17-byte PING ACK, copying eight bytes from a seven-byte
payload, then processes the WINDOW_UPDATE frames and continues the upload. The
resumable driver rejects the same PING before staging any ACK. Replacing the
first frame with an eight-byte PING carrying the ACK flag produces the same
oracle/driver divergence: the blocking pump answers an ACK with another ACK,
while the driver consumes it without replying.

The existing backend PING fixture sends its PING before the response
([test/h2/h2c_server.py:648](/home/linnea/linnea/test/h2/h2c_server.py:648)
through [:668](/home/linnea/linnea/test/h2/h2c_server.py:668)). The existing
throttled upload fixture forces the body sender to wait, but emits only
WINDOW_UPDATE frames ([test/h2/h2c_server.py:51](/home/linnea/linnea/test/h2/h2c_server.py:51)
through [:60](/home/linnea/linnea/test/h2/h2c_server.py:60)). No current test
combines a blocked upload with a backend PING, and the end-to-end upload rows
exercise the resumable driver rather than this blocking oracle.

### Recommended fix

Make the flow-control pump use the same PING validation as the other blocking
sites: require stream 0 and length 8, inspect ACK before calling the echo
helper, consume an ACK without replying, and reject a malformed PING before
the helper reads its payload. A shared helper would reduce the chance that a
future frame-reading loop repeats this omission.

Extend the backend fixture with throttled-upload cases for a seven-byte PING, a
PING on stream 1, and an already-ACKed PING, each followed by legal window
updates and a normal response. Assert refusal for the malformed stream/length
cases and no returned ACK for the ACK case in both the blocking oracle and the
resumable driver. Retain the existing legal PING and unused-flag controls.

## Verification

This finding is a source-level trace through all three blocking PING call sites,
the resumable dispatcher, the frame reader, and the qword-copying ACK helper.
`make -j4` completed with no work required. Existing backend PING coverage
exercises the settle/response path, while existing upload coverage exercises
only WINDOW_UPDATE during the pump; neither covers this combination. No source,
configuration, or test file was changed that required runtime verification.

## Resolution (2026-08-25) — CONFIRMED as filed, and it is my omission from 46

### Reproduced

A fixture that throttles the upload to a 1024-byte initial window and then puts
a PING in front of the WINDOW_UPDATEs that unblock the sender — so the frame is
read inside `h2c_pump_window` and nowhere else. On the audited binary:

```
                oracle (blocking)                      driver (resumable)
pumpok   200, ACK "ABCDEFGH"                   200, ACK "ABCDEFGH"   <- control
pump7    200, ACK hex 3132333435363700         H2C-FAIL
pumpsid  200, ACK "ABCDEFGH"                   H2C-FAIL
pumpack  200, and an ACK answered with an ACK  200, no reply         <- driver right
```

`3132333435363700` is the finding, measured: `"1234567"` and an eighth byte
from past the frame, echoed back to the backend. The driver is correct on all
four rows, so the divergence is exactly the one the report describes.

Report 46's resolution says "The two blocking-oracle sites get the same check."
There were three. This is that miss, filed back to me.

### The fix

The rule now exists once, as `h2c_ping_frame`: stream 0, length 8, an ACK
consumed and never answered. All three blocking loops call it — settle, the
response loop, and the flow-control pump. The report asks for exactly this and
is right that three copies is how the omission happened in the first place.

Its contract is `0 = handled, -1 = malformed OR the ACK could not be sent`. The
send result was previously discarded at all three sites; a failed ACK now ends
the exchange rather than continuing into a read that would fail anyway. That is
a small tightening beyond what was asked, and the header comment says so rather
than leaving it to be discovered.

### Coverage

Eight new rows, four fixture modes on each parser. Against a binary built from
the audited source:

```
pre-fix: pump ping (oracle): a 7-octet PING is refused              FAIL
pre-fix: pump ping (oracle): a PING naming a stream is refused      FAIL
pre-fix: pump ping (oracle): an ACK is consumed, never answered     FAIL
pre-fix: pump ping (oracle): a legal PING is echoed with ACK        PASS  <- control
pre-fix: pump ping (driver): all four rows                          PASS  <- control
```

Three of eight are this fix's work; the four driver rows passing is the
measurement that says the defect was oracle-only, not an assumption. The
`pumpok` row is the control that stops this becoming a rule against PINGs
during an upload — the pump must still answer a legal one.

No end-to-end row is added, deliberately: `h2c_pump_window` belongs to the
blocking oracle, and every end-to-end upload row drives the resumable driver.
An e2e check here would pass on the broken build.

### One trap, mine

My first pass reported the driver as equally broken on three rows. Two probe
faults, not server behaviour:

- I passed the mode as `POST 0 $m` where the harness takes `argv[4]` as the
  chunk cap, so `drv` landed in `argv[6]` and every "driver" run was the oracle
  again.
- Before that, one port was reused across four fixture modes and a stale
  fixture served later runs.

Both were caught by making the fixture log which mode it fired and what the
client actually sent, rather than trusting the client's output alone. A third:
the pre-fix response body carries a literal NUL — the out-of-frame byte — so
`grep` treated the stream as binary and printed nothing, which reads as "no
response". The shard helper strips NUL and CR so a check cannot mistake that
for a pass.

Full suite **922 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the blocking oracle and the resumable driver, with the fixture
reporting the PING ACK it received rather than the client reporting itself. The
echoed out-of-frame byte was read off the wire in hex. The existing
response-phase PING rows (legal, ACK, unused-flag, 7-octet, wrong-stream) were
re-run on both parsers to confirm the shared helper did not change them.
