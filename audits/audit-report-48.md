# Audit Report 48

Audited at `5e31ffa`, 2026-08-25.

Audit report 47's `WINDOW_UPDATE` validation is present in both backend-H2
paths, and the flow-controlled upload now has production-path coverage. The
next control-frame gap is in backend `SETTINGS` handling:

1. **Medium: backend `SETTINGS` frames are accepted without structural and
   value validation, and `INITIAL_WINDOW_SIZE` replaces the current send window
   instead of applying the required delta during an upload.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — backend `SETTINGS` validation and window updates are incomplete

Severity: **Medium (P2, malformed or mid-upload settings can grant incorrect
request-body credit)**  
Confidence: **High**  
Status: **Confirmed as filed**, both halves (see Resolution). Fixed — with a
third change the report does not mention, without which its own recommendation
turns a 1024-byte over-credit into a 21808-byte one.

RFC 9113 §6.5.2 requires a `SETTINGS` frame to use stream 0. A non-ACK frame's
payload length must be a multiple of six, each setting is a two-octet identifier
plus a four-octet value, and an ACK frame must have an empty payload. The
`SETTINGS_INITIAL_WINDOW_SIZE` value must not exceed `2^31 - 1`. When that
setting changes after a stream has been used, the change is a delta from the
previous initial window and must be applied to every affected stream's current
window.

The resumable backend dispatcher checks only the ACK flag
([src/server/linnea_h2_client.asm:2569](/home/linnea/linnea/src/server/linnea_h2_client.asm:2569)).
For a non-ACK frame it passes the payload and length to `d_apply_settings`,
stages an ACK, and marks the leg settled
([src/server/linnea_h2_client.asm:2573](/home/linnea/linnea/src/server/linnea_h2_client.asm:2573)).
There is no check for stream 0, ACK length zero, or a payload length divisible by
six.

`d_apply_settings` walks only complete six-byte records and silently drops any
remainder ([src/server/linnea_h2_client.asm:1982](/home/linnea/linnea/src/server/linnea_h2_client.asm:1982)).
When it sees `INITIAL_WINDOW_SIZE`, it writes the four-byte value directly into
the current stream window ([src/server/linnea_h2_client.asm:1990](/home/linnea/linnea/src/server/linnea_h2_client.asm:1990)). It
does not reject `0xffffffff`, and it does not subtract or add the difference
between the new and previous initial windows.

The blocking/reference path has the same behavior. Its SETTINGS branches skip
any frame carrying ACK and otherwise apply the payload without validation
([src/server/linnea_h2_client.asm:985](/home/linnea/linnea/src/server/linnea_h2_client.asm:985),
[src/server/linnea_h2_client.asm:1237](/home/linnea/linnea/src/server/linnea_h2_client.asm:1237)). Its
`h2c_apply_settings` loop has the same remainder and direct-assignment behavior
([src/server/linnea_h2_client.asm:893](/home/linnea/linnea/src/server/linnea_h2_client.asm:893)).

The absolute assignment is correct only for the first server SETTINGS received
before any request body has been sent. It is not correct for a later SETTINGS
while `d_stage_body` or `h2c_pump_window` is sending the upload. For example,
with the default initial window of 65535, after 1000 bytes have been sent the
current stream window is 64535. If the peer then changes
`INITIAL_WINDOW_SIZE` to 1, RFC 9113 requires applying a delta of -65534, making
the current window -999. The current code instead writes 1 and permits another
byte, over-crediting the stream by 1000 bytes. Conversely, increasing the
setting writes the new initial value and over-credits by the amount already sent.

An invalid value of `0xffffffff` is stored as 4294967295, so the body sender can
treat a peer's illegal setting as a very large positive send window. A SETTINGS
frame naming stream 1, an ACK carrying bytes, or a five-byte non-ACK payload is
also accepted and the exchange continues. These are malformed upstream frames,
not optional peer settings to ignore.

The frontend HTTP/2 implementation already tests the corresponding failures:
non-multiple-of-six SETTINGS, an ACK with payload, an initial window above the
maximum, and a SETTINGS frame naming a stream
([test/tls/h2_error_codes.py:96](/home/linnea/linnea/test/tls/h2_error_codes.py:96),
[test/tls/h2_error_codes.py:98](/home/linnea/linnea/test/tls/h2_error_codes.py:98),
[test/tls/h2_error_codes.py:104](/home/linnea/linnea/test/tls/h2_error_codes.py:104),
[test/tls/h2_error_codes.py:113](/home/linnea/linnea/test/tls/h2_error_codes.py:113)).
The new backend upload coverage exercises repeated `WINDOW_UPDATE`, but does not
send a mid-upload SETTINGS change or malformed SETTINGS frame.

### Reproduction

Before a normal response, have the backend send any of these frames:

```text
SETTINGS  stream 1, length 6, {INITIAL_WINDOW_SIZE = 65535}
SETTINGS  stream 0, ACK, payload = 00
SETTINGS  stream 0, length 5, payload = 00 04 00 00 00
SETTINGS  stream 0, {INITIAL_WINDOW_SIZE = 0xffffffff}
HEADERS   stream 1, :status = 200, END_HEADERS
DATA      stream 1, END_STREAM, payload = "body"
```

The driver accepts the malformed cases instead of failing the backend exchange.
For the mid-upload case, let the client send some DATA, then send a non-ACK
SETTINGS changing `INITIAL_WINDOW_SIZE` before returning more credit. The
driver overwrites the remaining window with the new absolute value rather than
adjusting it by the setting delta, so subsequent DATA can exceed the peer's
actual flow-control allowance.

### Recommended fix

Validate SETTINGS before acknowledging or mutating flow-control state in both
backend paths:

1. Require stream 0.
2. Require an empty payload when ACK is set, and a payload length divisible by 6
   otherwise.
3. Validate each known setting's value, including
   `INITIAL_WINDOW_SIZE <= 0x7fffffff`; continue ignoring unknown identifiers as
   required by RFC 9113.
4. Track the previous initial stream window. On every valid
   `INITIAL_WINDOW_SIZE`, apply `new_initial - old_initial` to the current stream
   window using signed, checked arithmetic; do not replace the current window.
5. Keep the state unchanged and do not stage an ACK when the frame is invalid.

Add backend-fixture cases for a nonzero stream ID, a non-multiple-of-six payload,
an ACK with a payload, and an out-of-range initial window. Add a throttled upload
case that changes `INITIAL_WINDOW_SIZE` after DATA has been sent in both
directions (increase and decrease), asserting the amount of DATA remains within
the adjusted window and that the exchange either completes or blocks exactly as
the peer's credit dictates. Cover the blocking oracle as well as the resumable
driver.

## Verification

This finding is a source-level trace through the resumable SETTINGS dispatcher,
the blocking settling and response loops, both settings walkers, and the
flow-controlled body sender. `make -j4` completed with no work required.
Existing malformed SETTINGS tests cover the frontend HTTP/2 server only; the
backend fixture sends valid initial settings and does not change them during its
throttled upload. Runtime socket reproduction was not available in this
restricted environment, and no source change was made that required executable
verification.

## Resolution (2026-08-25) — CONFIRMED, both halves — and the fix as specified makes it worse

### Both halves reproduce

Structural, at `5e31ffa`: a SETTINGS naming stream 1, an ACK carrying a payload,
a five-octet non-ACK payload, and `INITIAL_WINDOW_SIZE = 0xffffffff` were all
accepted and acknowledged, on the driver and the oracle alike.

The value half, measured rather than argued. A fixture that advertises 8192,
lets the body spend all of it, then lowers `INITIAL_WINDOW_SIZE` to 1024 and
grants nothing, reporting what arrives afterwards:

```
at 5e31ffa:  AFTER=1024
```

1024 bytes of DATA the peer never authorised — exactly the over-credit the
report describes. The correct answer is none: `0 + (1024 - 8192)` is negative.

### The recommendation, applied literally, is worse than the bug

Converting the assignment to a delta is right, and on its own it took the same
measurement from 1024 to **21808** — the entire rest of the body.

Because a delta makes the stream window **genuinely negative** for the first
time, and `d_stage_body` chose `min(stream_win, conn_win)` with an **unsigned**
compare. A negative stream window read as enormous, the connection window won
the minimum, and the sender spent credit no one had granted. The `jle` guarding
"blocked" immediately below it was already signed; the comparison two
instructions earlier was not, and nothing had ever put a negative value through
it because the old assignment could not produce one.

So the fix is three things, not two:

1. structure — stream 0, an empty ACK, a payload that is a multiple of six, and
   `INITIAL_WINDOW_SIZE <= 0x7fffffff`, checked before anything is applied or
   acknowledged;
2. the delta — a per-leg `peer_init_win` (65535, the protocol default, so the
   first SETTINGS behaves exactly as the old assignment did) and
   `stream_win += new - old`;
3. **both window minima made signed**, in `d_stage_body` and its oracle twin,
   without which (2) is a regression rather than a fix.

A fourth thing, briefly: the first version of (2) initialised the global twin
but not the per-leg field, so it began at 0 and the first SETTINGS became a
`+8192` delta instead of an assignment. The same fixture caught it — the
measurement moved rather than going to zero, which is what said the change was
half-applied.

### Coverage

Six new checks. Against a binary built from the audited source:

```
pre-fix: /set-sid is refused                                  FAIL
pre-fix: /set-acklen is refused                               FAIL
pre-fix: /set-len5 is refused                                 FAIL
pre-fix: /set-maxwin is refused                               FAIL
pre-fix: lowering INITIAL_WINDOW_SIZE is a delta              FAIL  (AFTER=1024)
pre-fix: a legal later SETTINGS is applied, response relays   PASS  <- control
```

The delta check reports the number it measured in its own label, so a future
failure says *how* it broke: `AFTER=1024` is an assignment, `AFTER=21808` is a
delta with an unsigned comparison behind it, and anything else is new.

Not covered as the report asks: it wants the increase direction as well as the
decrease. A raise is the safe direction — it over-credits by what was already
sent, which cannot exceed the peer's real allowance — and the fixture as built
observes bytes arriving after a lowering, which a raise cannot express. The
decrease is the one that lets a sender exceed the peer's window, and it is the
one asserted.

tls shard **282 passed, 0 failed**; full suite **868 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the resumable driver and the blocking oracle. The intermediate state
— delta applied, comparison still unsigned — was measured too, which is the only
reason the second defect was found before it shipped rather than after. The
throttled 50000-byte upload and the 64 KiB end-to-end upload were re-run, since
a change to how the send window is computed can satisfy every malformed case and
still stall or over-send a legitimate body.
