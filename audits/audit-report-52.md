# Audit Report 52

Audited at `9a5370b`, 2026-08-25.

Audit report 51's `RST_STREAM`/`GOAWAY` checks are present in both backend-H2
paths. The next response-frame gap is enforcement of the peer's maximum frame
size:

1. **Low: backend response parsers accept DATA and other frames larger than the
   negotiated 16 KiB `MAX_FRAME_SIZE` default.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — backend frame-size limits are replaced by buffer limits

Severity: **Low (P3, a malformed upstream can relay a frame the HTTP/2 peer was
not permitted to send)**  
Confidence: **High**  
Status: **Confirmed as filed**. Fixed in both parsers. One of its suggested
checks is kept but labelled as a control: end to end, an oversized HEADERS
frame was already refused by an unrelated head bound.

RFC 9113 §4.2 limits frame payloads to the endpoint's advertised
`SETTINGS_MAX_FRAME_SIZE`. Linnea does not send that setting in its backend
SETTINGS frame, so the protocol default of 16384 bytes applies. The internal
receive buffers are not a substitute for this protocol limit: a frame can fit
in memory and still be invalid on the wire.

The blocking backend parser checks the declared payload length only against its
20480-byte frame buffer, accepting lengths through 20471
([src/server/linnea_h2_client.asm:819](/home/linnea/linnea/src/server/linnea_h2_client.asm:819)). It
then reads and dispatches the whole payload. A 16385-byte `DATA` frame is
therefore accepted even though the backend was limited to 16384.

The resumable parser has no frame-size check after decoding the 24-bit length.
It waits until the whole frame is present, then dispatches it
([src/server/linnea_h2_client.asm:2605](/home/linnea/linnea/src/server/linnea_h2_client.asm:2605)). Its
only relevant bound is the 65536-byte accumulation arena
([src/server/linnea_h2_client.asm:2580](/home/linnea/linnea/src/server/linnea_h2_client.asm:2580)), so a
complete frame up to 65527 payload bytes can reach `d_dispatch`. The DATA path
then appends and relays that payload normally.

This is not a maximum-header-list issue. Linnea does advertise its response
header-list bound and separately caps header-block storage; it simply omits
`MAX_FRAME_SIZE`, which leaves 16384 as the default for every frame the backend
sends. Nor can the backend's own `MAX_FRAME_SIZE` setting enlarge what the
client is willing to receive: that setting describes the sender's receive
limit, while the client's setting controls the backend's frame size.

The frontend HTTP/2 implementation already tests exactly this boundary. With
no `SETTINGS_MAX_FRAME_SIZE` advertised, a 16385-byte `DATA` frame must produce
`FRAME_SIZE_ERROR`
([test/tls/h2_error_codes.py:218](/home/linnea/linnea/test/tls/h2_error_codes.py:218)). The backend
fixture currently sends only small DATA frames and has no oversized-frame
case.

### Reproduction

After a valid response `HEADERS` block, have the backend send:

```text
DATA  stream 1, flags = END_STREAM, length = 16385,
      payload = "U" repeated 16385 times
```

The blocking parser reads the frame because 16385 is below its 20471-byte
buffer bound. The resumable parser accumulates and dispatches it because the
frame plus header is below `LINNEA_H2C_D_IN_CAP`. Both paths append the body and
complete the response instead of rejecting the peer's oversized frame.

A 16384-byte DATA frame is the legal control case. A response header block that
needs more than one frame remains legal when split across HEADERS and
CONTINUATION frames; the check belongs to each frame, not to the total header
block.

### Recommended fix

Introduce a backend receive-frame maximum initialized to 16384, matching the
default used by the SETTINGS sent on this leg. Enforce it immediately after
decoding the nine-byte frame header, before the blocking parser reads the
payload and before the resumable dispatcher treats the frame as complete. If
the client later advertises a different legal `MAX_FRAME_SIZE`, update this
per-leg limit from that setting rather than from the receive-buffer capacity.

Add backend-fixture cases for a 16384-byte DATA frame and a 16385-byte DATA
frame in both the blocking oracle and resumable driver. Assert that the legal
case relays intact and the oversized case fails before its payload is relayed;
also cover an oversized single HEADERS frame and a legal split header block.

## Verification

This finding is a source-level trace through the blocking frame reader, the
resumable frame parser, the DATA dispatch path, and the backend SETTINGS emitted
by both request builders. `make -j4` completed with no work required. Existing
oversized-frame coverage exercises the frontend HTTP/2 server only; no backend
fixture sends a frame above 16384 bytes. Runtime socket reproduction was not
available in this restricted environment, and no source change was made that
required executable verification.

## Resolution (2026-08-25) — CONFIRMED

### Reproduced

At the audited source, a fixture sending the frames the report describes, read
by both backend parsers directly:

```
             oracle              driver
/fsz-ok      HTTP/1.1 200 OK     HTTP/1.1 200 OK    <- legal, 16384-byte DATA
/fsz-big     HTTP/1.1 200 OK     HTTP/1.1 200 OK    <- 16385-byte DATA
/fsz-hdr     HTTP/1.1 200 OK     HTTP/1.1 200 OK    <- ~20000-byte HEADERS
```

Both oversized frames were relayed whole. The report's account of why is
accurate: the blocking reader bounded the length against its 20480-byte frame
buffer and the resumable one waited for the frame to be complete inside a
65536-byte arena, so a frame the peer was never permitted to send fitted in
memory and passed.

### The fix

`LINNEA_H2C_RX_FRAME_MAX equ 16384`, enforced immediately after the 24-bit
length is decoded and before anything is done with the payload — in the
resumable parser right after `mov r15, rax`, and in the blocking one ahead of
its existing buffer check, which stays where it is. Two comparisons.

The constant is named for what it is: the RFC 9113 §4.2 default, which applies
because our backend SETTINGS carries no `SETTINGS_MAX_FRAME_SIZE`. It is
deliberately not derived from the buffer sizes, and the header says so, because
that derivation is exactly what was wrong before. If a `MAX_FRAME_SIZE` is ever
advertised on this leg, this must move with the setting.

### What the checks actually prove, and one row that proves nothing

Eight new rows drive both parsers directly through `bin/linnea-h2client`, plus
three end to end. Against a binary built from the audited source:

```
pre-fix: framesize (oracle): a 16385-byte DATA frame is refused        FAIL
pre-fix: framesize (driver): a 16385-byte DATA frame is refused        FAIL
pre-fix: framesize (oracle): an oversized HEADERS frame is refused     FAIL
pre-fix: framesize (driver): an oversized HEADERS frame is refused     FAIL
pre-fix: framesize (oracle): a 16384-byte DATA frame relays            PASS  <- control
pre-fix: framesize (driver): a 16384-byte DATA frame relays            PASS  <- control
pre-fix: framesize (oracle): a legally split header block relays       PASS  <- control
pre-fix: framesize (driver): a legally split header block relays       PASS  <- control
pre-fix: framesize: a DATA frame of exactly 16384 relays (e2e)         PASS  <- control
pre-fix: framesize: /fsz-big is refused (e2e)                          FAIL
pre-fix: framesize: /fsz-hdr is refused (e2e)                          PASS  <- see below
```

The end-to-end `/fsz-hdr` row is **not** evidence for this fix. A 20000-byte
header block is refused either way by the 6144-byte response-head bound added
during the nginx work — the right outcome for an unrelated reason. It is kept
as a control and labelled as one in the shard. The header-frame evidence is the
direct probe, which has no head bound of its own.

`/fsz-split` is the row that keeps the fix from being a ban on large header
blocks: the *same* ~20000-byte head, split legally across HEADERS +
CONTINUATION with each frame under the limit, still relays. §4.2 bounds each
frame, which is what CONTINUATION is for; a fix that read the limit as a bound
on the block would fail that row.

### The blocking oracle gets coverage here, which it usually does not

Every backend-h2 audit so far has had the same gap: the end-to-end path runs
the resumable driver, so a fix to the blocking oracle went in unverified by the
suite (named as a gap in report 46's resolution). `bin/linnea-h2client` runs
both, and it was in no shard. It is now in the shard and in the pre-build list
in `test/shards/run_shards.sh`, so both parsers are asserted against the same
fixture, agreeing frame for frame.

One trap while writing it: the tool prints its refusal on **stderr**, so the
first form of the check — `2>/dev/null`, compare to `H2C-FAIL` — compared
against an empty string and passed for the wrong reason. The probe captures
`2>&1`; the comment says why.

### Interop

This is a limit on what a backend may send us, so it is the change most able to
break a working upstream. The nginx interop shard is green: real nginx
advertises `MAX_FRAME_SIZE = 16777215` for its own receive side, and correctly
sends us frames within our default 16384. That distinction — the peer's setting
describes what the peer will receive, not what it may send — is the one the
report warned about, and it is the one the nginx rows check.

Full suite **897 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the resumable driver and the blocking oracle, end to end through a
real `proxy_h2` front, and against live nginx. The pre-fix table names which
rows the fix is responsible for and which were already passing — including one
end-to-end row that passes for an unrelated reason and is therefore not
evidence.
