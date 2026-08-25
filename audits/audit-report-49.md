# Audit Report 49

Audited at `26c8410`, 2026-08-25.

Audit report 48's SETTINGS structure checks, value checks, and signed
`INITIAL_WINDOW_SIZE` deltas are present in both backend-H2 paths. One related
response-frame boundary gap remains:

1. **Low: backend PADDED `HEADERS` and `DATA` handlers read the pad-length byte
   before checking that the frame payload contains it.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — padded backend frames read before validating their payload

Severity: **Low (P3, a malformed upstream can trigger an out-of-frame read at
the backend trust boundary)**  
Confidence: **High**  
Status: **Confirmed as filed** — the read does precede the bounds check. Fixed.
Note that every malformed case was ALREADY refused downstream, so the change is
ordering, not behaviour, and no test here demonstrates it.

RFC 9113 §6.1 defines the `PADDED` flag for `DATA` and `HEADERS`. When it is
set, the payload begins with a one-octet Pad Length field; therefore a padded
frame with a zero-length payload is malformed and must be rejected before any
payload byte is read.

The blocking/reference response loop sets `rsi` to the payload start and `rdx` to the
declared payload length. If `PADDED` is set, it immediately reads `[rsi]`, then
decrements the length and subtracts the padding count
([src/server/linnea_h2_client.asm:1315](/home/linnea/linnea/src/server/linnea_h2_client.asm:1315)). The
same sequence exists for response `DATA`
([src/server/linnea_h2_client.asm:1382](/home/linnea/linnea/src/server/linnea_h2_client.asm:1382)).

The append helpers do eventually reject the resulting negative length, but only
after the byte read has already happened. With a zero-length padded `HEADERS`,
the read is from the byte after the frame in `h2c_frame_buf`; with a zero-length
padded `DATA`, it is likewise beyond the declared payload. If the next frame is
already buffered, that byte belongs to its frame header; otherwise it is stale
or uninitialized buffer content. The later signed-length check prevents that
byte from being appended, so this finding is the read-before-validation defect,
not a claim that the current code relays the stale byte.

The resumable driver has the same ordering. Its `HEADERS` path reads the pad
length before calling `d_hdrblk_append`
([src/server/linnea_h2_client.asm:2728](/home/linnea/linnea/src/server/linnea_h2_client.asm:2728)), and
its `DATA` path does so before `d_body_append`
([src/server/linnea_h2_client.asm:2794](/home/linnea/linnea/src/server/linnea_h2_client.asm:2794)). The
helpers reject the negative result, but cannot undo the out-of-frame read.

The frontend HTTP/2 implementation already requires a padded `HEADERS` with an
empty payload to fail as `FRAME_SIZE_ERROR`
([test/tls/h2_error_codes.py:102](/home/linnea/linnea/test/tls/h2_error_codes.py:102)).
There is no corresponding backend fixture for padded `HEADERS` or `DATA`, and
the backend response paths do not validate the mandatory Pad Length field before
touching the payload.

### Reproduction

After the backend preface and request, send either of these on stream 1:

```text
HEADERS  flags = PADDED | END_HEADERS, length = 0, payload = ""
```

or, after a valid response head:

```text
DATA     flags = PADDED | END_STREAM, length = 0, payload = ""
```

The driver reads one byte past the declared payload and then rejects the frame
when the adjusted length reaches the append helper. The blocking oracle follows
the same read-before-reject path. If a complete next frame is already in the
resumable receive buffer, the observed byte is taken from that next frame's
header; with separate reads, it comes from the reusable buffer beyond the frame.

### Recommended fix

Before reading Pad Length in both response implementations, require the declared
payload length to be at least one. Then decode the pad length and require it to
fit within the remaining payload (`pad_length <= payload_length - 1`). Apply the
same bounds-first ordering to the optional five-octet HEADERS priority field
before advancing the payload pointer. On failure, return the backend protocol
error without invoking an append or flow-control-credit helper.

Add backend-fixture cases for zero-length padded `HEADERS` and zero-length
padded `DATA`, plus a nonempty frame whose pad length exceeds the remaining
payload. Assert a gateway failure and that a later independent request succeeds.
Exercise both the blocking oracle and the resumable driver, and include a
control case with valid padding that still relays the response body.

## Verification

This finding is a source-level trace through the blocking `HEADERS` and `DATA`
handlers, the resumable dispatcher, and all four append call sites. `make -j4`
completed with no work required. Existing malformed padding coverage exercises
the frontend HTTP/2 server only; no backend fixture sends padded response
frames. Runtime socket reproduction was not available in this restricted
environment, and no source change was made that required executable
verification.

## Resolution (2026-08-25) — CONFIRMED, and the report is right that nothing was relayed

### The ordering is as described

All four sites read the Pad Length octet before establishing that the payload
contains one, and the HEADERS paths advanced five octets for a PRIORITY field
without checking it was there either.

### What the tests can and cannot show

Measured at `26c8410`, before any change:

```
/pad-h0      PADDED HEADERS, empty payload        -> refused
/pad-d0      PADDED DATA, empty payload           -> refused
/pad-over    pad length past the payload          -> refused
/prio-short  PRIORITY set, two-octet payload      -> refused
/pad-ok      legal padding on HEADERS and DATA    -> 200, body relayed
```

Every malformed case was **already refused**, because the append helpers reject
the negative length the bad arithmetic produces. So this fix changes *when* the
frame is rejected, not *whether* — and no end-to-end test can demonstrate it.
The checks added here are controls: they pass before the change and after. The
report says as much ("not a claim that the current code relays the stale byte"),
and it is worth repeating in the commit rather than letting five green checks
imply they proved something.

### Why fix it at all

Because the downstream check is the only thing making it safe, and this codebase
has already shipped the same shape without one. `audit-report-46` was
`d_stage_ping_ack` reading eight bytes from a payload that declared seven —
identical read-then-hope, no length check below it, and the byte went back to
the backend in the ACK. The value here is removing the dependence, not fixing an
observable defect.

### The one thing that was genuinely uncovered

`/pad-ok`. Nothing in the suite had ever sent a padded frame from a backend, so
nothing said padding **works** — only that malformed padding fails. A tightening
that started refusing all padded frames would have passed every check that
existed. That row is the new coverage; the other four are not.

tls shard **294 passed, 0 failed**; full suite **873 passed, 0 failed**.

### An unrelated failure, seen once

The first full run after this change reported:

```
job 0 (base quic): FAIL: h3 (io_uring): concurrent responses survive loss + reordering
```

`h3_stress_test.py` drives an emulated lossy, reordering network across several
seeds — randomised by construction. It did not recur in four subsequent runs
(two quic-only, two full three-job). This change touches only the backend HTTP/2
client, which that path does not use. Recorded because "seen once" is data, not
chased.

## Verification (resolution)

The malformed cases were run against a binary built from the audited source and
after the change, on the resumable driver and the blocking oracle, and are the
same in both — which is the finding, not a shortcoming of the test. `/pad-ok`
was run the same way and passes in both, so the ordering fix does not refuse
legitimate padding.
