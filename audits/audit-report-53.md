# Audit Report 53

Audited at `61c789a`, 2026-08-25.

Audit report 52's receive-frame maximum is present in both backend-H2 paths. The
next response-frame validation gap is stream ownership:

1. **Low: the backend response parsers silently ignore known `HEADERS` and
   `DATA` frames on stream IDs other than Linnea's single response stream.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — known response frames on the wrong stream are accepted

Severity: **Low (P3, malformed upstream frames are tolerated and can be
interleaved with the real response)**  
Confidence: **High**  
Status: **Confirmed as filed**, and the consequence is worse than the report
states: skipping the frame is what silently corrupts later header blocks.
Fixed at six sites, two of which the report does not name.

This backend leg is single-stream: Linnea opens and tracks stream 1. HTTP/2
`DATA` and `HEADERS` frames carry the stream on which their payload belongs;
`DATA` on stream 0 is a connection error, and `HEADERS` on stream 0 is likewise
invalid (RFC 9113 §§6.1 and 6.2). A frame naming another stream cannot be part
of this backend response and should fail the backend exchange. It must not be
treated as if it had not arrived.

The blocking response loop does exactly that for both known response frame
types. Its `.headers` arm compares `h2c_fr_sid` with 1 and jumps to `.loop` on a
mismatch ([src/server/linnea_h2_client.asm:1344](/home/linnea/linnea/src/server/linnea_h2_client.asm:1344)
through [:1346](/home/linnea/linnea/src/server/linnea_h2_client.asm:1346)); its
`.data` arm has the same `jne .loop` ([src/server/linnea_h2_client.asm:1417](/home/linnea/linnea/src/server/linnea_h2_client.asm:1417)
through [:1419](/home/linnea/linnea/src/server/linnea_h2_client.asm:1419)). The
frame has already been read, so the parser simply advances to the next frame.

The resumable driver has the same behavior. `d_dispatch` returns success from
the `HEADERS` wrong-stream branch ([src/server/linnea_h2_client.asm:2813](/home/linnea/linnea/src/server/linnea_h2_client.asm:2813)
through [:2815](/home/linnea/linnea/src/server/linnea_h2_client.asm:2815)) and
from the `DATA` wrong-stream branch ([src/server/linnea_h2_client.asm:2890](/home/linnea/linnea/src/server/linnea_h2_client.asm:2890)
through [:2892](/home/linnea/linnea/src/server/linnea_h2_client.asm:2892)). The
caller therefore parses onward as though the peer had sent no frame at all.

This is not the already-fixed `CONTINUATION` check. When a header block is
open, the dispatcher now rejects any frame that is not a stream-1
`CONTINUATION`, including a continuation on another stream
([src/server/linnea_h2_client.asm:2694](/home/linnea/linnea/src/server/linnea_h2_client.asm:2694)
through [:2709](/home/linnea/linnea/src/server/linnea_h2_client.asm:2709)).
However, a standalone `HEADERS` or `DATA` with the wrong stream ID reaches the
no-op arms above whenever no continuation block is open.

The existing backend framing rows do not cover this boundary. The
`/cont-wrong-stream` fixture puts only a `CONTINUATION` on stream 3 after an
open stream-1 block ([test/h2/h2c_server.py:644](/home/linnea/linnea/test/h2/h2c_server.py:644)
through [:647](/home/linnea/linnea/test/h2/h2c_server.py:647)); the shard notes
that this case was already refused by the later DATA-before-head rule rather
than by direct wrong-stream validation ([test/shards/tls/70-backend-tls-client.sh:692](/home/linnea/linnea/test/shards/tls/70-backend-tls-client.sh:692)
through [:703](/home/linnea/linnea/test/shards/tls/70-backend-tls-client.sh:703)).
The frontend's independent HTTP/2 tests cover wrong-stream DATA, but they do
not exercise this backend response decoder.

### Reproduction

After the backend connection is established, send this sequence:

```text
HEADERS       stream 3, END_HEADERS, payload = a valid :status 200 block
DATA          stream 3, END_STREAM, payload = "ignored"
HEADERS       stream 1, END_HEADERS, payload = a valid :status 200 block
DATA          stream 1, END_STREAM, payload = "real"
```

Both backend parsers skip the first two frames and relay the stream-1 response
as a normal success. A smaller reproduction inserts `DATA stream 0` between a
valid stream-1 response HEADERS and DATA; the blocking and resumable paths both
drop it and continue. The wrong-stream frames do not get HPACK-decoded or
relayed, so the visible effect is acceptance of a malformed upstream exchange
and continued processing, not direct injection of their header or body bytes.

### Recommended fix

In both response walkers, reject a known `HEADERS` or `DATA` frame unless its
stream ID is exactly 1. Keep the existing stream-1 state checks unchanged:
`HEADERS` still drives the response/trailer classifier, and `DATA` still
requires a completed response head. The check must happen before any payload
interpretation or flow-control credit is staged.

Add backend-fixture cases for `HEADERS` on stream 0 and stream 3, `DATA` on
stream 0 and stream 3, and a valid stream-1 response after each malformed
prefix. Assert a backend failure rather than successful relay. Retain a legal
stream-1 response control and the existing open-block wrong-stream
`CONTINUATION` control.

## Verification

This finding is a source-level trace through the blocking response loop, the
resumable dispatcher, and the existing header-block sequencing gate. `make
-j4` completed with no work required. The backend fixture contains no direct
`HEADERS`/`DATA` wrong-stream case; its only related row is the
`CONTINUATION`-on-another-stream control described above. No production source,
configuration, or test file was changed that required runtime verification.

## Resolution (2026-08-25) — CONFIRMED, and the consequence is worse than filed

### Reproduced

At `61c789a`, driving both parsers directly against a fixture that sends the
report's sequences and then a perfectly good stream-1 response:

```
             oracle              driver
/sid-hdr0    HTTP/1.1 200 OK     HTTP/1.1 200 OK    <- HEADERS on stream 0
/sid-hdr3    HTTP/1.1 200 OK     HTTP/1.1 200 OK    <- a whole response on stream 3
/sid-data0   HTTP/1.1 200 OK     HTTP/1.1 200 OK    <- DATA on stream 0, mid-response
/sid-data3   HTTP/1.1 200 OK     HTTP/1.1 200 OK    <- DATA on stream 3, mid-response
```

Exactly as filed, on both paths, all four arms.

### One correction: this is not only tolerance

The report says the wrong-stream frames "do not get HPACK-decoded or relayed,
so the visible effect is acceptance of a malformed upstream exchange and
continued processing, not direct injection of their header or body bytes."

The first half is true and the conclusion does not follow. **Not decoding the
block is the mechanism.** HPACK state is per CONNECTION, not per stream: a
header block that inserts into the dynamic table and is skipped rather than
decoded leaves our table one entry short of the encoder's, and every later
dynamic index resolves one slot early.

`/sid-hdr3-skew` measures it. An informational 1xx inserts two entries, the
skipped stream-3 block inserts a third, and the final head then names index 63:

```
backend encoded:  x-b: bbb
linnea relayed:   x-a: aaa      HTTP/1.1 200 OK, no error anywhere
```

Same wire bytes, different header, on both parsers. That is silent corruption
of a response head from a frame we thought we were safely ignoring — a
different severity from P3 tolerance, and it is the reason the fix is to fail
rather than to skip more carefully.

The neighbouring route `/sid-hdr3-dyn` shows the same defect landing safely:
there the skew pushes the index past the END of our table, HPACK fails closed,
and the exchange is refused even pre-fix. Whether this defect corrupts or
refuses is decided by how many entries happen to be in the table — which is
precisely why the skipping had to go.

### The fix

Six sites, all four the report names plus two it does not:

- blocking `.headers`, `.data` — `jne .loop` becomes `jne .err`
- resumable `.headers`, `.data` — `jne .ok` becomes `jne .bad`
- both `.cont` arms — the same skip, though **unreachable**: the open-block
  gate added in report 45 already refuses a CONTINUATION that opens nothing or
  names another stream, in both directions. They are failed closed anyway so
  the pattern does not exist in these walkers, and the comment says they are
  dead rather than implying a hole was found.

The comment at `.headers` records the HPACK reason, because "skip the frame"
reads as the conservative choice until you know that.

### Coverage

Seventeen new rows: six refusal routes on each parser, a dynamic-indexing
control on each, and three end to end through a real `proxy_h2` front. Against
a binary built from the audited source, **13 fail and 4 pass as controls**:

```
pre-fix: stream (oracle|driver): /sid-hdr0 /sid-hdr3 /sid-data0 /sid-data3  FAIL x8
pre-fix: stream (oracle|driver): /sid-hdr3-skew is refused                  FAIL x2
pre-fix: stream: /sid-hdr3, /sid-data3, /sid-hdr3-skew e2e                  FAIL x3
pre-fix: stream (oracle|driver): /sid-hdr3-dyn is refused                   PASS <- control
pre-fix: stream (oracle|driver): legal dynamic indexing still decodes       PASS <- control
```

`/sid-dyn-ok` is the row that keeps the fix honest: the same two insertions and
the same indices with the wrong-stream frame removed, which must still decode
to `x-b: bbb` then `x-a: aaa` (62 is the most recent insertion). A fix that
broke dynamic indexing rather than the stream check passes every refusal row
above and fails that one. Writing it I had the index order backwards at first
and expected the wrong header — the control was corrected, not the server.

Full suite **914 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the resumable driver and the blocking oracle, and end to end through
a real `proxy_h2` front. The HPACK skew was read off the relayed response head,
not inferred: the fixture is the authority on what it encoded, and linnea
emitted a different header. The pre-fix table names which rows the fix is
responsible for and which passed already.
