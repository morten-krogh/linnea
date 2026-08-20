# Audit Report 38

Audited at `14295c0`, 2026-08-20.

## Review result

This audit reviewed the QUIC/HTTP-3 request-stream receive and dispatch path.
I found no new source-verifiable security or protocol defect in the reviewed
area.

The important boundaries line up in the current source:

* Initial request-stream receive credit is limited to
  `LINNEA_QUIC_RA_SMALL`, matching the pre-borrow reassembly capacity at
  [src/lib/linnea_quic.asm:1893](/home/linnea/linnea/src/lib/linnea_quic.asm:1893)
  through [:1906](/home/linnea/linnea/src/lib/linnea_quic.asm:1906).
* The incremental HTTP/3 frame walk retains split frame-header state rather
  than requiring an entire upload in the reassembly buffer:
  [include/linnea_http3.inc:94](/home/linnea/linnea/include/linnea_http3.inc:94)
  through [:115](/home/linnea/linnea/include/linnea_http3.inc:115).
* Dispatch rechecks `max_body` for the copy-free single-frame/FIN path and
  reconciles declared Content-Length with the decoded DATA total before routing:
  [src/server/linnea_quic_server.asm:3787](/home/linnea/linnea/src/server/linnea_quic_server.asm:3787)
  through [:3819](/home/linnea/linnea/src/server/linnea_quic_server.asm:3819).

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Suggested ongoing coverage

Keep targeted H3 tests for:

* a frame header split at each byte boundary;
* a DATA body exactly at, one byte below, and one byte above `max_body`;
* Content-Length equal to, shorter than, and longer than the DATA sum;
* out-of-order and duplicate STREAM fragments around a request FIN;
* multiple concurrent request streams competing for the small-to-large
  reassembly transition.

## Resolution — CONFIRMED, one coverage gap closed, no defect found (2026-08-20)

The review's three boundary claims hold, and I checked its coverage list rather
than filing it. Four of the five items are already covered thoroughly:

| suggested case | covered by |
|---|---|
| frame header split at each byte boundary | `h3_frame_walk_test.py` |
| Content-Length vs the DATA sum | `h3_content_length.py` (equal / short / long) |
| out-of-order and duplicate STREAM around a FIN | `h3_reorder_test.py`, `h3_reorder_body_test.py`, `h3_final_size.py`, `h3_fc_dedup_test.py`, `h3_dup_request_test.py`, `h3_fin_at_limit_test.py` |
| concurrent streams over the small-to-large transition | `h3_concurrent_uploads_test.py` (6 fill every context, 9 must refuse 3) |

The fifth was covered on one path only. `h3_single_frame_maxbody.py` pins the
copy-free path — one offset-zero STREAM frame carrying HEADERS+DATA+FIN — at
exactly `max_body` and one above. That is **a different cap check** from the one
the reassembly path uses, which bounds each DATA frame's declared length against
the headroom that is *left* (`max_body - spill_len`).

### The case that actually exercises it

A single frame at the limit does not test an accumulator; it tests one
comparison. The interesting shape is a body **split across DATA frames whose sum
crosses the cap while no single frame comes near it** — then the running total is
the only thing that can refuse it. `test/quic/h3_multi_frame_maxbody.py` drives
seven cases against the same `max_body=64` server: one frame at `CAP-1`, `CAP`
and `CAP+1`, then two frames and four frames summing to exactly `CAP` and to
`CAP+1`.

**All seven pass.** The accumulator is correct: `cmp rcx, rax / ja` at
[linnea_quic_server.asm:3128](/home/linnea/linnea/src/server/linnea_quic_server.asm:3128)
admits a body of exactly `max_body` and refuses one past it, and `spill_len` is
advanced before the next frame is judged. No defect — recorded because "we
measured it and it was right" is worth as much as a finding, and cheaper to
trust later than a source trace.

### The new test asserts its own premise

A multi-frame driver is worthless if the sends coalesce: the request becomes one
offset-zero STREAM frame, silently retesting the single-frame path — **and it
would pass**, because that path caps correctly too. Exactly the shape report 37
turned up, so the driver counts the datagrams each send actually flushes and
fails loudly if any send produced none. Verified by deliberately removing a
flush, which trips it:

```
two frames summing to exactly max_body: sends did not leave as separate packets
COALESCED[1, 0, 1] -- this case would have tested the single-frame path instead
```

### Coverage

One new check, `h3 max_body bounds a body split across DATA frames`. Full suite:
**782 passed, 0 failed**.

## Verification (resolution)

The boundary was measured, not read: seven cases on a live `max_body=64` server
over real QUIC. The coalescing guard was proved able to fire before its silence
was taken as evidence.

## Verification (as filed)

No executable tests were run: this report makes no source change. The review is
a source trace of receive credit, incremental frame state, and dispatch guards.

## Conclusion

The reviewed HTTP/3 upload path has consistent credit, reassembly, body-limit,
and framing checks, and measurement agrees with the source trace. The one item
on its coverage list that was covered on only one of the two cap paths now has a
driver for the other; it found nothing, which is the outcome the source trace
predicted.
