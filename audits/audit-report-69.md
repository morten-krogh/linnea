# Audit Report 69

Audited at `febf408` (`backend h2: a standalone PRIORITY frame is validated,
not skipped`), 2026-08-26.

Audit report 68's standalone `PRIORITY` validation is present in both backend
H2 readers. The next response-lifecycle gap is in the resumable driver's
handling of frames already buffered after response completion:

1. **Medium: the resumable backend-H2 driver accepts and forwards DATA that
   follows a response's END_STREAM when both frames arrive in one read.**

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — post-END_STREAM DATA is appended after response validation

Severity: **Medium (P2, a malformed backend response can alter the relayed
body after its framing and content-length checks have completed)**  
Confidence: **High**  
Status: **Confirmed as filed and reproduced end to end.** Fixed. One case is
worse than described: a 204 acquires a body, reaching an h1 client as
`204 No Content` with `content-length: 4`.

HTTP/2 marks a response complete when the client receives a frame carrying
`END_STREAM`. A server MUST NOT send another frame on the now-closed stream,
except for `PRIORITY`; a client must not accept the resulting malformed
response. The response's content-length and no-content rules must therefore be
final when the END_STREAM frame is processed.

The driver records completion in `d_dispatch` only after validating the body:
the `.complete` path reads `ctx.body_len`, calls `h2c_body_ok`, then sets
`linnea_h2c.state` to `LINNEA_H2C_ST_DONE` ([src/server/linnea_h2_client.asm:3508](/home/linnea/linnea/src/server/linnea_h2_client.asm:3508)
through [:3519](/home/linnea/linnea/src/server/linnea_h2_client.asm:3519)).
However, the DATA handler checks only that a response header block has been
decoded ([src/server/linnea_h2_client.asm:3469](/home/linnea/linnea/src/server/linnea_h2_client.asm:3469)
through [:3492](/home/linnea/linnea/src/server/linnea_h2_client.asm:3492)). It
does not reject DATA when the context is already `ST_DONE`.

The receive loop continues unconditionally after every nonnegative dispatch:
it advances past one frame, calls `d_dispatch`, and jumps back to `.parse`
([src/server/linnea_h2_client.asm:3159](/home/linnea/linnea/src/server/linnea_h2_client.asm:3159)
through [:3174](/home/linnea/linnea/src/server/linnea_h2_client.asm:3174)).
The `ST_DONE` check occurs only after the entire buffered chunk has been parsed
([src/server/linnea_h2_client.asm:3195](/home/linnea/linnea/src/server/linnea_h2_client.asm:3195)
through [:3209](/home/linnea/linnea/src/server/linnea_h2_client.asm:3209)).
That check reports completion too late to prevent a later DATA frame in the
same chunk from mutating `ctx.body_buf`.

This is a driver-only gap. The blocking response loop returns from its `.done`
path as soon as the first END_STREAM is seen and does not read a following
frame ([src/server/linnea_h2_client.asm:1750](/home/linnea/linnea/src/server/linnea_h2_client.asm:1750)
through [:1784](/home/linnea/linnea/src/server/linnea_h2_client.asm:1784)).
The production path, by contrast, reads up to the driver's 32 KiB staging
capacity ([src/server/linnea_uring.asm:4693](/home/linnea/linnea/src/server/linnea_uring.asm:4693)
through [:4703](/home/linnea/linnea/src/server/linnea_uring.asm:4703)) and
feeds that whole result to `linnea_h2c_drv_on_recv`
([src/server/linnea_http2.asm:3929](/home/linnea/linnea/src/server/linnea_http2.asm:3929)
through [:3935](/home/linnea/linnea/src/server/linnea_http2.asm:3935)).

### Reproduction

Have the backend send the required SETTINGS preface, then this stream-1
sequence in a single TCP/TLS read (the frames are small enough to fit together):

```text
HEADERS  END_HEADERS, :status 200, content-length: 4
DATA     END_STREAM, payload = "body"
DATA     no END_STREAM, payload = "EVIL"
```

The current driver trace is:

1. The response HEADERS establishes `hdr_done` and the declared length.
2. The first DATA appends `body`; its END_STREAM enters `.complete`.
3. `h2c_body_ok` validates `body_len == 4`, then the context becomes
   `ST_DONE`.
4. The receive loop parses the second DATA anyway. Its only lifecycle gate is
   `hdr_done`, so it appends `EVIL`, updates `body_len` to 8, and returns success
   without rerunning `h2c_body_ok`.
5. `on_recv` finally notices `ST_DONE` and returns `DRV_DONE`. The proxy then
   consumes the mutated body buffer.

The same defect is reachable when a final response HEADERS frame itself carries
END_STREAM: once its no-body check sets `ST_DONE`, a later DATA frame in the
same receive chunk still passes the DATA handler's `hdr_done` test.

The blocking oracle does not expose this exact coalescing condition because it
reads one frame at a time and returns immediately on END_STREAM. A test that
exercises only that oracle, or that sends the extra frame in a later read after
the driver has already returned DONE, misses the production path's bug.

### Impact

The backend controls the extra frame, but the first response can be completely
valid and the injected DATA is the only malformed part. The driver has already
validated the declared content length—or that a 204, 304, 205, or HEAD response
has no content—when the extra bytes are appended. The proxy's response bridge
then uses the final `ctx.body_len` and body buffer
([src/server/linnea_http2.asm:4071](/home/linnea/linnea/src/server/linnea_http2.asm:4071)
through [:4094](/home/linnea/linnea/src/server/linnea_http2.asm:4094)), so a
post-END_STREAM body can be forwarded as if it belonged to the successful
response. For an initially declared length of 4, the synthesized response is
rewritten from the validated four-byte body to an eight-byte body and its
forwarded length is derived from those eight bytes.

This is not a memory overwrite: `d_body_append` still applies the one-MiB body
cap. It is a framing and response-integrity failure, and it creates a
driver/oracle disagreement in the deployed `proxy_h2` path.

### Recommended fix

Make response completion terminal for the driver before dispatching another
frame from the same input buffer:

- after `d_dispatch` returns successfully, stop parsing and return
  `LINNEA_H2C_DRV_DONE` if the context is `ST_DONE`; or
- add an early `ST_DONE` guard in `d_dispatch` that rejects any subsequent
  defined frame except the narrowly permitted `PRIORITY` case, while preserving
  any required connection-level handling.

The first option is sufficient for the single-stream response API because the
driver is complete and the proxy will not arm another backend read. A stricter
frame-state implementation may instead reject post-completion DATA/HEADERS and
retain only the RFC-permitted priority handling, but it must not append body
bytes after the completion predicate has run.

Add a fixture that sends final DATA with END_STREAM followed immediately by
DATA without END_STREAM in the same read. Assert failure, or at minimum that
the extra bytes are never relayed, through the resumable driver and the real
`proxy_h2` front. Add the analogous final-HEADERS-with-END_STREAM case, and
keep a control where the valid response is split across reads so the fix does
not reject ordinary buffered processing.

## Verification

The source trace follows the production receive path: a single 32 KiB read is
parsed frame by frame; completion sets `ST_DONE`, but parsing continues and the
DATA handler checks only `hdr_done`. The completion check runs only after the
parse loop, and the proxy subsequently copies `ctx.body_len` bytes from the
driver body buffer. The blocking reader returns at the first END_STREAM and is
not affected by this exact coalesced-frame condition. `make -j4` completed with
no work required. No production source, configuration, or test file was
changed in this audit.

References:

- [RFC 9113 §5.1 — Stream States](https://www.rfc-editor.org/rfc/rfc9113.html#section-5.1)
- [RFC 9113 §8.1 — HTTP Message Exchanges](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1)

## Resolution (2026-08-26) — CONFIRMED, and worse in one case than filed

### Reproduced, and it reaches real clients

Both parsers, at the audited commit, with the frames coalesced into one write:

```
                     oracle                    driver
/post-data     200, cl=4, "body"        200, cl=8, "bodyEVIL"
/post-hdr-es   204, cl=0, no body       204, cl=4, "EVIL"
/post-ok       200, cl=4                200, cl=4     <- control, coalesced
/post-split    200, cl=4                200, cl=4     <- control, two reads
```

Through a real `proxy_h2` front, before the fix, an h1 **and** an h2 client both
received `content-length: 8` and `bodyEVIL`. The validated four-byte body was
rewritten with four bytes of the backend's choosing, *after* `h2c_body_ok` had
passed on it.

**The 204 case is worse than the report describes.** It says the same defect is
reachable when the head itself carries END_STREAM; what actually happens is that
a **204 No Content acquires a body** — relayed to an h1 client as
`204 No Content` with `content-length: 4`. A 204 is terminated by its header
section, so a client will not read those bytes: they are left in the connection
for whatever parses next. That is the same hazard the request-side parity sweep
found for content on a no-content status, arriving by a different route and
past the check that was added for it.

### The fix, and why it stops rather than refuses

The parse loop now returns at `ST_DONE` instead of continuing through the rest
of the chunk. The response is complete and validated at that point, and a
backend may legitimately coalesce a GOAWAY or SETTINGS behind it — failing the
exchange over trailing bytes would discard a good response to punish a peer for
something we can simply not read. What must never happen is the **body changing
after the completion predicate ran**, and it no longer can.

This is the report's own first recommendation, and it is deliberately not the
stricter second one.

### The oracle was never affected, which is why the pair matters

The blocking reader returns at the first END_STREAM and reads no further, so
this was a driver-only defect in the deployed path. The pre-fix control shows
exactly that shape — the oracle rows pass, the driver rows fail:

```
pre-fix: post-end (oracle): DATA after END_STREAM is not appended     PASS
pre-fix: post-end (oracle): ...nor after a head that ended the stream PASS
pre-fix: post-end (driver): DATA after END_STREAM is not appended     FAIL
pre-fix: post-end (driver): ...nor after a head that ended the stream FAIL
pre-fix: post-end: the extra bytes never reach a client               FAIL
pre-fix: post-end (both): /post-ok and /post-split relay normally     PASS
```

Ten rows, **3 fail and 7 pass as controls**. The rows assert the **bytes** and
the absence of `EVIL`, not the status: a status check reads 200 either way,
which is precisely how audit-report-64's boundary row failed to notice
audit-report-67.

`/post-split` is the control that says why this went unseen for so long — the
same legal response across two reads never triggers it, and every other fixture
in the suite writes its frames separately.

Full suite **1151 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the blocking oracle and the resumable driver, and end to end through
a real `proxy_h2` front with both an h1 and an h2 client — the injected bytes
were read off the client's own response, not inferred. The coalesced and split
controls both relay normally afterwards.
