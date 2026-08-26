# Audit Report 67

Audited at `c6d780b` (`backend h2: TE is request-only, so a response carrying
it is malformed`), 2026-08-26.

Audit report 66's response-side `TE` rejection is present. The next backend-H2
boundary gap is capacity accounting during response composition:

1. **Medium: a legal body at the 1 MiB accumulation limit makes the blocking
   composers write past their 1 MiB output buffer.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — the body cap leaves no room for the synthesized response head

Severity: **Medium (P2, a backend-controlled response causes an out-of-bounds
write in the blocking response APIs)**  
Confidence: **High**  
Status: **Confirmed and measured.** 1048646 bytes into a 1048576-byte
buffer, on both composers. Fixed by construction and by check. The defect has
no black-box signature — see the Resolution's note on the pre-fix control.

The backend client defines `LINNEA_H2C_RESP_CAP` as 1 MiB and allocates both
the synthesized response output and the accumulated body at exactly that size
([include/linnea_h2_client.inc:55](/home/linnea/linnea/include/linnea_h2_client.inc:55)
through [:63](/home/linnea/linnea/include/linnea_h2_client.inc:63), and
[src/server/linnea_h2_client.asm:86](/home/linnea/linnea/src/server/linnea_h2_client.asm:86)
through [:96](/home/linnea/linnea/src/server/linnea_h2_client.asm:96)).

The body append check permits an accumulated body whose length is exactly the
cap: it rejects only when `body_len + frame_len` is greater than
`LINNEA_H2C_RESP_CAP` ([src/server/linnea_h2_client.asm:1571](/home/linnea/linnea/src/server/linnea_h2_client.asm:1571)
through [:1586](/home/linnea/linnea/src/server/linnea_h2_client.asm:1586)).
The resumable driver's equivalent check likewise permits exactly
`LINNEA_H2C_D_BODY_CAP` bytes ([src/server/linnea_h2_client.asm:3518](/home/linnea/linnea/src/server/linnea_h2_client.asm:3518)
through [:3535](/home/linnea/linnea/src/server/linnea_h2_client.asm:3535)).

Neither full-response composer accounts for the head before copying the body:

- `h2c_compose` writes the status line, relayed fields, synthesized
  `content-length`, and blank line, then copies all `h2c_body_len` bytes into
  `linnea_h2c_resp_buf` without a capacity check
  ([src/server/linnea_h2_client.asm:2231](/home/linnea/linnea/src/server/linnea_h2_client.asm:2231)
  through [:2285](/home/linnea/linnea/src/server/linnea_h2_client.asm:2285));
- `linnea_h2c_drv_compose` performs the same unbounded head-plus-body copy into
  its caller-provided output pointer ([src/server/linnea_h2_client.asm:3543](/home/linnea/linnea/src/server/linnea_h2_client.asm:3543)
  through [:3592](/home/linnea/linnea/src/server/linnea_h2_client.asm:3592)).

For any nonempty response head, a body of exactly 1 MiB therefore makes the
returned response length larger than the 1 MiB `linnea_h2c_resp_buf`. The
`h2c_compose` path is reached directly from `linnea_h2c_exchange`
([src/server/linnea_h2_client.asm:270](/home/linnea/linnea/src/server/linnea_h2_client.asm:270)
through [:278](/home/linnea/linnea/src/server/linnea_h2_client.asm:278)). The
driver composer is reached by the blocking driver test entry as well
([src/server/linnea_h2_client.asm:3687](/home/linnea/linnea/src/server/linnea_h2_client.asm:3687)
through [:3751](/home/linnea/linnea/src/server/linnea_h2_client.asm:3751)).

The deployed asynchronous proxy path currently uses `linnea_h2c_drv_head`,
which has a caller-supplied capacity check and sends the body separately. That
protects the normal proxy path, but it does not make the two public/full-result
composers safe for their documented output contract.

### Reproduction

Have the backend send an otherwise valid 200 response with a nonempty ordinary
header, `content-length: 1048576`, and exactly 1 MiB of DATA across legal
16,384-byte frames, with the last frame carrying END_STREAM.

The current trace is:

1. Each DATA handler accepts the body because the final accumulated length is
   equal to, rather than greater than, the 1 MiB body cap.
2. Response validation succeeds because the declared length equals the DATA
   total.
3. The composer writes a response head of positive length at the beginning of
   the 1 MiB output buffer.
4. It then copies the full 1 MiB body after that head and returns a length
   greater than the output buffer capacity.

The blocking oracle's adjacent storage is overwritten by the tail of the
composed response. The driver composer also writes beyond the global output
buffer, into unrelated storage following it. Depending on layout, a caller
can receive a response with extra/corrupted tail bytes, and subsequent global
state can be damaged.

This does not require a malformed HTTP/2 response. The body size is accepted
by the advertised receive-window/body policy, and the response's
`content-length` assertion is correct. The overflow is created solely by
combining two independently valid boundary conditions: maximum body and a
nonzero synthesized head.

### Existing coverage

The flow-control boundary test deliberately sends a 1 MiB response and checks
only that its first line is `HTTP/1.1 200` ([test/shards/tls/70-backend-tls-client.sh:1145](/home/linnea/linnea/test/shards/tls/70-backend-tls-client.sh:1145)
through [:1153](/home/linnea/linnea/test/shards/tls/70-backend-tls-client.sh:1153)).
That route includes `content-type` and `content-length`, so its synthesized
head is nonempty, but the assertion does not check the returned byte count or
the exact body. The same check runs through both the blocking oracle and the
resumable driver.

The production asynchronous path's separate head/body handling is covered by
the end-to-end 1 MiB status check, but that does not exercise either full-result
composer. No test asks whether `head length + body length` fits before a full
response is written.

### Impact

The immediate input is controlled by the backend, but the response body can be
fully protocol-valid and within the client's advertised limit. The bug turns
that valid boundary response into a memory-safety violation in
`linnea_h2c_exchange` and `linnea_h2c_drv_compose`. The latter's output pointer
is supplied by the caller, so any caller that provides only the documented
1 MiB output capacity is exposed to an overwrite. The current standalone
test client writes the returned oversized length to stdout, also reading past
the output object.

The normal deployed `proxy_h2` path uses the bounded head-only composer and is
not shown to have this specific overwrite. The unsafe functions nevertheless
are exported interfaces in the backend-H2 object and are used by the test
driver, so the capacity contract must be fixed at the shared composition
boundary rather than assumed from one caller.

### Recommended fix

Make full-response composition capacity-aware before writing any bytes:

- pass an output capacity to `h2c_compose` and
  `linnea_h2c_drv_compose`, or give them a preflight helper that computes the
  complete head length and checks `head_len + body_len <= capacity`;
- return a failure before composition when the combined response does not fit;
  and
- keep the separate production `linnea_h2c_drv_head`/body path bounded as it is.

Alternatively, allocate the full-result output buffer larger than the maximum
body plus the maximum synthesized head, but retain a checked total-length
contract so future cap changes cannot recreate the mismatch. Do not merely
lower one body bound without documenting that it changes the advertised body
limit used by the asynchronous path.

Extend the boundary test to assert exact output length and exact body bytes,
and add a case at the largest body that still fits after the head. Run those
checks through both full-result composers, while retaining the deployed
head/body 1 MiB control.

## Verification

The finding is a source-level capacity trace. Both body append helpers accept a
body exactly equal to the 1 MiB body cap, while both full-response composers
append a positive-length response head and then copy that entire body without
checking the output capacity. `linnea_h2c_exchange` and the blocking driver
both expose these paths. Existing 1 MiB coverage checks only the status line,
so it does not detect the oversized return or overwrite. No production source,
configuration, or test file was changed in this audit.


## Resolution (2026-08-26) — CONFIRMED, and measured to the byte

### Reproduced

A legal 200 with a header, `content-length: 1048576`, and exactly 1 MiB of DATA
in 16,384-byte frames. On the audited binary:

```
oracle  (h2c_compose)           returned 1048646 bytes
driver  (linnea_h2c_drv_compose) returned 1048646 bytes
LINNEA_H2C_RESP_CAP                       1048576 bytes
                                  excess:      70 bytes
```

Seventy bytes written past `linnea_h2c_resp_buf`, from a response that is
entirely valid: the body is inside the advertised limit and its declared length
matches the DATA total. Two independently correct boundaries, combined.

The .bss layout is why nothing has ever crashed: `h2c_body_buf` immediately
follows `linnea_h2c_resp_buf`, so the overrun lands in the buffer being copied
*from*, far behind the read cursor, and `body_len` is reset per exchange. That
is luck, not safety — if the output buffer were last, or followed by something
live, this would corrupt it.

### It has been running in the suite since audit-report-64 — mine

Report 64 tied the advertised window to the body cap and added
`/fc-size-1048576` to exercise the boundary. That row asserted the **first
line**. So the boundary case has been composing 70 bytes past the buffer on
every suite run since, and the check watched the status line go by.

### The fix

Sized by construction, then checked:

- `LINNEA_H2C_HEAD_MAX` names the largest synthesized head (the field lines are
  already bounded by `HDRBLK_CAP`), and `LINNEA_H2C_RESP_CAP` is now
  `D_BODY_CAP + HEAD_MAX` rather than a number that happened to match the body.
- The oracle's body buffer and its append bound use `D_BODY_CAP` too, so both
  paths have **one** body policy and cannot disagree about what fits.
- Both composers preflight `head + body <= capacity` before writing a byte.
  `linnea_h2c_drv_compose` takes the capacity as a **parameter**, because its
  output pointer is the caller's and no assembly-time assert can bound it — the
  sibling production uses, `linnea_h2c_drv_head`, has taken one since
  audit-report-52.
- An assembly-time guard asserts the relationship, and it was proven by putting
  the old constants back:

```
src/server/linnea_h2_client.asm:89: error: the response buffer cannot hold a
    maximum body plus its head
```

While adding the preflight I pushed `r12` in a prologue that already pushed it,
against a three-pop epilogue. Caught before building, by reading the epilogue
rather than trusting the patch.

### The pre-fix control found nothing, and that is the finding

**Every new runtime row passes on the audited binary.** I expected otherwise: I
gave the fixture body distinct end markers (`A…H…Z`) on the theory that the
overflow would make the last 70 bytes come back as the first 70. It does not.
The copy runs off the end *into the buffer it is reading from*, writing the
correct tail there, and the caller reads those same bytes straight back — so the
output is byte-correct and past the end of the object at the same time.

This defect has no black-box signature through this harness. Its evidence is:

1. **arithmetic** — the returned length (1048646) exceeds the buffer
   (1048576), measured from the binary's own output; and
2. **the guard firing** on the old constants.

The new rows are regression coverage against a future truncation, and the shard
says so rather than implying they caught this.

Full suite **1129 passed, 0 failed**.

## Verification (resolution)

Measured on a binary built from the audited source: both composers return
1048646 bytes into a 1048576-byte buffer. The fix was verified by re-measuring
the same case against the enlarged buffer, by asserting the exact returned
length and the exact body bytes on both parsers, and by restoring the old
sizing and watching the build refuse it. The production path
(`linnea_h2c_drv_head` plus a separately queued body) was never affected, and
its 1 MiB end-to-end row stays green.
