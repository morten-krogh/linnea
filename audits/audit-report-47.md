# Audit Report 47

Audited at `96f8543`, 2026-08-25.

Audit report 46's PING framing checks are present in both backend-H2 paths. One
related control-frame validation gap remains:

1. **Medium: malformed backend `WINDOW_UPDATE` frames are accepted, and the
   window helper reads four payload bytes and adds the increment without
   validating the frame length, nonzero rule, stream, or maximum window.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — backend `WINDOW_UPDATE` framing and flow-control checks are missing

Severity: **Medium (P2, an untrusted upstream can cause an out-of-frame read and
alter the amount of request data the client believes it may send)**  
Confidence: **High**  
Status: **Confirmed as filed** — all four malformed cases were accepted.
Fixed in both backend paths, with the maximum-window test signed because a
flow-control window may legitimately be negative.

RFC 9113 §6.9 requires a `WINDOW_UPDATE` payload to be exactly four octets. The
increment, after ignoring the reserved high bit, must be nonzero; the resulting
flow-control window must not exceed `2^31 - 1`. A connection-level update uses
stream 0, while a stream-level update must name the relevant stream.

The resumable backend dispatcher routes every `WINDOW_UPDATE` directly to
`d_apply_window` without checking `r15` or the frame stream ID
([src/server/linnea_h2_client.asm:2494](/home/linnea/linnea/src/server/linnea_h2_client.asm:2494),
[src/server/linnea_h2_client.asm:2533](/home/linnea/linnea/src/server/linnea_h2_client.asm:2533)). The
helper unconditionally reads four bytes from the payload pointer, masks the
reserved bit, and adds the result to either the connection window or the one
active stream window ([src/server/linnea_h2_client.asm:1979](/home/linnea/linnea/src/server/linnea_h2_client.asm:1979)).

Consequently:

- A three-byte update reads one byte beyond the declared frame, from the next
  buffered frame or stale bytes in the receive arena.
- An increment of zero is silently accepted as a no-op, although it is a
  protocol error.
- Any nonzero stream ID, including an unrelated stream such as 3, is treated as
  an update for stream 1. The driver has only one request stream, but that does
  not make another stream ID valid.
- An increment can raise the tracked window above `2^31 - 1`; the unchecked
  `add` has no overflow or maximum-window guard. The body sender subsequently
  uses this inflated credit when deciding how much request data to stage.

The blocking/reference path has the same unsafe helper. During initial settling,
`h2c_settle` accepts every `WINDOW_UPDATE` and calls `h2c_apply_window`
([src/server/linnea_h2_client.asm:949](/home/linnea/linnea/src/server/linnea_h2_client.asm:949)); the
helper reads four bytes and adds the masked value without any of these checks
([src/server/linnea_h2_client.asm:925](/home/linnea/linnea/src/server/linnea_h2_client.asm:925)). In the
later response loop, a `WINDOW_UPDATE` is simply accepted and skipped
([src/server/linnea_h2_client.asm:1194](/home/linnea/linnea/src/server/linnea_h2_client.asm:1194)), so
the oracle does not reject malformed control frames there either.

The frontend HTTP/2 implementation already treats a three-byte update as
`FRAME_SIZE_ERROR` and an update that would exceed the maximum connection window
as `FLOW_CONTROL_ERROR`
([test/tls/h2_error_codes.py:100](/home/linnea/linnea/test/tls/h2_error_codes.py:100)). That coverage
does not exercise the backend driver or its blocking oracle. A malformed
upstream response is therefore able to change backend request-flow state while
the documented security posture says malformed upstream responses are refused
([docs/security.md:28](/home/linnea/linnea/docs/security.md:28)).

### Reproduction

Have a backend send one of these before its response:

```text
WINDOW_UPDATE  stream 1, length 3, payload = 00 00 01
HEADERS        stream 1, :status = 200, END_HEADERS
DATA           stream 1, END_STREAM, payload = "body"
```

The resumable driver accepts the update, reads a fourth byte beyond its
payload, and continues with the response. A `WINDOW_UPDATE` on stream 3 follows
the same nonzero-stream branch and changes stream 1's credit. A four-byte
increment of `0x7fffffff` is also accepted and adds more than the permitted
maximum to the current window. A zero increment is accepted without a backend
failure in all of these cases.

These are not client-controlled reads across the process address space under the
normal loopback-backend deployment model, but they are out-of-frame reads at an
upstream trust boundary and can make request-body transmission depend on bytes
that were not part of the control frame.

### Recommended fix

Validate `WINDOW_UPDATE` before invoking either helper, in both backend paths:

1. Require a payload length of exactly 4.
2. Require stream 0 or the active request stream 1; reject other IDs.
3. Decode the 31-bit increment, reject zero, and perform a checked addition.
4. Reject any result greater than `0x7fffffff` without changing the tracked
   window.

The blocking response loop should run the same validation even when it does not
need to apply a window update in that state. Treat an invalid update as a
backend protocol failure, and keep the connection and stream windows unchanged
on every failure path.

Add backend-fixture cases for a three-byte payload, zero increment, an unrelated
stream ID, and a maximum increment that would overflow the current window. Assert
that each exchange fails before request data is sent or a response is relayed;
also assert that a later independent request succeeds. Add a direct driver test
that the helper never reads or changes state for a short or invalid update.

## Verification

This finding is a source-level trace through the resumable dispatcher, the
blocking settling path, the blocking response loop, and both window helpers.
`make -j4` completed with no work required. Existing malformed-frame tests cover
the frontend HTTP/2 server only; no backend fixture currently sends malformed
`WINDOW_UPDATE` frames. Runtime socket reproduction was not available in this
restricted environment, and no source change was made that required executable
verification.

## Resolution (2026-08-25) — CONFIRMED as filed, all four cases

### Every malformed update was accepted

At `96f8543`, each of these was taken and the response relayed as a normal 200,
on the resumable driver and on the blocking oracle alike:

```
/win3      WINDOW_UPDATE stream 1, length 3        -> 200
/win0      WINDOW_UPDATE stream 1, increment 0     -> 200
/win-sid   WINDOW_UPDATE stream 3, increment 1     -> 200
/win-max   two increments of 0x7fffffff            -> 200
```

`d_apply_window` reads four bytes from the payload pointer whatever the frame
declared, masks the reserved bit, and adds — so the three-octet case took its
fourth byte from past the frame, and the stream-3 case credited stream 1
because the helper's only test was `sid == 0` versus anything else.

### The fix

The dispatcher now requires a four-octet payload on stream 0 or stream 1 before
the payload pointer is touched; the helper rejects a zero increment and performs
a **checked** addition, leaving the window untouched on any failure. The
blocking oracle gets the same, including its response loop, which previously
skipped `WINDOW_UPDATE` without looking at it at all.

**The maximum-window comparison is signed, deliberately.** A flow-control window
may legitimately be negative — a SETTINGS that lowers `INITIAL_WINDOW_SIZE`
takes it there, and `d_stage_body` already treats `<= 0` as blocked. An unsigned
`ja` would read a negative window as enormous and refuse a perfectly good
increment, turning a conformance fix into a stall. `jg` against `0x7fffffff`,
which sign-extends to itself as an imm32, is the correct test.

### Coverage

Five new checks. Against a binary built from the audited source:

```
pre-fix: /win3 is refused                                            FAIL
pre-fix: /win0 is refused                                            FAIL
pre-fix: /win-sid is refused                                         FAIL
pre-fix: /win-max is refused                                         FAIL
pre-fix: legal WINDOW_UPDATEs are applied and the response relays    PASS  <- control
```

`/win-ok` sends a legal increment on the stream **and** one on the connection,
so the fix cannot pass by refusing the whole frame type — the failure mode a
validation change most easily hides behind.

Not done as specified: the report asks for "a direct driver test that the helper
never reads or changes state for a short or invalid update". The checks here are
end-to-end, and prove the exchange fails rather than that no read occurred. The
absence of the read follows from the ordering in the source — the length test
precedes the payload dereference — but it is not independently asserted, and
saying so is more useful than implying otherwise.

tls shard **274 passed, 0 failed**; full suite **860 passed, 0 failed**.

### Unrelated, found while testing the window path

The `h2c_server.py` fixture's `smallwin` mode — a tiny `INITIAL_WINDOW_SIZE`
with dribbled updates, which exists to exercise exactly this code — cannot carry
an upload past about 1 KB:

```
smallwin,    100-byte upload -> 210 bytes back
smallwin,   1000-byte upload -> 1111 bytes back
smallwin,   5000-byte upload ->    0 bytes back
normal,    20000-byte upload -> 20112 bytes back
```

A/B'd at `96f8543`: identical before this fix, so it is not caused by it. It is
invisible to the suite because the `linnea-h2client` harness is in no shard —
the flow-controlled upload path has no automated coverage at all. Whether the
fault is linnea's or the fixture's is not established here; it is recorded
rather than chased.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the resumable driver, on the blocking oracle, and end to end through
a real `proxy_h2` front. Uploads of 200000 bytes and a 100000-byte response
were re-run against the normal fixture to confirm the window arithmetic still
carries a body, since a validation change to flow control can pass every
malformed case and still stall a legitimate one.
