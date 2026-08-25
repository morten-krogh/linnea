# Audit Report 46

Audited at `6591f4f`, 2026-08-24.

Audit report 45's header-block sequencing gate is present in both backend-H2
dispatchers. One control-frame validation gap remains:

1. **Medium: malformed backend PING frames are accepted without checking their
   stream, flags, or required eight-byte payload, and the ACK helper reads eight
   bytes regardless of the advertised payload length.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — backend PING framing is unchecked

Severity: **Medium (P2, malformed upstream can trigger an out-of-frame read and
stale-byte echo)**  
Confidence: **High**  
Status: **Confirmed as filed** for the length and stream checks — the
out-of-frame echo was measured. Its third recommendation, rejecting unused
flag bits, is declined: RFC 9113 4.1 requires those to be ignored.

HTTP/2 PING frames have a fixed eight-byte payload, must use stream 0, and may
carry only the defined ACK flag ([RFC 9113 §6.7](https://www.rfc-editor.org/rfc/rfc9113#section-6.7)).
The backend resumable dispatcher checks only whether ACK is set. For a
non-ACK frame it unconditionally passes the payload pointer to
`d_stage_ping_ack`; it never checks `d_fr_sid`, `r15`, or the remaining flags
([src/server/linnea_h2_client.asm:2452](/home/linnea/linnea/src/server/linnea_h2_client.asm:2452)
through [:2459](/home/linnea/linnea/src/server/linnea_h2_client.asm:2459)).

`d_stage_ping_ack` then reads a full qword from that pointer and constructs an
eight-byte ACK payload
([src/server/linnea_h2_client.asm:1839](/home/linnea/linnea/src/server/linnea_h2_client.asm:1839)
through [:1852](/home/linnea/linnea/src/server/linnea_h2_client.asm:1852)). If
the backend advertised fewer than eight payload bytes, the read crosses the
current frame boundary into the next buffered frame or into stale bytes left
in the per-leg receive arena. Those bytes are sent back to the backend in the
ACK. A PING on a nonzero stream, or a PING with invalid flags, is likewise
acknowledged instead of failing the backend exchange.

The blocking/reference path has the same unchecked behavior: it dispatches
PING before the response and calls `h2c_send_ping_ack` without validating the
stored frame length or stream ID
([src/server/linnea_h2_client.asm:1149](/home/linnea/linnea/src/server/linnea_h2_client.asm:1149)
through [:1177](/home/linnea/linnea/src/server/linnea_h2_client.asm:1177)). The
ACK builder always copies eight bytes from the frame buffer
([src/server/linnea_h2_client.asm:833](/home/linnea/linnea/src/server/linnea_h2_client.asm:833)
through [:848](/home/linnea/linnea/src/server/linnea_h2_client.asm:848)).

### Reproduction

Have a backend send this before its valid response:

```text
PING  stream 0, length 7, payload = "1234567"
HEADERS :status = 200, END_HEADERS
DATA    END_STREAM, payload = "body"
```

The current backend driver accepts the malformed PING, emits a 17-byte ACK,
and continues to return the later 200 response. The eighth ACK byte comes from
the byte immediately after the seven-byte payload when it is buffered, or from
stale receive-arena contents when it is not. The blocking helper does the same
from its reusable frame buffer.

The sibling malformed case is a valid eight-byte PING on stream 1. It is also
accepted and answered as though it were a connection-level PING. The frontend
HTTP/2 implementation already rejects these classes of input: its test matrix
requires a seven-byte PING to produce FRAME_SIZE_ERROR and a PING naming a
stream to produce PROTOCOL_ERROR
([test/tls/h2_error_codes.py:93](/home/linnea/linnea/test/tls/h2_error_codes.py:93)
through [:115](/home/linnea/linnea/test/tls/h2_error_codes.py:115)). There is no
equivalent backend-response validation.

This is not a client-controlled cross-request disclosure under the normal
loopback-backend deployment model, but it is an unsafe trust-boundary read and
can echo bytes from a prior response in the same reused leg arena to a
malformed backend. It also makes a malformed control frame capable of being
silently accepted while the project otherwise states that malformed upstream
responses are refused
([docs/security.md:24](/home/linnea/linnea/docs/security.md:24)
through [:30](/home/linnea/linnea/docs/security.md:30)).

### Recommended fix

Validate PING before reading its payload in both paths: require stream 0,
length exactly 8, and only the legal flag bit. Treat an invalid PING as a
backend protocol failure and never invoke the ACK builder for it. Keep the
existing behavior for a valid non-ACK PING (echo it with ACK); a valid ACK
should be consumed without producing another ACK.

Add backend-fixture cases for a seven-byte PING, a PING on stream 1, and an
invalid flag, each followed by a normal response. Assert a gateway failure and
that a subsequent independent request still succeeds. Add a direct driver
assertion that no ACK is staged for the malformed cases.

## Verification

The finding is a source-level trace through the production resumable dispatcher,
the blocking backend-H2 oracle, and both PING ACK builders. `make -j4`
completed with no work required. Existing malformed-frame coverage exercises
the frontend HTTP/2 server only; the backend fixture sends only valid eight-byte
connection-level PINGs. Runtime socket reproduction was not available in this
restricted environment, and no source change was made that required executable
verification.

## Resolution (2026-08-25) — CONFIRMED, with one recommendation declined

### The out-of-frame read is real, and measured

A backend sending `PING stream 0, length 7, payload "1234567"` before its
response, on the audited driver:

```
linnea sent PING flags=0x01 len=8 payload=b'1234567\x00'
```

Eight bytes echoed for a seven-byte payload. The eighth came from past the end
of the frame — `d_stage_ping_ack` does `mov rax,[rsi]` regardless of the length
the frame declared. A PING naming stream 1, and a PING carrying an unused flag
bit, were likewise accepted and answered. All four cases returned a normal 200.

One detail worth recording for anyone reproducing it: the echo is only
observable when the PING is parsed in a pass of its **own**. Sent immediately
before the response, all three frames are parsed in one call, the exchange
completes, and the staged ACK is dropped before it ever reaches the wire — the
out-of-frame read still happens, but nothing comes back to see. The fixture
sleeps between the PING and the response for exactly that reason.

### The fix

`d_dispatch`'s `.ping` now requires stream 0 and a length of exactly 8 before
the payload pointer is touched; either failing is a backend protocol failure and
the ACK builder is never reached. The two blocking-oracle sites get the same
check.

**An extra defect, not in the report:** both oracle sites called
`h2c_send_ping_ack` without looking at the ACK flag at all, so they answered the
backend's ACKs with ACKs of their own — which RFC 9113 6.7 forbids outright.
The production driver already checked. The oracle exists to prove the two agree,
so it now checks too.

### One recommendation declined: unused flags

The report asks for "only the legal flag bit" and lists a PING with an invalid
flag among the malformed cases. That would be over-strict. RFC 9113 4.1:
*unused flags MUST be ignored on receipt*. The frontend's own matrix, which the
report cites as the standard to match, asserts exactly two PING errors — a
seven-byte payload and a PING naming a stream — and no flag case, for the same
reason.

So a PING carrying an unused flag bit is still accepted and answered, and there
is now a check asserting that it is, to keep a later tightening from quietly
turning a MUST-ignore into a refusal.

### Coverage

Five new checks. Against a binary built from the audited source:

```
pre-fix: /ping7 is refused                                   FAIL
pre-fix: /ping-sid is refused                                FAIL
pre-fix: a legal PING is echoed with ACK                     PASS  <- control
pre-fix: an ACK is consumed, never answered                  PASS  <- control
pre-fix: an unused flag bit is ignored, not refused          PASS  <- control
```

Two of five are this fix's work. The three controls were already correct **on
the driver**; the "ACK is never answered" control does not cover the oracle fix,
because the end-to-end path exercises the driver. That is a gap in what the
suite can see, not a claim that the oracle was fine.

The two `/ping-ok` and `/ping-ack` checks assert what came **back** — the
fixture reports the ACK it received in the response body — rather than merely
that a response arrived. A check that only looked for 200 would have passed on
the broken build for all five cases.

tls shard **268 passed, 0 failed**; full suite **854 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the resumable driver and on the blocking oracle, and end to end
through a real `proxy_h2` front. The echoed byte was read off the wire by the
fixture, not inferred from the source. The pre-fix control names which of the
five checks the fix is responsible for and which were already passing.
