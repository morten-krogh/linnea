# Audit Report 50

Audited at `527d6bf`, 2026-08-25.

Audit report 49's bounds-first padding checks are present in both backend-H2
paths. The SETTINGS parser now checks structure and
`INITIAL_WINDOW_SIZE`, but one known-setting validation gap remains:

1. **Low: invalid values for known backend SETTINGS identifiers, including
   `ENABLE_PUSH` and `MAX_FRAME_SIZE`, are silently ignored and acknowledged.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — known backend SETTINGS value bounds are not enforced

Severity: **Low (P3, malformed upstream configuration is accepted instead of
terminating the HTTP/2 connection)**  
Confidence: **High**  
Status: **Confirmed as filed**. Fixed — and stricter than recommended on
`ENABLE_PUSH`, where 6.5.2 permits a server to send only 0. The report also
correctly rebuts a comment added in `1d3bd6f`; see Resolution.

RFC 9113 §6.5.2 gives bounds for the defined SETTINGS identifiers. In
particular, `SETTINGS_ENABLE_PUSH` may only be 0 or 1, and
`SETTINGS_MAX_FRAME_SIZE` must be between 16384 and 16777215 inclusive. An
endpoint that receives an invalid value must treat it as a connection error.
These are known identifiers, not extension settings that may be ignored.

The resumable dispatcher now validates stream 0, ACK payload length, record
alignment, and `INITIAL_WINDOW_SIZE` before acknowledging a non-ACK SETTINGS
frame ([src/server/linnea_h2_client.asm:2646](/home/linnea/linnea/src/server/linnea_h2_client.asm:2646)
). But
`d_apply_settings` branches only for `INITIAL_WINDOW_SIZE`; every other setting
falls through `.next` as if it were unknown
([src/server/linnea_h2_client.asm:2034](/home/linnea/linnea/src/server/linnea_h2_client.asm:2034)
). Thus a
known `ENABLE_PUSH = 2` or `MAX_FRAME_SIZE = 1` is accepted and the frame is
ACKed.

The blocking/reference path has the same distinction. Its structural wrapper
calls `h2c_apply_settings`, whose walk acts only on `INITIAL_WINDOW_SIZE` and
ignores every other identifier ([src/server/linnea_h2_client.asm:902](/home/linnea/linnea/src/server/linnea_h2_client.asm:902)
). The
SETTINGS branches then send an ACK after that incomplete validation in settling,
window pumping, and response handling
([src/server/linnea_h2_client.asm:1009](/home/linnea/linnea/src/server/linnea_h2_client.asm:1009),
[src/server/linnea_h2_client.asm:1076](/home/linnea/linnea/src/server/linnea_h2_client.asm:1076),
[src/server/linnea_h2_client.asm:1273](/home/linnea/linnea/src/server/linnea_h2_client.asm:1273)).

The comments describing this as deliberate do not change the protocol rule:
ignoring unknown identifiers is correct, but these identifiers are defined by
RFC 9113. `MAX_FRAME_SIZE = 1` is especially misleading: the client continues
to emit DATA frames up to its hard-coded 16384-byte chunk size, even though it
has accepted a peer setting that claims a smaller maximum. The setting itself is
invalid and should have failed the connection instead of being silently
discarded.

The frontend HTTP/2 error matrix already requires the corresponding failures:
`SETTINGS_ENABLE_PUSH = 2` and `SETTINGS_MAX_FRAME_SIZE` below and above its
legal range all produce `PROTOCOL_ERROR`
([test/tls/h2_error_codes.py:119](/home/linnea/linnea/test/tls/h2_error_codes.py:119),
[test/tls/h2_error_codes.py:122](/home/linnea/linnea/test/tls/h2_error_codes.py:122),
[test/tls/h2_error_codes.py:124](/home/linnea/linnea/test/tls/h2_error_codes.py:124)).
The backend fixture currently covers only malformed SETTINGS structure and
`INITIAL_WINDOW_SIZE`; it has no cases for these known setting values.

### Reproduction

Before a normal response, have the backend send either of these frames on
stream 0:

```text
SETTINGS  { ENABLE_PUSH = 2 }
SETTINGS  { MAX_FRAME_SIZE = 1 }
HEADERS   stream 1, :status = 200, END_HEADERS
DATA      stream 1, END_STREAM, payload = "body"
```

Both backend paths walk past the unhandled known identifier, stage a SETTINGS
ACK, and continue to relay the response. The invalid `MAX_FRAME_SIZE` value is
not applied, but that is not compliant handling: receipt of the invalid value
must fail the connection rather than silently converting a malformed peer into
one with the local 16384-byte behavior.

### Recommended fix

Extend both settings walkers to validate every defined identifier whose value
has protocol bounds before acknowledging the frame:

1. Reject `SETTINGS_ENABLE_PUSH` values greater than 1. Since this is a
   single-stream client that has already disabled pushes, it need not otherwise
   change its behavior for a legal value.
2. Reject `SETTINGS_MAX_FRAME_SIZE` below 16384 or above 16777215. Continue
   emitting frames no larger than the negotiated legal limit.
3. Keep ignoring genuinely unknown identifiers, and preserve the existing
   `INITIAL_WINDOW_SIZE` delta handling.
4. Do not stage an ACK or partially mutate settings when a known value is
   invalid, in either the blocking oracle or the resumable driver.

Add backend-fixture cases for `ENABLE_PUSH = 2`, `MAX_FRAME_SIZE = 1`, and
`MAX_FRAME_SIZE = 16777216`, each asserting a gateway failure. Add a legal
`MAX_FRAME_SIZE = 16384` control case and retain the existing legal later
SETTINGS test so the fix cannot simply reject every frame carrying these IDs.

## Verification

This finding is a source-level trace through the resumable SETTINGS dispatcher,
both settings walkers, and all three blocking SETTINGS call sites. `make -j4`
completed with no work required. Existing invalid-known-setting tests cover the
frontend HTTP/2 server only; the backend fixture does not send invalid
`ENABLE_PUSH` or `MAX_FRAME_SIZE` values. Runtime socket reproduction was not
available in this restricted environment, and no source change was made that
required executable verification.

## Resolution (2026-08-25) — CONFIRMED, and it corrects a comment I wrote

### Reproduced

At `527d6bf`, each of these was accepted and the frame acknowledged, on both
paths:

```
ENABLE_PUSH = 2          -> 200
MAX_FRAME_SIZE = 1       -> 200
MAX_FRAME_SIZE = 16777216 -> 200
```

### The report is right about the comment, which was mine

`1d3bd6f` added a comment to `d_apply_settings` explaining that acting on only
`INITIAL_WINDOW_SIZE` was a decision rather than an omission. For
`MAX_FRAME_SIZE` it argued we are already under any legal ceiling, so ignoring
the setting "forfeits an optimisation, never correctness".

That conflates two rules. *Ignoring unknown identifiers* is required by 6.5.2.
*Ignoring an invalid value for a defined identifier* is not the same thing —
6.5.2 says a value outside the bounds is a connection error. "We need not act on
it" and "we need not validate it" are different claims, and the comment made the
first while implying the second. It has been rewritten to say which is which.

### Stricter than the report asks, on ENABLE_PUSH

The report asks for values greater than 1 to be rejected. 6.5.2 is stronger for
an endpoint in our position: a **server** must not set `ENABLE_PUSH` to 1 at
all, and a **client** must treat receipt of 1 as a connection error. Zero is the
only value that may legitimately reach us, and that is what is enforced —
`/set-push1` is refused as well as `/set-push2`.

That is a deliberate strictness with a small interop cost: a backend that wrongly
announces `ENABLE_PUSH = 1` becomes unusable rather than merely non-conforming.
No server we test against sends the setting at all, and one that sets it to 1 is
already broken in a way that matters, but the choice is worth naming rather than
burying.

### The legal-value controls are the ones that matter

`MAX_FRAME_SIZE = 16777215` is not a hypothetical upper bound — it is exactly
what real nginx advertises. A bounds check written a byte out, or one that
rejected the identifier rather than the value, would have broken every nginx
backend. `/set-mf-ok` sends both ends of the legal range, `/set-push0` sends the
legal push value, and the fix was additionally run against live nginx before
being committed: `/hello` and a 200000-byte body both relayed.

### Coverage

Six new checks. Against a binary built from the audited source:

```
pre-fix: /set-push1 is refused    FAIL
pre-fix: /set-push2 is refused    FAIL
pre-fix: /set-mf-low is refused   FAIL
pre-fix: /set-mf-high is refused  FAIL
pre-fix: /set-push0 is accepted   PASS  <- control
pre-fix: /set-mf-ok is accepted   PASS  <- control
```

tls shard **293 passed, 0 failed**; full suite **879 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the resumable driver and the blocking oracle, and against a live
nginx backend — which advertises `MAX_FRAME_SIZE = 16777215`, the exact value a
bounds check is most likely to get wrong.
