# Audit Report 79

Audited at `414e7ce` (`h3: remember every uni stream closed before it typed, not just the last`), 2026-08-27.

Audit report 78's multi-stream closure tracking is present. The next HTTP/3 control-stream gap is malformed `PRIORITY_UPDATE` payload handling:

1. **Low: a truncated PRIORITY_UPDATE element ID is silently accepted.**

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — truncated PRIORITY_UPDATE payloads are treated as valid

Severity: **Low (P3, malformed control-stream input is accepted instead of terminating the HTTP/3 connection)**  
Confidence: **High**  
Status: **Confirmed by source trace; the minimal frame sequence below is independently reproducible.**

RFC 9218 §7.2 defines a `PRIORITY_UPDATE` payload as an element identifier encoded as a QUIC variable-length integer followed by a priority field value. A payload that ends in the middle of that required identifier is malformed; HTTP/3's frame payload error handling requires `H3_FRAME_ERROR` for a frame whose contents cannot be parsed ([RFC 9218 §7.2](https://www.rfc-editor.org/rfc/rfc9218.html#section-7.2), [RFC 9114 §7.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1)).

The control-stream walker captures `PRIORITY_UPDATE` and invokes `.pu_apply` once the declared payload ends ([src/server/linnea_quic_server.asm:4829](/home/linnea/linnea/src/server/linnea_quic_server.asm:4829) through [src/server/linnea_quic_server.asm:4850](/home/linnea/linnea/src/server/linnea_quic_server.asm:4850)). `.pu_apply` decodes the element ID, but when `linnea_quic_varint_decode` reports an incomplete varint (`rdx = 0`) it jumps directly to `.pu_ok`, returning success and clearing the capture ([src/server/linnea_quic_server.asm:5120](/home/linnea/linnea/src/server/linnea_quic_server.asm:5120) through [src/server/linnea_quic_server.asm:5133](/home/linnea/linnea/src/server/linnea_quic_server.asm:5133)). No `H3_FRAME_ERROR` is generated.

### Reproduction

After opening a valid HTTP/3 control stream with SETTINGS, send a control-stream frame with type `0xF0700` (`PRIORITY_UPDATE`), length 1, and payload `40` (the first byte of a two-byte QUIC varint, with its continuation byte missing):

```text
control stream: 00 00                         # stream type + empty SETTINGS
frame:         40 f0 70 00 01 40              # type, length=1, truncated ID
```

The server completes `.pu_apply` successfully and continues the connection. The required result is an HTTP/3 `CONNECTION_CLOSE` carrying `H3_FRAME_ERROR` (`0x102`).

### Impact

This is primarily an interoperability and protocol-validation defect. A malformed control frame can be acknowledged and ignored, leaving the peer believing a priority signal was processed when it was not. It also makes malformed-input detection inconsistent with the SETTINGS, GOAWAY, and MAX_PUSH_ID payload checks in the same walker.

### Recommended fix

Treat `rdx = 0` from the element-ID varint decoder as `LINNEA_H3_ERR_FRAME`, and likewise reject any other incomplete or structurally invalid `PRIORITY_UPDATE` payload before applying or discarding it.


## Resolution (2026-08-27) — CONFIRMED, and there were TWO sites, not one

### Reproduced

At the audited source, driving the control stream through the existing
`h3_ctrl_frames_test.py` harness:

```
PRIORITY_UPDATE ending inside its id        no close   <- wanted 0x0106
PRIORITY_UPDATE with an empty payload       no close   <- wanted 0x0106
PRIORITY_UPDATE ending inside a 4-byte id   no close   <- wanted 0x0106
PRIORITY_UPDATE_PUSH ending inside its id   no close   <- wanted 0x0106
PRIORITY_UPDATE with a 2-byte id            kept serving  <- control
```

The report's trace of `.pu_apply` is exact, and its consistency point stands:
`.valen_apply` already refuses a CANCEL_PUSH, GOAWAY or MAX_PUSH_ID whose
payload does not match its single varint, and PRIORITY_UPDATE was the one frame
on the same walk whose truncated varint returned success.

RFC 9114 7.1 is a MUST here — "a frame payload that terminates before the end of
the identified fields MUST be treated as a connection error of type
H3_FRAME_ERROR" — so this is a plain conformance gap.

### The report has the error code wrong

It says `H3_FRAME_ERROR (0x102)` twice. H3_FRAME_ERROR is **0x0106**; 0x0102 is
H3_INTERNAL_ERROR. The recommendation names the right constant
(`LINNEA_H3_ERR_FRAME`), so nothing turned on it, but a reproduction written
against 0x102 would have failed for the wrong reason.

### The second site, which the finding does not mention

Fixing `.pu_apply` alone does NOT fix an empty payload: a PRIORITY_UPDATE
declaring length 0 never reaches `.pu_apply`. The walker's `.cw_prio` drops it
first —

```asm
    test rcx, rcx
    jz .cw_loop                       ; no element id can fit: not a priority frame
```

— reasoning that a frame too small to hold an element id is not a priority
frame, and ignoring it as if it were an unknown extension. But the type IS
known, and 7.1 is about exactly this: a payload that ends before its fields.
That is now `.cw_frame_err`. The empty-payload row is what found it; a
reproduction limited to the report's own truncated-id case would have left half
the defect in place and the suite green.

The neighbouring bound is deliberately NOT changed. A payload longer than
`LINNEA_QUIC_PU_BUF` is still ignored rather than refused: we cannot call a
payload truncated without parsing it, priority is advisory (RFC 9218 2), so
dropping one costs nothing — while refusing a LEGAL frame for being large would
cost interoperability. The comment now says so, since "too small" and "too big"
sit two lines apart and now behave differently.

### Ordering

`.pu_frame_err` is placed ahead of `.pu_id_error`: a frame that cannot be
PARSED is a frame error, whatever the id it failed to carry would have meant.
The push variant makes this visible — a well-formed PRIORITY_UPDATE_PUSH is
H3_ID_ERROR (we never promise a push), and a truncated one is now H3_FRAME_ERROR.
Both are asserted, so a later edit cannot quietly swap them.

### Coverage

Seven new rows in `test/quic/h3_ctrl_frames_test.py`, which already held the
same table for the three sibling frames. Against a binary built from the
audited source:

```
pre-fix: PRIORITY_UPDATE ending inside its id            FAIL
pre-fix: PRIORITY_UPDATE with an empty payload           FAIL  <- the second site
pre-fix: PRIORITY_UPDATE ending inside a 4-byte id       FAIL
pre-fix: PRIORITY_UPDATE_PUSH ending inside its id       FAIL
pre-fix: PRIORITY_UPDATE with a 2-byte id                PASS  <- control
pre-fix: PRIORITY_UPDATE with a 2-byte id and a value    PASS  <- control
pre-fix: PRIORITY_UPDATE id split across frames          PASS  <- control
```

Three of seven are controls, and they are the ones that matter: this fix's
failure mode is refusing a PRIORITY_UPDATE that is perfectly legal. A multi-byte
element id, one with a priority field value after it, and one whose id is SPLIT
ACROSS STREAM FRAMES — the capture path, where a partial payload legitimately
exists mid-walk and must not be judged truncated — all still keep the connection
serving.

`h3_priority_update_test.py` and `h3_priority_test.py` pass unchanged, including
their two H3_ID_ERROR rows, so the new frame-error path has not swallowed the
semantic id checks that run after it.

quic shard **170 passed, 0 failed**; full suite **1184 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, driving the control stream over a live h3 connection and reading the
CONNECTION_CLOSE code, for both the truncated-id site the report names and the
empty-payload site it does not. The pre-fix table names which rows the fix is
responsible for; the three that passed before and after are the legal
PRIORITY_UPDATEs this change could have broken, including one whose element id
is split across STREAM frames.
