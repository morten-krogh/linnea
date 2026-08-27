# Audit Report 89

Audited at `811b46f` (`quic: track duplicate extension transport parameters, not just ids below 64`), 2026-08-27.

Audit report 88's high-numbered transport-parameter tracking is present. A bounded-table edge remains:

1. **Low: duplicate high-numbered transport parameters are accepted after the tracking table fills.**

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — extension-ID duplicate checking stops after 32 distinct IDs

Severity: **Low (P3, a malformed authenticated transport-parameter extension can bypass the recommended duplicate signal)**  
Confidence: **High**  
Status: **Confirmed by source trace.**

RFC 9000 §7.4.1 recommends treating any duplicate transport parameter as `TRANSPORT_PARAMETER_ERROR`, including extension and GREASE IDs. The recommendation is not limited to the first few extension parameters ([RFC 9000 §7.4.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-7.4.1)).

`linnea_quic_tp_parse` records high-numbered IDs in a temporary list of `LINNEA_QUIC_TP_HI` entries. Once that list is full, `.tp_hi_add` jumps to `.tp_after_dup` without recording the new ID ([src/lib/linnea_quic.asm:2026](/home/linnea/linnea/src/lib/linnea_quic.asm:2026) through [src/lib/linnea_quic.asm:2047](/home/linnea/linnea/src/lib/linnea_quic.asm:2047)). A later duplicate of any unrecorded 33rd-or-later extension ID is therefore accepted, even though the same ID would be rejected before the table filled.

### Reproduction

Construct a ClientHello transport-parameter extension containing 33 distinct unknown IDs at or above `0x40`, followed by a second occurrence of the 33rd ID. All entries may carry valid zero-length payloads. The parser accepts the extension and completes the handshake; a duplicate-aware implementation may return `TRANSPORT_PARAMETER_ERROR`.

### Impact

This is low severity: unknown extension parameters are ignored, and RFC 9000 makes duplicate receipt a SHOULD-level error. It nevertheless creates input-dependent validation and allows a peer to bypass the duplicate check by first filling the bounded table with distinct extension IDs.

### Recommended fix

Either retain all IDs that occur in the bounded ClientHello extension (the extension length already bounds the maximum count), or treat table saturation as a transport-parameter error when another high-numbered ID is encountered. At minimum, document that duplicate checking is intentionally best-effort after the cap.


## Resolution (2026-08-27) — CONFIRMED; the table is now sized so it cannot fill

### Reproduced

Against the 32-entry table audit-report-88 introduced:

```
33 distinct extension ids, then the 33rd again    tp_error = 0   accepted
40 distinct extension ids, then the 40th again    tp_error = 0   accepted
33 distinct ids and no repeat                     tp_error = 0   correct
```

The finding is right, and it is right about my own reasoning. 88's resolution
argued the cap "costs nothing observable" because an unknown parameter is
ignored either way. That is still true of the *consequence*, but it is the wrong
test for the *rule*: a check a peer can step around by spending distinct ids
first is not a check, and "input-dependent validation" is the report's phrase
for exactly that.

### The fix: pick the bound from the input, not from a round number

The report offers three options and the first is the right one — "retain all IDs
that occur in the bounded ClientHello extension (the extension length already
bounds the maximum count)". The arithmetic:

- a ClientHello is capped at `LINNEA_QUIC_CH_BUF` = 4096 bytes;
- an id at or above 64 needs a two-byte varint, and its length needs one more,
  so the cheapest such parameter is **three bytes**;
- therefore at most `CH_BUF / 3` of them can exist in one extension.

`LINNEA_QUIC_TP_HI` is now `(LINNEA_QUIC_CH_BUF / 3) + 1` — 1366 entries, 11 KB —
and is written as that expression rather than the number, so raising the
ClientHello bound raises this with it. The table moves to `.bss` beside the
other transport-parameter statics (one ClientHello is parsed at a time per
worker, and the count that indexes it lives on the parser's frame, so nothing
survives a call). The frame goes back from `sub rsp, 280` to `sub rsp, 24`.

This is the same move as audit-report-78: there the client uni stream ids were
bounded by a STREAM_LIMIT_ERROR gate, so one bit per possible stream was exact;
here the parameters are bounded by the ClientHello, so one slot per possible
parameter is exact. In both cases the ring that could be evicted was replaced by
a table that cannot be.

### Saturation is now an error, and it is unreachable from a ClientHello

Filling the table means the caller handed the parser more high-numbered
parameters than a ClientHello can carry — 4101 bytes of them, in the test below.
That is refused rather than waved through: it is not input this function is
defined over, and refusing costs nothing because no ClientHello can produce it.
It also means the table cannot be written past its end, which the last row
asserts.

The report's third option — "at minimum, document that duplicate checking is
intentionally best-effort" — is not taken, because it no longer is.

### Coverage

Four cases in `test/quic/linnea_rtxtest.asm`: **281/281** after, **278/280** with
audit-report-88's 32-entry table (the saturation row is new to this fix). The
two that move are the 33- and 40-id duplicates.

Two rows are controls and they pull in opposite directions, which is the point:
33 distinct ids with **no** repeat must still parse cleanly, so this cannot
become a cap on how many extension parameters a peer may send; and the 4101-byte
blob must be refused rather than overrun the table.
