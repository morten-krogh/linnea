# Audit Report 88

Audited at `1540fde` (`h3: walk an unknown priority member's inner list instead of skipping it`), 2026-08-27.

The HTTP/3 priority parser now validates inner lists as well as ordinary members and parameters. The broader QUIC transport-parameter pass found one remaining duplicate-detection gap:

1. **Low: duplicate extension/GREASE transport parameters are accepted.**

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — duplicate transport-parameter IDs at or above 64 bypass duplicate detection

Severity: **Low (P3, repeated authenticated transport declarations are accepted with last-value/ignored semantics)**  
Confidence: **High**  
Status: **Confirmed by source trace.**

RFC 9000 §7.4.1 says an endpoint MUST NOT send a transport parameter more than once in a transport-parameters extension, and recommends treating a received duplicate as `TRANSPORT_PARAMETER_ERROR`. The rule applies to extension and GREASE parameters as well as the standardized low-numbered parameters ([RFC 9000 §7.4.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-7.4.1)).

`linnea_quic_tp_parse` stores a seen-ID bitmap only for IDs below 64. IDs at or above 64—where QUIC extension and GREASE parameters are expected—jump directly to `.tp_after_dup` and are never recorded ([src/lib/linnea_quic.asm:1995](/home/linnea/linnea/src/lib/linnea_quic.asm:1995) through [src/lib/linnea_quic.asm:2022](/home/linnea/linnea/src/lib/linnea_quic.asm:2022)). Two identical unknown parameters such as ID `0x40` are therefore accepted and skipped independently.

### Reproduction

Construct a ClientHello transport-parameter extension containing two occurrences of the same unknown ID `0x40`, each with a valid one-byte payload. The parser accepts the extension and continues the handshake. A duplicate-aware implementation may close with `TRANSPORT_PARAMETER_ERROR`; the current parser cannot distinguish the duplicate from two different extension parameters.

### Impact

This is low severity because unknown parameters are otherwise ignored and the RFC characterizes duplicate receipt as a SHOULD-level error. Nevertheless, it creates an observable interoperability difference and permits an authenticated peer to send contradictory extension declarations without the duplicate signal that prevents ambiguous negotiation.

### Recommended fix

Track duplicate IDs for the complete parameter namespace, not only IDs below 64. A bounded hash/set sized to the extension length is sufficient; alternatively, retain all parsed IDs in a temporary list and compare each new ID before accepting it. Treat a duplicate as `TRANSPORT_PARAMETER_ERROR` (or explicitly document the intentional SHOULD-level exception).


## Resolution (2026-08-27) — CONFIRMED; the reason in the comment was true of the space, not of the traffic

### Reproduced

There was no unit coverage of `linnea_quic_tp_parse` at all — `linnea_quictp.asm`
exercises the *building* of transport parameters, not the parsing — so the
finding was measured by driving the parser directly with hand-built extensions
(`0x4040` is the two-byte varint for id 64):

```
04 01 0f  04 01 0f                          tp_error = 1   id 0x04 twice: caught
04 01 0f  4040 01 aa  4040 01 aa            tp_error = 0   id 64 twice: NOT caught
4040 01 aa  4041 01 bb  4040 01 cc          tp_error = 0   nor with 65 between
```

The report's trace is exact, and the code said so itself: "ids at or above 64
(grease) are not tracked (unbounded)".

### The reason did not hold

The id space is 62 bits, so no bitmap can span it — that part is true. It does
not follow that nothing can be tracked. What a peer can *send* is bounded: the
ClientHello is capped at `LINNEA_QUIC_CH_BUF` = 4096 bytes and every parameter
costs at least two, so an extension holds at most a couple of thousand of them,
and a conforming peer sends one or two above 64. Remembering the ids that
actually arrive is a different problem from indexing the space they come from,
and the comment had conflated the two. That is the same shape as
audit-report-84, where "cannot change scheduling" turned out to be a reason for
not looking rather than a reason there was nothing to find.

### The fix

`LINNEA_QUIC_TP_HI` = 32 ids kept on the parser's own frame — the bitmap and
this table together turn `sub rsp, 8` into `sub rsp, 280`, which keeps the same
16-byte alignment the varint calls need. Each id at or above 64 is compared
against the ones already seen (at most 32 register compares, no decoding) and
then recorded.

Past 32 distinct extension parameters the *checking* stops, not the connection.
That bound is deliberate on a path that runs before the handshake completes, and
it costs nothing observable: an unknown parameter is ignored either way, so a
peer that spends 33 of them to hide a duplicate has hidden a duplicate of
something that was already being discarded. The RFC's concern — contradictory
declarations — applies to parameters whose value is *stored*, and every one of
those is below 64, where the bitmap is exact.

### On severity

This is a SHOULD, and the report says so plainly. The sentence is in RFC 9000
**7.4**, not 7.4.1 as cited: "An endpoint MUST NOT send a parameter more than
once in a given transport parameters extension. An endpoint SHOULD treat receipt
of duplicate transport parameters as a connection error of type
TRANSPORT_PARAMETER_ERROR." The practical consequence of the gap was nil — both
copies of an unknown parameter were skipped — so this is conformance, not a
behaviour fix, and it is worth being clear about which.

### Coverage

Six cases in `test/quic/linnea_rtxtest.asm`, the first coverage this parser has
had: **277/277** after, **275/277** on the audited source. The two that moved
are the extension-range duplicates; the low-id duplicate passes on both sides
and is kept precisely because it proves the bitmap was already right and the
change did not disturb it.

Three of the six are controls, and they matter here more than usual: a peer's
GREASE parameter is a normal thing to receive, and a duplicate check that is one
comparison too eager would start killing handshakes. Ids 64 and 65 together, a
single extension parameter, and two different standardised ids must all parse
cleanly.
