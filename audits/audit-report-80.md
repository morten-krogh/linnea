# Audit Report 80

Audited at `56e7510` (`h3: a PRIORITY_UPDATE that ends inside its element id is H3_FRAME_ERROR`), 2026-08-27.

Audit report 79's truncated `PRIORITY_UPDATE` handling is present. The next control-stream gap is validation of the referenced request-stream ID:

1. **Low: PRIORITY_UPDATE accepts request IDs beyond the peer's stream limit.**

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — out-of-limit request IDs are buffered as valid priorities

Severity: **Low (P3, malformed or unusable control state is accepted and retained instead of being rejected at the HTTP/3 boundary)**  
Confidence: **High**  
Status: **Confirmed by source trace.**

RFC 9218 §7.2 requires the request-stream form of `PRIORITY_UPDATE` to identify a client-initiated bidirectional request stream. The identifier must be within the client-initiated bidirectional stream limit; an identifier beyond that limit is to be treated as an HTTP/3 ID error by implementations that enforce the limit ([RFC 9218 §7.2](https://www.rfc-editor.org/rfc/rfc9218.html#section-7.2)).

Linnea's `.pu_apply` validates only the low two bits of the element ID (`00` means client-initiated bidirectional). It never compares the stream ordinal against `ms_bidi_max`, the limit granted to the peer and used elsewhere by the transport stream-limit validator ([src/server/linnea_quic_server.asm:5270](/home/linnea/linnea/src/server/linnea_quic_server.asm:5270) through [src/server/linnea_quic_server.asm:5281](/home/linnea/linnea/src/server/linnea_quic_server.asm:5281)). Consequently, an ID such as `4000000` is accepted and stored in the pending-priority ring even when the connection has advertised a much smaller client bidirectional stream limit. The only stream-ID check in this path is `test r13, 3`.

### Reproduction

Open a normal HTTP/3 control stream with SETTINGS, then send a request-stream `PRIORITY_UPDATE` whose element ID is a client-bidirectional ID above the advertised limit (for example, ID `4000000`) and whose priority value is `u=7`. The server accepts the frame, inserts the ID into `pu_sid`, and continues instead of returning `H3_ID_ERROR` (`0x108`).

### Impact

An attacker can fill the bounded pending-priority ring with references to streams that cannot legally exist under the connection's stream limit. This consumes priority-state entries and can evict updates for real request streams; it also leaves the peer and server disagreeing about which stream IDs are valid control targets.

### Recommended fix

After confirming the request-stream type, compute `(element_id >> 2) + 1` and compare it with the connection's current `ms_bidi_max`. Reject an out-of-limit ID with `LINNEA_H3_ERR_ID` (or deliberately document and test the RFC's optional-ignore policy rather than retaining it as a valid pending update).


## Resolution (2026-08-27) — CONFIRMED, and the RFC is more specific than the report

### Reproduced

At the audited source, on a connection whose advertised bidi limit is
`LINNEA_QUIC_MS_INIT` = 100 (ordinals 1..100, ids 0, 4, ... 396):

```
an id one past the bidi stream limit (400)   no close   <- wanted 0x0108
a far out-of-limit id (4000000)              no close   <- wanted 0x0108
the last id within the limit (396)           no close   <- correct
```

The report's trace is exact: `test r13, 3` was the only check on the id.

### What RFC 9218 7.2 actually says

Worth quoting in full, because it both supports the finding and names the escape
that an implementation might claim:

> The request-stream variant of PRIORITY_UPDATE (type=0xF0700) MUST reference a
> request stream. ... **The stream ID MUST be within the client-initiated
> bidirectional stream limit.** If a server receives a PRIORITY_UPDATE
> (type=0xF0700) with a stream ID that is beyond the stream limits, this
> **SHOULD** be treated as a connection error of type H3_ID_ERROR. Generating an
> error is not mandatory because HTTP/3 implementations might have practical
> barriers to determining the active stream concurrency limit that is applied by
> the QUIC layer.

So it is a MUST on the sender and a SHOULD on us, with an explicit excuse for
implementations that cannot see the QUIC layer's live limit. **That excuse does
not apply here.** The QUIC layer is this one; `ms_bidi_max` is the live grant,
MAX_STREAMS regrants included, and the transport's own
`linnea_quic_stream_limit` already judges STREAM and RESET_STREAM frames against
it. Declining a SHOULD is defensible when the reason the RFC gives for making it
a SHOULD holds; here it does not.

### The fix

Four instructions after the existing type check, computing the ordinal exactly
as `linnea_quic_stream_limit` computes it — `(id >> 2) + 1`, compared `ja`
against the same `ms_bidi_max` — so the two paths cannot drift into disagreeing
about the same id.

### The stated impact does not survive scrutiny; the conformance case does

The report argues an attacker can "fill the bounded pending-priority ring with
references to streams that cannot legally exist" and evict updates for real
streams. The ring is `LINNEA_QUIC_PU_PEND` = 8 entries, and a peer can fill all
eight with ids that are perfectly WITHIN the limit — 0, 4, ... 28 — simply by
never opening those streams. The out-of-limit ids buy an attacker nothing that
in-limit ones do not, so this fix should not be credited with closing that door;
it was never the door. What the fix does close is a real conformance gap, and
it stops the pending ring holding entries that provably can never be claimed.

### Coverage

Three rows in `test/quic/h3_priority_update_test.py`, beside the two H3_ID_ERROR
rows it already had. Against a binary built from the audited source:

```
pre-fix: an id one past the bidi stream limit is H3_ID_ERROR   FAIL
pre-fix: a far out-of-limit id is H3_ID_ERROR                  FAIL
pre-fix: the last id within the limit is accepted              PASS  <- control
```

The boundary row is the one that matters. This check fails by being one too
strict — refusing a PRIORITY_UPDATE for the last stream the peer is actually
allowed to open — and that row is the only thing standing between the ordinal
arithmetic and an off-by-one nobody would notice until a client hit its hundredth
concurrent request. It is also why the ordinal is computed with the same
`(id >> 2) + 1` and the same `ja` as the transport check rather than
independently.

The existing rows keep their meaning: a non-request id and a push id are still
H3_ID_ERROR, a PRIORITY_UPDATE ahead of its request is still remembered and
applied, and one split across STREAM frames still works.

quic shard **170 passed, 0 failed**; full suite **1184 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, over a live h3 connection, reading the CONNECTION_CLOSE code for an id
one past the limit, for the report's own 4000000, and for the last id the limit
allows. The pre-fix table names which rows the fix is responsible for; the
boundary row passed before and after and is the one guarding the off-by-one this
change could introduce.
