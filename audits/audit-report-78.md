# Audit Report 78

Audited at `3fa9e94` (`h3: a completed stream keeps its final size (RFC 9000 4.5)`), 2026-08-27.

Audit report 77's completed-stream final-size state is present. The next HTTP/3 state boundary is reordered closure of unidirectional streams:

1. **Medium: multiple pre-typed critical-stream resets overwrite one another.**

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — a single closed-stream slot loses earlier critical-stream resets

Severity: **Medium (P2, a reordered control or QPACK stream can evade the required closed-critical-stream connection error)**  
Confidence: **High**  
Status: **Confirmed by source trace; the packet sequence below is independently reproducible.**

RFC 9114 §6.2 requires the peer to treat closure of the control stream or either QPACK stream by any means, including `RESET_STREAM`, as `H3_CLOSED_CRITICAL_STREAM`. This includes a type frame that arrives after a reset because QUIC packets can be reordered ([RFC 9114 §6.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2), [RFC 9000 §13.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-13.3)).

The receive loop scans every `RESET_STREAM` in a packet. For a client unidirectional stream whose type has not arrived, it records the ID in `uni_closed_sid` ([src/server/linnea_quic_server.asm:2378](/home/linnea/linnea/src/server/linnea_quic_server.asm:2378) through [src/server/linnea_quic_server.asm:2397](/home/linnea/linnea/src/server/linnea_quic_server.asm:2397)). That field is a single qword ([include/linnea_quic_conn.inc:693](/home/linnea/linnea/include/linnea_quic_conn.inc:693) through [include/linnea_quic_conn.inc:697](/home/linnea/linnea/include/linnea_quic_conn.inc:697)); each later reset simply overwrites the previous ID.

When a delayed offset-0 type frame eventually arrives, the control and QPACK typing paths compare only that one saved ID before accepting the stream ([src/server/linnea_quic_server.asm:4517](/home/linnea/linnea/src/server/linnea_quic_server.asm:4517) through [src/server/linnea_quic_server.asm:4524](/home/linnea/linnea/src/server/linnea_quic_server.asm:4524), [src/server/linnea_quic_server.asm:4618](/home/linnea/linnea/src/server/linnea_quic_server.asm:4618) through [src/server/linnea_quic_server.asm:4624](/home/linnea/linnea/src/server/linnea_quic_server.asm:4624)). Thus only the most recently reset untyped stream is recognized as closed.

### Reproduction

After the HTTP/3 handshake, inject authenticated 1-RTT packets in this order (client unidirectional IDs 2 and 6 are both legal):

```text
1. RESET_STREAM(stream=2, final_size=1)
2. RESET_STREAM(stream=6, final_size=1)
3. STREAM(stream=2, offset=0, data=varint(0), FIN=0)
```

The first two resets leave `uni_closed_sid = 6`. When stream 2's reordered type frame is processed, it is accepted as the control stream and proceeds to the SETTINGS walk; no `H3_CLOSED_CRITICAL_STREAM` (`0x104`) connection error is generated. Reversing 2 and 6 makes the other stream evade the check. A hand-built aioquic 1-RTT injector can construct these frames using the same packet-key setup as `test/quic/h3_critical_reset_test.py`.

### Impact

The implementation can continue an HTTP/3 connection after a critical stream was reset. The peer and server then disagree about whether a control/QPACK stream is live, and subsequent control-state processing can be accepted on a stream that QUIC has already closed. This is a protocol-state validation failure and weakens the mandatory connection-error signal used to prevent an unusable HTTP/3 session from continuing.

### Recommended fix

Replace `uni_closed_sid` with a bounded set/ring of closed untyped unidirectional stream IDs, or check the reset list against the ID at type time. Retain every reset that can still be followed by a reordered type frame, and remove an entry once the stream proves to be a non-critical/grease stream.


## Resolution (2026-08-27) — CONFIRMED, fixed with a bitmap rather than a ring

### Reproduced

At the audited source, injecting the report's sequence in authenticated 1-RTT
packets, one connection per row:

```
control:   two resets, the FIRST types      no close   <- wanted 0x0104
control:   two resets, the LAST types       0x0104     <- the case that always worked
qpack-enc: two resets, the FIRST types      no close
qpack-dec: two resets, the FIRST types      no close
grease:    two resets, the first types      no close   <- correct
```

The report's trace is exact, and the distinction it draws is the whole finding:
the LAST closed stream was always caught. A test that closes one stream, or
types the later of two, passes on the broken build — which is why the existing
`h3_critical_reorder.py` did not catch this.

The single slot was deliberate; the comment on the field argued that "a
conforming client closes no uni stream, so a closed one is already anomalous,
and the connection ends the moment it types". That reasoning holds for one
closure and quietly fails for two: the connection ends the moment the LAST one
types, and the peer chooses which one that is.

### The fix is a bit per stream, not a ring

The report recommends "a bounded set/ring of closed untyped unidirectional
stream IDs" plus logic to release an entry once a stream proves non-critical. A
ring would work, but it can be evicted: reset N+1 streams, then type the first,
and the finding comes straight back at whatever N is chosen.

It is not needed here. Client unidirectional ids are `4k + 2`, and the
per-packet `STREAM_LIMIT_ERROR` gate (RFC 9000 4.6) refuses `k >=
LINNEA_QUIC_MSU_INIT` **before** either the reset scan or the stream scan runs.
So one bit per POSSIBLE client uni stream covers every id the peer can legally
use, for the life of the connection: nothing to evict, nothing to release, and
16 bytes rather than a ring of ids. `fc_uni_sid` next to it is sized by exactly
the same argument, which is what suggested it.

`uni_closed_mark` / `uni_closed_known` replace the load-and-compare at all four
sites — the RESET_STREAM scan, the untyped-FIN path, and the control and QPACK
typing checks. Both clobber only `rax`, because the reset loop needs its
`rdi`/`rsi` afterwards and the typing path carries the stream type in `cl`
across the call.

### Coverage

Fourteen rows, one connection each. Against a binary built from the audited
source:

```
pre-fix: control/qpack-enc/qpack-dec: two resets, the FIRST types    FAIL (x3)
pre-fix: control/qpack-enc/qpack-dec: both resets in ONE packet      FAIL (x3)
pre-fix: control/qpack-enc/qpack-dec: FIN then reset, FINNED types   FAIL (x3)
pre-fix: control/qpack-enc/qpack-dec: two resets, the LAST types     PASS (x3) <- controls
pre-fix: grease: two resets, the first types                         PASS  <- control
pre-fix: control: no closure at all                                  PASS  <- control
```

Five of fourteen are controls and they are the ones that matter. "The last one
types" is what the old code got right, so it proves the fix did not simply
replace one working case with another. The grease row is the risk: a bit set for
a stream that turns out to be grease must not become "close the connection on
any late type frame", and nothing else in the suite asserts that a closed
non-critical stream may still type. "No closure at all" keeps the check from
degenerating into closing on every uni type frame.

Both sibling tests still pass unchanged: `h3_critical_reorder.py` (one closure,
reordered) and `h3_critical_reset_test.py` (closure after typing).

### One row was measuring the wrong thing, before I tightened it

The FIN rows originally sent a data byte with the FIN, copying the sibling test.
On the fixed build all three passed; on the broken build the qpack-encoder row
"failed" with `0x0201` — QPACK_ENCODER_STREAM_ERROR — because that byte reached
an encoder whose advertised capacity is 0. It was refused for a reason that has
nothing to do with this finding, and a row asking only "did the connection
close?" would have called that a pass. The FIN now carries no data, so all three
rows fail cleanly with no close on the broken build.

The first version of the probe failed every row including the ones that must
pass — the signature of a broken measurement, not a broken server. It hand-rolled
its own close detection (reading CONNECTION_CLOSE off the wire, as
audit-report-77 needed) and looked only at the first byte of the packet, which
here is an ACK: the close sat behind it. Rewritten to use the same handshake,
injection and close-reading helpers as its sibling, which is what it should have
been built from to begin with.

quic shard **170 passed, 0 failed**; full suite **1184 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, over injected 1-RTT packets, for all three critical stream types and
for both closure kinds (RESET_STREAM and FIN), with the two resets delivered in
one packet and in separate packets. The pre-fix table names which rows the fix
is responsible for; the five that passed before and after are what keep the
change from being "close on any late type frame". Both sibling tests still pass
unchanged.
