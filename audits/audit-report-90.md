# Audit Report 90

Audited at `089c19f` (`quic: size the extension-parameter table so a duplicate cannot be stepped around`), 2026-08-27.

Audit report 89's transport-parameter duplicate-table bypass is addressed. The next QUIC timing issue is effective idle-timeout enforcement:

1. **Low: peer idle timeouts are rounded upward before enforcement.**

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — sub-second peer idle timeouts can be exceeded

Severity: **Low (P3, a connection remains allocated after the peer's negotiated idle timeout has elapsed)**  
Confidence: **High**  
Status: **Confirmed by source trace.**

RFC 9000 §10.1 defines the effective idle timeout as the minimum of the two advertised values. When that period expires without receiving a packet, the endpoint may discard the connection; it must not treat a longer locally rounded value as the negotiated timeout ([RFC 9000 §10.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-10.1)).

After parsing the peer's `max_idle_timeout` in milliseconds, the server adds 999 and divides by 1000, explicitly rounding upward to whole seconds before storing `idle_secs` ([src/server/linnea_quic_server.asm:1383](/home/linnea/linnea/src/server/linnea_quic_server.asm:1383) through [src/server/linnea_quic_server.asm:1403](/home/linnea/linnea/src/server/linnea_quic_server.asm:1403)). The idle sweep uses that integer-second value. A peer advertising 1001 ms is consequently retained for up to 2 seconds, and a peer advertising 1 ms is retained for a full second, despite the negotiated timeout having already expired.

### Reproduction

Complete a QUIC handshake with a client transport parameter `max_idle_timeout = 1001` milliseconds, then send no further packets. Observe the server's connection slot: it remains allocated until the 2-second sweep threshold rather than being eligible immediately after approximately 1.001 seconds.

### Impact

The effect is bounded to less than one second (and is therefore low severity), but it can accumulate across many deliberately short-lived connections and makes the server's timeout behavior disagree with the peer's negotiated value. Under connection churn, delayed reclamation consumes connection slots and associated per-connection memory longer than advertised.

### Recommended fix

Store the negotiated idle deadline in milliseconds (or a monotonic absolute deadline) and compare it at millisecond precision. If the sweep must remain second-granular, round down with a minimum floor only for scheduling and perform a precise check before reclaiming, rather than rounding the negotiated timeout upward.


## Resolution (2026-08-27) — REJECTED as filed; the same three lines hold the opposite defect, and it is a MUST

### The rounding is not a violation, because a larger floor sits above it

The finding quotes RFC 9000 10.1 on the effective idle timeout being the minimum
of the two advertised values. The same section carries a sentence it does not
quote:

> To avoid excessively small idle timeout periods, endpoints **MUST** increase
> the idle timeout period to be at least three times the current Probe Timeout
> (PTO). This allows for multiple PTOs to expire, and therefore multiple probes
> to be sent and lost, prior to idle timeout.

That is a mandatory **floor**, and it is bigger than the rounding the finding
objects to. On a connection with no RTT sample yet — which is every connection
at the moment its transport parameters are read — linnea's own PTO is
`kInitialRtt + 4*rttvar + max_ack_delay` = `333 + 664 + 25` = **1022 ms**, so
three of them is **3.07 s**.

So for the report's own example, `max_idle_timeout = 1001 ms`: the RFC requires
the idle period to be at least 3.07 s. Rounding up to 2 s does not hold the slot
*too long*; it releases it too **early**. And "a peer advertising 1 ms is
retained for a full second, despite the negotiated timeout having already
expired" describes the MUST being partially obeyed, not a defect. The
recommended fix — millisecond-precise discard at the negotiated value — would
move linnea further from that MUST, not closer.

### What was actually wrong

The floor was a flat one second, with a comment admitting it was invented: "never
below one, so a tiny value cannot reclaim a connection the instant it is made."
That is reaching for the 3×PTO rule without naming it, and lands at a third of
it. A peer advertising a short idle timeout could lose its connection while it
was still probing — precisely what the sentence exists to prevent.

Measured end to end. A client advertising `max_idle_timeout = 1000 ms` completes
a handshake, stays silent for two seconds without driving its own idle timer,
then asks again:

```
                          first request   after 2s quiet
one-second floor              200             none        the slot was gone
three-PTO floor               200             200
```

### The fix

The peer's milliseconds still round up to the sweep's second granularity —
holding a slot for the remainder of a second violates nothing, and the floor is
larger than the rounding in either direction. The floor is now
`ceil(3 * linnea_quic_pto_ms(conn, app_space) / 1000)` instead of 1. It is asked
for in *application* space so it uses the peer's `max_ack_delay`, which was
stored a few lines above, and it is computed per connection rather than as a
constant because the PTO is.

A peer asking for longer than three PTOs is unaffected: 10 s stays 10 s, and
Chrome's 30 s still meets ours at 30. Only the short values move, and they move
to the number the RFC names.

### Correction — the first version of this fix was wrong, and the suite caught it

The change above computed the floor while parsing transport parameters. RFC 9000
says three times the **current** PTO, and at that moment the connection has no
RTT sample, so the only PTO available is the initial-RTT one — about 1022 ms.
That number was then frozen for the connection's life, making the floor 4 s on
every connection including a loopback one whose real PTO is roughly 28 ms. It
overstated the requirement by about fortyfold.

The full suite failed one check:

```
FAIL: h3 (io_uring): the client's max_idle_timeout is honoured (and only it)
```

`h3_idle_tp_test.py` has a client advertise 1 s, stay quiet 4 s, and asserts the
slot is gone — with a generous-value control beside it so the row cannot pass by
coincidence. That test is right: on loopback three PTOs is about 90 ms, so a
one-second window already clears the floor comfortably, and reclaiming at one
second is conformant. The pre-existing behaviour was not a violation there at
all.

Which makes the A/B above **circular**: `h3_idle_floor.py` asserted the
behaviour my patch produced rather than the rule the RFC states, and it
contradicted a test that encodes the rule properly. It has been deleted, along
with its shard row. A test whose expected value comes from the implementation
under test measures nothing.

### Where the floor actually belongs

In the sweep, against the PTO the connection has at the moment it is considered
for reclamation — which is what "current" means, and where the figure has
dropped to whatever the path really costs. On a fast path it is tens of
milliseconds and changes nothing; on a slow path it is seconds, which is exactly
when the rule matters, and it now tracks that path instead of a guess made
before the first round trip.

`rcx` is the sweep's slot counter, so the call saves it with the rest and returns
the floor in `r9`, which the walk does not use — the comparison happens after
every register the walk owns is back.

### What remains true, and what cannot be shown here

The finding is still rejected: rounding the peer's milliseconds up to the
sweep's granularity is not a violation, because the three-PTO floor is larger
than the rounding in every case where the rounding could matter.

The floor's effect is **not observable on loopback** — that is the point of the
correction above — so no test in this suite demonstrates it, and none is added
pretending to. What is asserted is that it changes nothing where it should
change nothing: `h3_idle_tp_test.py` passes in both of its cases, as do the
multi-request and multi-connection tests that exercise the same sweep.
