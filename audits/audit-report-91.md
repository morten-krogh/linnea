# Audit Report 91

Audited at `0ad7394` (`quic: the idle floor is three PTOs, not an invented second`), 2026-08-27.

This audit revisited the QUIC transport-parameter parser, effective idle-timeout calculation, packet/frame validation, and HTTP/3 control-stream state after reports 88–90.

## Result — no new independently reproducible finding

The high-numbered transport-parameter duplicate table is now sized for the complete bounded ClientHello extension. The idle timeout uses the minimum advertised value, rounds only to the sweep’s granularity, and applies the RFC 9000 three-PTO minimum. Packet/frame and HTTP/3 control-stream validation paths reviewed in this pass have corresponding bounds or error handling.

I found no additional issue with sufficient evidence to report without relying on a speculative interpretation or an RFC SHOULD-level preference. No production source, configuration, or test files were changed in this audit. Only this report was added.


## Resolution (2026-08-27) — no findings, and one correction to audit-report-90

Nothing to fix in this report: it is a clean pass over the transport-parameter
parser, the idle-timeout calculation, and the packet/frame and control-stream
paths, and it says so rather than manufacturing a SHOULD-level preference. That
is the right outcome to record.

The full suite run for it did surface something — not in this report's scope,
but in the previous one's fix:

```
job 0 (base quic):  170 passed, 1 failed
    FAIL: h3 (io_uring): the client's max_idle_timeout is honoured (and only it)
```

audit-report-90's three-PTO floor had been computed while parsing transport
parameters, where no RTT sample exists yet, so it used the initial-RTT PTO
(~1022 ms) and froze a 4-second floor on every connection — about fortyfold the
real figure on a loopback path. RFC 9000 10.1 says three times the *current*
PTO, and the floor has been moved to the sweep, where "current" is the PTO the
connection actually has. The test that caught it is right and was right before:
on loopback three PTOs is ~90 ms, so reclaiming a one-second client at one
second was already conformant.

The test added with that fix asserted the behaviour of the patch rather than the
rule, contradicted the existing test, and has been removed. Details are in
audit-report-90's own Correction section, where they belong.

**The suite is the reason this was caught.** Reports 85 through 90 were resolved
without one, on the grounds that each change was confined to a single function
and covered by the unit harness. That held for the parser work — every one of
those came back green here — and did not hold the moment a change touched a
per-connection timer, where the unit harness has nothing to say and a behavioural
test did.
