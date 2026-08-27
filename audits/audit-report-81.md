# Audit Report 81

Audited at `411bdb2` (`h3: a PRIORITY_UPDATE id past the bidi stream limit is H3_ID_ERROR`), 2026-08-27.

Audit report 80's stream-limit check is present. The remaining priority-control gap is malformed Structured Fields handling:

1. **Low: malformed PRIORITY_UPDATE priority values are silently converted to defaults.**

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — invalid priority members are accepted without an error signal

Severity: **Low (P3, malformed HTTP/3 control input is acknowledged and applied as a different priority)**  
Confidence: **High**  
Status: **Confirmed by source trace.**

RFC 9218 §7.2 defines the `PRIORITY_UPDATE` value as an ASCII Structured Fields priority value. A recipient may choose to treat a failure to parse that value as a connection error, but it must not mistake malformed syntax for the sender's explicit priority signal ([RFC 9218 §7.2](https://www.rfc-editor.org/rfc/rfc9218.html#section-7.2)).

Linnea routes every captured priority value through `linnea_quic_parse_priority` ([src/server/linnea_quic_server.asm:5258](/home/linnea/linnea/src/server/linnea_quic_server.asm:5258) through [src/server/linnea_quic_server.asm:5267](/home/linnea/linnea/src/server/linnea_quic_server.asm:5267)). That parser initializes urgency to 3 and incremental to false, then ignores unknown, duplicate, and malformed members while retaining those defaults ([src/lib/linnea_quic.asm:2169](/home/linnea/linnea/src/lib/linnea_quic.asm:2169) through [src/lib/linnea_quic.asm:2245](/home/linnea/linnea/src/lib/linnea_quic.asm:2245)). `.pu_apply` never receives a parse-failure indication; it stores the default priority and returns success.

### Reproduction

After a valid control-stream SETTINGS frame, send a request-stream `PRIORITY_UPDATE` for an in-limit request ID with values such as `u=7x`, `u=1,u=5`, or `i=?2`. The server acknowledges the frame and applies either the default urgency (`3`) or the first/last partially recognized member instead of rejecting the malformed value or clearly discarding the update.

### Impact

This is a low-severity interoperability issue: a sender's malformed signal is silently interpreted as a valid but different scheduling decision, making priority behavior dependent on parser leniency. It can also let malformed control traffic consume the bounded pending-priority ring.

### Recommended fix

Return a parse-status flag from `linnea_quic_parse_priority`. For `PRIORITY_UPDATE`, either reject a syntax failure with the permitted HTTP/3 general protocol error or discard the entire update without storing a default derived from malformed members; retain the current defaults only for an omitted/empty priority value.


## Resolution (2026-08-27) — REJECTED as filed; one of its three examples is a real defect, in the opposite direction

### The premise is wrong: ignoring malformed members IS the required handling

RFC 9218 4, verbatim:

> unknown priority parameters, priority parameters with out-of-range values, or
> values of unexpected types **MUST be ignored**.

An ignored member leaves the default standing. So "malformed priority values are
silently converted to defaults" is not a defect — it is the behaviour the RFC
mandates. And 7.2:

> Failure to parse the Priority Field Value **MAY** be treated as a connection
> error.

MAY, not MUST. The recommended fix — "reject a syntax failure with the permitted
HTTP/3 general protocol error or discard the entire update" — asks for a MAY in
place of a MUST, and would make linnea *less* conformant on the parameter cases
while gaining nothing on the whole-value case.

### The three examples, measured

`linnea_quic_parse_priority` is a pure function, so these were measured directly
rather than inferred, on the audited binary. Each result is urgency, incremental:

```
u=7x        3 0    correct: not a number, ignored, default stands
u=1,u=5     5 0    correct: RFC 8941 4.2.2, a repeated key takes the LAST value
i=?2        3 1    WRONG: "?2" is not a boolean, so it must be IGNORED
```

Two of three were already right, and the second is not malformed at all. The
third is a genuine defect — but note which way it points: the report's thesis is
that malformed input wrongly becomes the *default*, and here malformed input
wrongly becomes a *non-default*. The finding's own reasoning would not have
caught it.

### The defect is wider than that one value

`.pp_i` set incremental true and then cleared it only for exactly `i=?0`, so
every member that reached the branch and was not `i=?0` came out true:

```
i=?2         3 1    not a boolean
i=x          3 1    not a boolean
i=?1x        3 1    a boolean that does not end the member
i=?0,i=?2    3 1    an invalid member UNDOING an explicit "off"
important=1  3 1    not this key at all -- any unknown key beginning with "i"
```

`important=1` is the one worth pausing on: an unknown dictionary member turned
on a scheduling flag, which is precisely what "unknown priority parameters MUST
be ignored" forbids. The urgency branch beside it already validates its digits
and requires them to end the member before applying anything; the incremental
branch applied first and asked afterwards.

`.pp_i` now mirrors it: check the shape, then apply. A bare `i` is still the
RFC 8941 3.2 shorthand for true, `i=?0`/`i=?1` still work with or without a
trailing parameter, and anything else leaves incremental exactly as the previous
member left it.

### Coverage

Thirteen cases in `test/quic/linnea_rtxtest.asm`, which already exercised this
parser — the right home, since it is a pure function and the unit harness can
assert the exact pair it returns rather than inferring priority from response
ordering. Against a binary built from the audited source the harness goes from
**133/133 to 128/133**: the five invalid-boolean rows fail, and the eight others
pass on both sides.

Those eight are the controls, and three of them are the report's own examples —
`u=7x`, `u=1,u=5`, `i,i=?0` — kept precisely because they are correct. A test
that only added failing rows would leave the next reader thinking all of the
report was right. The remaining controls are `i;q=1` and `i=?1;q=2`: this fix
fails by being too strict, and RFC 8941 lets any member carry parameters, so
tightening the grammar must not start refusing the legal ones.

### What was NOT changed

The whole-value parse failure remains non-fatal. 7.2's MAY permits either, the
frame is still discarded in the sense that no malformed member is applied, and
turning a MAY into a connection close is the kind of strictness that breaks
clients for no protocol benefit. The report's other suggestion — discarding the
whole update when any member is malformed — is contradicted by 4's MUST, which
is per-member.

The pending-priority ring point ("malformed control traffic can consume the
bounded ring") is the same argument audit-report-80 made and it is no stronger
here: a peer can fill all eight entries with perfectly valid updates for streams
it never opens.

`bin/linnea-rtxtest` **133/133** (128/133 on the audited source); full suite
**1184 passed, 0 failed**.

## Verification (resolution)

`linnea_quic_parse_priority` is a pure function, so every claim above is a
direct measurement of the pair it returns for a given value, taken on a binary
built from the audited source and again after the change — not an inference from
response ordering. The RFC quotations are verbatim from RFC 9218 sections 4 and
7.2. Two of the report's three examples were measured to be already correct and
are kept as controls precisely for that reason.
