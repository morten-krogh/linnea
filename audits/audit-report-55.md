# Audit Report 55

Audited at `c732018`, 2026-08-25.

Audit report 54's shared PING validation is now used by all three blocking
frame loops. The next backend-H2 SETTINGS gap is duplicate-identifier handling:

1. **Low: both backend SETTINGS walkers accept multiple instances of the same
   setting in one SETTINGS frame instead of treating the frame as a protocol
   error.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — duplicate SETTINGS entries are applied and acknowledged

Severity: **Low (P3, malformed upstream configuration is accepted and can
apply repeated state changes)**  
Confidence: **High**  
Status: **NOT CONFIRMED — rejected.** The no-duplicates rule is HTTP/3's
(RFC 9114 7.2.4.1) and QUIC's (RFC 9000 7.4), both of which this server
enforces; RFC 9113 6.5 requires in-order processing instead. Measured
against nginx, nghttp2 and our own frontend. No source change; 11 checks
added to pin the behaviour.

RFC 9113 §6.5.2 requires a sender not to include more than one value for a
setting identifier in a single SETTINGS frame, and requires the receiver to
treat duplicate instances as a connection error. This rule is about entries
within one frame; the same identifier in separate SETTINGS frames is legal and
must continue to work.

The blocking walk validates stream 0 and six-octet record alignment, then
iterates directly over every record. It has no per-frame set of identifiers:
the `INITIAL_WINDOW_SIZE`, `ENABLE_PUSH`, and `MAX_FRAME_SIZE` branches are
entered again when their identifiers recur
([src/server/linnea_h2_client.asm:932](/home/linnea/linnea/src/server/linnea_h2_client.asm:932)
through [:980](/home/linnea/linnea/src/server/linnea_h2_client.asm:980)). A
duplicate `INITIAL_WINDOW_SIZE` is therefore applied as two deltas to the
stream-1 send window, and the caller then acknowledges the frame. The helper
is shared by the blocking settle, flow-control pump, and response loops, so
the omission applies in all three blocking states.

The resumable path has the same gap. `d_dispatch` checks the frame structure
and calls `d_apply_settings`, but the walk has no duplicate check before
dispatching each identifier ([src/server/linnea_h2_client.asm:2761](/home/linnea/linnea/src/server/linnea_h2_client.asm:2761)
through [:2788](/home/linnea/linnea/src/server/linnea_h2_client.asm:2788),
[src/server/linnea_h2_client.asm:2139](/home/linnea/linnea/src/server/linnea_h2_client.asm:2139)
through [:2184](/home/linnea/linnea/src/server/linnea_h2_client.asm:2184)).
It applies each repeated `INITIAL_WINDOW_SIZE` delta, stages a SETTINGS ACK,
and continues the exchange as though the frame were valid.

The absence of duplicate detection also means repeated unknown identifiers are
silently accepted. Unknown identifiers are individually required to be
ignored, but that does not remove the separate no-duplicates rule for the
SETTINGS frame. A complete fix should track the identifier before either
ignoring or applying its value.

### Reproduction

Send one non-ACK SETTINGS frame on stream 0 containing two records with the
same identifier, followed by a normal response:

```text
SETTINGS  stream 0,
          { INITIAL_WINDOW_SIZE = 1024,
            INITIAL_WINDOW_SIZE = 2048 }
HEADERS   stream 1, END_HEADERS, payload = a valid :status 200 block
DATA      stream 1, END_STREAM, payload = "body"
```

The blocking and resumable parsers both process the two records, acknowledge
the SETTINGS frame, and relay the response. The blocking helper first changes
its remembered peer window to 1024 and then to 2048; the driver performs the
same two sequential updates in its context. The malformed frame should instead
terminate the backend exchange before an ACK is sent.

The same result occurs for duplicate `ENABLE_PUSH` or `MAX_FRAME_SIZE` records,
and for an unknown identifier repeated with two values. The observable result
is acceptance rather than a response-body injection, but accepting malformed
connection configuration undermines the parser's otherwise strict SETTINGS
validation and leaves the two implementations non-compliant in the same way.

The existing backend fixture covers invalid values and record alignment but no
duplicate within one frame ([test/h2/h2c_server.py:610](/home/linnea/linnea/test/h2/h2c_server.py:610)
through [:638](/home/linnea/linnea/test/h2/h2c_server.py:638)). Its
`/set-mf-ok` control sends two legal SETTINGS **frames**, each with one
`MAX_FRAME_SIZE` record ([test/h2/h2c_server.py:633](/home/linnea/linnea/test/h2/h2c_server.py:633)
through [:635](/home/linnea/linnea/test/h2/h2c_server.py:635)); that does not
exercise the prohibited duplicate-in-one-frame case.

### Recommended fix

Before applying a non-ACK SETTINGS payload, scan its six-octet records and
reject any identifier that has already appeared in that frame. Track the full
16-bit identifier space so repeated unknown settings are rejected as required,
while still ignoring a single genuinely unknown identifier. Perform the scan
before mutating the remembered initial window or staging an ACK; then retain
the existing value validation and delta handling.

Apply the same rule to the blocking and resumable walkers, ideally through a
shared validation helper or equivalent per-frame bitmap. Add backend-fixture
cases for duplicate `INITIAL_WINDOW_SIZE`, duplicate `ENABLE_PUSH`, duplicate
`MAX_FRAME_SIZE`, and a repeated unknown identifier in one frame. Assert
failure and no SETTINGS ACK. Keep `/set-mf-ok` and a legal later SETTINGS frame
as controls proving that duplicates across separate frames remain accepted.

## Verification

This finding is a source-level trace through both SETTINGS walks, all three
blocking call sites, and the resumable dispatcher. `make -j4` completed with no
work required. Existing backend SETTINGS coverage has no duplicate-record case;
its two `MAX_FRAME_SIZE` records are in separate legal frames. No production
source, configuration, or test file was changed that required runtime
verification.

## Resolution (2026-08-25) — NOT CONFIRMED: HTTP/2 has no no-duplicates rule

### The rule the report cites belongs to the neighbouring protocols

RFC 9113 §6.5.2 defines value *ranges* for the defined settings, and a value
outside them is a connection error — which this parser already enforces
(audit-report-50). It contains no prohibition on repeating an identifier.
§6.5 says the opposite of what the finding needs: *"The values in the SETTINGS
frame MUST be processed in the order they appear, with no other frame
processing between values."* Order only matters if a later value can supersede
an earlier one.

The no-duplicates rule the report describes is real, but it is:

- **HTTP/3**, RFC 9114 §7.2.4.1 — "The same setting identifier MUST NOT occur
  more than once in the SETTINGS frame", and
- **QUIC transport parameters**, RFC 9000 §7.4.

This server enforces both. The h3 control-stream parser records every
identifier and catches every duplicate; that is `Finding 8` from an earlier
audit, and the code carries the seen-list to this day. Having those two nearby
is the most likely reason the rules got crossed.

### Three implementations, measured, not argued

A client that sends one SETTINGS frame containing `INITIAL_WINDOW_SIZE = 1024`
followed by `INITIAL_WINDOW_SIZE = 2048`, then a normal GET:

```
nginx 1.30.4     HEADERS + DATA   (200, no GOAWAY)
nghttp2 1.66.0   HEADERS + DATA   (200, no GOAWAY)
linnea's own h2 front  HEADERS + DATA   (200, no GOAWAY)
```

nghttp2 is the reference implementation h2spec is written against. Our own
frontend accepts it too, and its RFC-derived error matrix
(`test/tls/h2_error_codes.py`) has SETTINGS rows for stream id, length, ACK
payload, and all three out-of-range values — and no duplicate row, because
there is no such rule to test.

Implementing the finding would have made the backend leg refuse frames that
HTTP/2 permits and that two widely deployed servers send happily, and would
have put the backend client at odds with our own frontend.

### What we do is not merely "accepting" — it is in-order, and measured

The `dupwin` fixture mode puts `INITIAL_WINDOW_SIZE = 1024` then `= 8192` in
**one** frame and then grants nothing, so the bytes that arrive before the
first WINDOW_UPDATE are exactly the window the client believed in:

```
oracle  DUPWIN=8192      driver  DUPWIN=8192
```

8192 is in-order processing (the last value stands). 1024 would be first-wins,
9216 would be a summed delta. The delta arithmetic from audit-report-48 gets
this right: 65535 → 1024 → 8192 composes to exactly 8192.

### One thing the report is right about, already true

Its underlying worry — that a repeated identifier might skip validation — does
not hold, but it is worth pinning. `/set-dup-2ndbad` sends
`MAX_FRAME_SIZE = 16384` followed by `MAX_FRAME_SIZE = 1` in one frame and is
refused on both parsers: every record is validated, not just the first one seen
for an identifier.

### Coverage: 11 rows, and they are not vacuous

No production change. Eleven checks pin the behaviour so a later reading of
this report cannot quietly introduce the HTTP/3 rule into HTTP/2:
duplicates accepted (`/set-dup-ok`, `/set-dup-unknown`), a repeat with an
illegal value refused (`/set-dup-2ndbad`), and the in-order window measurement
(`dupwin`), each on both parsers, plus three end to end.

To prove they discriminate, the report's own recommendation was implemented as
a throwaway patch in the driver's settings walk and the rows re-run:

```
counterfactual: /set-dup-ok        H2C-FAIL   <- would break
counterfactual: /set-dup-unknown   H2C-FAIL   <- would break
counterfactual: dupwin             H2C-FAIL   <- would break
counterfactual: /set-mf-ok         200        <- still passes (two SEPARATE frames)
counterfactual: /set-ok            200        <- still passes
```

That patch was discarded; `src/` is unchanged by this report.

Full suite **933 passed, 0 failed**.

## Verification (resolution)

Measured against three independent HTTP/2 servers (nginx 1.30.4, nghttp2 1.66.0
via `nghttpd`, and linnea's own frontend) with a hand-built client that sends
the duplicate frame, rather than argued from the source. The in-order result was
measured through a fixture that withholds credit, on both backend parsers. The
new rows were shown to fail under the report's prescribed rule before that
implementation was discarded.
