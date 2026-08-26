# Audit Report 57

Audited at `0248c2a`, 2026-08-26.

Audit report 56's server-preface gate is present in both backend-H2 parsers. The
next response-section validation gap is the grammar of the `:status` value:

1. **Low: the backend HTTP/2 client accepts a `:status` value with trailing or
   non-digit bytes and normalizes it into a valid status code.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — malformed `:status` values are truncated to three digits

Severity: **Low (P3, malformed upstream response accepted and rewritten)**  
Confidence: **High**  
Status: **Confirmed as filed and reproduced.** Fixed in the one shared
`:status` arm. Three of its six malformed cases were already refused — by the
range check, not the grammar — and are kept as controls.

RFC 9113 §8.3.2 defines the response `:status` pseudo-header as carrying the
HTTP status code, and RFC 9110 §15.1 requires a status code to be exactly three
digits. A backend value such as `200x`, `2000`, or `200 ` is therefore not a
valid HTTP/2 response status.

The shared backend decoder recognizes `:status` by calling the case-insensitive
`h2c_ci_eq` helper at
[src/server/linnea_h2_client.asm:1712](/home/linnea/linnea/src/server/linnea_h2_client.asm:1712)
through [:1718](/home/linnea/linnea/src/server/linnea_h2_client.asm:1718).
Its parser then stops successfully as soon as it has consumed three digits, or
as soon as it sees a non-digit. It does not require the value length to be
three and does not reject an unconsumed suffix
([src/server/linnea_h2_client.asm:1737](/home/linnea/linnea/src/server/linnea_h2_client.asm:1737)
through [:1759](/home/linnea/linnea/src/server/linnea_h2_client.asm:1759)).
The resulting integer is all that survives; the original value and the final
cursor are not retained for validation.

The later classifier checks only the integer range `200..599`
([src/server/linnea_h2_client.asm:2320](/home/linnea/linnea/src/server/linnea_h2_client.asm:2320)
through [:2329](/home/linnea/linnea/src/server/linnea_h2_client.asm:2329)).
Consequently, `200x` becomes numeric status 200 and passes as a final response.
The blocking oracle reaches this classifier from both completed HEADERS and
CONTINUATION blocks
([src/server/linnea_h2_client.asm:1422](/home/linnea/linnea/src/server/linnea_h2_client.asm:1422)
through [:1438](/home/linnea/linnea/src/server/linnea_h2_client.asm:1438),
and [:1448](/home/linnea/linnea/src/server/linnea_h2_client.asm:1448)
through [:1464](/home/linnea/linnea/src/server/linnea_h2_client.asm:1464)).
The resumable driver uses the same `h2c_classify_block` call from
`d_decode_block`
([src/server/linnea_h2_client.asm:2363](/home/linnea/linnea/src/server/linnea_h2_client.asm:2363)
through [:2384](/home/linnea/linnea/src/server/linnea_h2_client.asm:2384)).

After accepting the malformed value, the response composer emits only the
numeric status as a normal three-digit HTTP/1 status line. The resumable proxy
then reparses that synthesized head through `h2p_resp_begin`
([src/server/linnea_http2.asm:4026](/home/linnea/linnea/src/server/linnea_http2.asm:4026)
through [:4046](/home/linnea/linnea/src/server/linnea_http2.asm:4046)), so
the downstream validation sees `HTTP/1.1 200 OK`, not the original malformed
`:status` value. The malformed backend response is therefore converted into a
valid response rather than rejected as a gateway error.

### Reproduction

Have the backend send a legal preface and this response on stream 1:

```text
HEADERS  END_HEADERS, payload = :status "200x", content-type "text/plain"
DATA     END_STREAM, payload = "body"
```

The current decoder consumes the first three bytes of the value, stores 200,
and ignores the `x`. Both the blocking entry point and the resumable driver
complete the exchange as a successful 200 response. Through `proxy_h2`, the
existing H1 response bridge receives a synthesized `HTTP/1.1 200 OK` and the
client sees the body.

The same acceptance applies to `2000` and `200 `; a control with exactly
`200` should remain successful. A malformed value such as `20x` happens to be
rejected later because the truncated integer is below 200, but that does not
make the parser correct: the acceptance boundary depends on the first three
bytes rather than the complete field value.

The fixture's `enc_header` helper can already encode an arbitrary literal name
and value ([test/h2/h2c_server.py:199](/home/linnea/linnea/test/h2/h2c_server.py:199)
through [:204](/home/linnea/linnea/test/h2/h2c_server.py:204)), but every current
response route uses the valid `enc_status` helper or a valid static-table
`:status`. The backend response matrix therefore has no malformed-status
control.

### Impact

This is not an attacker-controlled downstream status injection: the malformed
suffix is discarded and the resulting status is still in the valid range. It
is nevertheless a protocol-boundary failure. A faulty or compromised HTTP/2
backend can send a response that is invalid on the wire and have Linnea claim
that it answered with a clean 200. The original and translated messages no
longer have the same status semantics, and callers of the backend driver that
do not pass through the synthesized-head validator would observe the same
accepted numeric result directly.

### Recommended fix

In `h2c_emit`, validate the complete `:status` value before converting it:

- require `r15 == 3`;
- require all three bytes to be ASCII digits; and
- only then compute and store the integer status.

Do not stop parsing at the first invalid byte and do not silently normalize a
malformed value. Keep the existing `200..599` semantic range check, since a
three-digit value can still be outside the HTTP status-code range. Apply the
same helper to the shared blocking and resumable decoder path.

Add backend-fixture cases for `200x`, `2000`, `200 `, and a valid `200` control.
Assert that each malformed case fails before a downstream response head is
emitted on both the blocking oracle and the resumable driver, and through a
real `proxy_h2` front. Keep an in-range, unregistered three-digit status as a
separate control so the fix checks the grammar and range independently.

## Verification

The finding is a source-level trace through the shared HPACK emission path, the
blocking and resumable response classifiers, and the synthesized-head parser.
`make -j4` completed with no work required. Existing backend-H2 response tests
cover missing status, informational ordering, trailers, and status range, but
not a `:status` value containing more or fewer than exactly three digits. No
production source, configuration, or test file was changed that required
runtime verification.

References:

- [RFC 9113 §8.3.2 — Response Pseudo-Header Fields](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.2)
- [RFC 9110 §15.1 — Status Codes](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.1)

## Resolution (2026-08-26) — CONFIRMED as filed

### Reproduced

Both parsers, against a fixture that sends each `:status` value as a literal
field:

```
:status      oracle      driver
"200"        200 OK      200 OK     <- control
"299"        299         299        <- control: in range, unregistered
"200x"       200 OK      200 OK     <- the suffix discarded
"2000"       200 OK      200 OK     <- FOUR digits truncated into a legal one
"200 "       200 OK      200 OK
"2x0"        H2C-FAIL    H2C-FAIL   <- refused, but see below
"20"         H2C-FAIL    H2C-FAIL
""           H2C-FAIL    H2C-FAIL
```

`2000` is the sharpest of these: a four-digit status is truncated into a valid
one and relayed as a clean response. The report's own caveat is right and the
pre-fix control confirms it — the last three were already refused, but only
incidentally, because they parse to a number below 200 and die on the *range*
check. Right outcome, wrong reason; they are controls, not evidence.

### The same shape as report 56: a rule enforced in one direction

The h1 leg has checked this for a long time, in `linnea_http_check_response_head`
— exactly three digits, delimited, range 100..599, with a comment noting that
`"HTTP/1.1 2000"` is not a status line and that an unregistered 299 must still
be forwarded. The h2 leg never asked. That is the second report running whose
root is a rule this server enforces on one peer and not the mirror-image one.

### The reference client agrees, row for row

nghttp2 1.66.0 as a client, against a server sending each value:

```
"200x" "2000" "200 " "20" "":
  [ERROR] Invalid HTTP header field was received: ... name: [:status], value: [...]
  send RST_STREAM
"200", "299":  recv :status: ... (served)
```

One difference worth naming: nghttp2 makes it a *stream* error (RST_STREAM);
we fail the exchange, which on a single-stream backend leg reaches the client
as a 502. Same verdict on the field, same effect on the one stream in flight.

### The fix

`h2c_emit`'s `:status` arm now requires the value to be exactly three bytes and
all three to be digits, before any conversion. Malformed returns CF=1, the same
failure the append path already used. The range check stays where it is, in the
classifier: three digits is necessary, not sufficient. One site — the arm is
shared by the blocking oracle and the resumable driver, and by HEADERS and
CONTINUATION blocks alike.

### Coverage

Nineteen rows: six malformed values and two legal controls on each parser, plus
three end to end. Against a binary built from the audited source, **8 fail and
11 pass as controls**.

```
pre-fix: status (oracle|driver): /st-x /st-4 /st-sp        FAIL x6
pre-fix: status: "200x" and a four-digit :status e2e       FAIL x2
pre-fix: status (oracle|driver): /st-2x0 /st-short /st-empty  PASS <- incidental
pre-fix: status (oracle|driver): 200 and 299 still relay      PASS <- controls
pre-fix: status: an unregistered 299 relayed e2e              PASS <- control
```

### A probe correction, and one to report 56

`test/h2/probe_h2.py` is new: a minimal HTTP/2 server that answers the first
HEADERS frame **without decoding it**. It exists because our fixture decodes the
request block to dispatch on path and cannot read nghttp2's huffman-coded
literals — so nghttp2 gets no response from that fixture on any route, and any
conclusion drawn from its silence is worthless.

That is exactly the mistake in report 56's resolution, which claimed nghttp2
"served normally" on the empty-preface fixture. It could not have. That row has
been re-measured with the probe server and the conclusion held — and `prefwin`,
which was never run at all, was measured too. Report 56's file carries the
correction.

Full suite **964 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the blocking oracle and the resumable driver, and end to end through
a real `proxy_h2` front. The rule was put to nghttp2 1.66.0 as a client on every
row, through a probe server written for the purpose after the existing fixture
was found unable to serve it. The pre-fix control separates the three rows this
fix is responsible for from the three that were already refused for an
unrelated reason.
