# Audit Report 58

Audited at `0939002`, 2026-08-26.

Audit report 57's exact-three-digit `:status` check is present in the shared
backend decoder. The next response-integrity gap is the HTTP/2
`content-length` assertion:

1. **Low: the backend HTTP/2 client discards `content-length` without checking
   it against the response DATA bytes, then synthesizes a new value.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — mismatched backend `content-length` is silently repaired

Severity: **Low (P3, malformed upstream response accepted and normalized)**  
Confidence: **High**  
Status: **Confirmed as filed and reproduced.** Fixed in both parsers, against
the h1 leg's existing no-content predicate rather than a fourth copy of it. The
HEAD and 304 exceptions are asserted as controls.

RFC 9113 §8.1.1 makes a request or response malformed when its
`content-length` value does not equal the sum of the DATA payload bytes that
form the content, except for statuses and request methods defined to have no
content. Intermediaries that detect such a response must not forward it.

The backend response emitter treats `content-length` as a field to skip, but
never parses or stores its value. The fixed-name table includes it in
`h2c_is_skip`
([src/server/linnea_h2_client.asm:508](/home/linnea/linnea/src/server/linnea_h2_client.asm:508)
through [:542](/home/linnea/linnea/src/server/linnea_h2_client.asm:542)).
When `h2c_emit` decodes an ordinary response field, a matching name returns
from that helper and the field is discarded before
`h2c_hdrline_append` can copy it
([src/server/linnea_h2_client.asm:1723](/home/linnea/linnea/src/server/linnea_h2_client.asm:1723)
through [:1728](/home/linnea/linnea/src/server/linnea_h2_client.asm:1728)).
There is no expected-length variable in either response context.

The blocking decoder counts only the bytes it appends from DATA frames. Its
body helper checks capacity and increments `h2c_body_len`, but has no relation
to a backend-declared length
([src/server/linnea_h2_client.asm:1294](/home/linnea/linnea/src/server/linnea_h2_client.asm:1294)
through [:1312](/home/linnea/linnea/src/server/linnea_h2_client.asm:1312)).
The resumable driver has the same independent counter in `d_body_append`
([src/server/linnea_h2_client.asm:3069](/home/linnea/linnea/src/server/linnea_h2_client.asm:3069)
through [:3089](/home/linnea/linnea/src/server/linnea_h2_client.asm:3089)).
Neither counter is compared with a value received in the response HEADERS
block when END_STREAM completes the exchange.

The missing check is masked by the response bridge. Both composers always
write a fresh `content-length` equal to the number of DATA bytes actually
buffered
([src/server/linnea_h2_client.asm:1853](/home/linnea/linnea/src/server/linnea_h2_client.asm:1853)
through [:1869](/home/linnea/linnea/src/server/linnea_h2_client.asm:1869),
and [:3119](/home/linnea/linnea/src/server/linnea_h2_client.asm:3119)
through [:3134](/home/linnea/linnea/src/server/linnea_h2_client.asm:3134)).
The resumable proxy then parses that synthesized head through
`h2p_resp_begin`
([src/server/linnea_http2.asm:4026](/home/linnea/linnea/src/server/linnea_http2.asm:4026)
through [:4046](/home/linnea/linnea/src/server/linnea_http2.asm:4046)). A
downstream client therefore sees a self-consistent response, but not the
response the backend sent: the invalid declaration has been erased and
replaced with Linnea's measurement.

### Reproduction

Have the backend send a legal connection preface, then this stream-1 response:

```text
HEADERS  END_HEADERS,
         :status 200,
         content-length: 1,
         content-type: text/plain
DATA     END_STREAM, payload = "body"
```

The DATA content is four bytes, so the response is malformed. The current
blocking and resumable paths discard `content-length: 1`, append all four DATA
bytes, and complete as a 200 response. Their synthesized H1 bridge reports:

```text
HTTP/1.1 200 OK
content-type: text/plain
content-length: 4

body
```

The correct handling is to fail the backend exchange before exposing a final
response. A zero-length declaration with a nonempty DATA frame is an even
simpler variant. A declaration equal to the DATA length must remain a legal
control.

The existing fixture deliberately sends a matching value derived from the body
length at
[test/h2/h2c_server.py:490](/home/linnea/linnea/test/h2/h2c_server.py:490)
through [:495](/home/linnea/linnea/test/h2/h2c_server.py:495), so its normal
responses cannot expose this. The trailer fixture's `content-length` case is
not a control for the initial response: trailer fields are handled after the
initial response section and the client already drops them.

### Impact

This does not create a downstream framing mismatch in the current bridge; the
new length agrees with the bytes Linnea forwards. It does, however, make a
malformed backend response indistinguishable from a valid one and changes an
upstream framing assertion without recording that a protocol error occurred.
Any caller that relies on the backend driver to validate the response rather
than only on the synthesized H1 output receives the same normalized result.
It also makes backend-H2 behavior differ from a strict HTTP/2 peer, which would
reset the response stream for the malformed message.

### Recommended fix

Retain the `content-length` declaration from the initial final response HEADERS
block instead of dropping it without interpretation. Parse its value as a
nonnegative decimal field value, reject malformed or conflicting declarations,
and compare it with the accumulated content length when the response ends.

Keep the protocol exceptions explicit: a status-defined no-content response
such as 204 or 304 has no DATA content, while its permitted `content-length`
metadata is not necessarily the number of bytes received; similarly account
for a request method such as HEAD if the backend leg can issue one. For an
ordinary response carrying DATA, a mismatch must fail both the blocking and
resumable backend exchanges before the synthesized response is composed.

Add fixture cases for `content-length: 1` with a four-byte body,
`content-length: 0` with a nonempty body, a matching value, and a malformed
non-decimal value. Include a no-content status control so the fix does not
mistakenly reject the RFC-permitted metadata on 204/304 responses. Assert
failure in the blocking oracle, the resumable driver, and end to end through a
`proxy_h2` front.

## Verification

The finding is a source-level trace through the shared HPACK emitter, both DATA
accumulators, and both response composers. `make -j4` completed with no work
required. Existing backend-H2 routes use only matching `content-length` values;
there is no negative response-length case. No production source, configuration,
or test file was changed that required runtime verification.

Reference: [RFC 9113 §8.1.1 — Malformed Messages](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1.1)

## Resolution (2026-08-26) — CONFIRMED as filed

### Reproduced

Both parsers, against a fixture that declares one length and sends another:

```
route        declared   sent    pre-fix result
/cl-ok       4          4       200, content-length: 4    <- control
/cl-short    1          4       200, content-length: 4
/cl-zero     0          4       200, content-length: 4
/cl-bad      "abc"      4       200, content-length: 4
/cl-neg      "-4"       4       200, content-length: 4
```

Exactly as filed: the declaration is discarded, our measurement is written in
its place, and the malformed response is repaired into a valid one. `"abc"` and
`"-4"` were never even parsed — the field was dropped by name.

### Third report running with the same root

The h1 leg validates this. The h2 leg never asked. That is reports 56, 57 and
58 in a row whose root is a rule enforced on one peer and not its mirror image,
and this one differs only in that the h1 leg's rule is more than a check — it
is a *predicate*, `linnea_http_status_no_content`, whose own comment records
that three copies of that list once disagreed on 205 (audit-report-10).

So the fix calls it rather than copying it. That needed the function to move:
`linnea_h2_client.asm` links into the standalone `bin/linnea-h2client`, which
must not drag in the server, so the predicate now lives in
`src/lib/linnea_http_status.asm` and both legs call the one definition. A fourth
copy of that list is exactly what this codebase has already paid for once.

### The exceptions are the whole difficulty

Two kinds of response legitimately declare a length they do not send, and both
are byte-for-byte indistinguishable from the defect:

- **HEAD** — the length a GET would have returned, with no body at all.
- **1xx, 204, 205, 304** — no content, whatever the head says.

`/cl-head` is the control that proves the HEAD exception is implemented rather
than the check quietly skipped. It sends the *same bytes* both times — 200,
`content-length: 4`, no DATA — and the verdict is decided by the request:

```
/cl-head asked with GET   -> H2C-FAIL       (malformed)
/cl-head asked with HEAD  -> HTTP/1.1 200   (correct)
```

The leg now remembers which method it sent, noted where the request head is
built, so both paths get it from one place.

### Coverage

Twenty-one rows: four malformed values, four exception/legality controls and
the HEAD pair on each parser, plus three end to end (including a `curl -I`
through a real `proxy_h2` front). Against a binary built from the audited
source, **11 fail and 10 pass as controls**.

### Two probe faults of mine, both caught by the control

- The first pre-fix run had the HEAD row failing, which made no sense on a
  build that accepted everything. The harness reads a request body from stdin
  for any method that is not GET, so the HEAD probe inherited the shard's stdin.
  `</dev/null`, and the comment says why. Had I not run the control, this would
  have shipped as a check that passes for the wrong reason.
- The pre-fix build needed the new lib file removed, or the symbol is defined
  twice; restoring it afterwards is a step `git stash` does not do for an
  untracked file, and the rebuild is the only thing that says so.

### What the reference client does

nghttp2 1.66.0 as a client, against a server declaring a length it does not
send: `RST_STREAM` for a mismatch, and `Invalid HTTP header field ... name:
[content-length], value: [abc]` for a non-numeric one. It serves the matching
case. Same verdicts, on every row.

Full suite **985 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the blocking oracle and the resumable driver, and end to end through
a real `proxy_h2` front. The rule was put to nghttp2 as a client on each row
through `probe_h2.py`. The HEAD exception is asserted as a *pair* over identical
response bytes, so a fix that skipped the check entirely would fail the GET half
and one that ignored the method would fail the HEAD half.
