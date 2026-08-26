# Audit Report 65

Audited at `dd4becc` (`backend h2: advertise the receive window we can actually
honour`), 2026-08-26.

Audit report 64's advertised response-window mismatch is fixed: the stream
window is now tied to the retained body cap and guarded at assembly time. The
next backend-H2 response-field gap is pseudo-header name validation:

1. **Low: the backend HTTP/2 client accepts an uppercase `:status` name by
   matching it case-insensitively.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — uppercase response pseudo-header names are accepted

Severity: **Low (P3, a malformed upstream response is silently normalized)**  
Confidence: **High**  
Status: **Confirmed as filed and reproduced.** Fixed. It is an ordering
defect in audit-report-60's own gate: the `:status` match ran before the
validity check, and matched case-insensitively.

HTTP/2 field names are case-sensitive on receipt for validity purposes: the
minimal validation in RFC 9113 §8.2.1 prohibits every uppercase ASCII letter
in a field name. A response field block may contain only the response
pseudo-header `:status`, and pseudo-header names are required to follow the
same field-name validity rules. `:Status`, `:STATUS`, and mixed-case spellings
are therefore malformed response fields, not alternate spellings of
`:status`.

The shared backend response emitter recognizes `:status` using
`h2c_ci_eq`, whose contract and implementation explicitly fold both operands
to lower case before comparing ([src/server/linnea_h2_client.asm:520](/home/linnea/linnea/src/server/linnea_h2_client.asm:520)
through [:542](/home/linnea/linnea/src/server/linnea_h2_client.asm:542)). In
`h2c_emit`, that comparison happens before the ordinary-field validation:

1. the decoded name is compared case-insensitively with the literal
   `:status` ([src/server/linnea_h2_client.asm:1990](/home/linnea/linnea/src/server/linnea_h2_client.asm:1990)
   through [:1996](/home/linnea/linnea/src/server/linnea_h2_client.asm:1996));
2. a matching name jumps directly to `.status`; and
3. `h2c_field_ok`, which rejects uppercase field-name bytes, is called only on
   the ordinary-field branch ([src/server/linnea_h2_client.asm:1997](/home/linnea/linnea/src/server/linnea_h2_client.asm:1997)
   through [:2010](/home/linnea/linnea/src/server/linnea_h2_client.asm:2010)).

The `.status` arm then checks duplicate/order state and validates the value's
three ASCII digits ([src/server/linnea_h2_client.asm:2063](/home/linnea/linnea/src/server/linnea_h2_client.asm:2063)
through [:2107](/home/linnea/linnea/src/server/linnea_h2_client.asm:2107)),
but never checks the original name's case. Thus a literal HPACK field named
`:Status` with value `200` follows the same path as the legal `:status` field,
sets the response status to 200, and is later emitted as a normalized HTTP/1
status line.

This is not limited to a missing test in one parser. The blocking response
decoder calls the shared `h2c_emit` from `h2c_decode`
([src/server/linnea_h2_client.asm:1791](/home/linnea/linnea/src/server/linnea_h2_client.asm:1791)
through [:1846](/home/linnea/linnea/src/server/linnea_h2_client.asm:1846)),
and the resumable driver reuses the same emitter through `d_decode_block`
([src/server/linnea_h2_client.asm:2768](/home/linnea/linnea/src/server/linnea_h2_client.asm:2768)
through [:2817](/home/linnea/linnea/src/server/linnea_h2_client.asm:2817)).
Both backend-H2 implementations therefore accept the malformed spelling.

### Reproduction

Have the backend send a response HEADERS block containing the literal HPACK
fields equivalent to:

```text
:Status: 200
content-type: text/plain
content-length: 9
```

followed by a nine-byte DATA frame and END_STREAM. The current trace is:

1. HPACK decoding returns the name bytes `:Status` and value bytes `200`.
2. `h2c_emit` calls the case-insensitive `h2c_ci_eq` comparison, which returns
   equal for `:Status` and `:status`.
3. The ordinary `h2c_field_ok` call is skipped; `.status` accepts the three
   digits and stores status 200.
4. Response completion succeeds and the composer writes `HTTP/1.1 200`, so the
   original malformed name has disappeared rather than causing a failure.

The same result holds for `:STATUS` and mixed-case variants. A conforming
backend response with the exact lowercase `:status` remains the control and
must continue to relay normally.

### Existing coverage

The response pseudo-header matrix covers duplicate `:status`, pseudo-header
placement, undefined pseudo-headers, and a legal single literal `:status`
([test/shards/tls/70-backend-tls-client.sh:880](/home/linnea/linnea/test/shards/tls/70-backend-tls-client.sh:880)
through [:898](/home/linnea/linnea/test/shards/tls/70-backend-tls-client.sh:898)).
Those cases all use the correctly lowercased name. The separate field-validity
matrix does test an uppercase ordinary name such as `Content-Type`
([test/shards/tls/70-backend-tls-client.sh:907](/home/linnea/linnea/test/shards/tls/70-backend-tls-client.sh:907)
through [:947](/home/linnea/linnea/test/shards/tls/70-backend-tls-client.sh:947)),
but that check reaches `h2c_field_ok` and does not exercise the pseudo-header
fast path. No existing response test sends `:Status` or another mixed-case
spelling of `:status`.

### Impact

The backend controls the malformed bytes, so this is an upstream response
validation failure rather than direct client input injection. The accepted
field does not currently choose a different status value—the value validator
still runs—and the downstream composer normalizes it. Nevertheless, RFC 9113
requires an intermediary not to accept a malformed response, and a tolerant
endpoint can disagree with stricter HTTP/2 peers or validators about whether a
response field block is valid. The normalization also erases evidence that the
backend violated the protocol.

### Recommended fix

Validate the complete pseudo-header name before semantic classification. The
smallest safe change is to compare `:status` byte-for-byte, not with
`h2c_ci_eq`, while retaining case-insensitive comparison only for HTTP field
names whose specifications explicitly require it. Preferably, route every
decoded field name through one validity gate that rejects uppercase bytes and
then apply the response pseudo-header rules.

Add blocking and resumable cases for `:status`, `:Status`, `:STATUS`, and a
mixed-case spelling, plus the existing legal lowercase control. Assert that
the malformed rows fail before response composition and that the legal row
still produces the same status.

## Verification

The finding is a source-level trace through the shared response emitter. Its
case-insensitive pseudo-header comparison runs before the ordinary field-name
validator, so uppercase `:status` variants are accepted and normalized in both
backend-H2 paths. Existing tests cover uppercase ordinary fields but not this
pseudo-header branch. `make -j4` completed with no work required. A local socket
reproduction was unavailable under the restricted audit environment, so no
runtime result is claimed. No production source, configuration, or test file
was changed in this audit.

References:

- [RFC 9113 §8.2.1 — Field Validity](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.1)
- [RFC 9113 §8.3.2 — Response Pseudo-Header Fields](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.2)

## Resolution (2026-08-26) — CONFIRMED as filed

### Reproduced

Both parsers, at the audited commit, a response whose only pseudo-header is
spelled with capitals:

```
:Status: 200   -> HTTP/1.1 200 OK
:STATUS: 200   -> HTTP/1.1 200 OK
:StAtUs: 200   -> HTTP/1.1 200 OK
:status: 200   -> HTTP/1.1 200 OK   <- control
```

nghttp2 1.66.0 as a client refuses the first: *"Invalid HTTP header field was
received: ... name: [:Status], value: [200]"*.

### It is an ordering defect in a fix of mine

The validity gate added in audit-report-60 refuses every uppercase byte in a
field name — but it lives on the ordinary-field branch, and the `:status`
comparison runs **before** the dispatch reaches it. So the one field that
skipped the gate was the one matched first, and it was matched with
`h2c_ci_eq`, which folds both sides to lower case. Case-insensitivity there is
not a convenience; it is the bug.

### The fix

A byte-for-byte `h2c_eq` beside the case-insensitive one, used for the
pseudo-header. That alone is complete, and the reason is worth stating: for a
response, `:status` is the only pseudo-header there is, so anything that is not
exactly it falls to the undefined-pseudo-header rule from audit-report-59 and is
already malformed. No new rule was needed — only a comparison that tells the
truth.

The case-insensitive comparisons that remain are for ordinary field names, and
they are reached only after `h2c_field_ok` has refused every uppercase byte. By
then both sides are lowercase and the fold is a no-op; the header comment says
so, so the next reader does not have to re-derive it.

### One thing found beside it

`cmp byte [r12], ':'` read the name's first byte before anything had checked
that the name has one. An empty name owns no bytes, and the request side
carries a note about exactly this — *"left the pseudo-header test reading a
byte the field does not own"*. The length test now comes first. It was reading
inside the decoder's own buffer, so nothing was ever at risk; it is fixed
because it is the same mistake, not because it had a consequence.

### Coverage

Seven rows: three spellings on each parser plus one end to end. Against a
binary built from the audited source, **all 7 fail** — an unusually clean
split because the legal control (`/ps-one`) and the whole surrounding
pseudo-header matrix were already in the suite from audit-report-59, and they
stay green.

Full suite **1127 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the blocking oracle and the resumable driver, and end to end through
a real `proxy_h2` front. The spelling was put to nghttp2 as a client. The
static-table `:status` path (`/hello`, an indexed field) and the literal
lowercase path (`/st-299`) are both asserted, because an exact comparison would
break them if the static table's name were not already lowercase.
