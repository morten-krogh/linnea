# Audit Report 74

Audited at `d0ad181` (`backend h2: reserve both window updates before staging
either`), 2026-08-26.

Audit report 73's all-or-nothing response-credit flush is present. The next
backend-H2 validation gap is in response trailers:

1. **Low: the backend HTTP/2 client accepts a prohibited `content-length`
   trailer and completes the response.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — `content-length` in a response trailer is decoded, discarded, and accepted

Severity: **Low (P3, a malformed backend response is relayed as a clean
response; the forbidden trailer is not exposed downstream)**  
Confidence: **High**  
Status: **Confirmed in both parsers, and fixed.** Its RFC 9110 6.5.1 citation is
sender-side, so the fix rests instead on nghttp2 refusing the same field and on
this leg already refusing `transfer-encoding`.

(Original status note.) The existing `/trailers-cl` fixture
returns a clean `200` with its ordinary 20-byte body through both the blocking
oracle and the resumable driver.

HTTP semantics prohibit a sender from generating a trailer field unless that
field's definition permits trailers. `content-length` describes message
framing, which is specifically a class that cannot be evaluated after the
content has arrived ([RFC 9110 §6.5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5.1)).
In HTTP/2, a response containing prohibited fields is malformed, an
intermediary must not forward it, and a client must not accept it
([RFC 9113 §8.1.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1.1)).

Both backend-H2 readers classify a completed block after the final response
head as a trailer. `h2c_classify_block` deliberately snapshots the initial
head's status and content-length, clears the content-length state, and decodes
the new block ([src/server/linnea_h2_client.asm:2775](/home/linnea/linnea/src/server/linnea_h2_client.asm:2775)
through [src/server/linnea_h2_client.asm:2800](/home/linnea/linnea/src/server/linnea_h2_client.asm:2800)).
That is the right isolation mechanism for a valid ignored trailer.

However, the ordinary `content-length` emitter accepts and parses the field
into that temporary state ([src/server/linnea_h2_client.asm:2113](/home/linnea/linnea/src/server/linnea_h2_client.asm:2113)
through [src/server/linnea_h2_client.asm:2225](/home/linnea/linnea/src/server/linnea_h2_client.asm:2225)).
The trailer path then restores the original response state and checks only two
things: no pseudo-header and `END_STREAM`
([src/server/linnea_h2_client.asm:2843](/home/linnea/linnea/src/server/linnea_h2_client.asm:2843)
through [src/server/linnea_h2_client.asm:2869](/home/linnea/linnea/src/server/linnea_h2_client.asm:2869)).
It never rejects the temporary `h2c_cl_seen` set by that decoded trailer.

The shared classifier makes this one gap affect both paths:

- the blocking response loop invokes it after a completed HEADERS or
  CONTINUATION block ([src/server/linnea_h2_client.asm:1757](/home/linnea/linnea/src/server/linnea_h2_client.asm:1757)
  through [src/server/linnea_h2_client.asm:1769](/home/linnea/linnea/src/server/linnea_h2_client.asm:1769));
- the resumable driver invokes the same helper through `d_decode_block`
  ([src/server/linnea_h2_client.asm:2879](/home/linnea/linnea/src/server/linnea_h2_client.asm:2879)
  through [src/server/linnea_h2_client.asm:2915](/home/linnea/linnea/src/server/linnea_h2_client.asm:2915)).

The `content-length` is not relayed: restoring the initial state means the
composer retains the original correct length. That limits the present impact,
but discarding a prohibited field is not the same as refusing the malformed
response. It also leaves the trailer policy asymmetric: `transfer-encoding` is
rejected by the response's connection-specific-field check, while the other
message-framing field is specially parsed and silently forgiven.

### Reproduction

The checked-in fixture already has the precise case:

```text
HEADERS  stream=1, :status=200, content-length=20
DATA     stream=1, "hello with trailers\\n"  (without END_STREAM)
HEADERS  stream=1, content-length=5, END_HEADERS|END_STREAM
```

Running `/trailers-cl` against a binary built at the audited revision produced
the same successful response on both parsers:

```text
                result
blocking        HTTP/1.1 200 OK, content-length: 20, 20-byte body
resumable       HTTP/1.1 200 OK, content-length: 20, 20-byte body
```

The forbidden trailer value is absent from the synthesized HTTP/1 response,
which demonstrates the exact bug: it was decoded and ignored rather than
causing the exchange to fail. `/trailers` and `/trailers-frag`, whose trailer
fields are ordinary metadata, remain the controls that must continue to
succeed.

### Impact

This is an upstream protocol-validation defect. It neither changes the body
length that Linnea relays nor injects a downstream header, because the trailer
state is restored before composition. A backend that sends a malformed
framing-related trailer nevertheless receives a successful response exchange
instead of a rejected stream. That weakens the strict response boundary the
same client applies to a `content-length` in the initial response head, where
it correctly treats the field as an assertion about DATA bytes.

### Recommended fix

After decoding a trailer block and before restoring the initial response state,
reject it when the temporary block contains `content-length`. Keep decoding the
block first so HPACK dynamic-table state remains synchronized, then fail the
exchange rather than simply dropping the prohibited field.

More generally, make the trailer classifier own a small trailer-field policy:
it should reject every framing, routing, or control field whose definition does
not permit trailers, while retaining the current no-pseudo-header rule and the
intentional discard of valid trailer metadata.

Add direct oracle and driver rows for `/trailers-cl` that require
`H2C-FAIL`; add an end-to-end `proxy_h2` row requiring `502`. Preserve the
existing valid ordinary and fragmented trailer controls, and a final-header
`content-length` control, so the test distinguishes a forbidden trailer from
the valid framing assertion in the response head.

## Verification

`make -j4 bin/linnea-h2client` was current. A loopback run of the existing
`/trailers-cl` fixture returned a clean 200 response on both the blocking
oracle and the resumable driver, even though the final trailer carried
`content-length: 5`. The ordinary and fragmented valid-trailer controls both
returned their expected 20-byte body on both parsers. The source trace shows
why the bad case passes: the shared classifier decodes the field, restores the
first block's length, and has no trailer-specific content-length rejection. No
production source, configuration, or test file was changed in this audit.

References:

- [RFC 9110 §6.5.1 — Limitations on Use of Trailers](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5.1)
- [RFC 9113 §8.1.1 — Malformed Messages](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1.1)

## Resolution (2026-08-26) — CONFIRMED, with the RFC argument put on firmer ground

### Reproduced

The checked-in `/trailers-cl` fixture, on the audited binary, both parsers:

```
HTTP/1.1 200 OK, content-length: 20, 20-byte body
```

Exactly as the report says: the prohibited trailer is decoded, discarded, and
the exchange completes cleanly.

### The citation needed checking, and the reference settled it

RFC 9110 §6.5.1 is written at the **sender**: "a sender MUST NOT generate a
trailer field unless...", with message framing named as a disallowed class.
That alone does not tell a receiver to fail — three earlier reports in this
series (55, 64, 66) turned on exactly that distinction, and two of them were
rejected for it.

nghttp2 1.66.0 as a client decides it:

```
trailcl  [ERROR] Invalid HTTP header field was received: ... name: [content-length]
normal   recv :status: 200
```

The reference refuses it. And our own leg already refuses `transfer-encoding` —
the *other* framing field — anywhere in a response, through the
connection-specific rule. Forgiving one framing field while refusing the other
is the asymmetry the report names, and that is the argument this fix rests on
rather than the sender-side MUST NOT.

### The fix, and how narrow it is

The trailer arm checks `h2c_cl_seen` **before** `.restore` puts the response
head's values back, so it sees this block's own field. The block is still
decoded first: HPACK state is per connection, and skipping a block
desynchronises every later one (audit-report-53).

Deliberately narrow. §6.5.1 disallows several classes in trailers — routing,
response control data, payload processing — and the report suggests a general
policy. I implemented only the framing field, because that is what the
reference enforces and what this leg already has an opinion about; extending it
to `date`, `cache-control` or `etag` would refuse trailers that real backends
send. The comment in the source says so, so the choice is visible rather than
an oversight.

### Coverage

Seven rows: the refusal, an ordinary-trailer control and a head-`content-length`
control on each parser, plus one end to end. Against a binary built from the
audited source, **3 fail and 4 pass as controls**.

The two controls are the ones that matter: `/trailers` keeps this from becoming
a rule against trailers, and `/cl-ok` keeps it from becoming a rule against
`content-length` — in the response *head* it is exactly the framing assertion
audit-report-58 added.

**My first placement of these rows failed all six on the broken build**,
controls included. The block went in ahead of `st_probe`'s definition — line
1111 using a helper defined at line 697 — so every row ran a missing command.
A control that fails when it should pass is the same signal as one that passes
when it should fail: the rows were not testing what they named.

Full suite **1174 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the blocking oracle and the resumable driver, and end to end through
a real `proxy_h2` front. The rule was put to nghttp2 as a client before the fix
was written. The existing trailer suite — ordinary, fragmented, pseudo-header,
missing-END_STREAM, and the h1/h2/h3 relay rows — is unchanged and green.
