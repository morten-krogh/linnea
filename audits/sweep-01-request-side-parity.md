# Sweep 01 — request-side rule parity on the backend-H2 response leg

Swept at `52e1522`, 2026-08-26. Not an audit report: a deliberate pass over the
seam that produced reports 56 through 62, done in one go rather than waiting for
it to be filed one rule at a time.

## Why this seam exists

`linnea_h2_client.asm` is the newest peer role in the codebase — linnea as an
HTTP/2 *client*. Every other role had years of findings applied to it. Reports
56–62 were each one rule the request side already enforced and the response side
did not:

| report | rule | source of truth |
|---|---|---|
| 56 | the server's SETTINGS preface must come first | frontend h2 |
| 57 | `:status` is exactly three digits | h1 response-head validator |
| 58 | `content-length` equals the DATA bytes | h1 response-head validator |
| 59 | pseudo-header repetition, placement, undefined | `linnea_hpack.asm` |
| 60 | field name and value syntax | `linnea_hpack.asm` |
| 61 | HPACK table-size update placement | `linnea_hpack.asm` decoder |
| 62 | 101 is not an informational response | frontend h2 |

The pattern is worth naming precisely, because it predicts where the *next* one
is: the HPACK **primitives** are shared — the response decoder calls the same
`hpack_int`, `hpack_str`, `hpack_dyn_*` and static table as the request one. It
is the **state machine around them** that was written twice. So the gaps are
never in integer or Huffman decoding; they are in placement, ordering, and
field-level semantics — exactly what a second implementation forgets.

## Method

Enumerate the rules asserted on the request side (`emit_field` and the decoder
in `linnea_hpack.asm`) and on an h1 upstream response
(`linnea_http_check_response_head`), put each to the backend-H2 response leg as
a fixture route, and measure both parsers. Then put every disputed one to
nghttp2 1.66.0 acting as a client, so the verdict is not my reading of the RFC.

## Result

**Nine gaps, in two groups.**

### RFC 9113 §8.2.2 — connection-specific fields (six rows)

"Any message containing connection-specific header fields MUST be treated as
malformed." `connection`, `keep-alive`, `proxy-connection`,
`transfer-encoding` and `upgrade` were all on the leg's **skip list**: the
response was quietly cleaned up and relayed as though the backend had behaved.
`te` was accepted with any value.

Dropping a field is not refusing the message, and the request side has said so
in as many words since its own sweep: *"stripping them stopped the smuggle into
an h1 upstream; it did not make the request the malformed one the RFC says it
is."*

`te: trailers` was kept accepted here as "the one exception the section
allows". **That was wrong, and audit-report-66 corrected it**: the exception is
scoped to a *request* ("the TE header field, which MAY be present in an HTTP/2
request"), so a response has none. Both TE values are refused now.

### RFC 9110 — content on a status defined to carry none (three rows)

A 204, 205 or 304 whose backend sent a DATA frame was relayed. What went out
was worse than acceptance:

```
HTTP/1.1 204 No Content
content-length: 8
connection: close

sw-body
```

A 204 with a content-length *and* a body. No client reads content after a 204's
header section, so those bytes are left for whatever parses the connection
next. On this path the front happens to close the connection — but `/sw-ok`
closes too, so that is this configuration's default, not a defence.

The fix folds the rule into the completion predicate, now `h2c_body_ok`, in the
order that matters: *no-content* is asked first, because a 304's declared length
deliberately does not match what it sends, so asking the length question first
would ask the wrong thing. It uses `linnea_http_status_no_content` — the same
predicate the h1 leg calls, not a fourth copy of a list that has already
disagreed with itself once.

## What was already correct

Measured, not assumed, and now pinned in the suite so the sweep's coverage is
recorded rather than remembered:

- `:status` below 100 or above 599 — refused
- HPACK index 0, and an index past the table — refused
- a literal whose string runs off the end of the block — refused

These are the rows that come from the *shared* primitives, which is the point
made above.

## Deliberately not changed

- **`content-length` on a 1xx.** RFC 9110 8.6 forbids *sending* it and nghttp2
  refuses it, but report 58's per-block save/restore already keeps a non-final
  block's declaration away from the assertion: `/interim-clen` relays the final
  response's own length. No consequence, and refusing it would break a backend
  that attaches a harmless length to a 103. Pinned as a fixture route.
- ~~**`te: trailers` in a response.**~~ **Withdrawn by audit-report-66.** I wrote
  "odd but permitted"; it is not permitted, it is *tolerated by nghttp2*. RFC
  9113 8.2.2 scopes its only exception to a request, so a response carrying TE is
  malformed and 8.1.1 forbids forwarding it. Refusing it is now a deliberate
  divergence from the reference, named in `h2c_conn_specific`.

## Coverage

39 new rows: 16 refusals and 3 legality controls on each parser, plus 3 end to
end. Against a binary built from the swept commit, **20 fail and 19 pass as
controls** — the unusually large control half is deliberate, because half of
this sweep is a record of what must keep working.

Full suite **1095 passed, 0 failed**, nginx interop included: real backends do not send
connection-specific fields over h2, which is why the new strictness costs them
nothing.

## What is left

Nothing found by this sweep remains open. The seam itself is not closed —
`linnea_h2_client.asm` will keep needing rules the older roles already have —
but the request-side list it was measured against is now exhausted.
