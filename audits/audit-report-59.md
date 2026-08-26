# Audit Report 59

Audited at `0890354`, 2026-08-26.

Audit report 58's `content-length` assertion is now retained and checked in
both backend-H2 response paths. The next response-header validation gap is
pseudo-header multiplicity:

1. **Low: a backend response can contain `:status` more than once, and the
   last value silently replaces the first.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — duplicate `:status` fields are accepted with last-value-wins semantics

Severity: **Low (P3, malformed upstream response can change the relayed status)**  
Confidence: **High**  
Status: **Confirmed as filed and reproduced.** Fixed, along with two further
RFC 9113 8.3 rules found beside it: a pseudo-header behind a regular field, and
an undefined one. All three were already enforced on the request side.

RFC 9113 §8.2 requires the same pseudo-header field name not to appear more than
once in a field block. RFC 9113 §8.3.2 defines one response pseudo-header,
`:status`, and requires it in every response. Two `:status` fields in the same
completed HEADERS/CONTINUATION block are therefore a malformed response, even
if both values are individually valid.

The shared HPACK emitter has no per-block `status_seen` state. It recognizes
`:status` and unconditionally stores the parsed integer at
[src/server/linnea_h2_client.asm:1808](/home/linnea/linnea/src/server/linnea_h2_client.asm:1808)
through [:1840](/home/linnea/linnea/src/server/linnea_h2_client.asm:1840).
Decoding a second `:status` simply executes the same arm again and overwrites
`h2c_status`; the only pseudo-header state it records is the generic
`h2c_saw_pseudo` flag, which is used to reject pseudo-headers in trailers, not
to detect duplicates in the response head
([src/server/linnea_h2_client.asm:1804](/home/linnea/linnea/src/server/linnea_h2_client.asm:1804)
through [:1807](/home/linnea/linnea/src/server/linnea_h2_client.asm:1807)).

The classifier resets the numeric status at the start of each completed field
block and later validates only the final integer's range
([src/server/linnea_h2_client.asm:2397](/home/linnea/linnea/src/server/linnea_h2_client.asm:2397)
through [:2451](/home/linnea/linnea/src/server/linnea_h2_client.asm:2451)).
It never knows whether that integer came from one `:status` or several. This
reset is correctly per response block for informational responses and trailers,
but it leaves duplicate fields within one block indistinguishable from a legal
single field.

Both backend paths use this same classifier. The blocking parser invokes it
when a HEADERS or CONTINUATION sequence reaches END_HEADERS
([src/server/linnea_h2_client.asm:1422](/home/linnea/linnea/src/server/linnea_h2_client.asm:1422)
through [:1438](/home/linnea/linnea/src/server/linnea_h2_client.asm:1438),
and [:1448](/home/linnea/linnea/src/server/linnea_h2_client.asm:1448)
through [:1464](/home/linnea/linnea/src/server/linnea_h2_client.asm:1464)).
The resumable driver reaches it through `d_decode_block`
([src/server/linnea_h2_client.asm:2496](/home/linnea/linnea/src/server/linnea_h2_client.asm:2496)
through [:2512](/home/linnea/linnea/src/server/linnea_h2_client.asm:2512)).
The selected last value is then committed to the driver context and emitted as
the response status.

### Reproduction

Have the backend send a legal connection preface and this response on stream 1:

```text
HEADERS  END_HEADERS,
         :status 200,
         :status 500,
         content-type: text/plain
DATA     END_STREAM, payload = "body"
```

The current decoder stores 200 and then 500, accepts the field block as a final
response, and relays a 500 with the body. Reversing the order relays 200. Both
values are valid in isolation, so the observable difference is caused by the
duplicate and its order, not by status-range validation.

The same malformed block can be split legally across HEADERS and CONTINUATION;
the duplicate must still be rejected because the field block is the combined
sequence, not each frame independently. A single `:status 200` control and two
separate response blocks containing one status each — for example an interim
1xx followed by the final response — must remain legal.

The existing backend fixture exercises missing status, informational ordering,
trailers, and malformed status values, but every response block contains at
most one `:status`. Its `enc_status` helper therefore cannot expose this
last-value-wins behavior without a dedicated route.

### Impact

The backend is the authority for the response status, so this is not a
client-controlled status injection across requests. It is still a protocol
boundary failure: Linnea accepts a response that a conforming HTTP/2 peer must
treat as malformed and emits a status selected by the malformed field order.
That can alter error handling, caching, retry, or policy decisions downstream,
and it makes the backend driver disagree with strict HTTP/2 implementations.

The generic trailer flag does not cover this case. A duplicate `:status` in a
trailer is already rejected because any pseudo-header is forbidden there; the
uncovered state is a duplicate within the initial or informational response
field block.

### Recommended fix

Add a `status_seen` bit that is cleared at the start of every completed field
block and checked in the shared `:status` emitter before storing the value. A
second occurrence in the same HPACK field block must fail the backend exchange.
Do not clear the bit between HEADERS and CONTINUATION fragments; clear it only
when the previous completed block has been classified and the next block starts.

Keep the existing per-block reset of the numeric status and the separate
trailer pseudo-header check. This preserves legal informational-then-final
responses while rejecting duplicate `:status` fields in either individual
block. Add fixture cases for duplicate status in both orders, a duplicate split
across CONTINUATION, a single-status control, and a legal interim-plus-final
sequence. Assert failure in the blocking oracle, the resumable driver, and end
to end through a `proxy_h2` front.

## Verification

The finding is a source-level trace through the shared `h2c_emit` status arm,
per-block classifier reset, blocking HEADERS/CONTINUATION completion, and the
resumable driver commit. `make -j4` completed with no work required. Existing
backend-H2 response coverage has no repeated pseudo-header case. No production
source, configuration, or test file was changed that required runtime
verification.

References:

- [RFC 9113 §8.2 — HTTP Fields](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2)
- [RFC 9113 §8.3.2 — Response Pseudo-Header Fields](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.2)

## Resolution (2026-08-26) — CONFIRMED, plus two neighbours it did not file

### Reproduced

Both parsers, at the audited commit:

```
/ps-dup      :status 200, :status 500   ->  HTTP/1.1 500 Internal Server Error
/ps-dup-rev  :status 500, :status 200   ->  HTTP/1.1 200 OK
/ps-dup-cont the duplicate split across HEADERS + CONTINUATION -> 500
/ps-one      one :status                ->  200 OK   <- control
```

Exactly as filed, and the pair is the point: the *same two values* in opposite
orders relay different statuses, so the malformed field order — not any range
check — chose what the client saw. The split-across-CONTINUATION variant
behaves identically, because the field block is the frames combined.

### Two more rules from the same section, found beside it

RFC 9113 §8.3 says three things about pseudo-headers, and the response side had
none of them. The report filed the first:

```
/ps-after    content-type, then :status  ->  200 OK   (a pseudo-header behind
                                                       a regular field)
/ps-unknown  :status 200, :unknown x     ->  200 OK   (an UNDEFINED one)
```

The undefined case is the more interesting miss. `h2c_emit` did have a
`saw_pseudo` flag and did notice the field — it set the flag and dropped the
field. But that flag serves a *different* rule (no pseudo-headers in a trailer),
and satisfying one rule with the machinery of another is how this looked
covered. §8.3 makes an undefined pseudo-header malformed outright.

### The same shape, for the fourth report running

The request side has enforced all three for a long time — `linnea_hpack.asm`,
"pseudo-header placement and repetition (RFC 9113 8.3 / 9114 4.3.1)", whose
comment calls a repeated pseudo-header "the h2/h3 twin of a repeated Host: we
would keep the last, an intermediary the first, and one request becomes two
different ones." That is precisely what the response side was doing to statuses.

### The reference client, on all three

nghttp2 1.66.0 as a client, through `probe_h2.py`:

```
psdup      [ERROR] Invalid HTTP header field ... name: [:status], value: [500]
psafter    [ERROR] Invalid HTTP header field ... name: [:status], value: [200]
           send RST_STREAM
psunknown  [ERROR] Invalid HTTP header field ... name: [:unknown], value: [x]
normal     recv :status: 200
```

### The fix

Two per-block bits in the shared emitter — `status_seen` and `regular_seen` —
cleared where the block's `:status` and `content-length` are already cleared, so
they are per FIELD BLOCK and not per frame. `:status` is refused if either bit
is already set; a regular field sets `regular_seen`; and the unknown-pseudo arm
now fails instead of dropping the field. One site, both parsers.

The per-block reset is what keeps the legal neighbours legal: an interim 1xx
followed by a final response is two blocks with one `:status` each, and it is
asserted on both parsers rather than assumed.

### Coverage

Seventeen rows: five malformed cases and two legality controls on each parser,
plus three end to end. Against a binary built from the audited source, **12
fail and 5 pass as controls**. `/trailers-frag` and `/fsz-split`, already in the
suite, are the standing proof that a legal block split across a CONTINUATION
still works.

One false alarm worth recording: `/cont-ok`, which I used as a control while
checking for regressions, returned `H2C-FAIL`. It is not a route — anything
matching `/cont-` reaches the framing fixture, whose four negative cases fall
through and send nothing. A backend 404 relays normally, which is what that
check should have asked.

Full suite **1002 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the blocking oracle and the resumable driver, and end to end through
a real `proxy_h2` front. All three rules were put to nghttp2 as a client. The
duplicate is asserted in *both orders*, so a fix that kept the first value
rather than refusing the block would still fail one of the two rows.
