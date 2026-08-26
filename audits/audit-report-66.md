# Audit Report 66

Audited at `3c48a90` (`backend h2: match :status exactly, not
case-insensitively`), 2026-08-26.

Audit report 65's exact `:status` comparison and empty-name guard are present.
The next backend-H2 response-validation gap is direction handling for `TE`:

1. **Low: the backend HTTP/2 client accepts `TE: trailers` in a response.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — response `TE: trailers` is accepted and discarded

Severity: **Low (P3, a malformed upstream response is silently normalized)**  
Confidence: **High**  
Status: **Confirmed as filed.** Fixed — and it corrects a decision made in
the request-side parity sweep, where I called response `te: trailers`
"permitted" when it is only tolerated by nghttp2.

RFC 9113 §8.2.2 prohibits connection-specific fields in HTTP/2 messages. Its
sole exception is narrow: `TE` may occur in an HTTP/2 **request**, and when it
does its value must be `trailers`. The exception does not authorize `TE` in a
response. RFC 9113 §8.1.1 consequently requires an intermediary not to forward
a response containing the prohibited field.

The backend response emitter calls `h2c_conn_specific` for every ordinary
response field ([src/server/linnea_h2_client.asm:2035](/home/linnea/linnea/src/server/linnea_h2_client.asm:2035)
through [:2059](/home/linnea/linnea/src/server/linnea_h2_client.asm:2059)).
That helper has no request/response direction parameter. It rejects
`connection`, `keep-alive`, `proxy-connection`, `transfer-encoding`, and
`upgrade`, but explicitly returns success when the field name is `te` and its
value is `trailers` ([src/server/linnea_h2_client.asm:991](/home/linnea/linnea/src/server/linnea_h2_client.asm:991)
through [:1053](/home/linnea/linnea/src/server/linnea_h2_client.asm:1053)).

After that successful validation, `h2c_is_skip` recognizes `te` and drops the
field rather than forwarding it ([src/server/linnea_h2_client.asm:2070](/home/linnea/linnea/src/server/linnea_h2_client.asm:2070)
through [:2078](/home/linnea/linnea/src/server/linnea_h2_client.asm:2078)).
Therefore a backend response containing `TE: trailers` is accepted, returned
to the downstream client without the field, and made to look like a clean
response. `TE: gzip` takes the other branch and is refused, which isolates the
bug to the request-only exception.

The same emitter is used by both the blocking response decoder and the
resumable driver, so this is not limited to one backend-H2 implementation. It
also applies to ordinary response fields in a trailer block: the shared field
emission path still has no direction or block-role distinction for this rule.

### Reproduction

Have the backend send a response HEADERS block equivalent to:

```text
:status: 200
te: trailers
content-length: 8
```

followed by an eight-byte DATA frame with END_STREAM. The current trace is:

1. HPACK decoding produces the ordinary field `te` with value `trailers`.
2. `h2c_emit` calls `h2c_conn_specific`.
3. The helper treats the request-only `TE` exception as applicable and returns
   success.
4. `h2c_is_skip` removes `te`, response completion succeeds, and the composer
   emits a normal 200 response with a synthesized content length.

The control with exact lowercase `:status` and no `TE` remains valid. A
response containing `te: gzip` is already refused by the current helper.

### Existing coverage

The connection-specific sweep explicitly treats `/sw-te-tr` as a successful
response and calls it “the one allowed value” ([test/h2/h2c_server.py:658](/home/linnea/linnea/test/h2/h2c_server.py:658)
through [:671](/home/linnea/linnea/test/h2/h2c_server.py:671)). The shard then
asserts that this response relays with 200, while `/sw-te-gz` is listed among
the failures ([test/shards/tls/70-backend-tls-client.sh:1033](/home/linnea/linnea/test/shards/tls/70-backend-tls-client.sh:1033)
through [:1047](/home/linnea/linnea/test/shards/tls/70-backend-tls-client.sh:1047)).
That test covers the value rule but not its message direction, and thereby
locks in the response-side acceptance.

The small reference probe has the same blind spot: its `tetr` mode sends
`te: trailers` in a response, but no assertion requires that response to fail
([test/h2/probe_h2.py:61](/home/linnea/linnea/test/h2/probe_h2.py:61)
through [:78](/home/linnea/linnea/test/h2/probe_h2.py:78)).

### Impact

The backend controls the malformed bytes, so this is an upstream response
validation failure rather than direct client-input injection. The field is
removed before the HTTP/1 response is composed, so it does not directly leak
`TE` downstream. However, the intermediary accepts and normalizes a response
that HTTP/2 requires it to reject. A strict HTTP/2 peer can therefore disagree
with Linnea about whether the upstream exchange was valid, and the normalized
response erases evidence of the protocol violation.

### Recommended fix

Make connection-specific validation response-aware. Since the current caller
is the backend response emitter, the smallest fix is for its response-side
check to reject every `te` field, while retaining the `trailers` exception only
in a request-side validator if one is needed there. Passing an explicit
direction flag or splitting the helper into request and response variants
would make the distinction difficult to regress.

Add blocking and resumable response cases for `te: trailers`, `te: gzip`, and
an ordinary response control. The first two should both fail; the ordinary
control should continue to relay. Keep a separate request-side test, if
applicable, proving that `TE: trailers` remains legal in that direction.

## Verification

The finding is a source-level trace through the shared backend response path.
`h2c_conn_specific` is called from `h2c_emit`, accepts `te: trailers` without a
direction argument, and the following skip table drops the accepted field.
Both blocking and resumable decoders use this path. Existing fixture and shard
coverage assert the incorrect successful response, so the issue is confirmed
without changing tests or production code in this audit.

References:

- [RFC 9113 §8.1.1 — Malformed Messages](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1.1)
- [RFC 9113 §8.2.2 — Connection-Specific Header Fields](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2)


## Resolution (2026-08-26) — CONFIRMED, and it corrects a decision of mine

### The report is right about the text

RFC 9113 §8.2.2's exception reads: *"the TE header field, which MAY be present
in an HTTP/2 **request**; when it is, it MUST NOT contain any value other than
'trailers'."* The permission is scoped to a request. A response carrying TE has
no exception to stand on, so it is an ordinary connection-specific field and
§8.1.1 forbids forwarding the message.

### It was my decision, and my word for it was wrong

The request-side parity sweep (`062827e`) added the connection-specific rule to
the response leg and deliberately kept `te: trailers` accepted, calling it "odd
but permitted, and the reference client serves it". *Permitted* is the wrong
word. It is **tolerated by nghttp2**; the text does not permit it. The sweep
document has been corrected rather than quietly re-decided, and the shard
comment now says which report changed its mind.

### The fix, and a divergence worth naming

`h2c_conn_specific` refuses `te` outright. It has exactly one caller — the
response emitter — and the comment now says so, because that single caller is
what makes a direction-free helper safe; the request-side rule lives in
`linnea_hpack.asm`'s `emit_field` and still allows `trailers`.

This is a **deliberate divergence from the reference**: nghttp2 serves
`te: trailers` in a response and refuses everything else in this group. It is
the one row where we are stricter, the text is the reason, and a server sending
TE in a response is sending a request header backwards — the interop cost is a
peer that is already broken. Naming it here rather than discovering it later.

### Coverage

The two `te` rows moved from "one allowed value" into the refusal list, on each
parser. Against a binary built from the audited source, **2 fail** — and they
fail *because a previously green check changed its mind*, which is the honest
shape of a corrected decision. `/sw-te-gz` was already refused and stays as the
control that this is about direction, not about the value.

The unused `val_trailers` constant went with it: leaving it would suggest the
leg still has a value exception.

Full suite **1127 passed, 0 failed**.

## Verification (resolution)

Reproduced and re-run on both parsers. The divergence from nghttp2 was measured,
not assumed — it serves the same response — and is recorded in the source, in
the shard, and in the sweep document that made the original call.
