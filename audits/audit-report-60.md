# Audit Report 60

Audited at `3d2e4f0`, 2026-08-26.

Audit report 59's response pseudo-header rules are now enforced: duplicate,
misplaced, and undefined pseudo-headers fail in both backend-H2 parsers. The
next response-field validation gap is ordinary field-name syntax:

1. **Low: uppercase backend HTTP/2 response field names are silently
   lowercased and forwarded instead of being rejected as malformed.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — uppercase response field names are normalized across the protocol boundary

Severity: **Low (P3, malformed upstream response accepted and rewritten)**  
Confidence: **High**  
Status: **Confirmed as filed and reproduced.** Fixed — together with the same
section's VALUE rules, which were unchecked and which allowed a backend to forge
a response header downstream. That half is measured end to end and is more
serious than the P3 assigned here.

RFC 9113 §8.2.1 requires HTTP/2 field names not to contain uppercase ASCII
letters. A request or response containing an uppercase field name is malformed,
and RFC 9113 §8.1.1 requires an intermediary not to forward a malformed
response. Lowercasing a name for output is not a valid repair because it hides
the protocol error and creates a different field block than the backend sent.

The backend HPACK emitter has no ordinary field-name validation. After checking
for `:status` and the leading-colon pseudo-header case, every other nonempty
name is sent through the skip table and then to `h2c_hdrline_append`
([src/server/linnea_h2_client.asm:1772](/home/linnea/linnea/src/server/linnea_h2_client.asm:1772)
through [:1803](/home/linnea/linnea/src/server/linnea_h2_client.asm:1803)).
The skip table itself compares names case-insensitively, but that is a routing
decision, not syntax validation.

`h2c_hdrline_append` explicitly converts every byte in the ranges `A` through
`Z` to lowercase while copying the decoded name
([src/server/linnea_h2_client.asm:1908](/home/linnea/linnea/src/server/linnea_h2_client.asm:1908)
through [:1936](/home/linnea/linnea/src/server/linnea_h2_client.asm:1936)).
Thus a literal HPACK field named `Content-Type` is not rejected; it becomes
`content-type` in the synthesized HTTP/1 response. The same path also accepts
other nonempty bytes in a name until a later consumer happens to reject them,
but uppercase names are the clean case that survives the entire bridge.

The decoded response is used by both backend implementations. The blocking
parser feeds completed HEADERS and CONTINUATION blocks into the shared decoder
and field emitter
([src/server/linnea_h2_client.asm:1640](/home/linnea/linnea/src/server/linnea_h2_client.asm:1640)
through [:1655](/home/linnea/linnea/src/server/linnea_h2_client.asm:1655),
and [:1724](/home/linnea/linnea/src/server/linnea_h2_client.asm:1724)
through [:1732](/home/linnea/linnea/src/server/linnea_h2_client.asm:1732)).
The resumable driver uses the same `h2c_do_decode` path when
`d_decode_block` classifies the response
([src/server/linnea_h2_client.asm:2496](/home/linnea/linnea/src/server/linnea_h2_client.asm:2496)
through [:2512](/home/linnea/linnea/src/server/linnea_h2_client.asm:2512)).
The result is then composed into a valid H1 head and parsed by the proxy
bridge, so the downstream protocol never sees the uppercase spelling that
should have caused the backend exchange to fail.

### Reproduction

Have the backend send a legal connection preface and this stream-1 response:

```text
HEADERS  END_HEADERS,
         :status 200,
         Content-Type: text/plain
DATA     END_STREAM, payload = "body"
```

The field name is intentionally uppercase in the HPACK literal. The current
backend decoder lowercases it and completes as a 200 response. Through
`proxy_h2`, the synthesized head contains:

```text
HTTP/1.1 200 OK
content-type: text/plain
content-length: 4

body
```

The exchange should instead fail as a malformed HTTP/2 response before a
client-facing head is emitted. The same result should be asserted with an
uppercase name in a CONTINUATION fragment, since field validity applies to the
combined field block rather than to the frame carrying the bytes.

An uppercase connection-specific name such as `Connection` is currently
dropped by the case-insensitive skip table, which can make the malformed input
look harmless. It must not be used as the only negative test: `Content-Type`
proves the name is accepted and crosses the boundary after normalization.

The normal fixture always constructs lowercase response names, for example
`content-type` at
[test/h2/h2c_server.py:490](/home/linnea/linnea/test/h2/h2c_server.py:490)
through [:494](/home/linnea/linnea/test/h2/h2c_server.py:494), so existing
backend response tests cannot expose this.

### Impact

This is not a cross-request injection by itself: the backend controls the
response and the normalized name is a valid ordinary HTTP field downstream.
It is still an acceptance and translation failure at a protocol boundary. A
faulty or compromised backend can send malformed HTTP/2 and have Linnea claim
that it sent a clean, separately spelled response. Any peer or audit tool that
observes the backend wire would disagree with the response Linnea forwards.

The more dangerous part of the general omission is that the same output helper
also copies name bytes that are not valid HTTP field-name characters. Those
forms may be caught later by the synthesized H1 validator, but relying on that
later path makes failure dependent on the translated representation. The
uppercase case is not caught later because the helper has already repaired it.

### Recommended fix

Validate every ordinary decoded field name before case-insensitive skip
matching or output:

- reject an empty name;
- reject bytes in `0x00..0x20`, `0x41..0x5a`, and `0x7f..0xff`; and
- reject any colon in an ordinary field name.

Pseudo-header names need their separate response rules already added for report
59; do not pass them through the ordinary-name lowercasing path. Once a name is
validated as an HTTP/2 field name, retaining a lowercase copy for the H1 bridge
is harmless, but invalid uppercase input must fail before that conversion.

Apply the check in the shared emitter so the blocking and resumable paths agree.
Add backend fixtures for uppercase `Content-Type`, an uppercase
connection-specific name, a name containing a space, an empty name, and a
valid lowercase control. Assert that malformed cases fail before output in
both parsers and through a real `proxy_h2` front; keep the lowercase control
relayed normally.

## Verification

The finding is a source-level trace through the shared backend HPACK emitter,
the explicit uppercase-to-lowercase copy loop, both response drivers, and the
synthesized H1 bridge. `make -j4` completed with no work required. Existing
backend-H2 response routes use lowercase names and have no field-name syntax
matrix. No production source, configuration, or test file was changed that
required runtime verification.

References:

- [RFC 9113 §8.1.1 — Malformed Messages](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1.1)
- [RFC 9113 §8.2.1 — Field Validity](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.1)

## Resolution (2026-08-26) — CONFIRMED, and the same rule's VALUE half is worse

### Reproduced, as filed

At the audited commit, both parsers accepted `Content-Type: text/plain` from
the backend and emitted `content-type: text/plain`. The uppercase spelling was
repaired, not detected — `h2c_hdrline_append` lowercases A–Z while copying, so
the protocol error left no trace at all.

### The half the report did not file: a CR LF in a VALUE forges a header

RFC 9113 §8.2.1 governs the value as well, and that half was not checked at
all. This leg writes `name: value CRLF` into a synthesized HTTP/1 head which
the proxy bridge then **re-parses**. So a value containing a CR LF does not
produce a strange-looking field — it produces an extra one.

A backend sending a single field, `x-test: "a\r\nx-injected: yes"`, on the
audited build, through a real `proxy_h2` front:

```
HTTP/1.1 200 OK          HTTP/2 200
x-test: a                x-test: a
x-injected: yes          x-injected: yes      <- the backend sent ONE field
content-length: 8        content-length: 8
```

Both an h1 and an h2 client received `x-injected` as a genuine response header.
That is response-header injection across the backend boundary, and it is the
exact mirror of the warning already written on the request side, in
`linnea_hpack.asm`'s `emit_field`: a CR or LF there "forges a second request at
the backend". Nobody had asked the same question of the response.

Severity, honestly: reaching it needs a backend that emits a CR LF inside a
header value, which a conforming HTTP/2 backend will not do — nghttp2 and nginx
both refuse to encode it. The realistic route is an application behind the leg
that reflects user-controlled data into a header value through a library that
does not validate. That is exactly the case §8.2.1 plus §8.1.1 exist to stop an
intermediary from laundering, and it is well above the P3 the report assigned to
the name half.

### The fix

One helper, `h2c_field_ok`, called for every ordinary field in the shared
emitter — so the blocking oracle and the resumable driver cannot disagree:

- **name**: non-empty; no `0x00..0x20` (SP included), no `0x41..0x5a`, no
  `0x7f..0xff`, no colon.
- **value**: no CR, LF or NUL anywhere; no leading or trailing SP or HTAB.

It runs **before** the hop-by-hop skip table, which is the detail the report
was right to flag: an uppercase `Connection` would otherwise be dropped by the
case-insensitive filter and never judged. `/fn-upper-conn` asserts it fails for
being malformed rather than vanishing for being unwanted.

### The reference client, on all four shapes

nghttp2 1.66.0 as a client rejects an uppercase name, a name with a space, a CR
LF in a value, and a leading SP in a value — `Invalid HTTP header field ...` in
each case — and serves the lowercase control.

### Coverage

Twenty-eight rows: eleven malformed cases and one control on each parser, plus
four end to end. Against a binary built from the audited source, **25 fail and 3
pass as controls**.

The end-to-end injection row asserts the **absence** of the forged header, not
merely a 502:

```
pre-fix: field: ...and forges no header downstream (1 lines)   FAIL
```

A check that only looked at the status would have passed on a build that still
forged the header, because the status was a perfectly ordinary 200.

Full suite **1030 passed, 0 failed**, nginx interop included — real backends send
lowercase names and clean values, so the new strictness costs them nothing.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the blocking oracle and the resumable driver, and end to end through
a real `proxy_h2` front with both an h1 and an h2 client. The injection was read
off the client's own response headers, not inferred from the synthesized head.
All four shapes were put to nghttp2 as a client through `probe_h2.py`.
