# Audit Report 63

Audited at `062827e`, 2026-08-26.

Audit report 62's HTTP/2 `101` rejection is present, and the subsequent
request-side parity sweep is present as well. The next response-framing gap is
the method-specific no-content rule for `HEAD`:

1. **Low: the backend HTTP/2 client accepts DATA in a response to a HEAD
   request, and its standalone response composer includes those bytes.**

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — backend HTTP/2 accepts a body for HEAD

Severity: **Low (P3, malformed upstream content is accepted and can be
exposed by the H2 client API)**  
Confidence: **High**  
Status: **Confirmed as filed and reproduced.** Fixed. The impact is
understated: an h1 client received the body through a real `proxy_h2` front.
A neighbour — every HEAD reporting `content-length: 0` — is fixed with it.

HTTP semantics require a server not to send content in a response to `HEAD`.
The method may carry representation metadata, including the length that a
corresponding `GET` would have sent, but the response itself has no content.
RFC 9113 §8.1.1 names the response to a `HEAD` request alongside 204 and 304
as a message defined to have no content. RFC 9110 §9.3.2 states the method
rule directly.

The backend H2 client already remembers the request method. Its method emitter
sets `h2c_is_head` when the request method is exactly `HEAD`
([src/server/linnea_h2_client.asm:420](/home/linnea/linnea/src/server/linnea_h2_client.asm:420)
through [:432](/home/linnea/linnea/src/server/linnea_h2_client.asm:432)). That
state reaches the shared completion check in both implementations:

- the blocking response loop passes `h2c_is_head` and the accumulated body
  length to `h2c_body_ok`
  ([src/server/linnea_h2_client.asm:1737](/home/linnea/linnea/src/server/linnea_h2_client.asm:1737)
  through [:1747](/home/linnea/linnea/src/server/linnea_h2_client.asm:1747));
- the resumable driver does the same from `d_dispatch`
  ([src/server/linnea_h2_client.asm:3382](/home/linnea/linnea/src/server/linnea_h2_client.asm:3382)
  through [:3391](/home/linnea/linnea/src/server/linnea_h2_client.asm:3391)).

The defect is in `h2c_body_ok`. It correctly rejects a nonzero body for a
status that carries no content, but its ordinary-content branch first returns
success when no `content-length` was declared, and then returns success for
every HEAD response before looking at `body_len`
([src/server/linnea_h2_client.asm:1114](/home/linnea/linnea/src/server/linnea_h2_client.asm:1114)
through [:1141](/home/linnea/linnea/src/server/linnea_h2_client.asm:1141)).
The `HEAD` exception currently waives only the content-length-versus-DATA
comparison; it does not enforce the required zero DATA length. The comment
above the helper says that a HEAD response “sends nothing,” but the code does
not check that statement.

The body has already been accepted and stored before this check. The blocking
and resumable DATA handlers append the payload, issue flow-control credit, and
only then invoke `h2c_body_ok` when END_STREAM arrives
([src/server/linnea_h2_client.asm:1685](/home/linnea/linnea/src/server/linnea_h2_client.asm:1685)
through [:1719](/home/linnea/linnea/src/server/linnea_h2_client.asm:1719), and
[src/server/linnea_h2_client.asm:3345](/home/linnea/linnea/src/server/linnea_h2_client.asm:3345)
through [:3391](/home/linnea/linnea/src/server/linnea_h2_client.asm:3391)).

For the standalone/client-facing API, the successful result is then made into
an HTTP/1 response by copying `body_len` bytes from `body_buf`
([src/server/linnea_h2_client.asm:3470](/home/linnea/linnea/src/server/linnea_h2_client.asm:3470)
through [:3517](/home/linnea/linnea/src/server/linnea_h2_client.asm:3517)).
Thus this is not only a bookkeeping discrepancy: the direct H2 client can
return a body for a HEAD request.

The production `proxy_h2` relay separately marks the client request as HEAD
and suppresses the body while parsing the synthesized response head
([src/server/linnea_http2.asm:4837](/home/linnea/linnea/src/server/linnea_http2.asm:4837)
through [:4853](/home/linnea/linnea/src/server/linnea_http2.asm:4853)). That
downstream suppression limits the direct client-visible impact on that route,
but it does not make the backend response valid: the H2 client has still
accepted malformed upstream content and marked the backend exchange complete.

### Reproduction

Send a `HEAD` request through the backend H2 client and have the backend return
this stream-1 sequence:

```text
HEADERS  END_HEADERS, no END_STREAM,
         :status 200, content-length: 4
DATA     END_STREAM, payload = "body"
```

The current trace is:

1. `h2c_is_head` is set to 1 while encoding the request.
2. The DATA payload is appended, making `h2c_body_len == 4`.
3. On END_STREAM, `h2c_body_ok` sees an ordinary 200 response, sees
   `h2c_is_head`, and returns success without requiring `body_len == 0`.
4. `linnea_h2c_drv_compose` emits the synthesized response and copies the four
   bytes after its blank line.

The same acceptance occurs with no `content-length` field, because the
no-declaration branch returns success before the HEAD check. A control with
`HEADERS END_STREAM` and `content-length: 4`, but no DATA frame, must remain
successful. A normal `GET` with the same `content-length: 4` and `body` is also
a legal control.

### Existing coverage

The backend fixture's `/cl-head` route sends a 200 with `content-length: 4`
and no DATA, explicitly exercising the legal HEAD shape
([test/h2/h2c_server.py:740](/home/linnea/linnea/test/h2/h2c_server.py:740)
through [:777](/home/linnea/linnea/test/h2/h2c_server.py:777)). The shard runs
that route for both GET and HEAD, and checks the direct H2 client plus a
head-only end-to-end request
([test/shards/tls/70-backend-tls-client.sh:831](/home/linnea/linnea/test/shards/tls/70-backend-tls-client.sh:831)
through [:861](/home/linnea/linnea/test/shards/tls/70-backend-tls-client.sh:861)).
Those controls prove that a declared HEAD length may differ from the received
DATA total when that total is zero; they do not send a DATA frame after a HEAD
request, so they do not exercise this omission.

### Impact

The backend peer controls the malformed bytes, so this is an upstream
validation failure rather than direct client input injection. Nevertheless,
the H2 client API presents a response with content where the requested method
forbids it. Consumers of `linnea_h2c_exchange` or
`linnea_h2c_drv_compose` can therefore receive bytes that a conforming HTTP
endpoint must not associate with a HEAD response. In the proxy H2 path, the
later HEAD suppression hides the bytes from the downstream H2 client, but the
backend leg still consumes and acknowledges them as a successful exchange
instead of failing the malformed response.

### Recommended fix

Make `h2c_body_ok` check the method-specific rule before the ordinary
content-length comparison:

- if `is_head != 0`, require `body_len == 0` and accept the response's
  content-length as the representation length metadata; and
- otherwise retain the existing no-content-status and ordinary
  content-length checks.

The no-content-status check can remain first or be folded into the same
zero-body gate, provided the existing legal `content-length` metadata cases
for 1xx, 204, 205, and 304 remain accepted. Add blocking and resumable tests
for HEAD with DATA, HEAD with DATA and no content-length, and legal HEAD with
only a content-length. Add an end-to-end proxy H2 case that confirms a
malformed backend HEAD response is rejected rather than merely hidden by the
downstream HEAD parser.

## Verification

The finding is a source-level trace from request-method recognition, through
both backend response completion paths, to the direct response composer. The
shared helper's HEAD branch demonstrably returns success without testing the
accumulated body length. Existing tests cover only the zero-DATA control shape.
`make -j4` completed with no work required. No production source,
configuration, or test file was changed in this audit.

References:

- [RFC 9113 §8.1.1 — Malformed Messages](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1.1)
- [RFC 9110 §9.3.2 — HEAD](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2)

## Resolution (2026-08-26) — CONFIRMED as filed; the impact is understated

### Reproduced

The exemption is mine, from audit-report-58: the HEAD branch waived the
content-length comparison — correctly, since a HEAD declares what a GET *would*
have returned — and never asked the other half. The comment said "sends
nothing" and nothing checked it.

Both parsers, at the audited commit, a HEAD whose backend sent DATA:

```
HTTP/1.1 200 OK
content-type: text/plain
content-length: 4

body            <- the client API returned the content
```

### One correction: it is not hidden on every route

The report says the proxy's downstream HEAD suppression "limits the direct
client-visible impact on that route". That is true for an **h2** client and
false for an **h1** one. Through a real `proxy_h2` front, before the fix:

```
h1 HEAD /cl-ok  ->  HTTP/1.1 200 OK ... content-length: 4 ... \r\n\r\nbody
h2 HEAD /cl-ok  ->  200, 0 body bytes
```

Four bytes of content delivered after a HEAD's header section — bytes no client
reads as content, left in the connection for whatever parses next. The front
closes here, which contains it, but `/sw-ok` closes too: that is this
configuration's default and not a defence.

### The fix, and the 2x2 that states the rule

`h2c_body_ok` asks the method first: HEAD requires `body_len == 0`, and the
declared length is left alone as the metadata it is. That also closes the
second half of the defect the report names — with **no** content-length the
helper returned success from its "nothing declared" branch before the method
was ever considered.

The suite states the rule as a matrix, because either half alone is
satisfiable by a wrong fix:

```
                      asked with GET      asked with HEAD
  /cl-ok    (4, DATA)   legal               malformed
  /cl-head  (4, none)   malformed           legal
```

### A neighbour found beside it: HEAD reported the wrong length

A *legal* HEAD — backend declares 4, sends nothing — was relayed as
`content-length: 0`. The composer writes its own measurement, which for a HEAD
is always zero, so the one thing the method exists to ask for was destroyed on
every HEAD through `proxy_h2`.

Fixed with the filed finding, since report 58 already retains the declared
value. **That composition exists three times** — the blocking oracle's
`h2c_compose`, the harness's `linnea_h2c_drv_compose`, and
`linnea_h2c_drv_head`, which is the one production actually uses (called from
`linnea_http2.asm` and `linnea_uring.asm`). All three now apply the rule; I
found the third only because a `sed` anchor matched twice and I went looking for
why. Verified on the production path with both an h1 and an h2 client:

```
h1 HEAD /cl-head -> 200, content-length: 4
h2 HEAD /cl-head -> 200, content-length: 4
GET  /cl-ok      -> 200, content-length: 4   (unchanged)
```

### Coverage

Fourteen rows: the 2x2, both HEAD-with-content shapes, and a length-fidelity
assertion on each parser, plus two end to end. Against a binary built from the
audited source, **10 fail and 4 pass as controls**.

One check of mine was wrong and the control caught it: the end-to-end helper
already carries `-D-`, so adding `-I` makes curl print the head twice and the
value read `4\n4` — equal to neither 4 nor 0. It takes the first line now, with
a comment saying why.

Full suite **1109 passed, 0 failed**, nginx interop included — its `-I`
row through `proxy_h2` is itself a HEAD, and it is green.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the blocking oracle and the resumable driver, through the direct
client API, and end to end through a real `proxy_h2` front with both an h1 and
an h2 client. The h1 leak was read off the socket, not inferred. The
length-fidelity rows assert the value, not merely the status.
