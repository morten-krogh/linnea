# Audit Report 9

Audited at `2d5d416` (`audit-report-8: both findings FIXED`), 2026-08-18.

Two further upstream-response handling issues remain:

**Both findings are fixed** in `d532224`; the resolutions are recorded under
each. One claim in Finding 2 needed a different client to see, and one thing the
report did not know is recorded at the end: HTTP/1 had never relayed an interim
response at all.

1. **Medium: the shared status-line gate accepts a bare CR as a line ending.**
   A malformed upstream status line is normalized into a successful response on
   HTTP/1.1, HTTP/2, and HTTP/3 instead of being refused as a 502.
2. **Medium: the proxy forwards `Content-Length` on responses where HTTP
   forbids it.** An upstream `204 No Content` with `Content-Length` reaches
   H1 and H2 clients as such; it makes the H3 client used by the suite fail to
   complete the response. The same forwarding path affects interim 1xx heads.

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — A bare CR terminates an upstream status line

Severity: **Medium (P2, malformed-upstream handling and response
normalization)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

RFC 9112 section 4 defines an HTTP/1.1 status line as a line, with its
components separated by SP, and warns that lenient parsing of a status line can
produce response-splitting vulnerabilities. In particular, a CR only ends an
HTTP/1 line when it is followed by LF.

Report 8 moved version and status-code validation into the common gate. The
new code locates the first CR in the status line and unconditionally advances
two bytes, though:

- [src/server/linnea_http.asm:3477](/home/linnea/linnea/src/server/linnea_http.asm:3477)
  through [:3493](/home/linnea/linnea/src/server/linnea_http.asm:3493).

Unlike field lines, whose LF is checked at
[src/server/linnea_http.asm:3613](/home/linnea/linnea/src/server/linnea_http.asm:3613)
through [:3624](/home/linnea/linnea/src/server/linnea_http.asm:3624), the
status-line path never examines the byte after that CR. It therefore starts
field validation one byte too late when the upstream supplies a bare CR.

Every response path trusts this gate before translating the answer:

- HTTP/1 calls it before rewriting the status line at
  [src/server/linnea_http.asm:3688](/home/linnea/linnea/src/server/linnea_http.asm:3688)
  through [:3700](/home/linnea/linnea/src/server/linnea_http.asm:3700);
- HTTP/2 calls it before creating its HEADERS block at
  [src/server/linnea_http2.asm:3993](/home/linnea/linnea/src/server/linnea_http2.asm:3993)
  through [:4001](/home/linnea/linnea/src/server/linnea_http2.asm:4001);
- HTTP/3 does the same before selecting framing and QPACK-encoding at
  [src/server/linnea_h3_proxy.asm:593](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:593)
  through [:610](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:610).

HTTP/1 then copies only the bytes from the status-code offset through that CR
and emits a fresh CRLF, while H2 and H3 construct `:status` from the three
digits. Thus all three accept the malformed status line instead of rejecting
it; H2 and H3 turn it into a normal downstream success.

### Reproduction

An isolated loopback upstream returned exactly these bytes:

```text
HTTP/1.1 200\rX-Fold: accepted\r\n
Content-Length: 5\r\n
\r\n
valid
```

The CR after `200` is not followed by LF, so this is not an HTTP response
status line. The shared validator skips the `X` and validates the subsequent
`-Fold` field name, which is a legal token.

| Downstream protocol | Observed result |
| --- | --- |
| HTTP/1.1 | `200`, body `valid`, normalized `-Fold: accepted` header |
| HTTP/2 | `200`, body `valid`, `-fold: accepted` header |
| HTTP/3 | `:status 200`, body `valid`, `-fold: accepted` header |

The H3 result was decoded with the repository's aioquic helper, not inferred
from the source. This is the malformed-upstream boundary report 8 intended to
make uniform, but this spelling now bypasses it uniformly.

### Impact

A faulty or compromised backend can send a non-HTTP response head and have
Linnea treat it as a `200` on every downstream protocol. The HTTP/1 path
actively replaces the bare-CR ending with CRLF; HTTP/2 and HTTP/3 discard the
status text and create a valid `:status` field. That masks an upstream protocol
failure and leaves downstream parsers with a different message than the one
Linnea received.

### Recommendation

Require an actual CRLF after the status line in
`linnea_http_upstream_head_valid`, before advancing the cursor. Validate the
reason phrase's permitted bytes while there, and keep the status-line grammar
in that one shared gate so the three downstream translators cannot drift.

Add a `/api/badstatuscr` fixture containing the response above and require a
502 on H1, H2, and H3. A nearby valid status-line control should continue to
return 200.

### Resolution — FIXED (2026-08-18, `d532224`)

Confirmed exactly as reported. A `/api/badstatuscr` fixture returning the report's
bytes was answered `200` with `-Fold: accepted` relayed on all three protocols.

`.hv_status_eol` now requires the LF before advancing, the same rule the field
lines below it have always applied. Two things were done beyond the minimum:

- **The reason phrase is validated while we are there,** as the report asked:
  `reason-phrase = 1*( HTAB / SP / VCHAR / obs-text )` (RFC 9112 4). This is not
  decoration — HTTP/1 copies those bytes to the client verbatim, so it is the
  path by which a NUL or a bare LF in a reason phrase would reach a downstream
  parser. `obs-text` (0x80–0xFF) is still accepted, because the grammar accepts
  it.
- **Running off the end of the buffer is now `.hv_bad` rather than `.hv_ok`.** A
  head with no CRLF anywhere in its status line is not a head; it used to be
  waved through on the grounds that there were no field lines left to check.

A/B against the pre-fix binary on the same backend: `200` → `502` on HTTP/1,
HTTP/2 and HTTP/3, with the `/api/simple`, `/api/http10` and `/api/clpad`
controls unchanged. `badstatuscr` is now a row in the cross-protocol matrix.

## Finding 2 — `Content-Length` survives on 204 and interim responses

Severity: **Medium (P2, HTTP/3 proxy availability and protocol conformance)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

RFC 9110 section 8.6 says a server **MUST NOT** send `Content-Length` on a
1xx or 204 response. Such a field is allowed on a HEAD or a 304 response in
the carefully limited cases described immediately before that rule; those
exceptions do not apply to 204 or interim responses.

The common head validator validates that the value is decimal and consistent,
but has no status-aware rule for whether the field may be forwarded. Each
downstream translator subsequently preserves it:

- HTTP/1 identifies and copies the Content-Length line at
  [src/server/linnea_http.asm:3818](/home/linnea/linnea/src/server/linnea_http.asm:3818)
  through [:3902](/home/linnea/linnea/src/server/linnea_http.asm:3902), and
  only afterwards chooses the 204 no-body path at
  [src/server/linnea_http.asm:3920](/home/linnea/linnea/src/server/linnea_http.asm:3920)
  through [:3934](/home/linnea/linnea/src/server/linnea_http.asm:3934).
- HTTP/2 similarly classifies 204 as bodyless at
  [src/server/linnea_http2.asm:4060](/home/linnea/linnea/src/server/linnea_http2.asm:4060)
  through [:4090](/home/linnea/linnea/src/server/linnea_http2.asm:4090), but
  its header encoder explicitly forwards the first Content-Length it sees at
  [src/server/linnea_http2.asm:4541](/home/linnea/linnea/src/server/linnea_http2.asm:4541)
  through [:4556](/home/linnea/linnea/src/server/linnea_http2.asm:4556).
- HTTP/3 marks 204 and all final bodyless answers as `.h3_nobody` at
  [src/server/linnea_h3_proxy.asm:699](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:699)
  through [:717](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:717).
  Delivery then passes `-1`, meaning "forward the upstream's own
  Content-Length", to the QPACK encoder at
  [src/server/linnea_h3_proxy.asm:1085](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:1085)
  through [:1097](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:1097).
  The encoder consequently omits its replacement length and walks the upstream
  fields unchanged at
  [src/server/linnea_qpack.asm:781](/home/linnea/linnea/src/server/linnea_qpack.asm:781)
  through [:868](/home/linnea/linnea/src/server/linnea_qpack.asm:868).

The same H3 `-1` mode is intentionally used when re-encoding an interim head
at [src/server/linnea_h3_proxy.asm:1055](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:1055)
through [:1080](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:1080), so
a `103` carrying Content-Length is forwarded as well.

### Reproduction

An isolated loopback upstream returned:

```text
HTTP/1.1 204 No Content\r\n
Content-Length: 12\r\n
\r\n
```

| Downstream protocol | Observed result |
| --- | --- |
| HTTP/1.1 | `204 No Content` with `Content-Length: 12` |
| HTTP/2 | `204` with `content-length: 12` |
| HTTP/3 | no completed response from aioquic within its 20-second request deadline (`None, {}, ''`) |

The HTTP/3 control, the same 204 with no Content-Length, completed normally
as `204` with an empty body and no Content-Length. This distinguishes the
failure from the general H3 bodiless-response path.

The repository's existing `/api/204` fixture already supplies this forbidden
upstream field at [test/proxy_backend.py:279](/home/linnea/linnea/test/proxy_backend.py:279)
through [:281](/home/linnea/linnea/test/proxy_backend.py:281), but its tests
assert only the status and lack of a body, not the downstream field section.

### Impact

Linnea emits a response that HTTP forbids. More importantly, a standard H3
client in the test environment does not complete the response at all, while
the identical compliant control succeeds. An upstream application that sends a
harmless-looking 204 metadata response can therefore be unavailable to H3
clients. Forwarding the same field on an interim response also produces an
invalid response sequence, precisely in the newly added interim-relay path.

### Recommendation

Make response-field filtering status-aware. Drop `Content-Length` from 1xx and
204 responses in every H1, H2, and H3 emission path; do not replace it with
`Content-Length: 0`. Preserve the legal HEAD and 304 cases, which need their
upstream representation length. Apply the corresponding prohibition for a
successful CONNECT response wherever that response type is supported.

Extend `/api/204` (or add `/api/204cl`) so the H1/H2/H3 matrix requires a
normal 204 with no Content-Length, plus an H3 completion check. Add a
`103 Content-Length` followed by a final 200 fixture and assert that the
interim field section contains no Content-Length while the final response still
arrives.

### Resolution — FIXED (2026-08-18, `d532224`)

Both halves confirmed, and one of them only by changing client — see below.

The rule is now one predicate, `linnea_http_status_no_clen`, stating what
RFC 9110 8.6 states: 1xx and 204 may carry no `Content-Length`, while the HEAD
and 304 cases keep theirs. It is called from HTTP/1 and HTTP/2 directly. It
cannot be called from `linnea_qpack.asm` — `linnea_qpack.o` is linked by four
test harnesses that have no `linnea_http.o` — so the decision reaches the QPACK
encoder as a parameter: `r8 = -2` now means *state none and drop the upstream's
too*, beside the existing `-1` for *state none and forward the upstream's*. The
field is **dropped, not rewritten to `Content-Length: 0`**, as the report asked:
"no length" and "a length of zero" are different answers, and 204 means the
first.

CONNECT is not a supported method here, so its rule has nothing to apply to.

#### The HTTP/3 availability claim needed a different client

The report's HTTP/3 row — *no completed response within the deadline* — did not
reproduce under this repository's aioquic helper, which decoded the relayed 204
and its forbidden `content-length: 12` without complaint and returned a clean
`204`. It reproduces immediately under **curl-h3**, which is presumably what the
audit used:

```text
$ curl --http3-only -D - .../api/204        # pre-fix
HTTP/3 204
curl: (56) ngtcp2_conn_writev_stream returned error: ERR_CLOSING
```

So the finding stands and its severity stands; the tooling note is that *the
suite's own HTTP/3 client is the more permissive of the two*, and a conformance
claim checked only against it can pass while a real client fails. The shard
therefore asserts the 204's **completion** with curl-h3 — exit status, not body
— while the matrix asserts the **field**. Post-fix, curl-h3 completes it.

#### What the report did not know: HTTP/1 had never relayed an interim head

The report speaks of "the newly added interim-relay path" for HTTP/1. There was
none. `linnea_http_proxy_head` took the first head it found as *the* response, so
`/api/earlycl` was answered:

```text
HTTP/1.1 103 Early Hints\r\nContent-Length: 7\r\nLink: ...\r\n
Via: 1.1 linnea\r\nConnection: close\r\n\r\nHTTP/1.
```

— the interim delivered as the final answer, with seven bytes of the *next*
response consumed as its body. Dropping the forbidden field alone would not have
fixed that: without a length the head simply became close-delimited, and the real
response was relayed as the interim's unframed body, which lenient clients
reparse into the right answer. That accident is what report 8 was describing when
it said HTTP/1 "relays each 1xx as it arrives"; `/api/manyearly` showed it
plainly, one `103` head from linnea followed by eight more straight off the
upstream socket.

HTTP/1 now walks interim heads the way HTTP/2 has since Finding 30 and HTTP/3
since report 7: each is validated, rewritten and emitted, then stepped over, and
the parse restarts from the buffer's first byte on every call so a partial read
cannot emit one twice. There is no interim *count* cap on this path — the chain
is bounded by the head buffer it is parsed out of, and nothing is appended per
interim head beyond what the upstream sent, so `out_buf`'s 64 bytes of slack over
`up_buf` still covers the `Via` and `Connection` added to the final head.

## Verification

A pre-fix binary was left running while the new one came up beside it on its own
port, so every row below is the same request against the same backend.

| route | pre | post |
| --- | --- | --- |
| `/api/badstatuscr` | `200` + `-Fold: accepted`, all three | `502`, all three |
| `/api/204` | `Content-Length: 12` relayed, all three | dropped, all three |
| `/api/204` over curl-h3 | `ERR_CLOSING`, no completion | completes, exit 0 |
| `/api/earlycl` | h1 delivers the `103` as the answer | `103` then `200`, body `valid` |
| `/api/manyearly` over h1 | one head + raw upstream bytes | nine interim heads + the final |
| `/api/204clean`, `/api/simple`, `/api/chunked` | controls, unchanged | controls, unchanged |

The cross-protocol matrix grew the four routes and two assertions that apply to
every route it already had: **the interim sequence is now demanded of all three
protocols** rather than HTTP/3 alone — which is what would have caught HTTP/1
years ago — and **no 1xx or 204 field section may carry a Content-Length**. Its
HTTP/2 leg needed a real HPACK decoder to make the second assertion; it had been
finding the status by scanning the block for three digits.

Control run before the fix: 5 failures, exactly the intended ones. Full suite
after: **767 passed, 0 failed**.

### The A/B caught a crash this change introduced

Worth recording because it was invisible in every other way. In the HTTP/3
encoder call, `rdi` holds the output pointer and is set several lines before the
new `linnea_http_status_no_clen` call — which took `edi` as scratch for the
status. The first `/api/204` over HTTP/3 therefore encoded a field section to
address 204 and the worker died on SIGSEGV. The failing test rows looked nothing
like the cause: the four *unrelated* routes that happened to follow it returned
`None`, including controls that had passed moments earlier. The tell was
`worker … exited on signal 11, respawning` in the server's own log — see
`worker-deaths-2026-08-14` for why that line is often the only evidence there is.

## Conclusion

Both findings are fixed and both are covered by tests that fail against the
pre-fix binary. The through-line is the one every report in this series has had:
a rule that must hold in three places, held in none of them the same way. This
time the rule is written down once — `linnea_http_status_no_clen` — and the
matrix asks all three protocols the same question instead of asking the protocol
that was most recently fixed.
