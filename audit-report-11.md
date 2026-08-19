# Audit Report 11

Audited at `960156d` (`audit-report-10: both findings FIXED`), 2026-08-19.

**Both findings are fixed in `3f763c9`.** Finding 1 is a regression from
report 10's own fix, one day old, and is owned as such below. Finding 2 is real
and **broader than reported** — HTTP/2 has the same defect for a transfer coding
without `chunked`, which changed the shape of the fix from an HTTP/3 patch to one
shared rule. One consequence reaches beyond the report's ask and is flagged
explicitly rather than assumed.

Two further upstream-response translation issues remain:

1. **Medium: HTTP/1.1 forwards an `Upgrade` field that the upstream's
   `Connection` field names on an ordinary response.** The exception needed for
   a real 101 tunnel is unconditional, so a non-101 response can export a
   hop-by-hop `Upgrade` field after Linnea has replaced `Connection` with its
   own value.
2. **Medium: HTTP/3 removes unsupported upstream transfer codings without
   decoding them.** In particular, a valid HTTP/1.1 `Transfer-Encoding: gzip,
   chunked` response becomes an HTTP/3 `200` with a new `content-length` and
   raw gzip bytes presented as the response content.

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — HTTP/1.1 leaks a `Connection: Upgrade` field on a 200 response

Severity: **Medium (P2, hop-by-hop metadata leakage and protocol
conformance)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

RFC 9110 section 7.6.1 requires an intermediary to parse a received
`Connection` field, remove every field it names, and then remove or replace
`Connection` itself. This applies to `Upgrade` too: RFC 9110 section 7.8 says
a sender of `Upgrade` must name it as a `Connection` option so intermediaries
do not forward it. A server can use `Upgrade` on a response other than 101 to
advertise a later upgrade; it remains hop-by-hop on this connection, not an
end-to-end response field.

Report 10 added the missing dynamic response-side `Connection` walk, but gave
it an unconditional `Upgrade` exception:

- Its comment says that `upgrade` is never matched so the 101 tunnel can
  complete at
  [src/server/linnea_hpack.asm:1598](/home/linnea/linnea/src/server/linnea_hpack.asm:1598)
  through [:1600](/home/linnea/linnea/src/server/linnea_hpack.asm:1600).
  The code implements that before it even examines the upstream response head:
  every case-insensitive field name `Upgrade` returns "not named" at
  [src/server/linnea_hpack.asm:1621](/home/linnea/linnea/src/server/linnea_hpack.asm:1621)
  through [:1629](/home/linnea/linnea/src/server/linnea_hpack.asm:1629).
- HTTP/1 deliberately excludes `Upgrade` from its fixed hop-by-hop list so a
  real 101 handshake can pass it through at
  [src/server/linnea_http.asm:393](/home/linnea/linnea/src/server/linnea_http.asm:393)
  through [:397](/home/linnea/linnea/src/server/linnea_http.asm:397). Its
  normal response loop asks the helper whether each field was named at
  [src/server/linnea_http.asm:3944](/home/linnea/linnea/src/server/linnea_http.asm:3944)
  through [:3956](/home/linnea/linnea/src/server/linnea_http.asm:3956), then
  copies the surviving line verbatim at
  [src/server/linnea_http.asm:4063](/home/linnea/linnea/src/server/linnea_http.asm:4063)
  through [:4070](/home/linnea/linnea/src/server/linnea_http.asm:4070).
- The actual tunnel branch is already known precisely: it runs only when the
  parsed upstream status is 101 at
  [src/server/linnea_http.asm:4100](/home/linnea/linnea/src/server/linnea_http.asm:4100)
  through [:4104](/home/linnea/linnea/src/server/linnea_http.asm:4104), and
  documents why that path needs the backend's `Upgrade` line at
  [src/server/linnea_http.asm:4175](/home/linnea/linnea/src/server/linnea_http.asm:4175)
  through [:4189](/home/linnea/linnea/src/server/linnea_http.asm:4189). The
  unconditional helper exception is therefore broader than its only purpose.

HTTP/2 and HTTP/3 do not leak this particular field: their fixed response
tables drop `upgrade` at
[src/server/linnea_http2.asm:5746](/home/linnea/linnea/src/server/linnea_http2.asm:5746)
through [:5761](/home/linnea/linnea/src/server/linnea_http2.asm:5761) and
[src/server/linnea_qpack.asm:83](/home/linnea/linnea/src/server/linnea_qpack.asm:83)
through [:108](/home/linnea/linnea/src/server/linnea_qpack.asm:108),
respectively. That protocol split makes the defect an HTTP/1-only regression
from the deliberately broad report-10 exception.

### Reproduction

An isolated loopback upstream returned exactly:

```text
HTTP/1.1 200 OK\r\n
Content-Length: 4\r\n
Connection: Upgrade\r\n
Upgrade: websocket\r\n
\r\n
body
```

The downstream request did not request an upgrade. Results from the same
Linnea instance were:

| Downstream protocol | Observed result |
| --- | --- |
| HTTP/1.1 | `200`, body `body`, `Connection: keep-alive`, and the incorrectly relayed `Upgrade: websocket` |
| HTTP/2 | `:status 200`, body `body`, no `upgrade` field |
| HTTP/3 | `:status 200`, `content-length: 4`, body `body`, no `upgrade` field |

HTTP/1 and HTTP/2 were captured with curl. The HTTP/3 field section and DATA
were decoded with aioquic. The replacement `Connection` value shows that this
is not failure to remove `Connection`; it is failure to honour its `Upgrade`
option on a response that is not a protocol switch.

### Impact

An upstream can expose a connection-local protocol instruction as ordinary
response metadata. A downstream client sees `Upgrade: websocket` attached to a
normal, completed 200 response even though its connection to Linnea neither
requested nor switched protocols. That contradicts the hop-by-hop boundary and
can mislead clients, middleware, diagnostics, and future upgrade handlers that
interpret the field as end-to-end metadata.

The error is especially easy to perpetuate because Linnea simultaneously emits
`Connection: keep-alive`. The downstream head therefore advertises a persistent
ordinary HTTP connection while retaining a field that the upstream explicitly
scoped to a different hop.

### Recommendation

Make the dynamic `Connection` filter generic: `Upgrade` must be considered
named just like every other option. Preserve it only in the existing HTTP/1
101-tunnel path, where both the accepted client upgrade and upstream status
have been checked. This can be done by filtering it in the normal head-copy
loop and explicitly emitting/copying the validated backend `Upgrade` field in
`.upgrade_head`, or by passing a narrowly scoped "real 101 tunnel" flag into
the helper. Do not make an ordinary status depend on a global field-name
exception.

Add a cross-protocol fixture for the exchange above. It should require that
HTTP/1 drops `Upgrade` on the 200 while preserving the body; HTTP/2 and HTTP/3
should remain field-free controls. Keep the existing successful websocket/101
test as the regression control proving the narrow exception still works.

### Resolution — FIXED (2026-08-19, `3f763c9`)

Correct in every particular, and it is my regression: `4bb11cb` added the
dynamic `Connection` walk yesterday and gave it the unconditional `upgrade`
exception, with a comment saying so. Reproduced immediately — `/api/upgrade200`
returned `200` with `Upgrade: websocket` relayed on HTTP/1, beside the
`Connection: keep-alive` we had just substituted, while HTTP/2 and HTTP/3 were
clean.

That protocol split is the instructive part. The exception was written to keep
the 101 tunnel working, and it did; it also silently widened the rule on the one
protocol that has no fixed-table backstop for `upgrade`. A global field-name
exception cannot be scoped by the comment that explains it.

`linnea_http_head_conn_named` is generic again — `upgrade` is matched like any
other name. The tunnel's requirement is narrower than a name, so it now lives
where it can be justified: HTTP/1's copy loop skips the check **only when
`up_status` is 101 and the field is `upgrade`**, at a point where both the
client's upgrade wish and the upstream status have already been checked. An
interim head never arrives there with 101 in `up_status`.

The suite's 13 WebSocket checks still pass, including the tunnel end to end
("websocket backend, through linnea's tunnel", "ws server push and 101
leftover") — those are the regression control the report asked to keep.

## Finding 2 — HTTP/3 sends transfer-coded bytes as identity content

Severity: **Medium (P2, response integrity and cross-protocol consistency)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

RFC 9112 section 6.1 defines `Transfer-Encoding` as the sequence of codings
used to form the HTTP/1.1 message body. It explicitly gives
`Transfer-Encoding: gzip, chunked` as the example of content first compressed
with `gzip` and then chunk-framed. The final `chunked` coding makes the
message's length detectable; decoding only that outer coding does not undo the
preceding gzip transformation.

The HTTP/3 path recognizes merely that `chunked` appears somewhere in the
value. It then enables the chunk decoder without recording or rejecting any
other transfer coding:

- `linnea_h3_proxy` finds `transfer-encoding`, uses `.ph_val_has` to search
  for `chunked`, and selects `capture_chunked` at
  [src/server/linnea_h3_proxy.asm:643](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:643)
  through [:678](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:678).
  `gzip, chunked` takes this path just as a sole `chunked` value does.
- The body routine removes only the chunk syntax through
  `linnea_spill_chunked` at
  [src/server/linnea_h3_proxy.asm:934](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:934)
  through [:989](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:989).
  Its spill file consequently contains the still-gzip-coded octets.
- QPACK unconditionally drops `transfer-encoding` from every proxied HTTP/3
  response at
  [src/server/linnea_qpack.asm:83](/home/linnea/linnea/src/server/linnea_qpack.asm:83)
  through [:108](/home/linnea/linnea/src/server/linnea_qpack.asm:108). At the
  same time, the delivery path tells that encoder to state the captured length
  at
  [src/server/linnea_h3_proxy.asm:1100](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:1100)
  through [:1129](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:1129),
  and the encoder documents that the emitted length is the bytes actually
  captured at
  [src/server/linnea_qpack.asm:782](/home/linnea/linnea/src/server/linnea_qpack.asm:782)
  through [:803](/home/linnea/linnea/src/server/linnea_qpack.asm:803).

Removing connection-specific fields is required when translating into HTTP/3;
RFC 9114 section 4.2 says such fields make an HTTP/3 message malformed. But
removing the field is safe only after the proxy has performed every transformation
the field describes. Here it removes `chunked` framing but silently retains the
`gzip` transfer coding in the bytes.

### Reproduction

An isolated loopback upstream generated a gzip member whose decompressed content
was `transfer-coded payload`, then returned it as this valid HTTP/1.1 response:

```text
HTTP/1.1 200 OK\r\n
Transfer-Encoding: gzip, chunked\r\n
\r\n
<one valid chunk containing the gzip member>\r\n
0\r\n
\r\n
```

| Downstream protocol | Observed result |
| --- | --- |
| HTTP/1.1 | The original transfer coding is retained; curl rejects it as an unsolicited `gzip` transfer coding rather than treating it as a normal identity response. |
| HTTP/2 | `502 Bad Gateway` |
| HTTP/3 | `:status 200`, `content-length: 42`, no `transfer-encoding`, and the 42-byte gzip member (`1f8b08...`) as DATA |

The HTTP/3 body was decoded with aioquic. Its bytes decompress to the upstream
content but are not themselves `transfer-coded payload`; neither a
`Transfer-Encoding` nor a `Content-Encoding` field accompanies them. As a
control, a response containing only `Transfer-Encoding: chunked` produced a
normal HTTP/3 `200`, `content-length: 5`, and DATA `plain`.

### Impact

An H3 client receives a syntactically valid success response whose content bytes
are not the upstream response content. Applications can store, display, parse,
hash, cache, or pass along the unexpected binary gzip member as though it were
the representation. HTTP/2 already chooses the safe failure for this upstream
response, while HTTP/3 silently turns it into a success, so clients negotiating
different downstream protocols observe materially different outcomes.

This is not a client preference issue. `Transfer-Encoding` is a property of the
HTTP/1 message, whereas `Content-Encoding` is a representation property;
rewriting the former to the latter would silently alter representation metadata.
Absent an implementation of the non-chunked transfer coding, the proxy cannot
faithfully express these bytes in HTTP/3.

### Recommendation

For HTTP/3, accept a transfer-encoded upstream response only when its coding
list is exactly a supported transformation that Linnea fully removes — today,
sole `chunked` is the evident supported case. If any additional coding is
present, including `gzip, chunked`, discard the upstream response and return
502 before sending downstream HEADERS. The same rule should cover a
close-delimited response with a non-chunked transfer coding.

Alternatively, implement every advertised transfer coding and ensure the
emitted HTTP/3 body represents the fully decoded content; merely dropping the
field or relabeling it as `Content-Encoding` is not equivalent. Add H3-specific
fixtures for `gzip, chunked` and bare `gzip`, requiring 502, beside the existing
`chunked` success control. Assert decoded fields and DATA bytes, not just a
status code.

### Resolution — FIXED (2026-08-19, `3f763c9`)

Confirmed, and **the report understates it**. It credits HTTP/2 with choosing
the safe failure. Measured, HTTP/2 refuses `gzip, chunked` — but a bare
`Transfer-Encoding: gzip` returns `200` with the 42-byte gzip member delivered
as identity content, which is precisely the defect attributed to HTTP/3 alone:

```
h2 /api/tegzip     -> 502
h2 /api/tegzipbare -> 42 bytes, 1f8b08...     <- a gzip member as the representation
```

So one upstream message drew three different answers per coding list:

| upstream | HTTP/1.1 | HTTP/2 | HTTP/3 |
| --- | --- | --- | --- |
| `Transfer-Encoding: gzip, chunked` | relayed the coding | `502` | `200` + gzip bytes |
| `Transfer-Encoding: gzip` | relayed the coding | `200` + gzip bytes | `200` + gzip bytes |

That is what a rule kept in three places does, and it is why the fix is not the
HTTP/3-only one the report recommends. **The rule now lives once, in the shared
upstream-head validator**: a `Transfer-Encoding` whose coding list is not exactly
`chunked` — OWS-trimmed, case-insensitive — is a bad gateway, on every protocol.
`chunked` is the one coding this proxy removes; anything else is a transformation
it cannot express downstream, and inventing a `Content-Length` for bytes it never
decoded is worse than refusing.

#### One consequence beyond the report's ask

This makes **HTTP/1 refuse where it used to relay**. The report does not ask for
that, so it is stated rather than slipped in. The justification: RFC 9112 6.1
forbids sending a transfer coding to a client that has not offered `TE`, and the
report itself records curl rejecting what we relayed — so the previous behaviour
was serving no one, and leaving it would preserve exactly the three-way
disagreement this fix exists to end. Scoping it back to HTTP/2 and HTTP/3 is a
one-line change if that is preferred.

#### The control earned its keep immediately

`/api/tepad` (`Transfer-Encoding:  Chunked `, with OWS and mixed case) is there
so the rule cannot degenerate into "refuse anything unfamiliar". It, and the
pre-existing `/api/chunked`, both failed on the first version of the fix:
`linnea_string_iequal` takes its length in `ecx`, so `rcx` was no longer the CR
offset when the code walked back over trailing OWS, and **every chunked response
became a 502**. The Content-Length path immediately below has the same hazard and
re-finds the CR; the new code now does too.

## Verification

Both findings were reproduced against the pre-fix binary before anything
changed, on one TLS listener serving all three protocols.

| route | before | after |
| --- | --- | --- |
| `/api/upgrade200` | h1 relays `Upgrade: websocket`; h2/h3 clean | dropped on all three |
| `/api/tegzip` | h1 relays coding, h2 `502`, h3 `200`+gzip | `502` on all three |
| `/api/tegzipbare` | h1 relays coding, h2 `200`+gzip, h3 `200`+gzip | `502` on all three |
| `/api/tepad`, `/api/chunked` | served | served, unchanged |
| websocket tunnel | works | works (13 checks) |

Cross-protocol matrix: **86 checks green**, from 5 failures before. Full suite
**767 passed, 0 failed**.

The matrix's HTTP/1 helper also had to learn to de-chunk: HTTP/1 relays chunked
framing *as framing*, which is the protocol and not a defect, so a chunked
route's body was comparing raw `5\r\nplain\r\n0\r\n\r\n` against what
HTTP/2 and HTTP/3 had decoded.

## Conclusion

One finding was a regression from the previous report's fix, and the shape of it
is worth keeping: an exception written to protect one narrow path was expressed
as a global name, and it widened a rule on the only protocol without a second
line of defence. The other was reported as an HTTP/3 defect and turned out to be
a three-way disagreement, which is the same lesson these reports keep arriving
at — a rule that must hold in three translators will eventually hold differently
in each. Both are single shared functions now.
