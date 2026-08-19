# Audit Report 10

Audited at `6f8ea04` (`audit-report-9: both findings FIXED`), 2026-08-18.

**Both findings are fixed in `4bb11cb`**, verified against a pre-fix binary on
all three protocols; resolutions are recorded under each. Two shapes beyond the
report's own reproductions are covered as well, and are noted where they matter.

Two further proxy-response normalization issues remain:

1. **Medium: a proxied `205 Reset Content` is allowed to carry and deliver a
   body.** The HTTP/1, HTTP/2, and HTTP/3 paths all special-case 204 and 304,
   but omit the equally bodyless 205 status. A four-byte upstream 205 is
   relayed as a four-byte client response on all three protocols.
2. **Medium: fields nominated by an upstream `Connection` header are relayed.**
   Linnea strips `Connection` itself and the fixed known hop-by-hop names, but
   not an arbitrary field that the upstream declares connection-specific.
   `Connection: X-Backend-Only` therefore still exposes
   `X-Backend-Only: leaked` to HTTP/1, HTTP/2, and HTTP/3 clients.

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — A 205 response carries a body

Severity: **Medium (P2, response semantics and cross-protocol consistency)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

RFC 9110 section 15.3.6 says that a 205 response implies no additional content
and that a server **MUST NOT** generate content in one. It is not an alias for a
normal successful response with an optional empty body: the sender must make
the zero-length termination unambiguous.

Linnea has three independent lists of response cases that carry no body. Each
includes a HEAD request, 204, and 304; none includes 205:

- HTTP/1 selects `.no_body` only for HEAD, 204, and 304 at
  [src/server/linnea_http.asm:4024](/home/linnea/linnea/src/server/linnea_http.asm:4024)
  through [:4041](/home/linnea/linnea/src/server/linnea_http.asm:4041). A 205
  therefore takes the ordinary `Content-Length` path, and the same rewriter
  has already copied its `Content-Length` to the downstream head at
  [src/server/linnea_http.asm:3968](/home/linnea/linnea/src/server/linnea_http.asm:3968)
  through [:3982](/home/linnea/linnea/src/server/linnea_http.asm:3982).
- HTTP/2's final-response branch likewise sets `F_NO_BODY` only for HEAD,
  204, and 304 at
  [src/server/linnea_http2.asm:4075](/home/linnea/linnea/src/server/linnea_http2.asm:4075)
  through [:4087](/home/linnea/linnea/src/server/linnea_http2.asm:4087).
  The unmarked 205 is emitted with ordinary DATA frames.
- HTTP/3 makes the same framing decision at
  [src/server/linnea_h3_proxy.asm:700](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:700)
  through [:718](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:718).
  Without `.h3_nobody`, the body is captured; delivery then derives and emits
  a Content-Length from that capture at
  [src/server/linnea_h3_proxy.asm:1099](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:1099)
  through [:1125](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:1125).

The `linnea_http_status_no_clen` helper added by report 9 correctly limits its
different rule to 1xx and 204 at
[src/server/linnea_http.asm:3416](/home/linnea/linnea/src/server/linnea_http.asm:3416)
through [:3437](/home/linnea/linnea/src/server/linnea_http.asm:3437): a 205
may have a `Content-Length` only to make clear that it is zero. It cannot be
used as the no-content predicate, which is why the omission is easy to miss.

### Reproduction

An isolated loopback upstream returned exactly:

```text
HTTP/1.1 205 Reset Content\r\n
Content-Length: 4\r\n
\r\n
body
```

The same TLS request was sent over all three downstream protocols:

| Downstream protocol | Observed result |
| --- | --- |
| HTTP/1.1 | `205 Reset Content`, `Content-Length: 4`, body `body`, and `Connection: keep-alive` |
| HTTP/2 | `:status 205`, `content-length: 4`, one four-byte DATA body `body` |
| HTTP/3 | `:status 205`, `content-length: 4`, one four-byte DATA body `body` |

The HTTP/3 row was decoded with aioquic, not inferred from the QPACK encoder.
The HTTP/1 and HTTP/2 rows were independently captured by curl. Thus this is
not just a missing condition in one translator: all three turn an upstream
message that must have no content into a normal body-bearing client response.

### Impact

A backend error, compromise, or simply a 205 implementation that trusts the
proxy to enforce HTTP semantics reaches clients with content where the status
forbids it. HTTP/2 and HTTP/3 clients receive a syntactically ordinary DATA
sequence that contradicts the response's meaning. HTTP/1 is worse for clients
that honor 205's no-content semantics while retaining the keep-alive connection:
the proxy has declared four bytes of content behind a response for which such
clients are entitled to expect none, so client and proxy can lose agreement on
where the next response begins.

### Recommendation

Add one shared *no-content* status predicate and use it in all three response
framing paths. It must include 205 in addition to the existing HEAD, 1xx, 204,
and 304 cases; do not conflate it with report 9's narrower
`Content-Length`-forbidden predicate.

At the malformed-upstream boundary, reject a 205 that announces nonzero
content (or that later produces bytes) with 502 before a downstream head is
sent. A compliant `205 Content-Length: 0` control should still complete with
no HTTP/1 body, no HTTP/2 DATA, and no HTTP/3 DATA. If the project instead
chooses normalization, it must suppress the content and use only a zero-length
termination on HTTP/1; passing through `Content-Length: 4` while dropping its
body would create a different framing error.

Add `/api/205body` to `proxy_backend.py` with the exchange above and make the
cross-protocol matrix require 502 (or the chosen fully normalized no-content
answer). Pair it with `/api/205zero` so the legal zero-content case stays
served. The assertions need to inspect fields and DATA/body bytes, not merely
the status code.

### Resolution — FIXED (2026-08-19, `4bb11cb`)

Reproduced exactly as reported: `/api/205body` returned `205` with
`Content-Length: 4` and the body `body` on HTTP/1.1, HTTP/2 and HTTP/3.

The rule is now one predicate, **`linnea_http_status_no_content`** (1xx, 204,
205, 304 — HEAD stays the caller's business, since it depends on the request),
used by all three framing paths.

The report's warning against conflating it with report 9's predicate turned out
to be the whole explanation for the omission, so it is written into the code:
`linnea_http_status_no_clen` answers *may this response carry a Content-Length
**field***, `linnea_http_status_no_content` answers *may it carry **content***.
They part company on 205, which may carry a `Content-Length` precisely in order
to say zero. 205 was missing from three framing lists because the report-9
predicate looked like it already covered it.

**A 205 that frames content is refused with 502**, in the shared validator, so
the three protocols agree without being told separately. Refused rather than
normalised, for the reason the report gives: relaying `Content-Length: 4` with
no body is a different framing error, and dropping both leaves four bytes in the
upstream buffer that the next response on a kept-alive connection would be read
out of.

**One deliberate strictness, recorded so it stays a decision:** a 205 carrying
`Transfer-Encoding` is also refused. RFC 9110 15.3.6 does permit an empty
chunked section, but nothing can know the section is empty without reading it,
and the alternative is relaying content on a status that must have none.

Controls, which stop the fix becoming "refuse every 205": `/api/205zero`
(`Content-Length: 0`) and `/api/205bare` (no framing at all) both still serve
`205` with no body, no DATA frame and no HTTP/3 DATA, on all three protocols.

## Finding 2 — `Connection`-nominated response fields cross the proxy

Severity: **Medium (P2, hop-by-hop metadata exposure and protocol
conformance)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

RFC 9110 section 7.6.1 requires an intermediary to parse a received
`Connection` field and remove every field whose name it lists before forwarding
the message, then remove or replace `Connection` itself. This is deliberately
not a fixed list: the field is the extensibility mechanism for future
connection-specific options.

Linnea handles the fixed list but never applies the equivalent dynamic rule to
an upstream response:

- HTTP/1 drops a `Connection` line at
  [src/server/linnea_http.asm:3851](/home/linnea/linnea/src/server/linnea_http.asm:3851)
  through [:3857](/home/linnea/linnea/src/server/linnea_http.asm:3857), then
  checks only `http_hop_by_hop` at
  [src/server/linnea_http.asm:3858](/home/linnea/linnea/src/server/linnea_http.asm:3858)
  through [:3868](/home/linnea/linnea/src/server/linnea_http.asm:3868). Any
  other valid header line follows `.copy_line` to the client at
  [src/server/linnea_http.asm:3975](/home/linnea/linnea/src/server/linnea_http.asm:3975)
  through [:3982](/home/linnea/linnea/src/server/linnea_http.asm:3982).
- HTTP/2's response encoder makes its decision solely from the fixed
  `h2p_dropped_tab` through `h2p_name_dropped` at
  [src/server/linnea_http2.asm:4681](/home/linnea/linnea/src/server/linnea_http2.asm:4681)
  through [:4716](/home/linnea/linnea/src/server/linnea_http2.asm:4716), then
  HPACK-encodes every remaining field at
  [src/server/linnea_http2.asm:4510](/home/linnea/linnea/src/server/linnea_http2.asm:4510)
  through [:4588](/home/linnea/linnea/src/server/linnea_http2.asm:4588).
- HTTP/3 follows the same fixed-table pattern. `qp_drop_tab` has `connection`
  and the standard known names at
  [src/server/linnea_qpack.asm:83](/home/linnea/linnea/src/server/linnea_qpack.asm:83)
  through [:107](/home/linnea/linnea/src/server/linnea_qpack.asm:107), but
  `.ep_classify` has no input for the names nominated by the current head at
  [src/server/linnea_qpack.asm:985](/home/linnea/linnea/src/server/linnea_qpack.asm:985)
  through [:1066](/home/linnea/linnea/src/server/linnea_qpack.asm:1066).

The project already has a correct token-list walk for the inbound direction:
`http_conn_option_named` is expressly documented as the RFC 9110 rule at
[src/server/linnea_http.asm:654](/home/linnea/linnea/src/server/linnea_http.asm:654)
through [:750](/home/linnea/linnea/src/server/linnea_http.asm:750). It reads
the **client** connection options stored in `conn_opts`; no corresponding
upstream-response value is retained or queried by the three emitters. The
existing `/api/hopresp` fixture proves only the constant-name filter: it sends
no `Connection` field that names `X-Kept`, so it cannot exercise this rule.

For HTTP/2 and HTTP/3 the result is also a direct protocol violation. Both RFC
9113 section 8.2.2 and RFC 9114 section 4.2 require an HTTP/1.x-to-H2/H3
intermediary to remove the connection-specific fields named under RFC 9110
section 7.6.1.

### Reproduction

An isolated loopback upstream returned:

```text
HTTP/1.1 200 OK\r\n
Content-Length: 4\r\n
Connection: X-Backend-Only\r\n
X-Backend-Only: leaked\r\n
\r\n
body
```

| Downstream protocol | Observed result |
| --- | --- |
| HTTP/1.1 | `200`, body `body`; `Connection` is replaced, but `X-Backend-Only: leaked` is present |
| HTTP/2 | `:status 200`, body `body`, `x-backend-only: leaked` is HPACK-encoded |
| HTTP/3 | `:status 200`, body `body`, `x-backend-only: leaked` is QPACK-encoded |

The H2 fields were decoded by curl and the H3 fields by aioquic. The upstream
`Connection` line itself is absent in each result, which identifies the exact
missing half of the rule rather than a general failure to filter hop-by-hop
fields.

### Impact

An upstream can intentionally or accidentally export metadata that was scoped
only to its connection to Linnea. The declared name is unconstrained: it might
be a private routing, authentication, debugging, or future extension field.
The receiving client cannot distinguish that leaked backend-only field from an
ordinary end-to-end response field. HTTP/2 and HTTP/3 clients additionally
receive an HTTP/1-derived field section the proxy was required to normalize
before translating.

The request direction already closes the analogous header-smuggling primitive.
Leaving the response direction open means the same boundary is only enforced
when data travels toward the backend, not when the backend controls client
metadata.

### Recommendation

Parse every upstream `Connection` field before emitting any response head,
including interim heads. Apply the resulting case-insensitive token set to
every non-`Connection` field in that head, in addition to the fixed hop-by-hop
table. The implementation should handle repeated `Connection` lines and OWS
the same way it handles a request's connection options. Keep the HTTP/1 101
tunnel handshake as an explicit, narrowly scoped exception for the `Upgrade`
field it must forward; H2 and H3 already reject a 101 upstream response.

Extend `/api/hopresp` or add `/api/hopnamed` with the exchange above. Require
that `connection` and `x-backend-only` are absent from all H1/H2/H3 field
sections while an unrelated `X-Kept: yes` control remains present. Add the
same named field to a 103 fixture so the interim rewriters cannot drift from
the final-head rule.

### Resolution — FIXED (2026-08-19, `4bb11cb`)

Reproduced on all three protocols, and on two shapes the report did not test —
both of which mattered.

**`linnea_http_head_conn_named`** walks a head's `Connection` lines as a token
list and answers whether a given field name is nominated. Every emitter asks it
about every field, in addition to its fixed table: HTTP/1's copy loop,
`h2p_emit_headers`, and QPACK's `.ep_walk`.

It lives in `linnea_hpack.asm` rather than `linnea_http.asm` because
`linnea_qpack.o` is linked by four test harnesses that have no `linnea_http.o`
— the same constraint that put `linnea_http_authority_host` there. All four
harnesses were re-linked to confirm it.

`upgrade` is never matched, exactly as on the request side and as the report
asks: the 101 tunnel only completes if the backend's `Upgrade` field reaches the
client. That exception is unconditional rather than 101-only, matching
`http_conn_option_named`, and the WebSocket path is covered by the suite.

#### The two shapes beyond the report

- **`/api/hopnamedmulti`** — two `Connection` lines, tokens separated by commas
  with SP and HTAB around them, mixed case, and `close` among them. All three of
  `X-One`, `X-Two`, `X-Three` were relayed before; none is now. A single-line,
  single-token reproduction would have been satisfied by a much weaker fix.
- **`/api/earlyhop`** — a **103 interim head** that nominates `X-Hint-Only`.
  Every protocol has a separate rewriter for interim heads, which is precisely
  where a rule drifts; the report anticipated this and asked for it.

`X-Kept: yes` rides alongside in both, and is asserted present, so the filter
cannot quietly become "drop everything unfamiliar". The existing `/api/hopresp`
fixture is unchanged and still passes.

## Verification

Both findings were reproduced against the pre-fix binary before anything was
changed, on one TLS listener serving all three protocols against an isolated
loopback backend.

| route | before | after |
| --- | --- | --- |
| `/api/205body` | `205` + `Content-Length: 4` + body, all three | `502`, all three |
| `/api/205chunked` | `205` + chunked body, all three | `502`, all three |
| `/api/205zero`, `/api/205bare` | `205`, no body (correct) | unchanged |
| `/api/hopnamed` | `X-Backend-Only: leaked` relayed, all three | dropped, all three |
| `/api/hopnamedmulti` | `X-One`, `X-Two`, `X-Three` all relayed | all dropped |
| `/api/earlyhop` | `X-Hint-Only` on the 103, all three | dropped, all three |
| `/api/hopresp`, `X-Kept` | controls | unchanged |

The cross-protocol matrix's control run failed in **exactly five places** before
the change and reports **77 checks green** after. Full suite **767 passed, 0
failed**.

One honest note about that suite run: the first full run failed a
timing-sensitive HTTP/3 persistent-congestion check. It passed alone (204/204)
and on the re-run, and it downloads a **static** file — so none of the code
changed here is on its path. Recorded rather than quietly re-run.

## Conclusion

Both fixed, both covered by tests that fail against the pre-fix binary. The
report's closing observation was the useful one and is now literal: a response
can have no content without every form of `Content-Length` being banned, and
hop-by-hop filtering includes the names the current peer declares, not only the
names the implementation already knows. Each is one shared function now, rather
than a fact three translators are each expected to remember.

### The audit's own verification, for the record

The two findings were tested against the unmodified `6f8ea04` binary with an
isolated loopback backend, one TLS listener configured for H1/H2/H3, curl for
HTTP/1.1 and HTTP/2, and the repository's aioquic dependency for HTTP/3.

| upstream exchange | HTTP/1.1 | HTTP/2 | HTTP/3 |
| --- | --- | --- | --- |
| `205` + `Content-Length: 4` + `body` | `205`, header and body relayed | `205`, header and DATA relayed | `205`, header and DATA relayed |
| `Connection: X-Backend-Only` + named field | named field relayed | named field relayed | named field relayed |

The existing `hopresp` controls still explain why the defect survived: they
cover fixed hop-by-hop names and preserve an unrelated field, but never make
that unrelated field a `Connection` option. The existing 204 tests likewise
cover a status whose Content-Length is forbidden, not 205's separate
zero-content requirement.

## Conclusion

Report 9 centralized two narrowly phrased rules, but response semantics still
live in three translators. The next corrections should make the two broader
facts explicit and shared: a response can have no content without banning all
forms of `Content-Length`, and hop-by-hop filtering includes the names the
current peer declares, not only the names the implementation already knows.
