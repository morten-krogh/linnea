# Audit Report 13

Audited at `9a97cfb` (`test: the persistent-congestion check retries, and
stops asserting a theory`), 2026-08-19.

**Both findings are fixed in `c07a2df`**, verified against a pre-fix binary on
all three protocols, both at the shared gate as recommended.

Two upstream-response validation gaps remain open:

1. **Medium: the shared gate accepts HTTP status codes outside 100–599.** A
   `099` response is emitted to HTTP/1.1 clients as an informational response,
   while HTTP/2 and HTTP/3 reject the same upstream head with 502. Codes above
   599 pass through all three paths and are reissued as invalid downstream
   status codes.
2. **Medium: repeated `Transfer-Encoding: chunked` field lines are accepted.**
   Each line is checked in isolation, so two fields that collectively state
   `chunked, chunked` pass. HTTP/1.1 forwards the invalid duplicate framing;
   HTTP/2 and HTTP/3 de-chunk once, discard both fields, and present an ordinary
   success response.

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — The upstream gate accepts status codes outside HTTP's range

Severity: **Medium (P2, malformed-upstream handling and protocol
consistency)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

RFC 9110 section 15 says that all valid HTTP status codes are three-digit
integers in the inclusive range **100 through 599**. Three digits alone are
therefore necessary but insufficient validation.

The shared gate builds a numeric status from exactly three digit bytes at
[src/server/linnea_http.asm:3528](/home/linnea/linnea/src/server/linnea_http.asm:3528)
through [:3539](/home/linnea/linnea/src/server/linnea_http.asm:3539), but makes
no range check before returning success at
[src/server/linnea_http.asm:3831](/home/linnea/linnea/src/server/linnea_http.asm:3831)
through [:3833](/home/linnea/linnea/src/server/linnea_http.asm:3833). Thus
`000`, `099`, `600`, and `999` all pass the one validator that is meant to make
the three translation paths agree.

The emitters do not repair that omission consistently:

- HTTP/1 treats every status at or below 199 other than 101 as an interim
  response at [src/server/linnea_http.asm:3937](/home/linnea/linnea/src/server/linnea_http.asm:3951).
  It has no lower-bound check, so it forwards `099` and then accepts a following
  final response. Its output is a syntactically shaped HTTP/1.1 response stream
  containing an invalid status.
- HTTP/2 calls the shared gate first at
  [src/server/linnea_http2.asm:3996](/home/linnea/linnea/src/server/linnea_http2.asm:4004),
  then independently rejects values below 100 at
  [src/server/linnea_http2.asm:4063](/home/linnea/linnea/src/server/linnea_http2.asm:4074).
  It has no matching upper-bound check. A 600–999 value instead reaches the
  three-byte `:status` encoder at
  [src/server/linnea_http2.asm:4462](/home/linnea/linnea/src/server/linnea_http2.asm:4482).
- HTTP/3 has the same shape: it calls the gate at
  [src/server/linnea_h3_proxy.asm:608](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:613)
  and rejects only values below 100 at
  [src/server/linnea_h3_proxy.asm:627](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:634).

The later lower-bound checks do not make the common gate valid: they are after
the common decision, are absent from HTTP/1, and do nothing for a 6xx–9xx
number. This is the same placement problem as the earlier upstream-head
findings, just in the status code's semantic range rather than its byte grammar.

### Reproduction

An isolated loopback upstream returned this one write:

```text
HTTP/1.1 099 Invalid\r\n
X-Interim: should-not-pass\r\n
\r\n
HTTP/1.1 200 OK\r\n
Content-Length: 5\r\n
\r\n
final
```

The proxy was built at the audited commit. HTTP/1.1 was captured as raw TLS
bytes; HTTP/2 used curl; HTTP/3 used curl-h3.

| Downstream protocol | Observed result |
| --- | --- |
| HTTP/1.1 | Relayed `HTTP/1.1 099 Invalid` and `X-Interim`, then relayed `200` and `final` |
| HTTP/2 | `502 Bad Gateway` |
| HTTP/3 | `502 Bad Gateway` |

The invalid 099 is not an informational status that the proxy is required to
forward. It is outside HTTP's status-code namespace. The 200 is only included
to make HTTP/1's unintended interim classification visible; all three paths
should refuse the first head before it can be emitted.

The upper half is independently reachable: the validator admits `600` through
`999`, and the H2 encoder writes any such numeric value as three ASCII digits.
That turns an invalid upstream status into an invalid `:status`, rather than a
bad-gateway response.

### Impact

A faulty or compromised backend can make the response sequence depend on ALPN.
HTTP/1.1 clients receive a made-up informational response and its metadata;
HTTP/2 and HTTP/3 clients receive an explicit gateway failure. For an
above-range value every downstream protocol can receive a status that HTTP does
not define, leaving user agents, intermediaries, cache layers, and observability
tools to make incompatible recovery decisions.

Status-class tests are also framing and lifecycle tests. In this case `099` is
not merely displayed incorrectly: it selects HTTP/1's interim loop, which
changes when the proxy believes a response is complete and which headers become
visible before the actual final answer.

### Recommendation

Immediately after parsing the three digits in
`linnea_http_upstream_head_valid`, reject a value below 100 or above 599. Keep
the protocol-specific 101 rule: 101 is in the valid HTTP range but is
intentionally unsupported for H2/H3 proxy responses. The range rule itself
belongs at the common gate, before any translator emits an interim or final
head.

Add `/api/status099` and `/api/status600` fixtures to the cross-protocol
upstream-head matrix. Both must require 502, no relayed interim HEADERS/response
head, and no response content on every downstream protocol. Keep an unregistered
but in-range status such as 299 as a control: the proxy should forward valid
extension status codes rather than turn this fix into an allowlist.

### Resolution — FIXED (2026-08-19, `c07a2df`)

Reproduced exactly, and the report's point that this is a lifecycle question
rather than a display one is the part worth restating: h1 classified anything
at or below 199 as interim, so `099` did not merely look wrong — it selected the
interim loop, changing when the proxy believes a response is complete and which
fields reach the client before the real answer.

```
status099   h1: 99 (relayed as an interim, with X-Interim)   h2: 502   h3: 502
status600   600 on all three -- reissued downstream, including as an h2/h3 :status
status299   299 on all three
```

The range check now sits in `linnea_http_upstream_head_valid`, immediately after
the three digits are parsed. The translators' own lower-bound checks could not
have covered it: they run *after* the shared decision, HTTP/1 has none at all,
and none of the three looks upward.

`/api/status299` is kept as the control the report asked for, and it is the one
that matters most here — this is a **range, not an allowlist**. An unregistered
but in-range extension status must still be forwarded, and is.

## Finding 2 — Two `chunked` field lines pass as though they were one coding

Severity: **Medium (P2, response framing integrity and protocol consistency)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

RFC 9112 section 6.1 makes `Transfer-Encoding` a list of transfer codings and
says a sender **MUST NOT** apply the chunked coding more than once to a message
body. Repeated list-valued field lines combine in field order; therefore two
field lines that each say `chunked` represent `chunked, chunked`, an illegal
claim of two chunk layers. One outer chunked body does not satisfy that claim.

The shared validator holds only a boolean “a Transfer-Encoding was seen” at
[src/server/linnea_http.asm:3497](/home/linnea/linnea/src/server/linnea_http.asm:3497)
through [:3503](/home/linnea/linnea/src/server/linnea_http.asm:3503). For each
matching line it sets that same bit at
[src/server/linnea_http.asm:3650](/home/linnea/linnea/src/server/linnea_http.asm:3661),
then verifies that **that line alone** trims to the single token `chunked` at
[src/server/linnea_http.asm:3686](/home/linnea/linnea/src/server/linnea_http.asm:3718).
It never rejects the second occurrence or evaluates the combined list. Two
`Transfer-Encoding: chunked` lines consequently pass `.hv_ok`.

The translators then make incompatible choices about the bad head:

- HTTP/1 marks its single local framing flag for every `Transfer-Encoding` line
  and copies the original field line at
  [src/server/linnea_http.asm:4071](/home/linnea/linnea/src/server/linnea_http.asm:4082).
  It therefore sends both transfer-coding fields and the one-layer chunked body
  to the client.
- HTTP/2 finds only the first matching `Transfer-Encoding` value to enable its
  one-layer de-chunker at
  [src/server/linnea_http2.asm:4008](/home/linnea/linnea/src/server/linnea_http2.asm:4024).
  Its response-field table then removes every `transfer-encoding` line at
  [src/server/linnea_http2.asm:5748](/home/linnea/linnea/src/server/linnea_http2.asm:5773).
- HTTP/3 likewise finds one matching value and captures one chunk layer at
  [src/server/linnea_h3_proxy.asm:643](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:661),
while QPACK's drop table removes every `transfer-encoding` field at
  [src/server/linnea_qpack.asm:83](/home/linnea/linnea/src/server/linnea_qpack.asm:108).

This is not the legal duplicate-`Content-Length` case addressed by report 6.
Identical content lengths describe the same body size and are specifically
reconciled by the shared gate. Repeating `chunked` describes a second
transformation that is forbidden and which Linnea does not perform.

### Reproduction

The loopback upstream returned a single chunk layer with a duplicated field:

```text
HTTP/1.1 200 OK\r\n
Transfer-Encoding: chunked\r\n
Transfer-Encoding: chunked\r\n
\r\n
4\r\n
body\r\n
0\r\n
\r\n
```

| Downstream protocol | Observed result |
| --- | --- |
| HTTP/1.1 | `200`, both `Transfer-Encoding: chunked` lines, and body `body` |
| HTTP/2 | `200`, body `body`, no `transfer-encoding` field |
| HTTP/3 | `200`, `content-length: 4`, body `body`, no `transfer-encoding` field |

HTTP/1 and HTTP/2 were recorded with curl/raw TLS; HTTP/3 was recorded with
curl-h3. The backend did not send two chunk encodings; it sent the normal one
layer whose data is shown above. Thus the binary-protocol paths have silently
normalised an invalid upstream framing declaration, while HTTP/1 exports it.

### Impact

The same malformed backend response is either relayed as invalid transfer
framing or converted into a normal-looking identity response, depending on the
client's negotiated protocol. That hides an upstream protocol error from H2/H3
clients and exposes a body/header framing contradiction to H1 clients. A client
or intermediary that combines the H1 field values correctly sees an unsupported
second chunking layer; a lenient client might ignore the duplicate, creating
exactly the parser differential a proxy should not propagate.

The defect is small in code but sits at a security-sensitive boundary: transfer
framing decides where a message ends. The project already rejects coding lists
it cannot remove and rejects `Transfer-Encoding` plus `Content-Length`; allowing
the one syntactic form that says “remove chunked twice” reopens a per-protocol
normalisation gap beside those rules.

### Recommendation

Make the shared upstream gate validate the complete `Transfer-Encoding` field
set, not each line independently. For the current implementation, accept
exactly one effective coding token, `chunked`, with optional surrounding OWS;
reject a second field line and any comma-containing list before a translator
chooses framing. A count is sufficient for the intentionally narrow policy,
though parsing the combined list explicitly makes the reason clearer.

Add `/api/tedupe` to the cross-protocol matrix. It must require 502 everywhere,
with no H1 transfer-coding line and no H2/H3 successful response. Keep the
existing single-line `/api/chunked` and OWS/case `/api/tepad` routes as controls.

### Resolution — FIXED (2026-08-19, `c07a2df`)

Reproduced: HTTP/1 relayed **both** `Transfer-Encoding: chunked` lines alongside
a single-layer body, while HTTP/2 and HTTP/3 de-chunked once, dropped both
fields, and returned an ordinary-looking `200`.

The gate now counts `Transfer-Encoding` field lines and refuses a second, before
any translator chooses framing. A count suffices because the surrounding policy
is already "exactly one coding, and it must be `chunked`" — the value check
added in report 11 rejects any comma-bearing list on its own, so the two rules
together admit exactly one spelling.

**The distinction from report 6 is written into the code**, not just into this
report, because the two look alike and the wrong generalisation would have
broken `/api/cldupe`: two identical `Content-Length` lines describe the *same
body* and are reconciled; a second `chunked` describes a *second transformation*
that does not exist and cannot be reconciled with anything.

## Verification

| route | before | after |
| --- | --- | --- |
| `/api/status099` | h1 `99` relayed as an interim; h2/h3 `502` | `502` on all three |
| `/api/status600` | `600` on all three | `502` on all three |
| `/api/status299` | `299` on all three | unchanged — the control |
| `/api/tedupe` | h1 relayed both fields; h2/h3 `200` | `502` on all three |
| `/api/chunked`, `/api/tepad` | served | served, unchanged |

Cross-protocol matrix: **111 checks green**, from 3 failures before. Full suite
**767 passed, 0 failed**.

## Conclusion

Both were where the report said they were, and both fixes are two comparisons
each — the interesting part is placement rather than logic. The status range is
the clearer illustration: three separate lower-bound checks already existed in
the translators, and they were worth nothing here, because a rule applied after
the shared decision cannot stop the shared decision from being wrong, and one of
the three protocols had never had the check at all.

## Conclusion (as filed)

Both defects bypass the shared gate that previous audits correctly established
as the upstream boundary. The first lets a numeric-looking but non-HTTP status
reach different lifecycle decisions. The second lets individually acceptable
field lines form a collectively impossible transfer-coding chain. Both should
be rejected before HTTP/1, HTTP/2, or HTTP/3 begins translating the response.
