# Audit Report 12

Audited at `a79e1e1` (`audit-report-11: record that the h1 refusal is a
confirmed decision`), 2026-08-19.

**Both findings are fixed in `8168d78`**, verified against a pre-fix binary on
all three protocols. Both are fixed at the shared gate rather than in the
translators, which is what the report asks for and what the interim case makes
necessary. One observation about the test suite, unrelated to these findings, is
recorded at the end.

Two further upstream-response translation issues remain:

1. **Medium: forbidden `Transfer-Encoding` survives the shared upstream-head
   gate on 1xx and 204 responses.** HTTP/1.1 consequently emits an invalid 204
   with `Transfer-Encoding: chunked`, while HTTP/2 and HTTP/3 silently remove
   the field and return a clean success. An invalid interim response produces
   three different client-visible sequences.
2. **Medium: HTTP/2 and HTTP/3 silently discard valid response field names
   longer than 64 bytes.** HTTP/1.1 forwards the same field. The field-name
   limit is an encoder scratch-buffer limit, not an HTTP limit or configured
   policy, so a valid unrecognized extension field disappears solely when the
   client negotiates H2 or H3.

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — Prohibited transfer framing is accepted on 1xx and 204

Severity: **Medium (P2, malformed-upstream handling and cross-protocol
consistency)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

RFC 9112 section 6.1 is explicit: a server **MUST NOT** send
`Transfer-Encoding` in any 1xx or 204 response. Those statuses are also
terminated at the first empty line and cannot carry a message body regardless
of the fields present. This is not the special 205 rule from report 10; 205
may use transfer framing to make its required zero-length termination
unambiguous, whereas 1xx and 204 may not carry the field at all.

The shared upstream validator recognizes and validates a `Transfer-Encoding`
value, setting its framing-seen flag at
[src/server/linnea_http.asm:3645](/home/linnea/linnea/src/server/linnea_http.asm:3645)
through [:3656](/home/linnea/linnea/src/server/linnea_http.asm:3656), and now
correctly refuses a coding list other than sole `chunked` at
[src/server/linnea_http.asm:3657](/home/linnea/linnea/src/server/linnea_http.asm:3657)
through [:3713](/home/linnea/linnea/src/server/linnea_http.asm:3713). Its
only status-aware `Transfer-Encoding` rejection, however, is the deliberately
strict 205 branch at
[src/server/linnea_http.asm:3783](/home/linnea/linnea/src/server/linnea_http.asm:3783)
through [:3805](/home/linnea/linnea/src/server/linnea_http.asm:3805). A 1xx
or 204 with the otherwise accepted value `chunked` reaches `.hv_ok_go` as a
valid upstream head.

The three translators then diverge:

- HTTP/1 identifies `Transfer-Encoding`, marks it as its upstream framing, and
  copies the original line at
  [src/server/linnea_http.asm:4046](/home/linnea/linnea/src/server/linnea_http.asm:4046)
  through [:4057](/home/linnea/linnea/src/server/linnea_http.asm:4057). The
  no-content status predicate later prevents body relay but does not remove the
  already copied line at
  [src/server/linnea_http.asm:4191](/home/linnea/linnea/src/server/linnea_http.asm:4191)
  through [:4207](/home/linnea/linnea/src/server/linnea_http.asm:4207). Thus
  it manufactures an HTTP/1.1 response whose status forbids the field.
- HTTP/2 and HTTP/3 must not encode `Transfer-Encoding`, since it is
  connection-specific in those protocols. Their fixed drop tables include the
  name at
  [src/server/linnea_http2.asm:5741](/home/linnea/linnea/src/server/linnea_http2.asm:5741)
  through [:5766](/home/linnea/linnea/src/server/linnea_http2.asm:5766) and
  [src/server/linnea_qpack.asm:83](/home/linnea/linnea/src/server/linnea_qpack.asm:83)
  through [:108](/home/linnea/linnea/src/server/linnea_qpack.asm:108).
  Instead of rejecting the bad backend response at the common boundary, they
  turn it into a successful field-free 204.
- The interim paths disagree further. HTTP/1 notices its local framing flag and
  rejects an interim `Transfer-Encoding` at
  [src/server/linnea_http.asm:4156](/home/linnea/linnea/src/server/linnea_http.asm:4156)
  through [:4176](/home/linnea/linnea/src/server/linnea_http.asm:4176), but
  HTTP/2 has already selected an interim response after the same shared
  validation at
  [src/server/linnea_http2.asm:4063](/home/linnea/linnea/src/server/linnea_http2.asm:4075).
  Its encoder drops the offending field; the following chunk terminator is
  then read as the next response head and eventually yields 502.

### Reproduction

An isolated loopback upstream returned a 204 with both forbidden framing and
a nonempty chunk:

```text
HTTP/1.1 204 No Content\r\n
Transfer-Encoding: chunked\r\n
\r\n
5\r\n
body!\r\n
0\r\n
\r\n
```

The status itself means the five content bytes must not be treated as response
content; the defect is that Linnea accepts this invalid upstream head and makes
protocol-dependent choices about it.

| Downstream protocol | Observed result |
| --- | --- |
| HTTP/1.1 | `204 No Content`, `Transfer-Encoding: chunked`, `Connection: keep-alive`, and no relayed body |
| HTTP/2 | `:status 204`, no `transfer-encoding`, no DATA |
| HTTP/3 | `:status 204`, no `transfer-encoding`, no DATA |

The H1 response was captured as raw TLS bytes, H2 with curl, and H3 by decoding
the QPACK field section and DATA with aioquic. The zero-chunk variant has the
same results, so it is the prohibited field rather than the nonempty chunk that
opens the gap.

The 1xx half is independently observable. An upstream sequence of `103 Early
Hints` with `Transfer-Encoding: chunked` and a zero chunk, followed by a normal
200, produced these outcomes:

| Downstream protocol | Observed result |
| --- | --- |
| HTTP/1.1 | only `502 Bad Gateway` |
| HTTP/2 | a field-scrubbed `103` followed by `502 Bad Gateway` |
| HTTP/3 | only `502 Bad Gateway` |

All three should reject this head consistently before translating any part of
it. Relaying a sanitized 103 first is not a safe recovery: it tells a client
that valid early metadata was received when the upstream response is malformed.

### Impact

A faulty or compromised backend can make the response semantics depend on the
client's negotiated HTTP version. HTTP/1 clients receive a response that RFC
9112 forbids; H2 and H3 clients receive a normal-looking 204 that hides the
backend protocol error. For an interim response, H2 alone receives an early
header block before the error response, so clients can act on hints that the
other protocol paths never expose.

The project has deliberately chosen to reject 205 plus transfer framing because
it cannot safely establish no content without consuming the framing. Leaving
the absolute 1xx/204 prohibition outside that same shared decision recreates
the very per-translator drift the shared validator was introduced to stop.

### Recommendation

Extend `linnea_http_upstream_head_valid`'s status-aware framing rule: when the
parsed status is 100–199 or 204, any `Transfer-Encoding` field must make the
upstream response invalid and cause a 502 on all three protocols. Do this
before a translator emits an interim or final downstream head. Keep the 205
decision distinct and documented: it is a no-content status with different
field rules.

Add `/api/204te` and `/api/earlyte` fixtures to the cross-protocol upstream
matrix. Each must require 502, no response body/DATA, and no relayed interim
head. Include `204` without the field, the existing `205zero`, and a normal
`Transfer-Encoding: chunked` 200 as controls.

### Resolution — FIXED (2026-08-19, `8168d78`)

Reproduced exactly, including the part that made the placement obvious.

`linnea_http_upstream_head_valid` now refuses any `Transfer-Encoding` on a
status of 100–199 or 204, before a translator emits anything. The 205 branch is
untouched and stays documented as the different rule it is: 205 is a no-content
status that *may* carry framing to make its zero-length termination
unambiguous, where 1xx and 204 may not carry the field at all.

**The interim case is why this had to be at the gate rather than in each
emitter.** For a `103` with `Transfer-Encoding`, HTTP/2 emitted **two HEADERS
frames** — a field-scrubbed `103`, then a `502` — so a client was told valid
early metadata had arrived when the upstream response was malformed. Measured:

```
before   /api/earlyte -> 2 HEADERS frames
after    /api/earlyte -> 1 HEADERS frame
control  /api/early   -> 2 HEADERS frames, unchanged
```

That last row is the control that stops the fix from becoming "refuse interim
heads": a legitimate `103` still relays.

## Finding 2 — H2 and H3 drop valid field names at 65 bytes

Severity: **Medium (P2, response metadata integrity and protocol
consistency)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

RFC 9110 section 5.1 defines a field name as `token`; it does not impose a
64-byte limit. More importantly for a proxy, that section says a proxy **MUST
forward unrecognized header fields** unless the name is listed by `Connection`
or the proxy is specifically configured to block or transform it. HTTP/2 and
HTTP/3 require lowercased names when encoding, but neither defines this
64-byte field-name cutoff.

Linnea's shared gate accepts any token field name; after finding the colon it
passes the complete span to `linnea_string_is_token` at
[src/server/linnea_http.asm:3602](/home/linnea/linnea/src/server/linnea_http.asm:3602)
through [:3611](/home/linnea/linnea/src/server/linnea_http.asm:3611). HTTP/1
then applies the legitimate hop-by-hop and `Connection` filters and copies a
surviving line without a length cap at
[src/server/linnea_http.asm:3978](/home/linnea/linnea/src/server/linnea_http.asm:3978)
through [:4057](/home/linnea/linnea/src/server/linnea_http.asm:4057).

The two binary-protocol emitters instead use a 64-byte lowercase scratch buffer
and silently skip a field whose valid name needs one more byte:

- HTTP/2 checks `name length > 64` and branches to `.eh_next` at
  [src/server/linnea_http2.asm:4524](/home/linnea/linnea/src/server/linnea_http2.asm:4524)
  through [:4531](/home/linnea/linnea/src/server/linnea_http2.asm:4531). The
  storage that creates this policy is only `h2p_nmbuf: resb 64` at
  [src/server/linnea_http2.asm:5813](/home/linnea/linnea/src/server/linnea_http2.asm:5813).
- QPACK has the identical `> 64` skip at
  [src/server/linnea_qpack.asm:839](/home/linnea/linnea/src/server/linnea_qpack.asm:839)
  through [:846](/home/linnea/linnea/src/server/linnea_qpack.asm:846), backed
  by `qp_nmbuf: resb 64` at
  [src/server/linnea_qpack.asm:156](/home/linnea/linnea/src/server/linnea_qpack.asm:156).

This is not a forbidden field being correctly filtered. The shared validator
has accepted it, it is absent from both fixed drop tables, the upstream did not
name it in `Connection`, and no configuration supplies the 64-byte policy.
It is simply erased before either encoder lowers and emits it.

### Reproduction

An isolated loopback upstream returned a normal body-bearing response with an
otherwise unrecognized header whose name is `X-` followed by 63 `a` bytes:

```text
HTTP/1.1 200 OK\r\n
Content-Length: 4\r\n
X-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: kept\r\n
\r\n
body
```

The field name is 65 bytes and is a valid HTTP token. Results:

| Downstream protocol | Observed result |
| --- | --- |
| HTTP/1.1 | `200`, body `body`, and the 65-byte `X-aaa...` field with value `kept` |
| HTTP/2 | `:status 200`, body `body`, but no such field |
| HTTP/3 | `:status 200`, body `body`, but no such field |

The exact boundary is confirmed by the control name `X-` plus 62 `a` bytes:
all three protocols preserved that 64-byte field and value. HTTP/1/H2 were
captured with raw TLS/curl respectively; the H3 QPACK section and DATA were
decoded with aioquic.

### Impact

An application-visible extension field vanishes for H2 and H3 clients but not
H1 clients. This can break custom cache, authorization, feature-negotiation,
observability, or policy metadata and makes an application's response contract
depend on ALPN. Because the rule targets all unrecognized names, it is exactly
the type of extension that HTTP's forwarding rule protects.

Silent omission is worse than a clear resource-bound error: the backend and
client both observe an ordinary 200 and have no indication that metadata was
lost in transit. It also gives the caller no way to configure the behavior or
choose an HTTP-version-independent limit.

### Recommendation

Do not silently drop a valid field because it exceeds an encoder scratch
buffer. Prefer one of these explicit policies:

1. enlarge or replace the H2 and QPACK name buffers so they cover every field
   name permitted within Linnea's accepted upstream-head limit, then lowercase
   and encode the field; or
2. if a smaller implementation limit is intentional, reject the upstream head
   with 502 in the shared validator before any protocol emits a partial
   response, and document/configure that limit.

The first policy best matches HTTP's requirement to forward unrecognized fields.
Whichever is chosen must be common to H1, H2, and H3; retaining the field on H1
while dropping it only during binary-protocol encoding is not a safe limit.

Add 64- and 65-byte field-name fixtures to the cross-protocol proxy matrix.
The 64-byte control must continue to preserve the field everywhere. The 65-byte
case must either preserve it everywhere or return 502 everywhere; a successful
H2/H3 response without it is the regression to prevent.

### Resolution — FIXED (2026-08-19, `8168d78`)

Confirmed at exactly the stated boundary: `name64` was forwarded by all three,
`name65` by HTTP/1 only.

The report's first policy was taken, with the second used to make it coherent.
There is now **one number** — `LINNEA_HTTP_MAX_FIELD_NAME` (256) in
`linnea_config.inc`, beside the other cross-cutting constants. Both encoder
scratch buffers are sized *from* it, and the shared validator refuses anything
longer. So the three protocols agree in both directions: up to 256 bytes is
forwarded everywhere, past it is 502 everywhere, and neither answer depends on
ALPN.

The `> MAX` checks in the two encoders are kept as a backstop on their own
buffers and now say so in the code. They are unreachable — the gate has already
refused a longer name — where previously that same branch *was* the policy, at
64 bytes, enforced only on the two binary protocols.

256 is generous against the real world, where the longest field names in use are
well under 50 bytes. The point is not the number but that it is written down at
one place instead of implied by the size of a buffer.

## Verification

| route | before | after |
| --- | --- | --- |
| `/api/204te`, `/api/204tezero` | `204` on all three; h1 carrying the forbidden field | `502` on all three |
| `/api/earlyte` | h2 relayed a scrubbed `103` then `502`; h1/h3 `502` | `502` on all three, no interim relayed |
| `/api/name64` | forwarded on all three | unchanged |
| `/api/name65` | h1 forwarded, h2/h3 erased it | forwarded on all three |
| `/api/namebig` (302 bytes) | `200` on all three, field erased on h2/h3 | `502` on all three |
| `/api/early`, `/api/chunked`, `/api/205zero` | controls | unchanged |

Cross-protocol matrix: **103 checks green**, from 4 failures before. Full suite
**767 passed, 0 failed**.

### An unrelated observation about the suite

The HTTP/3 persistent-congestion check failed on the first full run and passed
on the re-run — the second time this has happened, both times under the
concurrent three-shard run, both times reporting the 32 MB transfer completing
in 4.9 s where an isolated run takes 4.1 s. It downloads a **static** file, so
no proxy code is on its path, and it passes alone (204/204). It is
timing-sensitive under load rather than wrong, but it has now cost two full
suite runs, and something that fails once per two runs is close to being a
coin toss on a deploy gate. Worth making robust — for instance by scaling its
deaf spell to the observed transfer rate rather than a fixed second — but that
is a change to the test, not to the server, and is left as a note rather than
folded into an audit fix.

## Conclusion

Both findings are fixed, and both fixes are at the shared gate. The interim
case is the clearest argument yet for that placement: a rule enforced inside
each translator cannot prevent one of them from having *already emitted* part
of a response before the error is found. The other finding is the same story in
a quieter register — a buffer size behaving as a protocol policy, on two of
three protocols, with nothing anywhere stating it was a policy at all.
