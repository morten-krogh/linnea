# Audit Report 8

Audited at c8bc356 (audit-report-7: both findings FIXED), 2026-08-18.

Two further proxy-response issues remain:

1. **Medium: HTTP/2 and HTTP/3 accept and normalize a malformed upstream
   response version.** The shared head validator deliberately skips the status
   line; H2 and H3 then check only HTTP/, one fixed space, and three status
   digits. A backend response beginning HTTP/x.y 200 OK becomes a normal
   downstream 200 instead of a 502.
2. **Medium: HTTP/3 rejects valid chains of large interim responses when their
   combined encoded size exceeds one fixed 8 KiB buffer.** Each 1xx head is
   below the documented 6144-byte per-head limit, but report-7's retained
   interim frames plus the final head must all fit in the one 8192-byte
   h3p_head buffer. H1 and H2 serve the same exchange; H3 returns 502.

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — H2 and H3 translate an invalid upstream HTTP version into a valid response

Severity: **Medium (P2, malformed-upstream handling and protocol consistency)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

An HTTP/1 status line starts with an HTTP-version; the version grammar is
HTTP-name "/" DIGIT "." DIGIT (RFC 9112 section 2). HTTP/x.y 200 OK is
therefore not an HTTP response status line.

The common upstream-head gate explicitly skips that line:

- [src/server/linnea_http.asm:3415](/home/linnea/linnea/src/server/linnea_http.asm:3415)
  through [:3452](/home/linnea/linnea/src/server/linnea_http.asm:3452).

The HTTP/1 proxy happens to apply a stricter policy afterwards, accepting only
the literal HTTP/1.0 and HTTP/1.1:

- [src/server/linnea_http.asm:3656](/home/linnea/linnea/src/server/linnea_http.asm:3656)
  through [:3683](/home/linnea/linnea/src/server/linnea_http.asm:3683).

The corresponding H2 and H3 parsers do not validate the three version bytes at
offsets 5--7. They require only HTTP, "/", the space at offset 8, and three
digits at offsets 9--11:

- [src/server/linnea_http2.asm:3925](/home/linnea/linnea/src/server/linnea_http2.asm:3925)
  through [:3952](/home/linnea/linnea/src/server/linnea_http2.asm:3952);
- [src/server/linnea_h3_proxy.asm:541](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:541)
  through [:569](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:569).

Both then manufacture a downstream protocol status from only those three
digits: H2 HPACK-encodes it at
[src/server/linnea_http2.asm:4429](/home/linnea/linnea/src/server/linnea_http2.asm:4429)
through [:4449](/home/linnea/linnea/src/server/linnea_http2.asm:4449), and
H3 QPACK-encodes it at
[src/server/linnea_qpack.asm:745](/home/linnea/linnea/src/server/linnea_qpack.asm:745)
through [:779](/home/linnea/linnea/src/server/linnea_qpack.asm:779).

### Reproduction

An isolated loopback upstream returned this exact 43-byte response to all
three proxy requests:

    HTTP/x.y 200 OK
    Content-Length: 5

    valid

The observed client result was:

| Downstream protocol | Result |
| --- | --- |
| HTTP/1.1 | 502 |
| HTTP/2 | 200, body valid |
| HTTP/3 | 200, body valid, QPACK :status: 200 |

Thus H2 and H3 do not merely accept a harmless spelling variation: they turn
bytes that fail the upstream response grammar into a valid-looking response
for the client.

### Impact

A faulty or compromised upstream can make the proxy attest to a response that
was not syntactically HTTP. Which outcome clients receive depends on ALPN:
HTTP/1 clients get the intended bad-gateway failure while H2/H3 clients see a
successful application response. That defeats the common malformed-head
boundary introduced in report 6 and makes backends behave differently across
otherwise equivalent clients.

### Recommendation

Add one shared status-line validator before
linnea_http_upstream_head_valid is called by any proxy path. It should enforce
the proxy's existing accepted version policy (HTTP/1.0 or HTTP/1.1), the
mandatory space before the three digits, and the required delimiter after the
code (either CRLF or the optional reason-phrase's SP). Validate the status
range as part of that helper if the project intends to reject unusable
three-digit codes.

Add /api/badversion to proxy_backend.py, returning the response above, and
assert a 502 on H1, H2, and H3 in proxy_upstream_head.py. Pair it with the
existing /api/http10 success case so valid upstream HTTP/1.0 translation stays
covered.

### Resolution — FIXED (2026-08-18, `f153586`)

Reproduced exactly: `HTTP/x.y 200 OK` was 502 on HTTP/1 and **200 on HTTP/2 and
HTTP/3**, body `valid`.

The validator now checks the status line instead of skipping it — the version
(1.0 or 1.1, which was already HTTP/1's upstream policy and is now shared rather
than local), the single SP, three digits, and the delimiter after the code, so
`HTTP/1.1 2000` is refused too. One gate, every protocol, as report 6 intended.
All three now answer 502, and `/api/http10` is the control that a legal
HTTP/1.0 upstream still translates on all three.

## Finding 2 — HTTP/3 interim-response buffering has only a single-head budget

Severity: **Medium (P2, HTTP/3 proxy availability)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

Report 7 correctly retained each upstream interim head in up_buf and added
.h3_hoff so delivery can emit it before the final response:

- [include/linnea_connection.inc:174](/home/linnea/linnea/include/linnea_connection.inc:174)
  through [:182](/home/linnea/linnea/include/linnea_connection.inc:182);
- [src/server/linnea_h3_proxy.asm:535](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:535)
  through [:544](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:544).

Each upstream head is individually allowed up to 6144 bytes, while the one
response-head staging buffer is 8192 bytes:

- [include/linnea_http3.inc:171](/home/linnea/linnea/include/linnea_http3.inc:171)
  through [:185](/home/linnea/linnea/include/linnea_http3.inc:185).

At delivery, every interim is QPACK-encoded into that same staging buffer,
then the final response is appended after them:

- interim loop:
  [src/server/linnea_h3_proxy.asm:1023](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:1023)
  through [:1078](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:1078);
- final append:
  [src/server/linnea_h3_proxy.asm:1079](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:1079)
  through [:1116](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:1116).

.dl_put_headers returns zero if the *aggregate* does not fit, and its callers
take the 502 path:

- [src/server/linnea_h3_proxy.asm:1206](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:1206)
  through [:1235](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:1235).

The per-head QPACK encoder also reserves space only relative to its own
invocation, not the cursor after earlier interim frames:

- [src/server/linnea_qpack.asm:765](/home/linnea/linnea/src/server/linnea_qpack.asm:765)
  through [:772](/home/linnea/linnea/src/server/linnea_qpack.asm:772).

### Reproduction

The loopback upstream sent the following legal sequence in one write:

    HTTP/1.1 103 Early Hints\r\n
    X-Filler: <4000 ASCII x bytes>\r\n
    \r\n
    HTTP/1.1 103 Early Hints\r\n
    X-Filler: <4000 ASCII x bytes>\r\n
    \r\n
    HTTP/1.1 200 OK\r\n
    Content-Length: 5\r\n
    \r\n
    valid

Each 103 head is **4040 bytes**, below the 6144-byte individual cap; the full
upstream exchange is **8123 bytes**, below LINNEA_CONN_UP_BUF's 8448 bytes.
The normal final response is therefore already buffered and no oversized
single response head is involved.

| Downstream protocol | Result |
| --- | --- |
| HTTP/1.1 | 200 |
| HTTP/2 | 200 |
| HTTP/3 | 502 Bad Gateway |

The H3 path buffers both QPACK-encoded 103 field sections (including its
per-response via, date, and server additions) and the final field section
before it sends anything. Their combined framed size exceeds the single
8192-byte reserve, so H3 discards a valid response chain before the client
receives either interim response.

### Impact

An upstream that emits two otherwise acceptable large 103 Early Hints
responses is unavailable only to HTTP/3 clients. This is especially likely
when applications use 103 to advertise many preload links or pass through
large policy metadata. The report-7 test cases cover several small interims,
so they do not exercise the cumulative bound introduced by retaining and
re-encoding the complete sequence.

### Recommendation

Give interim response frames an aggregate storage strategy rather than treating
the one-final-head reserve as an unbounded response sequence. The robust option
is to encode/write interim frames into the response spill file as they are
processed (or retain their encoded lengths and allocate the file region for the
whole sequence), then append the final head and body. If a bounded design is
intentional, track and enforce a documented total interim-header limit while
parsing, rather than discovering it only after the full body has been captured.

Add a two-big-interims backend fixture with two 4040-byte 103 heads and a
five-byte final body. The H3 assertion must require the status sequence
103, 103, 200 plus valid; H1 and H2 should continue to require 200 plus the
same final body.

### Resolution — FIXED (2026-08-18, `f153586`)

This one is mine, from `a81098e`. Retaining interim heads to re-encode them at
delivery put the whole sequence into the one staging buffer sized for a single
head. Reproduced: six legal `103 Early Hints` plus the final response were 200
on HTTP/1 and HTTP/2 and **502 on HTTP/3**.

Two things in fairness to the change rather than to me: it is still far better
than what preceded it — before `a81098e` a lone `103` broke HTTP/3 for *every*
interim response, final answer never delivered — and it failed cleanly rather
than corrupting the buffer, because the bound is checked per frame. What it
lacked was an **aggregate** budget.

- `LINNEA_H3_PROXY_RESERVE` doubles to **16384**. It holds anything `up_buf` can
  deliver, and it is a *hole* in a sparse capture file, so the extra costs
  nothing until it is written to.
- `LINNEA_H3_PROXY_IMAX` caps the chain at **8** interim responses, enforced
  **while parsing**. Bounding raw bytes cannot bound the encoded size — every
  head, however small, encodes to a field section carrying its own via, date and
  server, and `up_buf` holds hundreds of minimal 1xx heads. Refusing at the head
  also means no body is captured for a response that could never be sent, which
  is what the report asked for.

**A deliberate divergence, asserted so it stays deliberate:** HTTP/1 and HTTP/2
relay each 1xx as it arrives and have no such cap, so nine interims serve there
and are refused on HTTP/3. That is inherent to HTTP/3 buffering the sequence
before it sends anything.

### Verification

Control on the exact fixture: **502 at reserve 8192, 200 at 16384**; and **9
interims 502 against 6 interims 200**. Full suite **764 passed, 0 failed**.

Two traps in the *test*, both mine and both worth recording. `/api/bigearly`
first sent 8563 bytes against an 8448-byte `up_buf`, so it exercised the
buffer-full path rather than the bound under test. And the matrix reported a
QPACK decode error that curl-h3 does not reproduce: aioquic's decoder stops once
a stream's field sections total more than a few KiB, which any response large
enough to exercise this bound also exceeds. That route is therefore checked with
curl-h3 in the shard, and the matrix *prints* why it skips it rather than
silently omitting it.

## Conclusion

Both are fixed. The status line is now validated in the one gate every protocol
calls, and the interim delivery path has both a larger budget and a documented,
parse-time cap. The cross-protocol matrix covers `badversion`, `http10` and
`bigearly`; the two checks the matrix cannot make — the long chain and the cap
— run against curl-h3 in the shard, because the test client's own decoder is
the limit there, not the server.
