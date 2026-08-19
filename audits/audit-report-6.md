# Linnea server audit report 6

Date: 2026-08-18  
Audit baseline: commit `67ee1c8` (`audit-report-5: the static path is closed too`)  
Scope: read-only review of the current HTTP/1, HTTP/2, HTTP/3, QUIC/QPACK, and
proxy response paths, plus the relevant existing regression coverage.

## Executive summary

This was a read-only follow-up audit. The report-5 checked decimal parser and
static-location fixes remain present. I found one new high-confidence issue:

1. **Medium: the HTTP/3 proxy accepts malformed upstream response field
   sections that the HTTP/2 proxy rejects.** It uses the first matching
   `Content-Length` for framing, then re-derives a clean HTTP/3 length from the
   captured body. A conflicting duplicate can therefore become a normal `200`
   response. The same missing validation allows invalid field names and control
   bytes in field values to be QPACK-encoded for the HTTP/3 peer.

No source code, tests, configuration, or earlier report was changed by this
audit. Only this report was added.

## Finding 1 — HTTP/3 proxy skips upstream response-field validation

Severity: **Medium (P2, HTTP message integrity and downstream availability)**  
Confidence: **High**  
Status: **FIXED** (see Resolution)

### Evidence

The HTTP/3 upstream-head parser finds the terminating empty line and immediately
selects response framing. It does not validate the complete field section:

- [`src/server/linnea_h3_proxy.asm:559`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:559)
  through [`:629`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:629)
  move directly from finding `CRLF CRLF` to choosing `Transfer-Encoding` or
  `Content-Length` framing. There is no equivalent of the HTTP/2
  `h2p_head_validate` call.
- The helper used for both framing fields returns at its **first** matching
  line: [`src/server/linnea_h3_proxy.asm:682`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:682)
  through [`:754`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:754).
  Consequently, [`:610`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:610)
  through [`:628`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:628)
  parse and trust only the first `Content-Length`; a later conflicting value is
  neither parsed nor compared.
- The body collector accepts at most that selected length and marks the response
  complete when it reaches zero at
  [`src/server/linnea_h3_proxy.asm:863`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:863)
  through [`:903`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:903).
  Delivery then supplies the captured byte count as its own `Content-Length`
  ([`src/server/linnea_h3_proxy.asm:928`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:928)
  through [`:945`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:945)).
  QPACK emits that replacement length
  ([`src/server/linnea_qpack.asm:781`](/home/linnea/linnea/src/server/linnea_qpack.asm:781)
  through [`:799`](/home/linnea/linnea/src/server/linnea_qpack.asm:799)) and
  drops every upstream `content-length` while doing so
  ([`src/server/linnea_qpack.asm:994`](/home/linnea/linnea/src/server/linnea_qpack.asm:994)
  through [`:1005`](/home/linnea/linnea/src/server/linnea_qpack.asm:1005)).
  Thus the downstream peer never sees the contradictory fields that should have
  caused a bad-gateway response.

The repository already contains an exact control and a safer implementation on
the HTTP/2 path:

- The test backend's `/api/clconflict` response is
  `Content-Length: 5`, then `Content-Length: 7`, followed by `hello`
  ([`test/proxy_backend.py:181`](/home/linnea/linnea/test/proxy_backend.py:181)
  through [`:186`](/home/linnea/linnea/test/proxy_backend.py:186)). On the
  HTTP/3 path above, the first value selects five bytes, so this response is
  captured and re-issued as a normal `200` with `content-length: 5`.
- HTTP/2 instead calls `h2p_head_validate` before framing
  ([`src/server/linnea_http2.asm:4127`](/home/linnea/linnea/src/server/linnea_http2.asm:4127)
  through [`:4135`](/home/linnea/linnea/src/server/linnea_http2.asm:4135)).
  That validator requires token field names, disallows control bytes in values
  and obsolete folding, and parses and compares every repeated
  `Content-Length` ([`src/server/linnea_http2.asm:3911`](/home/linnea/linnea/src/server/linnea_http2.asm:3911)
  through [`:4034`](/home/linnea/linnea/src/server/linnea_http2.asm:4034)).
  A disagreement is rejected at [`:4027`](/home/linnea/linnea/src/server/linnea_http2.asm:4027)
  through [`:4031`](/home/linnea/linnea/src/server/linnea_http2.asm:4031).

The missing validation is broader than duplicate lengths. The QPACK translator
splits field lines and only rejects an empty or over-64-byte name; it lowercases
and encodes the remaining bytes without a token-name or field-value control-byte
check ([`src/server/linnea_qpack.asm:825`](/home/linnea/linnea/src/server/linnea_qpack.asm:825)
through [`:895`](/home/linnea/linnea/src/server/linnea_qpack.asm:895)). The
existing `/api/badname`, `/api/badvalue`, and `/api/nocolon` fixtures cover
those cases at [`test/proxy_backend.py:172`](/home/linnea/linnea/test/proxy_backend.py:172)
through [`:180`](/home/linnea/linnea/test/proxy_backend.py:180). HTTP/3 either
QPACK-encodes the bad name/value or silently drops the colonless line, instead
of rejecting the upstream response.

### Impact

A buggy or compromised proxy backend can send a contradictory response that
Linnea turns into a successful, apparently well-formed HTTP/3 response. For the
existing `5`/`7` fixture, the client receives `200`, `content-length: 5`, and
`hello`, where an HTTP intermediary must reject the conflicting framing rather
than choose one value and normalize the answer.

Invalid names or control bytes can likewise cross the HTTP/1-to-HTTP/3
translation boundary. A compliant HTTP/3 peer can treat the resulting field
section as malformed, potentially terminating its QUIC connection rather than
receiving Linnea's isolated `502`. Client behavior for these invalid fields may
vary, but the proxy must not pass them on.

The HTTP/3 leg requests `Connection: close` upstream and captures the whole
response before delivery, so this audit did **not** demonstrate cross-client
response smuggling or memory corruption. The confirmed issue is accepting an
invalid upstream message and changing its semantics, plus avoidable downstream
connection disruption; P2 is appropriate.

### Coverage gap

The HTTP/2 shard explicitly checks `badname`, `badvalue`, `nocolon`, and
`clconflict` for `502`, then checks that identical duplicate lengths are
normalized ([`test/shards/tls/40-http2.sh:470`](/home/linnea/linnea/test/shards/tls/40-http2.sh:470)
through [`:484`](/home/linnea/linnea/test/shards/tls/40-http2.sh:484)).

The HTTP/3 proxy test covers ordinary counted, chunked, close-delimited, and
hop-by-hop responses ([`test/quic/h3_proxy_test.py:102`](/home/linnea/linnea/test/quic/h3_proxy_test.py:102)
through [`:145`](/home/linnea/linnea/test/quic/h3_proxy_test.py:145)), but none
of these four malformed upstream response fixtures. The TLS/H3 shard only
exercises the separate `Transfer-Encoding` plus `Content-Length` case
([`test/shards/tls/30-h3-proxy.sh:80`](/home/linnea/linnea/test/shards/tls/30-h3-proxy.sh:80)
through [`:108`](/home/linnea/linnea/test/shards/tls/30-h3-proxy.sh:108)).

### Recommendation

Validate the complete HTTP/1 upstream response field section before HTTP/3
framing, capture, or QPACK encoding. The safest route is to extract a shared
proxy-head validator from HTTP/2's `h2p_head_validate` and invoke it from both
protocol paths immediately after locating the response head.

It should:

- reject a non-token or empty field name, obsolete folding, a missing colon,
  and prohibited control bytes in a field value;
- parse every `Content-Length` with `linnea_string_to_u64`, reject conflicting
  values, and retain one checked value for framing; and
- validate all framing-field occurrences before choosing a body decoder. Keep
  the existing rule that a `Transfer-Encoding`/`Content-Length` combination is
  a `502`.

Add HTTP/3 regressions using the existing backend routes: `badname`,
`badvalue`, `nocolon`, and `clconflict` must return `502`; `cldupe` must still
return `200` with `hello` and one canonical content length. Run the equivalent
matrix over both HTTP/2 and HTTP/3 so future parser changes cannot reintroduce
protocol-dependent upstream-response handling.

### Resolution — FIXED (2026-08-18, `978c077`)

The finding is right, and understating it. Measuring all three protocols against
the fixtures the report names found **three** behaviours, not two — HTTP/1 was
leaking as well:

| route | h1 before | h2 before | h3 before | all three now |
|---|---|---|---|---|
| `badname` | **200** | 502 | **200** | 502 |
| `badvalue` | **200** | 502 | **200** | 502 |
| `nocolon` | **200** | 502 | **200** | 502 |
| `clconflict` | 502 | 502 | **200** | 502 |
| `cldupe` | **502** | 200 | 200 | 200 |

HTTP/1 relayed `Bad Name: x` and `X-Test: va\0ue` to the client **verbatim**;
HTTP/3 put both on the wire QPACK-encoded. HTTP/1 was also the odd one out in
the other direction on `cldupe`, refusing a repeated `Content-Length` that
agreed with itself.

**The fix is the report's own recommendation.** `h2p_head_validate` became
`linnea_http_upstream_head_valid` and moved into the HTTP/1 module — an upstream
response head *is* an HTTP/1 message, whichever protocol relays it — and all
three call it before framing, capture or encoding. HTTP/1's private "any repeat
is bad" rule is gone, since the shared validator already proves repeats agree.
The move was verified behaviour-neutral for HTTP/2 *before* the new callers were
added, so the two halves remain separable.

### Two further defects the sharing surfaced

Both older than this work, both the same shape as report 5's Finding 1 — several
copies of a small routine, most subtly wrong. RFC 9112 5 puts OWS on **both**
sides of a field value, and of the four places that locate one, two had
forgotten the trailing half:

- **the validator itself**, so `Content-Length:   5  ` reached the number parser
  as `"5  "` and **HTTP/2 answered 502 to a legal response**. It went unnoticed
  because the `/api/clpad` fixture was only ever pointed at HTTP/1, which has
  its own parser that trims both ends.
- **HTTP/3's `.ph_find`**, the same, so HTTP/3 refused it too. HTTP/2's
  `h2p_head_find` has trimmed both ends all along.

Both now trim SP and HTAB. **Not fixed, and still a gap:** the *leading* skip in
`h2p_head_find` and `.ph_find` handles SP only, so `Content-Length:\t5` is still
refused — legal, vanishingly rare, and not worth widening the change for.

### Verification

[`test/proxy_upstream_head.py`](/home/linnea/linnea/test/proxy_upstream_head.py)
runs the matrix over HTTP/1, HTTP/2 **and** HTTP/3 in one file, because the
defect was never "protocol X is wrong" — it was the three disagreeing, so the
assertion that matters is that they agree. **8 of its checks fail on a pre-fix
binary**, and it prints the leaked bytes rather than a status mismatch:
`h1 [b'X-Test: va\0ue']`, `h3 [b'x-test: va\0ue']`. `clpad` and `cljunk` are
paired on purpose: the first proves trailing OWS is trimmed, the second that
`12 34` is still refused, so the trim cannot drift into permissiveness. HTTP/3
is skipped, loudly, when aioquic is unavailable. Full suite **762 passed, 0
failed**.

The `clpad` regression was found by the suite, not by inspection: the first run
after the shared validator landed failed `proxy CL whitespace`, which is what
led to both OWS defects.

## Audit notes

- Report-5's shared checked decimal parser is present at every reviewed
  `Content-Length` parse site. This finding is about repeated-field and
  field-section validation on the HTTP/3 *upstream response* path, not numeric
  overflow.
- I did not run or alter the test suite for this report-only task. The evidence
  above is a source trace against the current baseline and the repository's
  existing, deterministic backend fixtures.

## Conclusion

HTTP/2 already rejected malformed upstream response fields before translating
them; HTTP/1 and HTTP/3 now enforce the same boundary through one shared
validator, and a cross-protocol matrix pins that they agree. The audit is
complete — and it found more than it set out to: HTTP/1 was relaying invalid
field names and NUL bytes to clients, and two of the four field-value lookups
had been refusing legal responses that carried trailing whitespace.
