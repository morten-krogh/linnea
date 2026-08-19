# Audit Report 15

Audited at `8feed69` (`audit-report-14: both findings FIXED`), 2026-08-19.

**Both findings are fixed in `dfd3d05`.** This report made no source change and
ran no tests, so both were measured against a pre-fix binary before anything was
touched. Both held, and Finding 2 proved worse than described.

Two response-policy translation defects remain open in the proxy paths:

1. **High: configured HSTS and `nosniff` are absent from successful proxied HTTP/1 responses.** The same configured vhost adds them on proxied HTTP/2 and HTTP/3 responses, so a client can lose both protections merely by negotiating HTTP/1.1.
2. **High: an upstream can suppress configured HSTS and `nosniff` on HTTP/2 and HTTP/3 by declaring its fields connection-specific.** The fields are correctly removed before forwarding, but are incorrectly treated as a surviving backend policy when deciding whether Linnea must add its own.

No production source, configuration, or test files were changed in this audit. Only this report was added.

This is a source-trace audit against the stated baseline. The reproductions describe minimal upstream fixtures and the control flow they reach; they are not presented as captures from a modified backend.

## Finding 1 — HTTP/1 proxy responses omit the vhost security policy

Severity: **High (P1, transport-dependent security policy)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

`hsts` and `nosniff` are server-level policy: the configuration documents them as headers Linnea sends, and the TLS shard explicitly says configured security headers must ride proxied responses. That is true for the binary-protocol translators:

- HTTP/2 appends configured `Strict-Transport-Security` and `X-Content-Type-Options: nosniff` after translating an upstream head at [src/server/linnea_http2.asm:4628](/home/linnea/linnea/src/server/linnea_http2.asm:4628) through [:4665](/home/linnea/linnea/src/server/linnea_http2.asm:4665).
- HTTP/3 does the same at [src/server/linnea_qpack.asm:935](/home/linnea/linnea/src/server/linnea_qpack.asm:935) through [:960](/home/linnea/linnea/src/server/linnea_qpack.asm:960).

The HTTP/1 rewriter has no equivalent step. Its successful proxy-head path begins at [src/server/linnea_http.asm:3891](/home/linnea/linnea/src/server/linnea_http.asm:3891), copies the surviving upstream fields, and then appends only its own `Via` and `Connection` lines at [:4312](/home/linnea/linnea/src/server/linnea_http.asm:4312) through [:4325](/home/linnea/linnea/src/server/linnea_http.asm:4325). It reaches the ready state immediately afterwards at [:4351](/home/linnea/linnea/src/server/linnea_http.asm:4351) through [:4353](/home/linnea/linnea/src/server/linnea_http.asm:4353). No code in that path reads the selected vhost's `hsts_len` or `nosniff` fields.

This is not an intentional distinction in the HTTP/1 server generally. Static and generated heads share `.append_security` at [src/server/linnea_http.asm:2965](/home/linnea/linnea/src/server/linnea_http.asm:2965) through [:2990](/home/linnea/linnea/src/server/linnea_http.asm:2990), and the TLS end-to-end shard already requires both headers on static responses and on a proxy *failure*. Its successful `/api/simple` check verifies only the status and body, so it does not exercise this missing branch.

### Reproduction

Configure the TLS vhost with:

```json
"hsts": "max-age=31536000",
"nosniff": 1
```

and use an otherwise ordinary upstream response:

```text
HTTP/1.1 200 OK\r\n
Content-Length: 4\r\n
\r\n
body
```

The expected downstream response on HTTP/1.1, HTTP/2, and HTTP/3 contains:

```text
Strict-Transport-Security: max-age=31536000
X-Content-Type-Options: nosniff
```

The current paths instead produce:

| Downstream protocol | Configured headers on proxied `200` |
| --- | --- |
| HTTP/1.1 | neither |
| HTTP/2 | both |
| HTTP/3 | both |

The existing `/api/simple` TLS test is the appropriate control: it already uses this vhost and verifies the normal body on both HTTP/1.1 and HTTP/2.

### Impact

The configured origin policy is conditional on ALPN despite the proxy serving the same origin and representation. A TLS client that falls back to HTTP/1.1, uses an HTTP/1-only intermediary, or is deliberately routed to the HTTP/1 listener does not learn HSTS and does not receive the MIME-sniffing protection. HTTP/2 and HTTP/3 clients do. This is especially surprising because error responses already carry the policy on HTTP/1; a healthy backend response is the path that loses it.

### Recommendation

Give the HTTP/1 successful proxy-head rewriter the same explicit policy stage as the binary emitters, before it appends the final `Connection` terminator. It must add each configured field only when an end-to-end instance of that field survives the upstream-field filtering; a backend's own normal policy continues to win.

Extend `test/shards/tls/20-e2e.sh` so its existing HTTP/1 `/api/simple` request asserts both configured headers. Add an HTTP/3 equivalent beside the existing HTTP/2 proxy-policy test, and use the same backend response for all three.

### Resolution — FIXED (2026-08-19, `dfd3d05`)

Measured exactly as predicted, with the static path confirming the scope:

```
/api/simple   h1: nothing                  h2/h3: max-age=31536000 + nosniff
/             h1: both                     <- the static path always had it
```

So it is specifically the *successful proxied* HTTP/1 head that lost the policy;
HTTP/1 error heads and static heads already carried it, which is what made the
gap easy to miss.

HTTP/1 now emits the configured policy at `.conn_hdr`. It does so with its own
constants rather than the existing `.append_security`: the generated-head
constants lead with CRLF because that builder appends pieces before one final
terminator, while the proxy rewriter appends complete lines. Same policy, two
framing conventions — bending one appender to serve both would have been the
kind of sharing that produces a subtly wrong head.

## Finding 2 — Dropped connection-specific fields still suppress binary policy injection

Severity: **High (P1, backend-controlled removal of configured policy)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

RFC 9110 section 7.6.1 makes a `Connection` value a removal instruction for the current hop: the named fields are connection-specific and must not be forwarded. Linnea implements that dynamic filtering correctly in both binary emitters:

- HTTP/2 asks `linnea_http_head_conn_named` at [src/server/linnea_http2.asm:4563](/home/linnea/linnea/src/server/linnea_http2.asm:4563) through [:4572](/home/linnea/linnea/src/server/linnea_http2.asm:4572), before HPACK encodes a surviving field.
- HTTP/3 performs the same check at [src/server/linnea_qpack.asm:884](/home/linnea/linnea/src/server/linnea_qpack.asm:884) through [:895](/home/linnea/linnea/src/server/linnea_qpack.asm:895), before QPACK encodes it.

Their policy-presence decisions instead inspect the *raw* upstream head, or record presence before that filtering:

- HTTP/2 calls `h2p_head_find` over the raw head for HSTS at [src/server/linnea_http2.asm:4636](/home/linnea/linnea/src/server/linnea_http2.asm:4636) through [:4642](/home/linnea/linnea/src/server/linnea_http2.asm:4642), and does the same for `X-Content-Type-Options` at [:4652](/home/linnea/linnea/src/server/linnea_http2.asm:4652) through [:4658](/home/linnea/linnea/src/server/linnea_http2.asm:4658). `h2p_head_find` has no forwarding-policy input, so it reports a field even when the earlier loop removed it.
- HTTP/3 calls `.ep_classify` and ORs its “seen” bit at [src/server/linnea_qpack.asm:872](/home/linnea/linnea/src/server/linnea_qpack.asm:872) through [:883](/home/linnea/linnea/src/server/linnea_qpack.asm:883), *before* the dynamic `Connection` check. The HSTS and nosniff bits are then used to suppress configured injection at [:935](/home/linnea/linnea/src/server/linnea_qpack.asm:935) through [:960](/home/linnea/linnea/src/server/linnea_qpack.asm:960).

Thus the code applies two incompatible meanings to the same field: it is not part of the downstream response when it is emitted, but it is part of that response when it decides whether the origin's configured policy is already present.

### Reproduction

Use the configured vhost from Finding 1 and an upstream response such as:

```text
HTTP/1.1 200 OK\r\n
Connection: Strict-Transport-Security, X-Content-Type-Options\r\n
Strict-Transport-Security: max-age=0\r\n
X-Content-Type-Options: bogus\r\n
Content-Length: 4\r\n
\r\n
body
```

The two named upstream fields are correctly excluded from the response section. They must therefore not count as backend-provided policy; Linnea should append its configured `max-age=31536000` and `nosniff` values. The current HTTP/2 and HTTP/3 paths append neither, because each observes the upstream fields before the connection-option filter.

This is not a duplicate-header concern. A normal upstream HSTS/nosniff field that survives filtering is still a valid application policy and should continue to suppress Linnea's configured fallback. The distinction is whether the field will actually reach the client.

### Impact

An upstream application, an upstream intermediary, or a backend fault can turn off the configured security headers for every HTTP/2 or HTTP/3 response where it names them in `Connection`. The client receives neither the backend value nor Linnea's value. This is a direct policy-bypass surface at the proxy boundary, and it compounds Finding 1: HTTP/1 already misses the policy on all successful proxy responses, while HTTP/2 and HTTP/3 can be made to miss it on demand.

### Recommendation

Make “backend set this policy” mean “a field with this name survived all forwarding filters and will be emitted.” In HTTP/2, track the two presence bits inside the existing emit loop after `linnea_http_head_conn_named`, rather than performing raw-head lookups afterwards. In QPACK, move the seen-bit update below the same dynamic filter, or have `.ep_classify` return a bit only after the caller confirms the field is forwarded.

Implement the HTTP/1 policy stage from Finding 1 using that same surviving-field definition; otherwise a normal backend policy must not be duplicated, while a Connection-nominated one must not suppress the configured fallback. Add a `/api/security-hopnamed` backend fixture and test all three protocols for:

- no upstream `Connection` field or named security field;
- exactly the configured HSTS and nosniff values; and
- an ordinary upstream HSTS/nosniff response as the no-duplicate control.

### Resolution — FIXED (2026-08-19, `dfd3d05`)

Confirmed, and **worse than the report states**. The report expects HTTP/2 and
HTTP/3 to append neither value. Measured, no protocol sent anything at all:

```
/api/sechop   h1: []   h2: []   h3: []
```

The client received neither the backend's policy nor the origin's — an upstream
could turn the origin's security headers off on demand by naming its own copies
in `Connection`.

The fix is the report's own recommendation, taken literally: **a field counts as
backend policy only if it survives every forwarding filter.** That one definition
now lives in three places — HTTP/2 sets its bits inside the emit loop past
`linnea_http_head_conn_named` instead of re-scanning the raw head afterwards;
QPACK ORs its seen-bit *after* the same check rather than before; and HTTP/1's
new stage uses the same rule.

`/api/secown` is the control that keeps this from becoming "always append ours":
a backend policy that genuinely survives still wins (`max-age=99`) and is never
duplicated. Asserted as **exactly one** of each header, on every protocol and
every route.

## Verification

| route | before | after |
| --- | --- | --- |
| `/api/simple` | h1 none; h2/h3 configured | configured on all three |
| `/api/sechop` | **none on any protocol** | configured on all three, nominated fields dropped |
| `/api/secown` | backend's `max-age=99` | unchanged — backend wins, never duplicated |
| `/` (static) | policy present | unchanged |

Cross-protocol matrix: **133 checks green**, from 3 failures. Full suite
**767 passed, 0 failed**.

### One note about the test, worth more than the fix

`test/configs/tls-h3-proxy.json` gains `hsts`/`nosniff`. Without it the matrix
could not observe this defect at all — the proxy vhost the matrix runs against
configured no policy, so there was nothing to be absent.

That is also why the first full suite run failed while the same matrix passed
against a hand-built rig: **the rig proves the server behaves; only the suite
proves the assertion is true of a configuration the project actually ships.**
The assertion was demanding a policy that vhost had never been given.

## Conclusion

The report's closing line is the fix: what was missing was one shared definition
of whether the backend actually supplied a policy field. Applied after hop-by-hop
filtering it closes the binary bypass, and applied in the HTTP/1 rewriter it
closes the protocol split — and the two findings compound, since HTTP/1 was
missing the policy on every successful proxied response while HTTP/2 and HTTP/3
could be made to miss it on request.

## Verification (as filed)

No executable tests were run: this report makes no source change. The findings are traced from the currently checked-in response-head code and from the existing TLS-shard coverage gaps described above.

## Conclusion

The proxy already has the policy data and two of its three response translators already know how to add it. What is missing is one shared definition of whether the backend *actually supplied* a policy field. Applying that definition after hop-by-hop filtering fixes the binary bypass; applying it in the HTTP/1 rewriter closes the protocol split as well.
