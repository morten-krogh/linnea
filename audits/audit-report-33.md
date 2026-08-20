# Audit Report 33

Audited at `e7689e4`, 2026-08-20.

**Fixed in `535b512`**, verified against a pre-fix binary on all three
protocols. The distinction the report draws is the one implemented: where we are
the origin the expectation is refused, and a proxy location still forwards it,
because there the backend is the one being asked.

One request-expectation gap remains open:

1. **Medium: local/static requests silently ignore unsupported `Expect` values.**
   Only `100-continue` is recognized; every other expectation falls through to
   normal request processing rather than receiving `417 Expectation Failed`.

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — Unsupported expectations are accepted by the local server

Severity: **Medium (P2, request-semantics mismatch)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

The HTTP/1 parser compares an `Expect` value only to `100-continue`:

```asm
.expect_header:
    ...
    call linnea_string_iequal
    test eax, eax
    jz .header_next
```

at [src/server/linnea_http.asm:1265](/home/linnea/linnea/src/server/linnea_http.asm:1265)
through [:1282](/home/linnea/linnea/src/server/linnea_http.asm:1282). The
nonmatching branch merely continues parsing; no unsupported-expectation flag is
recorded and no 417 path exists. The comment itself identifies the required
status but notes that no response is available.

HTTP/2 and HTTP/3 likewise record only the recognized `100-continue` form for
local handling. The HPACK/QPACK rebuilding logic deliberately forwards another
expectation for a *proxy* upstream to answer at
[src/server/linnea_hpack.asm:615](/home/linnea/linnea/src/server/linnea_hpack.asm:615)
through [:640](/home/linnea/linnea/src/server/linnea_hpack.asm:640), but a
static location has no upstream and consequently ignores it.

### Reproduction

Send a request to a static resource:

```text
GET /hello.txt HTTP/1.1\r\n
Host: one.test\r\n
Expect: feature-required-by-client\r\n
\r\n
```

Linnea serves the ordinary resource response. A server that cannot meet an
expectation must instead respond with `417 Expectation Failed`; silently serving
the request tells the client its expectation was accepted when it was not.

### Impact

Clients and intermediaries can make different decisions about whether a request
was accepted under its declared precondition. This is particularly visible for
clients that use Expect extensions to guard request processing: Linnea processes
the request while a conforming endpoint would stop at 417. It also leaves local
static behavior inconsistent with proxied requests, where the unsupported value
is preserved for the backend to evaluate.

### Recommendation

Track an unsupported `Expect` value while parsing headers. Before routing a
local/static request, return a 417 response and close as appropriate. For proxy
locations, retain the current intentional behavior of forwarding unknown
expectations unchanged, while continuing to generate and strip only
`100-continue` locally. Apply the same distinction to H1, H2, and H3.

Suggested tests:

* A static GET with an unknown expectation returns 417 on all three protocols.
* `Expect: 100-continue` remains locally acknowledged where a body is pending.
* A proxy request with an unknown expectation reaches the backend unchanged;
  the backend’s 417 is relayed unchanged.
* Mixed/repeated Expect values must not let a recognized value conceal an
  unsupported one.

### Resolution — FIXED (2026-08-20)

Confirmed on all three protocols: an unknown expectation was served the ordinary
response.

```
                                 before            after
  unknown, static path           200 200 200       417 417 417
  unknown, redirect location     301 301 301       417 417 417
  unknown, proxy location        200 200 200       200 200 200   (forwarded)
  Expect: 100-continue           200 200 200       200 200 200
  100-continue, feature-x        200 200 200       417 417 417
  two lines, one unknown         200 200 200       417 417 417
```

RFC 9110 15.5.18 makes the 417 a MAY rather than a MUST, so the argument for
this is not conformance but honesty: serving the resource tells the client by
omission that its expectation was honoured, and this server had two answers to
the same request depending on which location matched.

The refusal is placed **after the proxy branch and before the redirect branch**
on all three, rather than on the static path alone. A redirect is equally our
own answer, and the line worth drawing is not static-versus-everything-else but
*are we the origin here*. The report's fourth suggested test decides the list
question too: the whole value is compared, so `100-continue, feature-x` and a
second field line carrying an unknown member are both unsupported — **a value we
do not understand in full is one we cannot promise to meet**, and a recognised
member cannot conceal an unsupported one.

### The bit I reused was not free

The first version set a flag in bit 2 of the request's option word. Bit 2 is
already "an Upgrade field was present", so every upgrade request to a static
location became a 417, and the suite said so:

```
FAIL: upgrade on static location (pattern: hello from linnea)
```

The build was clean and every probe I had written passed, because none of them
sent `Upgrade`. It is the same reuse trap this tree keeps recording, and the
thing that caught it was a check written years earlier for an unrelated
feature — **the value of an old test is that it is still there when someone
edits the thing it never mentions.**

### Coverage

`test/tls/conditional_field_dups.py` gains seven rows across h1, h2 and h3 —
the four refusals, the proxy exception, `100-continue` still being met, and a
redirect without an Expect still redirecting. Five fail on a pre-fix binary.

Full suite: **780 passed, 0 failed**.

## Verification

No executable tests were run: this report makes no source change. The finding
is a source trace of the HTTP/1 fall-through and the binary proxy-only handling.

## Conclusion

Linnea now handles `100-continue` correctly, but treats every other Expect
extension as if it were absent on local resources. Explicit 417 handling closes
that request-semantics gap without changing proxy forwarding.

It does, and the shape is worth naming: the field was handled where it was
*noticed* — in the proxy rewriter, which is the only place an unknown
expectation had anywhere to go — and nothing asked what the other path should
do. The same question is worth putting to every field a proxy forwards: **when
this location has no upstream, who answers?**
