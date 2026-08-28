# Audit Report 121

Audited commit `89379cf` (`x509: refuse a critical extension this build cannot
process (report 120)`), 2026-08-28.

This pass examined HTTP/1 field-value validation and the proxy's forwarding
path. It found that an ordinary request header value containing DEL (`0x7f`) is
accepted and copied verbatim to an upstream HTTP/1 backend. No production code,
test, or configuration was changed in this audit; only this report was added.

## Finding 1 — HTTP/1 accepts and forwards DEL in a field value

**Severity:** Medium  
**Confidence:** High  
**Status:** Open

[`linnea_http_handle`](../src/server/linnea_http.asm#L1166) refuses bytes below
SP, apart from HTAB, but has no upper-bound check. It therefore accepts DEL
(`0x7f`) in every ordinary HTTP/1 field value. The proxy then copies non-hop-by-
hop lines verbatim at [line 3096](../src/server/linnea_http.asm#L3096), so the
invalid byte crosses the trust boundary to the backend. The chunk-trailer parser
does contain the missing DEL rejection at
[line 5330](../src/server/linnea_http.asm#L5330), demonstrating that the
ordinary-header path is the inconsistency.

RFC 9110 defines `field-vchar` as VCHAR (`0x21`--`0x7e`) or `obs-text`
(`0x80`--`0xff`), excluding DEL; it calls other CTL characters invalid and only
permits retaining them when they occur in a safe context. A proxy forwarding
them to another HTTP parser is not that context ([RFC 9110
§5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5)).

### Reproduction

Starting at the repository root, run the fixture backend and server, then send
one ordinary control request and one request containing the literal `0x7f`:

```sh
d=$(mktemp -d /tmp/linnea-audit-121-XXXXXX)
LINNEA_TEST_RUNDIR="$d" python3 test/proxy_backend.py >"$d/backend.log" 2>&1 & backend=$!
./bin/linnea --config test/configs/listen.json >"$d/linnea.out" 2>"$d/linnea.err" & server=$!
trap 'kill "$server" "$backend" 2>/dev/null; wait "$server" "$backend" 2>/dev/null' EXIT
sleep 0.2
python3 - <<'PY'
import socket

for label, value in (("ordinary", b"before-after"),
                     ("DEL", b"before\x7fafter")):
    s = socket.create_connection(("127.0.0.1", 61080))
    s.sendall(b"GET /api/headers HTTP/1.1\r\nHost: one.test\r\nX-Test: "
              + value + b"\r\nConnection: close\r\n\r\n")
    response = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        response += chunk
    print(label + ": " + response.split(b"\r\n", 1)[0].decode())
    if label == "DEL":
        print("backend echo: " + ("<DEL>" if
              b"X-Test: before\x7fafter" in response else "missing"))
PY
```

Observed output:

```
ordinary: HTTP/1.1 200 OK
DEL: HTTP/1.1 200 OK
backend echo: <DEL>
```

The first line is the acceptance control. The second request should instead be
rejected as malformed; its `200` response and the backend echo prove both
acceptance and forwarding of the prohibited byte.

### Impact

An HTTP/1 client can make Linnea and an upstream disagree about whether a
request is syntactically valid. Backends, gateways, WAFs, and logging libraries
commonly reject, truncate, or otherwise special-case DEL, while Linnea forwards
it unchanged. That parser differential can bypass validation performed only at
one hop or make the request seen by operational tooling differ from the one
Linnea routed.

### Recommended fix

In the ordinary field-value loop, reject `0x7f` after the existing below-SP
check, just as the trailer loop does. Preserve HTAB, SP through `0x7e`, and
`0x80` through `0xff`, which are legal under the field-value grammar.

Add a raw HTTP/1 rejection test for `X-Test: before\x7fafter` on a proxy
route, asserting `400` and that the backend receives no request. Pair it with
the visible-ASCII control above, so a parser that rejects all field values (or
all requests) cannot pass.

## Resolution (2026-08-28)

**CONFIRMED and FIXED.** Reproduced before believing, with the report's own
script run verbatim against `89379cf`:

```
ordinary: HTTP/1.1 200 OK          <- acceptance control
DEL: HTTP/1.1 200 OK               <- should have been 400
backend echo: <DEL>
```

The ordinary field-value loop checked only the lower bound
(`cmp al, 0x20 / jb .resp_400`) and had no upper one, so DEL passed and the
proxy copied it to the backend verbatim. After the fix, same script:

```
ordinary: HTTP/1.1 200 OK
DEL: HTTP/1.1 400 Bad Request
backend echo: missing
```

`backend echo: missing` is the line that matters. A 400 alone would only show
linnea changed its mind; this shows the prohibited byte no longer crosses the
trust boundary, which is what the finding was about.

### The split is not h1 vs h2 — it is ordinary headers vs trailers

The report notes the h1 trailer parser already rejects DEL. Sweeping the rest
of the tree for the same shape found a second one: the h2 proxy leg's chunked
trailer decoder, `.dec_trail_value` at `src/server/linnea_http2.asm:5088`,
carries the identical `cmp al, 0x7f / je .dec_bad ; DEL`. So **both trailer
parsers rejected DEL and both ordinary header paths did not.** That is a
sharper statement of the defect than "h1 is inconsistent with itself", and it
is why the fix is written to make the ordinary loop agree with the two parsers
that were already right.

### We are now deliberately stricter than nginx

The independent oracle was asked rather than assumed, and it disagreed with the
fix. nginx 1.30.4, given the same request:

```
nginx ordinary   : HTTP/1.1 200 OK
nginx DEL (0x7f) : HTTP/1.1 200 OK
```

nginx accepts DEL in a field value and forwards it. Refusing it is therefore a
deliberate departure, not a conformance catch-up, and it is worth stating
plainly because report 114's lesson was that refusing what another
implementation accepts is the worst outcome available.

It is still the right call here, for reasons that did not apply to report 114:

- RFC 9110 5.5 defines `field-vchar` as VCHAR (`0x21`-`0x7e`) or `obs-text`
  (`0x80`-`0xff`). DEL is in neither. It is invalid, not merely unusual.
- The RFC's permission to RETAIN an invalid CTL is conditioned on it appearing
  "within a safe context (e.g., an application-specific quoted string that will
  not be processed by any downstream HTTP parser)". A forwarding proxy is the
  exact opposite of that context. The exemption does not cover us.
- No legal client emits it, so the refusal cannot cost a real request, and
  failing closed is the safe direction for a byte whose whole risk is that two
  parsers will read it differently.
- It makes this build self-consistent, which the trailer parsers show was
  always the intent.

Unlike an expired certificate (report 118) this verdict does not change with
the clock or the environment, so it is a refusal rather than a warning.

### Coverage

Three checks in `test/shards/h1/25-http-semantics.sh`, on a PROXY route because
crossing to the backend is the risk:

- `DEL in a field value is refused` -> 400
- `...and the same header without it still passes` -> 200. The acceptance
  control: without it a parser that refused every field value, or every
  request, would pass the check above.
- `...and 0x7e and 0x80 around it are still legal` -> 200. Not requested by the
  report, and the one most likely to catch a bad fix: `0x7e` closes VCHAR and
  `0x80` opens obs-text, so an implementation that clamped at "anything above
  0x7e" would refuse obs-text the grammar allows and nothing else in the suite
  would have noticed.

A/B confirms the rejection test is not vacuous: against the pre-fix `89379cf`
binary the DEL request is answered 200 and reaches the backend; against this
one it is 400 and does not.

### NOT fixed, and not measured: the h2 and h3 ordinary header paths

RFC 9113 8.2.1 prohibits only NUL, LF and CR in an HTTP/2 field value — DEL is
not forbidden there — so a client may legitimately send DEL over h2 or h3, and
this build may then translate it into an HTTP/1 request to a backend. That
would reopen the same differential through a different front door.

**I did not measure whether that path exists**, and this change does not
address it. It is stated here as the next report's subject rather than left to
look closed. Fixing h1 does not make the build immune; it makes the h1 door
agree with its own trailer parser.

### Measurements

- h1 shard **426 passed, 0 failed** (423 before the three new checks).
- The reproduction A/B above, both directions.
- nginx 1.30.4 as the independent oracle.
- The full suite was NOT run, and must be before deploying.
