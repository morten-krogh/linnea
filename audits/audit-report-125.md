# Audit Report 125

Audited commit `69ed9e3` (`audit 124: HTTP/2 accepts a malformed CONNECT authority as an ordinary 4`), 2026-08-28.

This pass followed the HTTP/2 CONNECT correction into the HTTP/1.1 request-target
parser. It found that HTTP/1.1 has no authority-form branch at all: a valid,
unsupported CONNECT is misclassified as malformed and answered 400. No source,
test, or configuration file was changed in this audit; only this report was
added.

## Finding 1 — HTTP/1.1 rejects a valid CONNECT authority-form as 400

**Severity:** Low  
**Confidence:** High  
**Status:** Open

[`linnea_http_handle`](../src/server/linnea_http.asm#L1014) recognizes only
asterisk-form and absolute-form before it enters the common target processing.
An authority-form target such as `localhost:443` is neither, so it reaches the
path decoder at [line 1951](../src/server/linnea_http.asm#L1951). The decoder
requires its first byte to be `/` at [line 1988](../src/server/linnea_http.asm#L1988)
and replies 400 otherwise. Method dispatch has already classified CONNECT as a
known but unsupported method, whose intended answer is 405, at
[lines 930–965](../src/server/linnea_http.asm#L930).

Authority-form is not a malformed target for CONNECT: HTTP defines CONNECT's
request target as the host and port to connect to
([RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)).
It is the HTTP/1.1 spelling of the `:authority` form that the current HTTP/2
path validates and then sends to its unsupported-method 405 response. A server
that declines to implement tunnelling may send 405, but should not describe a
well-formed request as invalid syntax.

### Reproduction

From the repository root, start the TLS test server and send an `OPTIONS *`
control followed by a CONNECT that differs in using CONNECT's legal
authority-form target. The Python client prints each status line.

```sh
d=$(mktemp -d /tmp/linnea-audit-125-XXXXXX)
./bin/linnea --config test/configs/tls.json >"$d/out" 2>"$d/err" & server=$!
trap 'kill "$server" 2>/dev/null; wait "$server" 2>/dev/null; rm -rf "$d"' EXIT
sleep 0.3
python3 - test/tls/server.crt 61443 <<'PY'
import socket, ssl, sys

ca, port = sys.argv[1], int(sys.argv[2])
ctx = ssl.create_default_context(cafile=ca)
ctx.check_hostname = False

for request in (
    b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n",
    b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n",
):
    sock = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)),
                           server_hostname="localhost")
    sock.sendall(request)
    print(request.split(b"\r\n", 1)[0], b"->",
          sock.recv(256).split(b"\r\n", 1)[0])
    sock.close()
PY
```

Observed output:

```
b'OPTIONS * HTTP/1.1' b'->' b'HTTP/1.1 200 OK'
b'CONNECT localhost:443 HTTP/1.1' b'->' b'HTTP/1.1 400 Bad Request'
```

The first request establishes that the listener is accepting valid
non-origin-form request targets. The second target is valid authority-form for
CONNECT, has an explicit valid port, and supplies one agreeing Host field; it
should take the known-unsupported-method path and receive 405, as HTTP/2 does.
Instead, it reaches the origin-path-only normalizer and gets 400.

### Impact

HTTP/1.1 clients and intermediaries cannot distinguish this server's deliberate
absence of CONNECT support from invalid request syntax. This is a request-target
form conformance error now, and it leaves a semantic mismatch between HTTP/1.1
and HTTP/2 if CONNECT support is later added: the latter already has an
authority-form validation path, while the former cannot reach any CONNECT
handler at all.

### Recommended fix

Recognize CONNECT before origin-path normalization and parse its target as
authority-form with the existing `linnea_http_authority_host` grammar, requiring
an explicit valid port. A valid authority-form CONNECT should continue through
normal method classification and receive 405 until tunnelling is implemented;
malformed, portless, or non-CONNECT authority-form targets should remain 400.
Add these paired cases to the HTTP/1 suite so a blanket 400 or blanket 405
cannot pass: `CONNECT example.com:443` must be 405, while `CONNECT bad/path`
and `CONNECT example.com` must be 400.

## Resolution (2026-08-28)

**CONFIRMED and fixed.** The recommendation is adopted in full. An independent
oracle agrees with it line for line, including the two parts of it that go
beyond "answer 405" — the mandatory port and the refusal of the other three
target forms.

### Reproduced first

Sixteen request lines against `69ed9e3` on `test/configs/authority-vhosts.json`,
over cleartext rather than TLS (the parser is the same one; the report's TLS
listener only adds a handshake). The report is right, and its cause is right:

```
OPTIONS * HTTP/1.1                   -> 200 OK             (the control)
GET / HTTP/1.1                       -> 200 OK             (the control)
CONNECT example.com:443 HTTP/1.1     -> 400 Bad Request    <- the finding
CONNECT [::1]:443 HTTP/1.1           -> 400 Bad Request
CONNECT example.com HTTP/1.1         -> 400 Bad Request
CONNECT bad/path HTTP/1.1            -> 400 Bad Request
CONNECT / HTTP/1.1                   -> 405 Method Not Allowed
CONNECT http://example.com/ HTTP/1.1 -> 405 Method Not Allowed
```

The last two lines are the ones the report did not predict, and they are the
tell. The only CONNECTs this build answered 405 were the ones carrying a target
form CONNECT may **not** send: an origin-form path or an absolute-form URI, both
of which reached the normalizer, matched a location, and fell out of the
static-location method check. Every legal CONNECT was 400 and every illegal one
was 405 — the classification was exactly inverted.

### The oracle: nginx 1.30.4, asked the same lines

There is no `openssl` verdict for an HTTP/1.1 request line, so the independent
implementation here is nginx — `/usr/bin/nginx`, a plain `listen 127.0.0.1:61977`
server, the same sixteen requests plus fourteen head-interaction cases.

| request line | nginx | before | after |
|---|---|---|---|
| `CONNECT example.com:443` | **405** | 400 | **405** |
| `CONNECT [::1]:443` | **405** | 400 | **405** |
| `CONNECT 127.0.0.1:443` | 405 | 400 | 405 |
| `CONNECT example.com:65535` / `:0` | 405 | 400 | 405 |
| `CONNECT example.com` (no port) | 400 | 400 | 400 |
| `CONNECT [::1]` (no port) | 400 | 400 | 400 |
| `CONNECT bad/path` | 400 | 400 | 400 |
| `CONNECT user@host:443` | 400 | 400 | 400 |
| `CONNECT example.com:99999` | 400 | 400 | 400 |
| `CONNECT example.com:44a` | 400 | 400 | 400 |
| `CONNECT /` | 400 | **405** | 400 |
| `CONNECT http://example.com/` | 400 | **405** | 400 |
| `CONNECT *` | 400 | 400 | 400 |
| `GET example.com:443` | 400 | 400 | 400 |
| `POST example.com:443` | 400 | 400 | 400 |
| `CONNECT ...` + two Host lines | 400 | 400 | 400 |
| `CONNECT ...` + no Host | 400 | 400 | 400 |
| `CONNECT ...` + `TE: gzip` | 501 | 501 | 501 |
| `CONNECT ... HTTP/9.9` | 505 | 505 | 505 |
| `CONNECT [deadbeef]:443` | **405** | 400 | **400** |
| `CONNECT example.com:` (empty port) | **405** | 400 | **400** |

Twenty-seven of the thirty lines now agree with nginx, and the report's own
recommendation — 405 for `example.com:443`, 400 for `bad/path` and for a
portless `example.com` — is confirmed by an implementation nobody in this tree
wrote. It also confirms the two rules I would otherwise have had to argue for:
that a portless CONNECT is a syntax error (nginx 400) and that CONNECT may not
use the other three target forms (nginx 400 on all three).

Three lines disagree. One is the `OPTIONS *` control itself — nginx answers it
400, this build has answered it 200 since the target-forms work, and it is not a
CONNECT line; it appears above only because the report used it as its control.
The other two are the interesting ones.

**The two CONNECT divergences are both the shared authority grammar, not new
strictness.** nginx does not check that a bracketed literal is a real IPv6
address and accepts a colon with no digits after it; this tree has refused both
since report 2, on `Host:` and on h2/h3 `:authority` alike — `Host: [deadbeef]`
and `Host: beta.test:` are 400 on this binary today. Writing a second, laxer
grammar for CONNECT to match nginx would reintroduce exactly the split report 2
consolidated, and it is the split report 124 closed on h2. Both are refusals
either way — this build implements no tunnel — so neither can turn a working
request into an outage.

### The change

Two insertions in `linnea_http_handle`, mirroring how `OPTIONS *` is already
handled: classify in the request-target-forms section, answer after the head has
been judged.

1. In the target-forms block, **ahead of** the asterisk and absolute-form
   branches — because CONNECT may use neither — a 7-byte `CONNECT` method test
   feeds the raw target to the existing `linnea_http_authority_host`. No new
   grammar. A `-1` is `.resp_400`, which is what makes origin-form, absolute-form
   and `*` 400 rather than 405, with no separate test for any of them. The port
   requirement is derived from what that function already returns
   (`rax` = host_len, `rdx` = host_off 0 or 1, one further past a `]`) rather
   than rescanning — the same derivation report 124 used on h2. Success sets
   `[rsp+552]`, a previously unused slot in the 560-byte frame, cleared on every
   request so a keep-alive connection cannot inherit it.
2. At the point where `OPTIONS *` is answered — after the Host, framing and
   Transfer-Encoding rules — `[rsp+552]` jumps to `.resp_405`. Placing it there
   rather than in the target block is what keeps `CONNECT` + two Hosts a 400,
   `CONNECT` + `TE: gzip` a 501 and `CONNECT ... HTTP/9.9` a 505, all three
   confirmed against nginx above.

`r14` (the head base) and `r15` (the cursor) are live across the new call;
`linnea_http_authority_host` saves `rbx`/`r12`/`r13` and touches neither, and
the call site copies the stack depth and alignment of the neighbouring
`target_absolute` call. h2 and h3 are untouched — this is inside
`linnea_http_handle`, which only h1 enters.

### A test that looked like CONNECT coverage and was not

`test/tls/canned_response_headers.py` already had a CONNECT case, asserting 405.
It passed before this change and it should not have: it sent
`CONNECT /hello.txt`, an **origin-form** target CONNECT may not carry, and got
its 405 from the static-location method check after the path matched `/`. It was
covering the inverted half of the bug while reading like coverage of the right
half, which is why the defect survived to report 125. It is now asked with
`one.test:443` (405, with `Allow`) **and** with `/hello.txt` (400), so neither a
blanket 400 nor a blanket 405 satisfies it.

### Coverage, A/B'd against the pre-fix binary

Twenty checks added to `test/shards/h1/25-http-semantics.sh`, in the
request-target-forms section next to the absolute-form and `OPTIONS *` ones:
four acceptance (`one.test:443` is 405, it carries `Allow: GET, HEAD`,
`[::1]:443` is 405 — the bracketed branch, `one.test:65535` is 405 — the port
bound from the accepting side), nine authority-grammar rejections, three
wrong-target-form rejections, two "no other method may send an authority"
controls (`GET`/`POST example.com:443` stay 400), and three head-interaction
controls (400 / 501 / 505).

Built the pre-fix binary and ran the same files against both:

```
pre-fix  (/tmp/linnea-prefix125)  6 of the 20 new checks FAIL, and
                                  canned_response_headers.py fails BOTH
                                  its CONNECT lines (405 wanted 400,
                                  400 wanted 405)
post-fix (bin/linnea)             all pass
```

The fourteen that pass on both are the point of them: a build that answered
every CONNECT 400 — the pre-fix build — satisfies all nine grammar rejections
and both non-CONNECT controls on its own, and the four 405 lines are what stop
it.

### Acceptance controls, run before the fix and again after

- **All 63 configs in `test/configs/`** (`--test` on each): exit codes
  byte-identical pre- and post-fix — 39 load, 24 are the negative fixtures that
  must not. `diff` of the two sweeps is empty.
- **`test/configs/doc_claims_test.py`**: 191 PASS lines, "all claims hold" —
  the count, not the banner. Report 124 recorded 191; unchanged. No documented
  claim mentions h1 CONNECT.
- **`test/tls/prod_cert_check.sh`**: exit 0, the real 3-certificate chain at
  `/etc/linnea/certs/linnea.amberbio.com/fullchain.pem` fully parsed. No
  certificate, PEM or DER code was touched by this change; run as a control
  because the workflow says to.

### What was run

```
./test/shards/run.sh h1/00-setup.sh h1/25-http-semantics.sh h1/50-teardown.sh
  -> 26s, the edit-test loop while A/B-ing
./test/shards/run.sh h1/00-setup.sh h1/30-proxying.sh h1/50-teardown.sh
  -> 74 checks, the file that owns canned_response_headers.py
./test/shards/run.sh h1
  -> 445 passed, 0 failed, 7 SKIPPED (fast run), 143s
```

`h1` is run whole rather than by file for the verdict: it is the shard that owns
`linnea_http_handle`, the run costs 143s, and naming files inside it is what
produced the five spurious failures seen while iterating (`$etag` and the access
log are set by `20-serving.sh`). The change is unreachable from h2, h3, QUIC and
the TLS-client paths, so no `tls` or `quic` file was run.

**The full suite was NOT run**, and neither was `LINNEA_SUITE=full`. One shard
is not the suite and does not gate a deploy; the full suite is run separately
before deploying.
