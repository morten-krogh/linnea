# Audit Report 124

Audited commit `02c380c` (`hpack: a field name must be a token on h2 and h3 too (report 123)`), 2026-08-28.

This pass examined the HTTP/2 CONNECT special case and its control-data
validation. It found that the special case checks that `:authority` is merely
nonempty, then bypasses the normal authority parser. No production code, test,
or configuration was changed in this audit; only this report was added.

## Finding 1 — HTTP/2 accepts a malformed CONNECT authority as an ordinary 405

**Severity:** Low  
**Confidence:** High  
**Status:** Open

[`h2_req_process`](../src/server/linnea_http2.asm#L1226) recognizes `CONNECT`
before calling the shared [`linnea_hpack_req_check`](../src/server/linnea_hpack.asm#L1636).
Its special branch at [lines 1241–1266](../src/server/linnea_http2.asm#L1241)
requires a nonempty `:authority`, rejects `:scheme` and `:path`, and compares an
optional `Host`, but never validates the contents of `:authority`. It falls
through to [`h2_serve`](../src/server/linnea_http2.asm#L1469), which correctly
does not implement CONNECT but replies 405.

That bypass admits `:authority: bad/path`. A slash cannot occur in CONNECT's
authority-form target: HTTP/2 requires the field to contain the host and port,
equivalent to the CONNECT authority-form request target
([RFC 9113 §8.5](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.5)).
HTTP semantics in turn require that target to consist only of host and port,
with no default port ([RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)).
RFC 9113 says a CONNECT request outside those restrictions is malformed and
invalid pseudo-header fields must be treated as malformed
([RFC 9113 §§8.5, 8.3](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.5)).

### Reproduction

From the repository root, start the TLS test server and send two literal,
unindexed HPACK CONNECT requests. The first is the acceptance control: a valid
but unsupported CONNECT receives the documented 405. The second differs only
in that its authority contains `/`; it must receive `RST_STREAM`, but Linnea
sends the same response HEADERS frame.

```sh
d=$(mktemp -d /tmp/linnea-audit-124-XXXXXX)
./bin/linnea --config test/configs/tls.json >"$d/out" 2>"$d/err" & server=$!
trap 'kill "$server" 2>/dev/null; wait "$server" 2>/dev/null' EXIT
sleep 0.3
python3 - test/tls/server.crt 61443 <<'PY'
import socket, ssl, sys

ca, port = sys.argv[1], int(sys.argv[2])
def frame(kind, flags, stream, payload=b""):
    return (len(payload).to_bytes(3, "big") + bytes((kind, flags))
            + stream.to_bytes(4, "big") + payload)
def literal(name, value):
    return b"\0" + bytes((len(name),)) + name + bytes((len(value),)) + value
def request(authority):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)),
                        server_hostname="localhost")
    assert s.selected_alpn_protocol() == "h2"
    fields = literal(b":method", b"CONNECT") + literal(b":authority", authority)
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0)
              + frame(1, 5, 1, fields))
    s.settimeout(3)
    while True:
        head = s.recv(9)
        while len(head) < 9:
            head += s.recv(9 - len(head))
        length = int.from_bytes(head[:3], "big")
        payload = b""
        while len(payload) < length:
            payload += s.recv(length - len(payload))
        if int.from_bytes(head[5:], "big") == 1 and head[3] in (1, 3):
            # This server emits :status 405 as literal-with-indexed-name: 08 03 405.
            print(f"{authority!r}: " +
                  ("HEADERS (:status 405)" if head[3] == 1 and payload[:5] == b"\x08\x03" + b"405"
                   else "RST_STREAM" if head[3] == 3 else f"frame {head[3]}"))
            break
    s.close()

request(b"localhost:443")
request(b"bad/path")
PY
```

Observed output:

```
b'localhost:443': HEADERS (:status 405)
b'bad/path': HEADERS (:status 405)
```

The control establishes that 405 is the intended application response for a
well-formed unsupported method. The second line shows the malformed request
took that same application path rather than being rejected at the HTTP/2
boundary.

### Impact

Although Linnea currently declines every CONNECT request, it reports malformed
protocol input as a valid request whose method happens to be unsupported. This
violates the stream-error boundary clients and intermediaries rely on, hides bad
input from protocol monitoring, and leaves an invalid authority admitted if
CONNECT is implemented later.

### Recommended fix

Keep the CONNECT-specific omission checks, but validate its `:authority` as
CONNECT authority-form before `.serve`: require a syntactically valid host and
an explicit valid port, including bracketed IPv6 handling. On failure take the
existing `.malformed_stream` path. Add the two requests above as paired tests,
plus malformed no-port and invalid-port cases; the valid unsupported CONNECT
must remain a 405 while each malformed form yields `RST_STREAM(PROTOCOL_ERROR)`.

## Resolution (2026-08-28)

**CONFIRMED and fixed.** The recommendation is adopted in full, including the
part that goes further than the reference implementation — with the measurement
that says so recorded below.

### Reproduced first

Ten CONNECT requests differing only in `:authority`, against `02c380c` on
`test/configs/tls-h2.json`. Every one of them, including the report's
`bad/path`, was answered 405:

```
b'example.com:443'   -> 405     b'exa mple.com:443'  -> 405
b'bad/path'          -> 405     b'user@host:443'     -> 405
b'example.com'       -> 405     b'[deadbeef]:443'    -> 405
b'example.com:99999' -> 405     b'example.com:44a'   -> 405
b'[::1]:443'         -> 405     b'[::1]'             -> 405
```

The report is right about the cause, not just the symptom. The CONNECT branch
exists to skip `linnea_hpack_req_check` (a CONNECT legitimately omits `:scheme`
and `:path`), and `req_check` is where the call to `linnea_http_authority_host`
lives. Skipping the mandatory-pseudo-header rules skipped the authority grammar
with them. `:authority` nonempty was the entire test.

### The oracle disagrees on half of it, and that is the interesting part

There is no `openssl` verdict for HTTP/2 framing, so the independent oracle here
is nghttp2's own server — `nghttpd --no-tls -d test/www 61999` — sent the same
ten requests over cleartext h2:

| `:authority` | nghttp2 | Linnea before | Linnea after |
|---|---|---|---|
| `example.com:443` | 405 | 405 | 405 |
| `[::1]:443` | 405 | 405 | 405 |
| `bad/path` | **RST(PROTOCOL_ERROR)** | 405 | RST |
| `exa mple.com:443` | **RST** | 405 | RST |
| `user@host:443` | **RST** | 405 | RST |
| `example.com` (no port) | 405 | 405 | **RST** |
| `[::1]` (no port) | 405 | 405 | **RST** |
| `example.com:99999` | 405 | 405 | **RST** |
| `example.com:44a` | 405 | 405 | **RST** |
| `[deadbeef]:443` | 405 | 405 | **RST** |

So the finding's own example is confirmed by an implementation nobody in this
tree wrote: nghttp2 resets `bad/path`, a space, and userinfo. On the other five
nghttp2 is lenient and this build is now stricter. I am taking that divergence
deliberately, for two separate reasons:

**Three of the five are not new strictness, they are the strictness this server
already had everywhere else.** Measured on the same binary with an ordinary
`GET`:

```
GET :authority=b'localhost:61446'   -> 200      GET :authority=b'example.com:99999' -> RST
GET :authority=b'example.com'       -> 200      GET :authority=b'example.com:44a'   -> RST
                                                GET :authority=b'[deadbeef]:443'    -> RST
                                                GET :authority=b'bad/path'          -> RST
```

An out-of-range port, a non-numeric port and `[deadbeef]` were already stream
errors on every request that went through `req_check`; only the two portless
forms are newly refused. CONNECT was the one hole in the one authority grammar
report 2 consolidated. Closing it is consistency;
had I written a second, laxer CONNECT grammar to match nghttp2 I would have
reintroduced exactly the split that finding.

**The mandatory port is the one genuinely new rule, and it is safe here because
it cannot refuse anything that would otherwise succeed.** RFC 9113 8.5 lists
"`:authority` contains the host and port to connect to" among the restrictions
whose violation is malformed, and RFC 9110 9.3.6 gives CONNECT no default port
to fall back on — a portless CONNECT names no destination. A `GET` still accepts
a bare `example.com`, because a scheme supplies its port; a CONNECT has no
scheme. And since this build implements no tunnels, both answers to
`CONNECT example.com` are refusals: 405 before, RST_STREAM(PROTOCOL_ERROR)
after. There is no legitimate request this can turn into an outage, which is not
something I would have said about tightening the shared grammar.

### The change

One insertion in `h2_req_process`, after the `:scheme`/`:path` checks and before
the `Host` comparison, so every path into `.serve` passes it. It calls the
existing `linnea_http_authority_host` — no new grammar — and derives whether a
port was present from what that function already returns (`rax` = host_len,
`rdx` = host_off 0 or 1) rather than rescanning: the host token ends at
`host_off + host_len`, one further for a bracketed literal's `]`, and anything
past that the grammar has already proved to be `":"` plus a port in 0..65535. So
the only remaining question is whether anything is there at all. Failure takes
the existing `.malformed_stream`, which emits RST_STREAM(PROTOCOL_ERROR).

`r12` (the input cursor, read at `.serve` and `.rl_ok`) is live across that call;
`linnea_http_authority_host` pushes and pops `rbx`/`r12`/`r13`, and the call site
sits at the same stack depth and alignment as the existing `req_check` call.

Two things checked rather than assumed while scoping it: `method_connect_h2` is
referenced only from `linnea_http2.asm`, so h3 has no parallel branch (a CONNECT
over h3 goes through `req_check` and is malformed for want of `:path`); and this
build never sends `SETTINGS_ENABLE_CONNECT_PROTOCOL`, so no client may send the
RFC 8441 extended CONNECT that would legitimately carry `:scheme` and `:path`.

### Coverage, A/B'd against the pre-fix binary

`test/tls/h2_connect.py` gains eight rejection cases and three acceptance
controls, and now asserts the RST_STREAM error code (PROTOCOL_ERROR) rather than
just "a reset". Built the pre-fix binary and ran the new file against both:

```
pre-fix  (/tmp/linnea-prefix):  8 FAIL   -- all eight malformed forms answered 405
post-fix (bin/linnea):         16 ok, exit 0
```

The three new acceptance controls — `[::1]:443` (the bracketed branch, with a
port), `example.com:65535` (the port bound, from the accepting side) and a
`Host` agreeing with `:authority` (the compare my insertion now sits in front
of) — pass on **both** binaries. That is what stops a build that reset every
CONNECT from passing the rejection half, and it is why they are there.

### Acceptance controls, run before the fix and again after

- **All 63 configs in `test/configs/`**: exit codes byte-identical pre- and
  post-fix (39 load, 24 are the negative fixtures that must not).
- **`test/configs/doc_claims_test.py`**: 191 PASS lines before, 191 after, "all
  claims hold" — the count, not the banner, since the banner prints either way.
- **`test/tls/prod_cert_check.sh`**: exit 0, the real 3-certificate chain at
  `/etc/linnea/certs/linnea.amberbio.com/fullchain.pem` fully parsed. No
  certificate, PEM or DER code was touched; run as a control anyway.

### What was run

```
./test/shards/run.sh tls/20-e2e.sh tls/40-http2.sh
  -> 108 passed, 0 failed, 5 SKIPPED (fast run), 80s, "*** PARTIAL RUN ***"
```

`20-e2e.sh` is prefixed only because `40-http2.sh` inherits the proxy backend
and `$U` from it. The change is reachable only when `:method` is exactly
`CONNECT`, so `40-http2.sh` — which owns the CONNECT test — is the shard file
that covers it; nothing in the h1, h3, QUIC or TLS-client paths can enter that
branch.

**The full suite was NOT run**, and neither was `LINNEA_SUITE=full`. The above is
a partial run of two named files, not shard coverage, and it does not gate a
deploy. The full suite is run separately before deploying.
