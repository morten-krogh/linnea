# Audit Report 123

Audited commit `077e214` (`test: let run.sh take single shard files, so an edit-test loop is not 486s`), 2026-08-28.

This pass examined the shared HTTP/2 and HTTP/3 field decoder at the point it
rebuilds a request for an HTTP/1 backend. It found that punctuation which is
not permitted in an HTTP field name is accepted and forwarded verbatim. No
production code, test, or configuration was changed in this audit; only this
report was added.

## Finding 1 — HTTP/2 proxy forwards a non-token field name into HTTP/1

**Severity:** Medium  
**Confidence:** High  
**Status:** Open

[`emit_field`](../src/server/linnea_hpack.asm#L368) validates a field name only
as a nonempty sequence below DEL with no uppercase ASCII and with `:` limited
to a pseudo-header prefix. Its scan at
[lines 387–411](../src/server/linnea_hpack.asm#L387) therefore accepts
`x@test`: `@` is printable, lowercase-neutral, and is not `:`, but it is not a
`tchar` and hence cannot occur in an HTTP field name. RFC 9110 defines a field
name as a token, whose allowed punctuation excludes `@` ([RFC 9110
§5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.1)).

For a proxy request, the decoder's ordinary-field rebuild writes the unchecked
name as `name: value\r\n` into `hb_start`, and
[`h2_serve`](../src/server/linnea_http2.asm#L2346) copies that rebuilt text into
the HTTP/1.1 request head sent upstream. Thus an HTTP/2 peer can make Linnea
emit an HTTP/1 request which its own HTTP/1 parser would reject. The same
`emit_field` routine is also used by QPACK, so the validation gap is shared by
HTTP/3; the reproduction below demonstrates the HTTP/2 proxy path.

### Reproduction

Starting at the repository root, run the fixture backend and TLS server, then
send one ordinary HTTP/2 field name and one containing literal `@`. The small
encoder uses literal, unindexed HPACK fields, so the invalid name is explicit
on the wire.

```sh
d=$(mktemp -d /tmp/linnea-audit-123-XXXXXX)
LINNEA_TEST_RUNDIR="$d" python3 test/proxy_backend.py >"$d/backend.log" 2>&1 & backend=$!
./bin/linnea --config test/configs/tls.json >"$d/linnea.out" 2>"$d/linnea.err" & server=$!
trap 'kill "$server" "$backend" 2>/dev/null; wait "$server" "$backend" 2>/dev/null' EXIT
sleep 0.3
python3 - test/tls/server.crt 61443 <<'PY'
import socket, ssl, sys

ca, port = sys.argv[1], int(sys.argv[2])
def frame(kind, flags, stream, payload=b""):
    return (len(payload).to_bytes(3, "big") + bytes((kind, flags))
            + stream.to_bytes(4, "big") + payload)
def literal(name, value):
    return b"\0" + bytes((len(name),)) + name + bytes((len(value),)) + value
def request(name):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)),
                        server_hostname="localhost")
    assert s.selected_alpn_protocol() == "h2"
    fields = b"".join((literal(b":method", b"GET"),
                        literal(b":scheme", b"https"),
                        literal(b":authority", b"localhost"),
                        literal(b":path", b"/api/headers"),
                        literal(name, b"yes")))
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0)
              + frame(1, 5, 1, fields))
    s.settimeout(3)
    data = b""
    try:
        while True:
            head = s.recv(9)
            if not head:
                break
            while len(head) < 9:
                head += s.recv(9 - len(head))
            length = int.from_bytes(head[:3], "big")
            payload = b""
            while len(payload) < length:
                payload += s.recv(length - len(payload))
            if head[3] == 0 and int.from_bytes(head[5:], "big") == 1:
                data += payload
            if head[3] == 0 and head[4] & 1:
                break
    except OSError:
        pass
    s.close()
    return data

for name in (b"x-test", b"x@test"):
    body = request(name)
    print(f"{name!r}: DATA={bool(body)}, backend echo="
          f"{name + b': yes' in body}")
PY
```

Observed output:

```
b'x-test': DATA=True, backend echo=True
b'x@test': DATA=True, backend echo=True
```

The `x-test` request is the acceptance control. The `x@test` backend echo
proves that Linnea did not merely accept the malformed HTTP/2 field locally:
it serialized the invalid field name into an HTTP/1 request and sent it across
the proxy trust boundary.

### Impact

An HTTP/2 client can cause Linnea to generate an HTTP/1.1 request outside the
field-name grammar. A stricter backend, WAF, cache, or audit parser can reject
or interpret that request differently after Linnea has already selected and
connected the backend. This creates the same class of parser differential that
the HTTP/1 token validation prevents on direct requests.

### Recommended fix

Make the shared HTTP/2/HTTP/3 field-name scan require an HTTP token for regular
fields: allow only `tchar` bytes, while retaining the existing separate
first-byte `:` rule for recognised pseudo-headers. Add raw HTTP/2 and HTTP/3
proxy tests that send `x@test: yes` and assert both refusal and no backend
request, paired with the ordinary `x-test: yes` control above.

## Resolution (2026-08-28)

**CONFIRMED and FIXED.**

### Provenance: this fix was written by an interrupted run and then verified, not trusted

The harness iteration that produced this report was interrupted partway through
the fix. It left the code change, a test and the shard wiring in the tree with
no Resolution, and — because `claude` exits 0 on SIGINT — the harness could not
tell that from success by exit status. What stopped it was the content check for
a `## Resolution` section; otherwise a half-finished, never-built fix would have
passed the build gate and been committed as a good iteration.

Everything below was re-derived rather than taken on faith. **The change had
never been assembled**: the build gate is the step after the one that died.

### What was wrong

`emit_field` held a field name to RFC 9113 8.2.1's MINIMAL list — no `0x00`-
`0x20`, no uppercase, no `0x7f`-`0xff`, no non-leading colon. That list is a
floor, not the definition: the same section opens by asking implementations to
"validate field names and values according to their definitions in Sections 5.1
and 5.5 of [HTTP]", and RFC 9114 4.2 sends HTTP/3 to the same 5.1. A field name
is a **token**, so every delimiter but `:` — `@ ( ) , " / [ ] { } \ =` — passed
the decoder and the proxy rebuild wrote it verbatim into the HTTP/1.1 head sent
upstream.

`emit_field` is shared by HPACK and QPACK, so HTTP/3 had it too.

### Why this is not the same trade as reports 121 and 122

Those two made this build stricter than nginx, and that needed justifying.
Measured again here, nginx 1.30.4 as an h2 front end also accepts `x@test`:

```
nginx h2 ordinary  x-test: HEADERS(accepted)
nginx h2 non-token x@test: HEADERS(accepted)
```

But the argument here does not rest on the RFC alone. **HTTP/1 in this build has
always enforced the token rule** — `linnea_http.asm:923` and `:1146` call
`linnea_string_is_token`, and the fix calls that same helper. So accepting was
not "being liberal"; it was one binary answering 400 at its h1 door and 200 at
its h2 door for the same field name, forwarding to the same backend. The fix
removes a differential inside a single build rather than adding strictness to it.

### Refused outright, not deferred — deliberately, and unlike report 122

Report 122 introduced `.h1_unsafe`, a flag the proxy paths read, because DEL in
a field **value** is legal in HTTP/2 and illegal only in HTTP/1: refusing it at
the decoder would reject a static h2 request RFC 9113 calls well-formed. A
non-token **name** is different in kind — it is prohibited by the definition
8.2.1 points at, so it is malformed wherever the request is going. It is
therefore refused at the decoder, static requests included.

### Verification of code this session did not write

Two things were checked before the fix was believed, both of the class that has
cost this tree a production outage:

- `linnea_string_is_token` exists with the contract the call assumes
  (`rdi=ptr, rsi=len -> rax`), and its `extern` was already declared — the file
  calls it elsewhere.
- **`r8` is dead at the insertion point.** The fix uses `r8d` for the verdict.
  `emit_field`'s own comment calls `rcx` and `r8` its scratch, and the name-scan
  loop that uses `r8b` ends immediately above `.ef_name_ok`. Report 114 was an
  `r8` clobbered across a call, so this was confirmed rather than assumed.
  Push/pop order around the call is correct LIFO.

### Measurements

- **A/B, and the test is not vacuous.** With the fix `tls/20-e2e.sh` +
  `tls/30-h3-proxy.sh` is 99 passed / 0 failed; with the change stashed and
  rebuilt it is 98 / 1, and the single failure is exactly
  `proxy: h1/h2/h3 agree on refusing a non-token field name`.
- **Acceptance control: the full fast suite, 1191 passed / 0 failed** in 499s.
  Not a shard — `emit_field` is on every h2 and h3 request path, so narrower
  coverage would not have supported this. base+quic 164 and h1 426 unchanged;
  tls 600 -> 601 on the new check.
- The control inside `test/proxy_field_name.py` is the one that keeps the
  refusal honest: a name containing every tchar punctuation mark 5.6.2 allows
  must still be served and echoed. A fix that refused punctuation wholesale
  would pass every rejection row and fail that one.
- nginx 1.30.4 as the independent oracle, above.
- **The full suite (`LINNEA_SUITE=full`) was NOT run** and must be before
  deploying.
