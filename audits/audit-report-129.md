# Audit Report 129

Audited commit `3034dd9` (`audit 128: Every HTTP/1.0 proxied request gets a synthetic Content-Length`), 2026-08-28.

This pass followed the HTTP/1 request's persistence decision through the proxy
response path. It found that an HTTP/1.0 client can use the obsolete
`Connection: keep-alive` mechanism through a proxy location, and Linnea both
advertises that persistence and leaves the downstream socket open. No source,
test, or configuration file was changed in this audit; only this report was
added.

## Finding 1 — A proxy honors HTTP/1.0 `Connection: keep-alive`

**Severity:** Low  
**Confidence:** High  
**Status:** Open

[`linnea_http_handle`](../src/server/linnea_http.asm#L1154) marks an HTTP/1.0
request and defaults its downstream persistence state to closed. But its
general `Connection` token loop subsequently treats `keep-alive` as an
unconditional request to set that state back to one
([lines 1358–1369](../src/server/linnea_http.asm#L1358)). The proxy setup copies
that state to `connection.keep_alive` ([lines 2883–2884](../src/server/linnea_http.asm#L2883)),
and the response writer emits `Connection: keep-alive` whenever the field is
set ([lines 5124–5128](../src/server/linnea_http.asm#L5124)).

That is not an available persistence mode for this request path. RFC 9112
§9.3 says that an HTTP/1.0 `keep-alive` request can persist only when the
recipient is *not* a proxy (or when the message is a response). Linnea is an
intermediary for a proxy location. The same section describes the required
alternative: the connection closes after the current response. Keeping it
open contradicts the protocol's specific guard against the historically
faulty HTTP/1.0 proxy mechanism ([RFC 9112 §9.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-9.3)).

### Reproduction

From the repository root, this starts the existing cleartext proxy fixture on
port 61080 and a minimal upstream on its configured port 61100. The client
prints the complete response, then checks whether Linnea closed the socket.

```sh
d=$(mktemp -d /tmp/linnea-audit-129-XXXXXX)
python3 - <<'PY' >"$d/upstream" 2>&1 & upstream=$!
import socket

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('127.0.0.1', 61100))
server.listen(1)
conn, _ = server.accept()
head = b''
while b'\r\n\r\n' not in head:
    head += conn.recv(4096)
print(head.decode('latin1'), flush=True)
conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n'
             b'Connection: close\r\n\r\nOK')
conn.close()
server.close()
PY
./bin/linnea --config test/configs/listen.json >"$d/server.out" 2>"$d/server.err" & server=$!
trap 'kill "$server" "$upstream" 2>/dev/null; wait "$server" "$upstream" 2>/dev/null; rm -rf "$d"' EXIT
sleep 0.3
python3 - <<'PY'
import socket

client = socket.create_connection(('127.0.0.1', 61080))
client.sendall(b'GET /api/echo HTTP/1.0\r\nHost: one.test\r\n'
               b'Connection: keep-alive\r\n\r\n')
response = b''
while b'\r\n\r\n' not in response:
    response += client.recv(4096)
while not response.endswith(b'OK'):
    response += client.recv(4096)
print(response.decode('latin1'), end='')
client.settimeout(0.5)
try:
    print('eof:', client.recv(1) == b'')
except TimeoutError:
    print('eof: false (still open)')
client.close()
PY
cat "$d/upstream"
```

Observed output:

```
HTTP/1.1 200 OK
Content-Length: 2
Via: 1.1 linnea
Connection: keep-alive

OK
eof: false (still open)
GET /api/echo HTTP/1.1
Host: one.test
Via: 1.1 linnea
Connection: close
```

The upstream's `Connection: close` is deliberately unrelated: it governs the
Linnea-to-upstream hop, which the rewrite correctly replaces. The failure is
on the client-facing hop: Linnea promises persistence to an HTTP/1.0 client and
does not close it. Removing only `Connection: keep-alive` from the client
request leaves the initial HTTP/1.0 default in place, so the response carries
`Connection: close` and the EOF check succeeds.

### Impact

An HTTP/1.0 client can keep a proxy worker connection allocated until its idle
timeout, despite the HTTP/1.0 proxy rule that requires it to close after the
response. More importantly, it advertises a legacy persistence behavior RFC
9112 explicitly withholds from proxies because old implementations could
forward the connection option and hang. Linnea currently strips the field on
its own upstream hop, but the downstream protocol violation remains externally
observable and can unnecessarily retain client-side connection state.

### Recommended fix

When parsing a `keep-alive` connection token, leave the persistence state
closed when the request is HTTP/1.0 and its selected location is a proxy; or,
more simply, force `connection.keep_alive` to zero in `.proxy_build` when flag
bit 8 says the client spoke HTTP/1.0. Add paired coverage: an HTTP/1.0 static
request with `Connection: keep-alive` may retain the legacy connection, while
the same request through `/api` must receive `Connection: close` and EOF after
the response. The static control prevents a blanket removal of the documented
HTTP/1.0 server behavior from passing.

## Resolution (2026-08-28)

**CONFIRMED; no code change was made in this audit.** The reproduction was run
against `3034dd9` and produced the advertised keep-alive field and open socket
shown above. The version branch, token loop, proxy state transfer, and response
writer establish the direct path from the client token to the non-closing
proxy connection.

---

## Resolution

**CONFIRMED and FIXED, as recommended — over the oracle's objection, which is
the part worth reading.** One `test` and a branch in `.proxy_build`: the
persistence state copied to `connection.keep_alive` is forced to zero when flag
bit 8 says the client spoke HTTP/1.0. Nine lines of comment, five of code, in
`src/server/linnea_http.asm`, plus a pointer in the `Connection` token loop —
the loop takes half of the RFC 9112 9.3 determination and cannot take the other
half, because it runs before the location is matched.

### Reproduced first, against the audited build

The report's fixture was run verbatim against `3034dd9` and produced exactly the
head it claims. Widened to the matrix that actually decides the question — the
field the client is told, and whether a second request on that same socket is
answered, which is what persistence *is* rather than what it says:

| request | pre-fix | post-fix |
|---|---|---|
| `1.0` + `keep-alive` → `/api` (proxy) | **`keep-alive`, reused** | `close`, not reused |
| `1.0` + `keep-alive` → `/hello.txt` (static) | `keep-alive`, reused | `keep-alive`, reused |
| `1.1` → `/api` | `keep-alive`, reused | `keep-alive`, reused |
| `1.0` plain → `/api` | `close` | `close` |
| `1.0` `close, keep-alive` → `/api` | `close` | `close` |

The connection was genuinely reused, not merely advertised: a second request
written to the same socket came back `HTTP/1.1 200`.

### The oracle disagrees with the fix, and was asked rather than assumed

nginx 1.30.4 — the repo's standing HTTP oracle, as in report 128 — was put in
front of the same backend at `proxy_pass http://127.0.0.1:61100`, with a static
location beside it, and sent the same four requests:

| request | nginx 1.30.4 | linnea, post-fix |
|---|---|---|
| `1.0` + `keep-alive` → proxy | **`keep-alive`, persisted** | `close` |
| `1.0` + `keep-alive` → static | `keep-alive`, persisted | `keep-alive`, persisted |
| `1.0` plain → proxy | `close` | `close` |
| `1.1` → proxy | `keep-alive`, persisted | `keep-alive`, persisted |

So this fix makes linnea the outlier on row one. That is stated plainly because
it is the honest result, and it was nearly grounds to decline. Three
measurements decided it the other way:

1. **9.3's determination has no branch that reaches "persist" here.** The
   HTTP/1.0 bullet requires `keep-alive` present **and** "either the recipient
   is not a proxy or the message is a response". A request on a proxy prefix
   satisfies neither disjunct, and the algorithm falls through to "the
   connection will close after the current response". There is no SHOULD to
   weigh.
2. **Closing cannot break a client.** This is the opposite risk profile from
   report 118's decline, where enforcement meant refusing to start. `close` is
   HTTP/1.0's own default and every 1.0 client already handles it; the cost is
   one TCP handshake per request for a client class that is health checkers and
   `curl -0`. Nothing is refused, so there is no configuration that stops
   working.
3. **The role split is per-request, and it is kept.** Where linnea is the origin
   — every static prefix — the 1.0 persistence is permitted by the same bullet
   and is still honored, matching nginx exactly. The change is scoped to the
   prefix where we are an intermediary, which is what 9.3 conditions on.

### One thing the report gets wrong in its Impact

The report reasons from the historical hazard: "old implementations could
forward the connection option and hang". Measured, that hazard does not exist
here in either direction. `/api/headers` echoes the head the backend received,
and it reads `Connection: close` before this change and after it — linnea has
never forwarded the option upstream. The finding stands on 9.3's text alone,
not on the failure mode that motivated the text. That distinction is why the
severity is Low and why the fix was worth this much scrutiny.

Framing was checked too, since a persistent connection to a client that cannot
frame the body is the way this becomes a real bug: it was already safe. An
upstream response that is chunked or close-delimited already forces
`Connection: close` downstream, pre-fix and post-fix.

### A/B, including two builds that cannot pass the controls

`test/tls/h1_proxy_http10_keepalive.py` is new, wired into `h1/30-proxying.sh`,
and was run against three binaries built from this tree:

| build | result |
|---|---|
| pre-fix (`3034dd9`) | **1 FAIL** — the proxy row, `keep-alive` and reused |
| blanket "never honor 1.0 keep-alive" | **1 FAIL** — the *static* control: we are the origin there and the persistence is permitted |
| blanket "a proxy prefix never keeps alive" | **1 FAIL** — the *1.1* control: nothing about being a proxy touches the 1.1 default |
| this fix | 9 ok |

Two blanket builds, because "the 1.0 proxy request closes" is satisfied by two
different wrong implementations and each needs its own control. Both were built
and run, not argued. The test also asserts what did **not** move: the backend
still sees `Connection: close`, and the relayed body still arrives whole.

### Found along the way, and NOT fixed here

A chunked upstream response is relayed to an **HTTP/1.0 client with its
`Transfer-Encoding: chunked` intact** — the chunk framing arrives as body bytes
to a client that has no coding to remove it. RFC 9112 7.1: a server MUST NOT
send `Transfer-Encoding` unless the request indicates HTTP/1.1 or later. nginx,
asked the same question against the same backend, **de-chunks for the 1.0
client** (decoded body, `Connection: close`, no `Transfer-Encoding`) and chunks
only for 1.1. It is not a framing hole for us — the response already forces
`close`, so the bytes terminate — and commit `60f45b7`'s claim that "no chunked
to a 1.0 client ... cost nothing, because linnea never [generates] chunked" is
true of the static path and untrue of the relay. It is a separate defect in a
separate path and belongs in its own report, not smuggled into this one.

### What was run

- `test/shards/run.sh base` — **66 passed, 0 failed, 0 skipped**, before the
  change as the acceptance control and again after. It loads every config in
  `test/configs/`.
- `test/configs/doc_claims_test.py` — **191 claims, all hold**, before and
  after. The count, not just the verdict.
- `test/tls/prod_cert_check.sh` — **0**, the real 3-certificate chain at
  `/etc/linnea/certs/linnea.amberbio.com/fullchain.pem` parsed. This change
  touches no certificate, PEM or DER code; run because the workflow says to run
  it, not because there was a reason to doubt it.
- `test/shards/run.sh h1/00-setup.sh h1/30-proxying.sh h1/50-teardown.sh` — the
  targeted iteration loop, PARTIAL, **76 passed / 0 failed**.
- `test/shards/run.sh h1` — the one full-directory run, at the end:
  **479 passed, 0 failed, 7 SKIPPED**. 478 before this work plus the new check.
  The 7 are the usual `extensive`-gated slow checks, unchanged. The three
  pre-existing HTTP/1.0 persistence checks in `25-http-semantics.sh` — defaults
  to close, keep-alive honored, a second request served on one 1.0 connection —
  all still pass; they are static-path checks, which is the half of 9.3 this
  change deliberately leaves alone.

**The full suite was NOT run, and `LINNEA_SUITE=full` was NOT run.** The `tls`
and `quic` shards were not run either: the change is one branch in the HTTP/1
request handler's proxy setup, reachable only by an HTTP/1.0 request, and h1 is
where that path lives. That is a deliberate turnaround choice, not a claim of
coverage — the full suite gates the deploy and is run separately.
