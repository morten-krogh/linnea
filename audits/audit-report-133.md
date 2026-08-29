# Audit Report 133

Audited commit `21f14cf` (`audit 132: no issues found`), 2026-08-29.

This pass examined HTTP/1 request-header parsing and proxy response framing,
HTTP/2 request-stream lifecycle and flow-control accounting, and TLS record and
ClientHello handling. The HTTP/2 and TLS areas came back clean. It found one
HTTP/1 upstream-response grammar defect: the shared validator accepts a status
line that omits the mandatory space after its status code, and the HTTP/1 proxy
then relays that malformed line to its client. No source, test, or configuration
file was changed in this audit; only this report was added.

## Finding 1 — A proxy accepts and relays a status line without the required space

**Severity:** Low  
**Confidence:** High  
**Status:** Open

[`linnea_http_upstream_head_valid`](../src/server/linnea_http.asm#L4234)
accepts either a space *or a CR* immediately after the three status-code digits:
the `cmp al, 13` / `je .hv_status` path treats `HTTP/1.1 200\r\n` as a complete,
valid status line. RFC 9112 §4 instead defines a status line as
`HTTP-version SP status-code SP [ reason-phrase ] CRLF`; the second `SP` is
mandatory even when the reason phrase is empty. The validator is the gate used
before the proxy response is rewritten, so [`linnea_http_proxy_head`](../src/server/linnea_http.asm#L4660)
then accepts the head and emits the same malformed first line to the downstream
HTTP/1 client.

### Reproduction

From the repository root, start the existing cleartext proxy fixture and a
one-shot upstream which omits the required post-code space. The client prints
the response's first line with `repr`, so the missing byte is visible.

```sh
d=$(mktemp -d /tmp/linnea-audit-133-XXXXXX)
python3 - <<'PY' >"$d/upstream.out" 2>&1 & upstream=$!
import socket

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 61100))
s.listen(1)
c, _ = s.accept()
request = b''
while b'\r\n\r\n' not in request:
    request += c.recv(4096)
c.sendall(b'HTTP/1.1 200\r\nContent-Length: 2\r\n'
          b'Connection: close\r\n\r\nOK')
c.close()
s.close()
PY
./bin/linnea --config test/configs/listen.json >"$d/server.out" 2>"$d/server.err" & server=$!
trap 'kill "$server" "$upstream" 2>/dev/null; wait "$server" "$upstream" 2>/dev/null; rm -rf "$d"' EXIT
sleep 0.3
python3 - <<'PY'
import socket

c = socket.create_connection(('127.0.0.1', 61080))
c.sendall(b'GET /api/status HTTP/1.1\r\nHost: one.test\r\n'
          b'Connection: close\r\n\r\n')
response = b''
while True:
    part = c.recv(4096)
    if not part:
        break
    response += part
c.close()
print(repr(response.split(b'\r\n', 1)[0]))
print(response.decode('latin1'), end='')
PY
```

Observed output:

```
b'HTTP/1.1 200'
HTTP/1.1 200
Content-Length: 2
Via: 1.1 linnea
Connection: close

OK
```

The response is a relayed `200`, rather than a `502 Bad Gateway`, and its first
line has no space after `200`. A conforming backend spelling, `HTTP/1.1 200 OK`,
is unaffected by requiring the missing delimiter.

### Impact

A faulty or malicious upstream can make Linnea emit an invalid HTTP response.
Clients that parse status lines strictly reject it; lenient clients may disagree
about the boundary, defeating the proxy's shared upstream-validation boundary.
The same validator is shared by the HTTP/2 and HTTP/3 proxy paths, where the
malformed upstream line is instead normalized into a downstream `:status 200`.

### Recommended fix

Require `r12[12]` to be a space, then scan the optional reason phrase after
that space. Keep the existing CRLF check and add paired proxy tests: reject
`HTTP/1.1 200\r\n` with 502 while accepting `HTTP/1.1 200 \r\n` and
`HTTP/1.1 200 OK\r\n`.

## Resolution (fix pass, 2026-08-29)

**Finding 1: FIXED** — reproduced at `21f14cf`, fixed in
[`linnea_http_upstream_head_valid`](../src/server/linnea_http.asm#L4234), and
every measurement below was re-run against the tree as it now stands.

A note on provenance, because it affects what this section is worth. The code
change and the test rows were written by the harness fix pass of run
`20260829-055419`, whose session ended while it was waiting on a shard run it
had started — it never reached this write-up. Nothing here is quoted from that
session's logs: the binaries were rebuilt from the current source and every
number below was measured again afterwards.

### What the defect is

The validator accepted either a space **or a CR** after the three status-code
digits, so `HTTP/1.1 200\r\n` passed the gate. RFC 9112 §4 spells a status line
`HTTP-version SP status-code SP [ reason-phrase ] CRLF`: the second SP is part
of the grammar even when the reason phrase is empty. The fix deletes the
CR-accepting path and requires the SP.

The wrong status was common to all three protocols. The malformed *first line*
is specific to HTTP/1, which relays the upstream line from the status code
onward rather than rebuilding it — the path the finding names.

### Measured, before and after

The A/B runs `test/proxy_upstream_head.py` against two binaries: the pre-fix
build and the current one, which are byte-different, and the current one
reproduces exactly from a forced rebuild of the tree's source.

| upstream sends | pre-fix | after |
|---|---|---|
| `HTTP/1.1 200\r\n` (`statusnosp`) | h1/h2/h3 all **200** | **502** on all three |
| `HTTP/1.1 404\r\n` (`statusnosp404`) | h1/h2/h3 all **404** | **502** on all three |
| `HTTP/1.1 103\r\n` interim (`earlynosp`) | h1/h2/h3 all **200** | **502** on all three |
| `HTTP/1.1 200 \r\n` (`statusspempty`) | 200 `valid` | 200 `valid` (unchanged control) |
| `HTTP/1.1 200\rX-Fold:` (`badstatuscr`) | 502 | 502 (unchanged control) |

`matrix rc=1` with 3 FAIL before, `matrix rc=0` with 0 FAIL after.

Separately, on the bytes actually written to the client — the claim the matrix
does not measure, since it judges status codes. The report's own reproduction
shape, run against both binaries:

```
linnea.prefix:  first line to client: b'HTTP/1.1 200'
linnea.fixed:   first line to client: b'HTTP/1.1 502 Bad Gateway'
```

Before the fix a client received a first line with no SP and no reason phrase —
bytes no HTTP/1 sender may send. That is the finding, confirmed directly.

### Coverage, and why the control is a control

Four rejection rows and one acceptance row were added to
`test/proxy_upstream_head.py`, with their upstream responses in
`test/proxy_backend.py`. `statusspempty` is the row that keeps the rule honest:
it sends `HTTP/1.1 200 \r\n`, a legal status line whose reason phrase is absent
but whose SP is present, and it answers **200 both before and after the fix**.
A gate that demanded `1*VCHAR` after the space would pass every rejection row
above and fail that one, so "refuse anything without a reason phrase" cannot
pass this matrix. `badstatuscr` (audit 9) sits directly above them unchanged
and also passes both sides.

### What was run

- `test/proxy_upstream_head.py` via a standalone A/B against both binaries —
  3 FAIL before, 0 FAIL after, detailed above.
- The report's reproduction against both binaries, for the wire bytes.
- `./test/shards/run.sh tls/20-e2e.sh tls/30-h3-proxy.sh` — the acceptance
  control, once, at the end: **99 passed, 0 failed, 2 SKIPPED (fast run)**,
  `rc=0`. This is the shard that invokes the changed matrix
  (`tls/30-h3-proxy.sh:16`).
- `test/configs/doc_claims_test.py` — **191 claims, "all claims hold"**.
- `make bin/linnea` — builds clean; a forced rebuild reproduces the tested
  binary exactly.

`test/tls/prod_cert_check.sh` was not required: no certificate, PEM or DER code
was touched.

**The full suite was not run.** `LINNEA_SUITE=full` and the other shards
(`base`, `h1`, `quic`) were deliberately not run — this pass was scoped to the
changed path, and the full suite is run separately before a deploy.
