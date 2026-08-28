# Audit Report 128

Audited commit `0a8ae33` (`audit 127: Percent-encoded reg-names are rejected as invalid authorities`), 2026-08-28.

This pass followed HTTP/1 request framing into the proxy rewrite. It found one
shared flag bit that means both “the client spoke HTTP/1.0” and “a chunked
request was decoded, so synthesize a Content-Length for the upstream.” No
source, test, or configuration file was changed in this audit; only this report
was added.

## Finding 1 — Every HTTP/1.0 proxied request gets a synthetic Content-Length

**Severity:** Medium  
**Confidence:** High  
**Status:** Open

[`linnea_http_handle`](../src/server/linnea_http.asm#L1149) sets bit 8 in its
request flags for HTTP/1.0. The chunked-body completion paths set that *same*
bit at [lines 1875 and 1895](../src/server/linnea_http.asm#L1875) to mark that
the proxy must add a Content-Length after removing `Transfer-Encoding`.
Finally, the proxy rewrite checks only bit 8 and appends a new
`Content-Length` field ([line 3182](../src/server/linnea_http.asm#L3182)).

Consequently, an ordinary HTTP/1.0 request is treated as if it had been
de-chunked. If it already has a Content-Length, Linnea copies the original line
and then appends a second one. If it has no body, Linnea nevertheless adds
`Content-Length: 0`. This is not a harmless rewrite: HTTP message framing is
driven by Content-Length ([RFC 9112 §6](https://www.rfc-editor.org/rfc/rfc9112.html#section-6)),
and an intermediary should not create a second framing field when it copied a
valid one. Even identical duplicates can break strict backends and create
needless request-framing ambiguity between hops.

### Reproduction

From the repository root, this uses the existing cleartext proxy fixture on
port 61080. The temporary upstream deliberately rejects any request that does
not contain exactly one Content-Length field; it also prints the count it saw.

```sh
d=$(mktemp -d /tmp/linnea-audit-128-XXXXXX)
python3 - <<'PY' >"$d/upstream" 2>&1 & upstream=$!
import socket

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('127.0.0.1', 61100))
server.listen(1)
conn, _ = server.accept()
buf = b''
while b'\r\n\r\n' not in buf:
    part = conn.recv(4096)
    if not part:
        break
    buf += part
count = sum(line.lower().startswith(b'content-length:')
            for line in buf.split(b'\r\n'))
print(buf.split(b'\r\n\r\n', 1)[0].decode('latin1'), flush=True)
print('content-length fields:', count, flush=True)
conn.sendall(b'HTTP/1.1 ' + (b'200 OK' if count == 1 else b'400 Bad Request') +
             b'\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
conn.close()
server.close()
PY
./bin/linnea --config test/configs/listen.json >"$d/server.out" 2>"$d/server.err" & server=$!
trap 'kill "$server" "$upstream" 2>/dev/null; wait "$server" "$upstream" 2>/dev/null; rm -rf "$d"' EXIT
sleep 0.3
python3 - <<'PY'
import socket

client = socket.create_connection(('127.0.0.1', 61080))
client.sendall(b'POST /api/echo HTTP/1.0\r\nHost: one.test\r\n'
               b'Content-Length: 3\r\n\r\nabc')
print(client.recv(4096).split(b'\r\n', 1)[0].decode())
client.close()
PY
cat "$d/upstream"
```

Observed output:

```
HTTP/1.1 400 Bad Request
POST /api/echo HTTP/1.1
Host: one.test
Content-Length: 3
Content-Length: 3
Via: 1.1 linnea
Connection: close
content-length fields: 2
```

The request is otherwise ordinary: changing only its version to `HTTP/1.1`
leaves the marker clear, so the upstream receives one Content-Length and
answers 200. The response status above is therefore the proxy's externally
visible failure, not a malformed client request or an unavailable upstream.

### Impact

Any HTTP/1.0 client using a proxy location can be refused by a conforming,
strict upstream whenever it sends a body. Backends that tolerate identical
duplicates still receive a message Linnea should not generate. Requests without
a body are affected too, because they gain an unsolicited `Content-Length: 0`.

### Recommended fix

Give the HTTP/1.0 state and the “decoded chunked body needs a synthetic
Content-Length” state separate bits (or store the latter in its own local).
Only set the synthetic-header state in the two chunked completion paths, and
only append the header when that state is set. Add a paired proxy test: an
HTTP/1.0 counted POST must reach the backend with exactly its original one
Content-Length, while an HTTP/1.1 chunked POST must reach it with exactly one
synthesized Content-Length and no Transfer-Encoding.

## Resolution (2026-08-28)

**CONFIRMED; no code change was made in this audit.** The reproduction was run
against `0a8ae33` and produced the status and field count shown above. The
three cited branches establish the direct cause: bit 8 is set solely by the
HTTP/1.0 version branch in this request, then independently interpreted as the
de-chunked-body marker by the proxy rewrite.

---

## Resolution

**CONFIRMED and FIXED, as recommended.** The two states now have a bit each.
Bit 8 keeps its original meaning — the client spoke HTTP/1.0 — and the new bit
128 means "a chunked body was decoded, so this rewrite owes the backend a
length". The two chunked completion paths set 128; the proxy rewrite tests 128.
Three lines in `src/server/linnea_http.asm`, plus the stack-local map at the top
of `linnea_http_handle`, which documented `[rsp+136]` as "1=CL, 2=TE" and stopped
— the shared bit was invisible from the one place written to make it visible.

### Reproduced first, against the audited build

The report's fixture was run verbatim against `0a8ae33` and produced exactly the
status and field count it claims. Re-run against the shard's own backend
(`/api/headers` echoes the head it received), on `bin/linnea` before and after:

| request | backend saw, before | after | nginx 1.30.4 |
|---|---|---|---|
| `POST` HTTP/1.0, `Content-Length: 3` | **`3`, `3`** | `3` | `3` |
| `GET` HTTP/1.0, no body | **`0`** | absent | absent |
| `POST` HTTP/1.1, `Content-Length: 3` | `3` | `3` | `3` |
| `GET` HTTP/1.1, no body | absent | absent | absent |
| `POST` HTTP/1.1, chunked | `3` | `3` | `3` |

Both failing rows are the finding, and the second one is not in the report's
fixture: a **bodyless** HTTP/1.0 request also gained a `Content-Length: 0`. The
report calls that out in Impact and it is real.

### The oracle, asked rather than assumed

nginx 1.30.4 — already an interop oracle in `tls/80-nginx-interop.sh` — was
configured as a proxy in front of the same echoing backend and sent the same
five requests, at `proxy_http_version 1.1` and at its 1.0 default. Both
configurations agree with the post-fix column on every row, including the one
where a case could have been argued for keeping the old behaviour: nginx does
**not** put `Content-Length: 0` on a forwarded bodyless HTTP/1.0 request either.
It also de-chunks and synthesizes exactly one `Content-Length: 3`, so the field
we owe is the field it writes.

### A/B, including a build that cannot pass the controls

`test/tls/h1_proxy_content_length.py` is new, wired into `h1/30-proxying.sh`,
and was run against three binaries built from this tree:

| build | result |
|---|---|
| pre-fix (`0a8ae33`) | **2 FAIL** — the two HTTP/1.0 rows, exactly as above |
| blanket "never append a Content-Length" | **5 FAIL** — all three chunked rows lose the synthesized field, and both de-chunked bodies arrive at the backend as **0 bytes** |
| this fix | 9 ok |

The blanket build is the pairing the workflow asks for. "The 1.0 request gets
one Content-Length" is satisfied by an implementation that never writes the
field at all — and that implementation silently truncates every chunked upload
to nothing, which is worse than the duplicate it removes. The chunked rows are
what refuses it.

### The size boundary is crossed on purpose

The state is set in **two** places for two different body shapes, so the test
exercises both: a 3-byte chunked body is decoded in place in `in_buf`, and a
60000-byte one (`LINNEA_CONN_IN_BUF` is 17408) is captured to a spill file and
takes its length from `spill_len` instead. Both must gain exactly one field with
the right value, and both echo bodies are compared byte for byte — a wrong
synthesized length truncates an upload without any error anywhere.

The crossing case is covered too: **HTTP/1.0 with a chunked body**, where both
bits are now set. The chunked one decides, and it reaches the backend with one
`Content-Length: 3`.

### What was checked for collateral damage

Bit 8 has two other readers, both of which run *before* the chunked completion
paths that used to set it — the Expect/100-continue refusal (RFC 9110 10.1.1)
and the "HTTP/1.0 may omit Host" fallback. Neither could ever see the borrowed
value, which is why this bug was one-directional: 1.0 leaked into the proxy
rewrite, but a de-chunked 1.1 request was never mistaken for 1.0. Nothing else
in the function reads `[rsp+136]` after those two paths. Bit 128 was free.

### What was run

- `test/shards/run.sh base` — **66 passed, 0 failed, 0 skipped**. Run FIRST, as
  the acceptance control: it loads every config in `test/configs/`.
- `test/configs/doc_claims_test.py` — **191 claims, all hold** (the count, not
  just the verdict).
- `test/tls/prod_cert_check.sh` — **0**, the real 3-certificate chain at
  `/etc/linnea/certs/linnea.amberbio.com/fullchain.pem` parsed. This change
  touches no certificate, PEM or DER code, so this was belt-and-braces.
- `test/shards/run.sh h1/00-setup.sh h1/30-proxying.sh h1/50-teardown.sh` — the
  targeted iteration loop, PARTIAL, 75 passed / 0 failed.
- `test/shards/run.sh h1` — the one full-directory run, at the end:
  **478 passed, 0 failed, 7 SKIPPED** (144s). The 7 are the usual
  `extensive`-gated slow checks, unchanged by this work.

**The full suite was NOT run, and `LINNEA_SUITE=full` was NOT run.** The `quic`
and `tls` shards were not run either: the change is three lines in the HTTP/1
request handler's own stack flags, and the h1 shard is where that path is
exercised. That is a deliberate scope choice for turnaround, not a claim of
coverage — the full suite gates the deploy and is run separately.
