# Audit Report 130

Audited commit `714fb0d` (`audit 129: A proxy honors HTTP/1.0 \`Connection: keep-alive\``), 2026-08-28.

This pass followed the HTTP/1 proxy response-framing decision for an HTTP/1.0
downstream request. It found that a chunked response from an upstream is passed
on as `Transfer-Encoding: chunked`, including its chunk framing, to a client
that requested HTTP/1.0. No source, test, or configuration file was changed in
this audit; only this report was added.

## Finding 1 — A proxy sends chunked transfer coding to HTTP/1.0 clients

**Severity:** Low  
**Confidence:** High  
**Status:** Open

The proxy response parser records whether the upstream response has
`Transfer-Encoding` in its framing flags. On a response without a
`Content-Length`, [`linnea_http_proxy_head`](../src/server/linnea_http.asm#L5078)
sets close-delimited mode, then unconditionally appends its own
`Transfer-Encoding: chunked` when that flag is set
([lines 5084–5101](../src/server/linnea_http.asm#L5084)). It deliberately
relays the body verbatim, so the receiving HTTP/1.0 client also gets the chunk
size lines and terminating chunk. There is no test of the request-version flag
which [`linnea_http_handle`](../src/server/linnea_http.asm#L1154) sets for an
HTTP/1.0 request.

That violates RFC 9112 §7.1: a server **MUST NOT** send `Transfer-Encoding`
unless the corresponding request indicates HTTP/1.1 or later. The protocol
version Linnea writes in its response line does not change the version the
client requested; the client-facing request below is HTTP/1.0. An intermediary
can instead de-chunk the upstream body and close the downstream connection to
delimit it, as it already does for close-delimited upstream responses
([RFC 9112 §7.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1)).

### Reproduction

From the repository root, this starts the existing cleartext proxy fixture and
a one-shot upstream which returns a chunked response. The client sends an
HTTP/1.0 request and prints every byte Linnea returns.

```sh
d=$(mktemp -d /tmp/linnea-audit-130-XXXXXX)
python3 - <<'PY' >"$d/upstream.out" 2>&1 & upstream=$!
import socket

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('127.0.0.1', 61100))
server.listen(1)
conn, _ = server.accept()
request = b''
while b'\r\n\r\n' not in request:
    request += conn.recv(4096)
print(request.decode('latin1'), end='', flush=True)
conn.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n'
             b'Connection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n')
conn.close()
server.close()
PY
./bin/linnea --config test/configs/listen.json >"$d/server.out" 2>"$d/server.err" & server=$!
trap 'kill "$server" "$upstream" 2>/dev/null; wait "$server" "$upstream" 2>/dev/null; rm -rf "$d"' EXIT
sleep 0.3
python3 - <<'PY'
import socket

client = socket.create_connection(('127.0.0.1', 61080))
client.sendall(b'GET /api/chunked HTTP/1.0\r\nHost: one.test\r\n\r\n')
response = b''
while True:
    chunk = client.recv(4096)
    if not chunk:
        break
    response += chunk
print(response.decode('latin1'), end='')
client.close()
PY
cat "$d/upstream.out"
```

Observed output:

```
HTTP/1.1 200 OK
Transfer-Encoding: chunked
Via: 1.1 linnea
Connection: close

5
hello
0

GET /api/chunked HTTP/1.1
Host: one.test
Via: 1.1 linnea
Connection: close
```

The final request block is what the upstream received. Linnea correctly uses
HTTP/1.1 on that independent upstream hop, but the first block is the response
to the HTTP/1.0 client and contains both the prohibited field and the raw
chunk framing.

### Impact

An HTTP/1.0 client which does not implement chunked transfer coding receives
the chunk delimiters as application data rather than `hello`. The response
does close, so it is delimited and does not desynchronize a subsequent request,
but it is still unusable to clients that require HTTP/1.0 compatibility. This
is particularly relevant to legacy health checkers and integrations placed in
front of a proxy location.

### Recommended fix

When the downstream request is HTTP/1.0 and the upstream response is chunked,
decode the chunk framing while relaying it, omit `Transfer-Encoding`, and keep
the existing `Connection: close`. Add a paired test: the HTTP/1.0 case must
receive an unframed `hello` with no `Transfer-Encoding`, while an HTTP/1.1
control must retain the current valid chunked relay. The latter prevents a
blanket de-chunking change from passing.

## Resolution (2026-08-28)

**CONFIRMED; no code change was made in this audit.** The reproduction above
was run against `714fb0d` and produced the downstream `Transfer-Encoding:
chunked` field and raw `5`/`0` chunk delimiters shown above. The response
framing branch appends that field based only on upstream framing and has no
downstream HTTP/1.0 condition.

## Resolution (2026-08-28) — the fixing pass

*(The short section above is the auditing agent's own confirmation of its
finding, written in the audit that produced this report. This is the pass that
worked it.)*

**CONFIRMED, and the recommendation was right.** The reproduction in the report
ran unchanged against `714fb0d` and produced exactly the transcript above: an
HTTP/1.0 request answered with `Transfer-Encoding: chunked` and the `5` / `0`
chunk delimiters relayed as content. The recommended fix — de-chunk while
relaying, drop the field, keep the close — is what shipped.

### The oracle agreed before a line was written

nginx 1.30.4 was configured as a reverse proxy in front of the same one-shot
chunked upstream and asked the same two questions. Its verdict, verbatim:

```
1.0 request  b'HTTP/1.1 200 OK\r\nServer: nginx/1.30.4\r\n...\r\nConnection: close\r\n\r\nchunked body'
1.1 request  b'HTTP/1.1 200 OK\r\n...\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nc\r\nchunked body\r\n0\r\n\r\n'
```

No disagreement: nginx strips the coding for 1.0 and keeps it for 1.1. (It
re-chunks the 1.1 case into one chunk rather than relaying the upstream's
framing byte for byte. That is a difference from linnea and both are
conformant; it is not what this report is about, and it was not changed.)
`curl --http1.0` against the fixed build now prints `chunked body`, not the
framing.

### What changed

`linnea_spill_chunked` gained a third mode. It already had `CAPTURE` (decode a
request body into the spill file) and `VALIDATE` (judge the relayed response
bytes and copy nothing, report 24). `DECHUNK` is `VALIDATE` plus one thing: each
chunk's data is moved down over the framing already consumed, in the caller's
own buffer, and `rdx` returns how many decoded bytes now sit at the front. The
destination is always at or behind the source — framing only shrinks a message —
so the copy is forward and never overruns bytes the decoder has not read. One
decoder still, now three directions.

The proxy response head reads a new `linnea_connection.req_http_10`, written on
every proxied HTTP/1 request from the same `[rsp+136]` bit 8 that report 129's
persistence branch reads. It has to live on the connection because the response
head is parsed long after that stack frame is gone. Written *unconditionally*,
not only when set: a slot serves many requests and a 1.0 one can be followed by
a 1.1 one — the test for that is in the file below.

When it is set, `.until_eof` skips `hdr_te_chunked` and both relay sites ask for
`DECHUNK` instead of `VALIDATE`: the leftover that arrives behind the head
(`linnea_http_proxy_head`) and each later read (`linnea_uring .relay_data`).
Nothing else moved. That branch was already the close-delimited one, so the
`Connection: close` that delimits the message for a 1.0 client was already being
sent, and the decoder was already running over these exact bytes.

Two consequences worth naming:

* A relay read that decodes to **zero** bytes — a terminal chunk and its
  trailers, most often — has no send to arm. It now takes the path a completed
  send takes (finish if the terminal chunk was seen, read on if not). Arming a
  zero-length send would have looked to the drain like a closed peer.
  `/api/chunksplitok` reaches this from the head side too: its leftover is the
  four bytes `4;a=`, all framing.
* `.relayed` (the access log's byte count) follows the decoded length, not the
  encoded one, for a de-chunked response.

### Coverage, and the A/B that proves it tests something

`test/tls/h1_proxy_http10_chunked.py`, wired into `h1/30-proxying.sh` as
"proxy de-chunks for HTTP/1.0 and only for it". Fourteen rows, every one paired,
because three different blanket builds pass a third of this on their own: one
that stops sending the field but relays the framing fails the 1.0 *body* rows;
one that de-chunks everything fails the 1.1 control rows; one that drops the
body while de-chunking fails both. The routes were chosen to reach both decode
sites and the cases only one of them reaches — `/api/chunked` (head and body in
one write), `/api/chunklategood` (relay read), `/api/chunksplitok` (a leftover
that decodes to nothing), `/api/chunkkeepalive` (timed: the exchange must still
end at the terminal chunk, report 26, even with the framing stripped),
`/api/chunktrunc` and `/api/chunklatebad` (report 24's refusal to finish must
survive de-chunking).

Run against the **pre-fix binary**, built from a stash of `src` and `include`:

```
FAIL 1.0 chunked                      Transfer-Encoding 'chunked' (want None)
ok   1.1 chunked (control)            TE chunked  body b'7\r\nchunked\r\n5\r\n body\r\n0\r\n\r\n'
FAIL 1.0 chunked late                 Transfer-Encoding 'chunked' (want None)
ok   1.1 chunked late (control)       TE chunked  body b'4\r\nbody\r\n0\r\n\r\n'
FAIL 1.0 chunked split ext            Transfer-Encoding 'chunked' (want None)
ok   1.1 chunked split ext (control)  TE chunked  body b'4;a=bad\r\nbody\r\n0\r\n\r\n'
FAIL 1.0 chunked truncated            Transfer-Encoding 'chunked' (want None)
ok   1.1 chunked truncated (control)  TE chunked  body b'4\r\nbo'
FAIL 1.0 chunked bad late             Transfer-Encoding 'chunked' (want None)
ok   1.1 chunked bad late (control)   TE chunked  body b''
ok   1.0 counted (control)            TE (absent) body b'backend body'
ok   1.0 close-delimited (control)    TE (absent) body b'eof delimited body'
ok   1.0 chunked closes               Connection: close
FAIL 1.0 ends at the terminal chunk   TE 'chunked' body b'4\r\nbody\r\n0\r\n\r\n'
```

Six fail before, all fourteen pass after, and **every control passes on both
binaries** — which is the half that says the change did not simply break the
1.1 relay. A separate hand-written probe added one more pairing that the shard
fixture cannot express: a 1.0 request on a *static* prefix (which keeps its
connection alive, report 129) followed by a 1.1 proxied request on that same
socket. The 1.1 response still carries its framing; that is the row that would
catch `req_http_10` going stale across requests on a reused slot.

### A wrong expectation of mine, corrected by running it

My first draft of the malformed-chunk row expected the 1.0 client to receive the
good prefix `abc` before the close. It does not: the decoder judges the whole
read before any of it is forwarded, so a read containing `3\r\nabc\r\nZZ\r\n`
delivers nothing. That is pre-existing behaviour and identical for 1.1 — the
report's finding does not touch it. The row was rewritten to split the good
chunk into its own read, which is where the two versions differ meaningfully
(`abc` vs `3\r\nabc\r\n`) and where both are now asserted.

### What was measured

* `./test/shards/run.sh h1/00-setup.sh h1/30-proxying.sh h1/35-uploads.sh
  h1/50-teardown.sh` — 129 passed, 0 failed, 77s. The iteration run; `35-uploads`
  is in it because `CAPTURE` mode shares the function I edited.
* `./test/shards/run.sh h1 > /tmp/h1.log` — **480 passed, 0 failed**, 7 skipped,
  146s. One directory run, at the end, as the acceptance control. Everything
  after that was grepped out of the saved log.
* Three of those seven skips are chunk-decoder work, so they were run directly
  against a hand-started fixture rather than left skipped:
  `h1_chunked_request.py` (the arrival-pattern sweep over `CAPTURE`) exit 0,
  `h1_chunk_relay.py` (reports 24/25/26) printed `OK`.
* `test/configs/doc_claims_test.py` — **191 claims before the change and 191
  after**, all holding. No block stopped executing.
* `test/tls/prod_cert_check.sh` — `ok /etc/linnea/certs/linnea.amberbio.com/fullchain.pem
  (3 certs): the whole chain parsed`, exit 0. This change touches no
  certificate, PEM or DER code — it is HTTP/1 framing only — so this was run to
  measure that rather than to assert it.

**The full suite was not run.** `LINNEA_SUITE=full` and the other shards (base,
quic, tls) were deliberately left alone: this loop is optimised for turnaround
and the full suite is run separately before deploying. Nothing here should be
deployed on the strength of the numbers above.
