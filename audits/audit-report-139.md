# Audit Report 139

Audited commit `332c491` (`audit 138: no issues found`), 2026-08-29.

This pass examined static conditional and content-coding negotiation, HTTP/1
proxy protocol-switching, and QUIC transport/control-stream frame boundaries.
The static and QUIC areas came back clean: encoded-variant selection applies
specific and wildcard `Accept-Encoding` rules before the identity fallback,
and the resumable QUIC control-frame walker bounds incomplete varints and
payload lengths before consuming them. It found one HTTP/1 proxy defect: an
upstream can trigger a protocol switch without supplying the header that
defines that switch. No source, test, or configuration file was changed in
this audit; only this report was added.

## Finding 1 — A proxy relays a 101 response without its required Upgrade field

**Severity:** Medium  
**Confidence:** High  
**Status:** Open

The proxy accepts any framing-free `101` once the client requested an upgrade.
It copies an upstream `Upgrade` field when one happens to be present
([`linnea_http.asm`](../src/server/linnea_http.asm#L4880)), but
[`.upgrade_head`](../src/server/linnea_http.asm#L5247) never records or
requires that field. It then synthesizes `Connection: upgrade` and changes the
connection into a blind tunnel. Consequently, an upstream response with just
`101` and `Connection: Upgrade` becomes a downstream `101` with no `Upgrade`
field at all.

That is not a valid switching-protocols response: RFC 9110 requires a server
that sends `101 (Switching Protocols)` to send an `Upgrade` header identifying
the protocol being selected ([RFC 9110 §7.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8)).
The upstream response is invalid and should be rejected as a `502`, rather
than turned into an invalid response to the client.

### Reproduction

From the repository root, run a one-connection upstream on the existing
WebSocket fixture port. It deliberately omits `Upgrade` but otherwise sends a
well-formed `101`; then start Linnea with the existing cleartext configuration
and issue an upgrade request.

```sh
python3 -c 'import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",61702)); s.listen()
c,_=s.accept(); c.recv(8192)
c.sendall(b"HTTP/1.1 101 Switching Protocols" + bytes([13,10]) +
          b"Connection: Upgrade" + bytes([13,10,13,10]))
c.close(); s.close()' & backend=$!
./bin/linnea --config test/configs/listen.json >/tmp/linnea-139.out 2>/tmp/linnea-139.err & server=$!
trap 'kill "$server" "$backend" 2>/dev/null; wait "$server" "$backend" 2>/dev/null' EXIT
sleep 0.3
python3 - <<'PY'
import socket

s = socket.create_connection(('127.0.0.1', 61080))
s.sendall(b'GET /ws HTTP/1.1\r\nHost: one.test\r\n'
          b'Connection: Upgrade\r\nUpgrade: websocket\r\n'
          b'Sec-WebSocket-Version: 13\r\n'
          b'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n')
print(repr(s.recv(4096).decode('latin1')))
s.close()
PY
```

Observed output:

```
'HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\n\r\n'
```

The response contains no `Upgrade` field and therefore does not identify any
new protocol, yet Linnea has already placed both sockets in tunnel mode.

### Impact

A faulty or malicious upstream can make Linnea emit an invalid protocol-switch
response and stop HTTP processing on that client connection. WebSocket and
other upgrade clients reject the handshake because they cannot verify the
chosen protocol. The connection can then remain a pointless tunnel until its
timeout, consuming a client and upstream socket for that period.

### Recommended fix

While parsing a final `101`, record whether at least one nonempty `Upgrade`
field is present (and, ideally, require that `Connection` names `upgrade`).
Enter `.upgrade_head` only when that invariant and the existing no-framing
invariant hold; otherwise use the normal malformed-upstream `502` path. Add a
paired integration test: a normal WebSocket `101` with `Upgrade: websocket`
must still tunnel, while the reproduction above must return `502` and never
enter tunnel state.

## Resolution (fix pass)

**Finding 1: FIXED.** The reproduction in the report is exact. Against
`332c491`, a backend answering a legitimate client upgrade with

```
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
```

produced, verbatim:

```
'HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\n\r\n'
```

— a `101` naming no protocol, with both sockets already in
`LINNEA_PROXY_UPGRADE`. The `Connection: upgrade` in that head is *ours*:
`.upgrade_head` synthesises it. So this is not a relay of someone else's
invalid message; it is one Linnea manufactures. That distinction is what
decided the fix.

### What changed

`linnea_http_proxy_head` already carried a per-head flag word at `[rsp+16]`
(Content-Length, Transfer-Encoding, and the two the security-header walk sets).
The `101` exception in the field-forwarding filter — the one place that already
knows "this name is `Upgrade` and this status is 101" — now also records
bit 16 when the value is **nonempty** after OWS trimming, and `.upgrade_head`
requires it:

```
    test qword [rsp + 16], 16  ; the backend's own Upgrade field, nonempty
    jz .bad                    ; a 101 that names no protocol is not a 101
    mov rax, [rsp + 16]
    and rax, ~16               ; every other flag ...
    test rax, rax
    jnz .bad
```

The mask keeps the old check's meaning exactly: `cmp qword [rsp+16], 0` refused
a `101` carrying *any* flag, including the HSTS/nosniff bits, and it still does.
`.bad` is the existing malformed-upstream path, so the client gets the ordinary
`502` and the connection never reaches tunnel state.

`Upgrade:` with an OWS-only value is refused too. That case is not the head
validator doing the work — the pre-fix binary accepted it and tunnelled (A/B
below) — because OWS-only is a legal field value. It names nothing, so the 101
rule refuses it.

### The independent oracle disagrees, and I went with the fix anyway

nginx 1.30.4 was set up as a plain `proxy_pass` upgrade proxy in front of the
same one-connection backend, and asked the same four questions:

| upstream 101 head                     | nginx 1.30.4 | linnea before | linnea after |
|---------------------------------------|--------------|---------------|--------------|
| `Upgrade: websocket` + `Connection`    | 101 (tunnel) | 101 (tunnel)  | 101 (tunnel) |
| no `Upgrade` at all                    | **101**      | 101           | **502**      |
| `Upgrade:` with an empty value         | —            | 101           | **502**      |
| `Upgrade` + `Content-Length: 0`        | **101**      | **502**       | **502**      |

nginx relays the bare `101` — it agrees with the pre-fix behaviour, not with the
report. I am still taking the fix, on three measured grounds:

1. **Linnea is already stricter here than nginx, and was before this audit.**
   Row 4 is untouched code: a `101` carrying framing has been a `502` since
   the `cmp qword [rsp+16], 0` was written, and nginx passes that one through.
   Requiring `Upgrade` is the same policy applied to the other half of RFC 9110
   §7.8, not a new departure from the neighbours.
2. **nginx is relaying; Linnea is authoring.** nginx forwards the upstream's
   head largely as it found it. Linnea drops the backend's `Connection` and
   writes its own `Connection: upgrade`, so the invalid downstream head is one
   we compose. Emitting a `502` we author is strictly better than emitting a
   `101` we author that no client can act on.
3. **The failure the report describes is real and costs a socket pair.** The
   client cannot verify the selected protocol, so it aborts; Linnea is in
   tunnel mode and holds both sockets to the idle timeout.

The trade is that a backend which sends a bare `101` and worked before now gets
a `502`. Every `101` emitter in this tree — `test/api/linnea_ws.asm:148` and
`test/proxy_backend.py`'s `ws_handshake` — sends `Upgrade: websocket`, and the
`502` is logged, which the invalid `101` never was.

### Declined: also requiring that `Connection` name `upgrade`

The report offers this as "ideally". Measured and declined. A backend sending
`Upgrade: websocket` with **no** `Connection` field at all is accepted by nginx
and, after this change, still tunnels through Linnea (row measured directly:
`linnea 101, Upgrade but no Connection -> 'HTTP/1.1 101 Switching Protocols'`).
Requiring it would turn that shape into a `502` and buy nothing downstream:
Linnea writes `Connection: upgrade` itself on every `101` it relays, so the
client's head is well-formed either way. The half of §7.8 that was actually
missing from the client's view is `Upgrade`, and that is the half now enforced.

### Coverage, and the A/B that proves it

- `test/proxy_backend.py`: two routes, `/ws-noupgrade` (101 with `Connection:
  Upgrade` and no `Upgrade`) and `/ws-emptyupgrade` (`Upgrade:` with an
  OWS-only value), both answering a *valid* client handshake.
- `test/ws_client.py`: modes `noupgrade` and `emptyupgrade`, each asserting the
  `502` **and** that no tunnel formed — bytes written after the error head must
  come back as EOF, not be relayed.
- `test/ws_client.py::expect_101` now asserts `Upgrade: websocket` reaches the
  client on the accepted path. This is the acceptance control the workflow asks
  for: an implementation that refused every `101` fails it, and so does one that
  filters the field out.
- `test/shards/h1/35-uploads.sh`: the two new checks, beside the existing
  `unrequested 101 becomes 502`.

A/B against the pre-fix binary (`/tmp/linnea-prefix`, built from stashed source;
the restored build is byte-identical to the fixed one):

```
=== PRE-FIX ===            === FIXED ===
echo           OK          echo           OK
noupgrade      expected a 502, got: b'HTTP/1.1 101 Switching Protocols'
emptyupgrade   expected a 502, got: b'HTTP/1.1 101 Switching Protocols'
                           noupgrade      OK
                           emptyupgrade   OK
```

Both refusals fail before the fix and pass after; the acceptance control passes
on both binaries, so it is not the thing doing the failing.

### What was run

- `./test/shards/run.sh h1/00-setup.sh h1/35-uploads.sh h1/50-teardown.sh`
  (targeted, PARTIAL RUN): 48 passed, 6 failed, 1 skipped. The six are the
  `proxy log …` greps, which read request lines written by `h1/30-proxying.sh`
  — a file the partial run does not execute. They pass in the directory run
  below, which is what confirms they were the partial run's own artefact.
- `./test/shards/run.sh h1` (the acceptance control, one directory run):
  **491 passed, 0 failed, 7 SKIPPED**, exit 0, including the three 101 checks
  and all six ws tunnel checks.
- `python3 test/configs/doc_claims_test.py`: **191 claims, all hold**, exit 0.
  No config or documentation was touched, so the count is expected to be
  unchanged, and it is the count rather than the verdict that says so.

Not run, and deliberately: `test/tls/prod_cert_check.sh` and the `base` shard.
This change is 12 instructions inside `linnea_http_proxy_head` and touches no
certificate, PEM or DER path. **The full suite was not run** — this is the fast
fix loop; `LINNEA_SUITE=full` is run separately before deploying, and nothing
here was committed or pushed.
