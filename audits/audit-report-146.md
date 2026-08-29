# Audit Report 146

Audited commit `9d0766c` (`audit 145: A malformed HTTP/2 PRIORITY frame closes unrelated streams`), 2026-08-29.

This pass examined HTTP/1 request-header and chunked/trailer framing; HTTP/2 frame and stream-state handling; HTTP/3 request-stream sequencing and field-section assembly; QUIC connection-ID demultiplexing and idle accounting; and configuration numeric limits. The HTTP/1, HTTP/3, QUIC, and configuration areas came back clean on source review: the three chunk decoders keep encoded and decoded bounds before arithmetic, HTTP/3 refuses DATA before headers and after trailers while bounding reassembly, QUIC refreshes both issued-CID and original-DCID traffic before sweep, and configuration values are parsed through `u64` before their key-specific limits apply. The HTTP/2 closed-stream path has the confirmed error-scope violation below. No source, test, or configuration file was changed in this audit; only this report was added.

## Finding 1 — HEADERS on a closed HTTP/2 stream closes the connection

**Severity:** Low  
**Confidence:** High  
**Status:** Open

RFC 9113 §5.1 requires a receiver to treat a frame other than `PRIORITY` on a closed stream as a `STREAM_CLOSED` stream error. After a completed stream's slot has drained, `h2_build_request` no longer finds it as a collecting body slot and takes `.req_new_stream`; its `stream_id <= h2_last_stream` check then takes the connection-level `.err` path. Thus a duplicate `HEADERS` on closed stream 1 sends `GOAWAY(PROTOCOL_ERROR)` and prevents a valid request on new stream 3 from being handled.

### Reproduction

From the repository root, start the existing HTTP/2 fixture. The client completes a request on stream 1, then sends a second complete request on that now-closed stream followed by a valid request on stream 3. It prints received frames as `(kind, stream-id)`; `GOAWAY` is `(kind, last-stream-id, error-code)`.

```sh
set -e
logdir=$(mktemp -d /tmp/linnea-audit-146.XXXXXX)
./bin/linnea --config test/configs/tls-h2.json >"$logdir/server.log" 2>&1 &
server_pid=$!
cleanup() { kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; }
trap cleanup EXIT
sleep 0.4
python3 - <<'PY'
import socket, ssl

SETTINGS, HEADERS, DATA, GOAWAY = 4, 1, 0, 7

def frame(t, flags, sid, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([t, flags]) + sid.to_bytes(4, "big") + payload

def literal(name, value):
    return b"\0" + bytes([len(name)]) + name + bytes([len(value)]) + value

block = b"".join((
    literal(b":method", b"GET"), literal(b":scheme", b"https"),
    literal(b":authority", b"localhost"), literal(b":path", b"/hello.txt"),
))
ctx = ssl.create_default_context(cafile="test/tls/server.crt")
ctx.check_hostname = False
ctx.set_alpn_protocols(["h2"])
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", 61446)), server_hostname="localhost")
s.settimeout(0.4)

def received():
    buf = b""
    while True:
        try:
            chunk = s.recv(65535)
        except TimeoutError:
            break
        if not chunk:
            break
        buf += chunk
    out, pos = [], 0
    while pos + 9 <= len(buf):
        length = int.from_bytes(buf[pos:pos + 3], "big")
        if pos + 9 + length > len(buf):
            break
        typ = buf[pos + 3]
        sid = int.from_bytes(buf[pos + 5:pos + 9], "big") & 0x7fffffff
        payload = buf[pos + 9:pos + 9 + length]
        if typ == GOAWAY:
            out.append(("GOAWAY", int.from_bytes(payload[:4], "big") & 0x7fffffff,
                        int.from_bytes(payload[4:8], "big")))
        else:
            out.append(("HEADERS" if typ == HEADERS else "DATA" if typ == DATA else str(typ), sid))
        pos += 9 + length
    return out

s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(SETTINGS, 0, 0) + frame(HEADERS, 5, 1, block))
print("first:", received())
s.sendall(frame(HEADERS, 5, 1, block) + frame(HEADERS, 5, 3, block))
print("after reused stream:", received())
PY
```

Observed output on `9d0766c`:

```text
first: [('4', 0), ('8', 0), ('4', 0), ('HEADERS', 1), ('DATA', 1)]
after reused stream: [('GOAWAY', 1, 1)]
```

The final frame is `GOAWAY(last_stream=1, PROTOCOL_ERROR)`; no `HEADERS` or `DATA` is returned for valid stream 3. The closed stream should instead receive `RST_STREAM(stream=1, STREAM_CLOSED)`, leaving stream 3 available to proceed.

### Impact

A peer's stale or duplicated `HEADERS` frame has connection-wide effect instead of the stream-local effect required by HTTP/2. It aborts unrelated in-flight streams and rejects new multiplexed work, turning an error scoped to one already-finished request into a connection failure.

### Recommended fix

Distinguish a stream identifier below or equal to `h2_last_stream` that is not a live collecting stream from a new stream-numbering violation. For closed streams, emit `RST_STREAM(STREAM_CLOSED)` and continue the frame loop; retain the connection error for idle/even identifiers and invalid new-stream ordering. Add a paired control showing a stale `HEADERS` on closed stream 1 is reset while a following request on stream 3 completes.

## Resolution (fix pass)

**Finding 1: DECLINED.** The behaviour reproduces exactly as written. The
recommendation does not survive contact with either RFC 9113 or a real HTTP/2
server, and applying it breaks a check this suite already carries.

### The report reproduces

Its fixture, run verbatim against `9d0766c`:

```text
first: [('4', 0), ('8', 0), ('4', 0), ('HEADERS', 1), ('DATA', 1)]
after reused stream: [('GOAWAY', 1, 1)]
```

`GOAWAY(last_stream=1, PROTOCOL_ERROR)`, and stream 3 goes unserved. Every
observation in the report is correct. What is wrong is the rule it is measured
against.

### The RFC clause the report quotes is the wrong half of the sentence

RFC 9113 5.1, "closed", reads:

> An endpoint that receives any frame other than PRIORITY after receiving a
> RST_STREAM MUST treat that as a stream error of type STREAM_CLOSED.
> **Similarly, an endpoint that receives any frames after receiving a frame
> with the END_STREAM flag set MUST treat that as a connection error of type
> STREAM_CLOSED**, unless the frame is permitted as described below.

The stream-scoped half applies only after a RST_STREAM. In the report's own
fixture stream 1 is closed by END_STREAM (`flags 5` on its HEADERS), so it is
the second half that governs, and that half says **connection** error.

RFC 9113 5.1.1 is more specific still, and it is the clause that actually
decides a HEADERS frame:

> The identifier of a newly established stream MUST be numerically greater than
> all streams that the initiating endpoint has opened or reserved. [...] An
> endpoint that receives an unexpected stream identifier MUST respond with a
> connection error of type PROTOCOL_ERROR.

A HEADERS frame on stream 1 after stream 1 has been opened is an attempt to
newly establish a stream on a non-increasing identifier. `GOAWAY(PROTOCOL_ERROR)`
is what 5.1.1 requires, and it is what the code does. The two clauses disagree
only about the error *code*; neither of them permits `RST_STREAM` plus carry on.

### The oracle: nginx 1.30.4 answers identically

Per WORKFLOW.md 3, asked rather than assumed. nginx 1.30.4 (OpenSSL 3.5.7,
`http2 on`, same `test/tls/server.crt`) on 127.0.0.1:61999, driven by the
report's own frame sequence:

| case | nginx 1.30.4 | linnea `9d0766c` |
|---|---|---|
| A. stream 1 served, then HEADERS on 1 again + HEADERS on 3 | `GOAWAY(last=1,PROTOCOL_ERROR)` | `GOAWAY(last=1,PROTOCOL_ERROR)` |
| B. stream 5 served, then HEADERS on 3 (never opened) | `GOAWAY(last=5,PROTOCOL_ERROR)` | `GOAWAY(last=5,PROTOCOL_ERROR)` |
| C. stream 1 closed by a *reset*, then HEADERS on 1 + on 3 | `GOAWAY(last=1,PROTOCOL_ERROR)` | `GOAWAY(last=1,PROTOCOL_ERROR)` |

Byte-for-byte agreement, including the error code, including case C — the one
sub-case where 5.1's stream-scoped half could be argued to apply. In every one
nginx also drops the following stream 3. Adopting the recommendation would have
made linnea the only one of the two that keeps the connection, on the strength
of a clause that does not cover the fixture.

### A/B: the recommendation was built, and it breaks an existing check

Not argued — implemented. A scratch build added `LINNEA_H2_STREAM_CLOSED equ 5`,
routed `.req_new_stream`'s `jbe` to a new `.req_closed` that still runs
`linnea_hpack_decode` (skipping it would desynchronise the connection's dynamic
table, the Q152 failure), and emitted `RST_STREAM(STREAM_CLOSED)` afterwards.
It does exactly what the report asks:

```text
after reused stream: [('RST_STREAM', 1, 5), ('HEADERS', 3), ('DATA', 3)]
```

and then:

```text
FAIL odd but below the floor: RST, want GOAWAY
FAIL a completed stream id, reused: RST, want GOAWAY (its first request: served)
```

The first of those is a **pre-existing** case in `test/tls/h2_stream_id.py`,
written for the 5.1.1 rule with its reasoning recorded in the file. The
recommendation cannot be applied without deleting a check that is already there
for the opposite conclusion. The experiment was reverted (`git checkout
src/server/linnea_http2.asm include/linnea_http2.inc`) and the tree rebuilt; the
fixture returns `GOAWAY(1, 1)` again, so nothing of it survives.

### What was added

`test/tls/h2_stream_id.py` gains the report's case, which the existing file did
not cover: its "odd but below the floor" case reuses an id that was never
*opened* (stream 3 after stream 5), whereas report 146 reuses one that was
opened, served and closed. Two new checks, a rejection and its control:

- **a completed stream id, reused** → `GOAWAY`, with the first request on that
  same id asserted to have been `served` first, so the case cannot pass by the
  connection having been broken all along;
- **a fresh id after a completed one still serves** → stream 1 served, then
  stream 3 on the *same* connection served. This is the blanket-build control
  WORKFLOW.md 5 asks for: a server that answered every second HEADERS with
  GOAWAY passes the rejection check and fails this one, and the experiment build
  above fails the rejection check and passes this one. Only the current
  behaviour passes both.

Both were seen failing — on the experiment build, above — before being kept.

### What was run

- The report's fixture, verbatim, before and after the experiment.
- The nginx oracle probe, three cases, both servers.
- `test/tls/h2_stream_id.py` standalone: 9 checks, `ok`, rc 0.
- `./test/shards/run.sh tls/20-e2e.sh tls/40-http2.sh tls/50-e2e-teardown.sh`
  — **115 passed, 0 failed, 5 skipped**, including "http2 stream-id rules are
  connection errors" with the two new cases in it. A PARTIAL RUN, named files
  only.
- `test/tls/prod_cert_check.sh` → `ok /etc/linnea/certs/linnea.amberbio.com/fullchain.pem (3 certs): the whole chain parsed`, rc 0. Nothing here touches
  certificate, PEM or DER code — the run confirms the experiment's revert and
  rebuild left the loader intact.
- `test/configs/doc_claims_test.py` → 200 PASS lines, "all claims hold",
  unchanged either side.

**The full suite was not run**, and `LINNEA_SUITE=full` was not run. Only the
three named tls files above, plus the standalone fixtures listed.

### Net change

No source, header or configuration file was modified. `test/tls/h2_stream_id.py`
gained two checks. The finding's *observation* stands and is now covered; its
recommended fix is declined, because 5.1.1, 5.1's second half, and nginx all say
the connection error is correct.
