# Audit Report 144

Audited commit `1e9113e` (`audit 143: HTTP/3 responses do not enforce SETTINGS_MAX_FIELD_SECTION_SIZE`), 2026-08-29.

This pass examined HTTP/2 connection-preface and frame-state handling, HTTP/1 request-header/message-framing and chunked-body paths, TLS encrypted-record and handshake-flight buffering, and QUIC connection/rate-limit state. The HTTP/1 and TLS areas came back clean on source review: request framing is settled before routing and the chunked decoder keeps its decoded and buffered lengths bounded, while TLS consumers validate complete record boundaries before decrypting into their fixed buffers. QUIC connection-state review did not yield a reproducible defect. The HTTP/2 preface state machine has the confirmed protocol violation below. No source, test, or configuration file was changed in this audit; only this report was added.

## Finding 1 — HTTP/2 accepts a SETTINGS acknowledgement as the client preface

**Severity:** Low  
**Confidence:** High  
**Status:** Open

RFC 9113 §3.4 requires the first frame after the 24-byte client magic to be a non-acknowledgement `SETTINGS` frame. Linnea's preface gate checks only the frame type, then sets `h2_saw_settings` before dispatching it. The ordinary `SETTINGS` handler sees `ACK`, verifies its zero payload, and accepts it. A following request is processed normally, even though the connection preface is invalid.

### Reproduction

From the repository root, start the existing HTTP/2 fixture and send an empty `SETTINGS` frame with the ACK flag followed by a valid request. This leaves all tracked files unchanged.

```sh
set -e
logdir=$(mktemp -d /tmp/linnea-audit-144.XXXXXX)
./bin/linnea --config test/configs/tls-h2.json >"$logdir/server.log" 2>&1 &
server_pid=$!
cleanup() { kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; }
trap cleanup EXIT
sleep 0.4
python3 - <<'PY'
import ssl, socket
ctx = ssl.create_default_context(cafile="test/tls/server.crt")
ctx.check_hostname = False
ctx.set_alpn_protocols(["h2"])
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", 61446)), server_hostname="localhost")
s.settimeout(1)
def frame(typ, flags, sid, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([typ, flags]) + sid.to_bytes(4, "big") + payload
def literal(name, value):
    return b"\0" + bytes([len(name)]) + name + bytes([len(value)]) + value
block = b"".join((literal(b":method", b"GET"), literal(b":scheme", b"https"), literal(b":authority", b"localhost"), literal(b":path", b"/hello.txt")))
s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 1, 0) + frame(1, 5, 1, block))
buf = b""
try:
    while True:
        buf += s.recv(65535)
except TimeoutError:
    pass
frames, pos = [], 0
while pos + 9 <= len(buf):
    n = int.from_bytes(buf[pos:pos + 3], "big")
    frames.append((buf[pos + 3], buf[pos + 4], int.from_bytes(buf[pos + 5:pos + 9], "big") & 0x7fffffff, n))
    pos += 9 + n
print(frames)
PY
```

Observed output on `1e9113e`:

```text
[(4, 0, 0, 24), (8, 0, 0, 4), (1, 4, 1, 197), (0, 1, 1, 18)]
```

The response `HEADERS` and ending `DATA` frames on stream 1 prove that the invalid preface reached request handling. The required result is a connection error with `GOAWAY(PROTOCOL_ERROR)`, before any response is generated.

### Impact

Malformed HTTP/2 peers are accepted as established connections rather than being rejected at the mandatory preface boundary. This is a protocol-conformance failure and weakens the framing gate that is supposed to establish both sides' HTTP/2 state before request processing.

### Recommended fix

At the first-frame gate, require `SETTINGS` with its ACK bit clear before setting `h2_saw_settings`. An ACK-only `SETTINGS` must take the existing `GOAWAY(PROTOCOL_ERROR)` path; subsequent SETTINGS acknowledgements should remain handled by `.f_settings_ack` as they are now.

## Resolution (fix pass)

**Finding 1: FIXED**

The report's reproduction was run verbatim against `1e9113e` and produced the
frames it predicted, byte for byte:

```text
[(4, 0, 0, 24), (8, 0, 0, 4), (1, 4, 1, 197), (0, 1, 1, 18)]
```

Server SETTINGS, WINDOW_UPDATE, then `HEADERS` and an END_STREAM `DATA` on
stream 1: the request behind an ACK-only preface was served, and no GOAWAY was
ever sent. (One note on the fixture: its read loop is `while True: buf +=
s.recv(...)`, which spins forever once the peer closes, so it only terminates
because the *unfixed* server holds the connection open. The copy used here
breaks on an empty read; that is why the same script does not hang after the
fix.)

The cause is where the report says it is, `src/server/linnea_http2.asm:297`.
The first-frame gate compared the frame type against `LINNEA_H2_FT_SETTINGS`
and set `h2_saw_settings` without looking at the flags byte, so an empty
`SETTINGS` with ACK passed the gate and then satisfied `.f_settings_ack`, which
checks only that the payload is empty.

### The oracle

nghttp2 was asked rather than assumed. `nghttpd --no-tls` (nghttp2 1.66.0,
`/usr/bin/nghttpd`) was given the identical byte sequence — magic string,
`SETTINGS` with ACK, then the same HEADERS block:

```text
ACK-preface              [(4,0,0,12), (7,0,0,25, err=0x00000001)]
control: plain SETTINGS  [(4,0,0,12), (4,1,0,0), (1,4,1,82), (0,1,1,6)]
```

It answers `GOAWAY(last_stream=0, PROTOCOL_ERROR)` and serves nothing, and
serves the request on the control. That is exactly the behaviour the report
asks for, and it is also what this tree already requires of a *backend*: the
`prefack` row in `test/shards/tls/70-backend-tls-client.sh` has refused an
ACK-only preface from an upstream since audit-report-56. The frontend was the
asymmetric side.

### The fix

Five lines at the gate in `linnea_http2.asm`: after the type check and before
`h2_saw_settings` is set, `test r10b, LINNEA_H2_FLAG_ACK` / `jnz .goaway_close`.
`.goaway_close` is already the PROTOCOL_ERROR entry, so the wire result matches
nghttpd's. Acknowledgements *after* the preface are untouched and still land in
`.f_settings_ack`, which is the point the recommendation makes and the point the
control below defends.

Post-fix, the same fixture:

```text
ack    [(4,0,0,24), (8,0,0,4), (7,0,0,8, err=0000000000000001)]
plain  [(4,0,0,24), (8,0,0,4), (4,1,0,0), (1,4,1,197), (0,1,1,18)]
```

GOAWAY(PROTOCOL_ERROR), no HEADERS, no DATA — and the ordinary preface still
serves `/hello.txt`.

### Coverage, and the control it is paired with

Two checks added to `test/tls/h2_error_codes.py`, beside the existing
preface pair it already carried:

- `a SETTINGS ACK as the preface is refused` — the rejection;
- `...and a SETTINGS ACK after the preface still is not` — the control a
  blanket "reject SETTINGS with ACK" would fail. A real preface, then an ACK,
  then a PING: the connection must survive and answer.

A/B against the two binaries, both built from this tree (`/tmp/linnea-prefix`
at `1e9113e`, `/tmp/linnea-fixed` with the change):

```text
PRE-FIX   FAIL a preface SETTINGS with ACK gave None, want PROTOCOL_ERROR   exit=1
FIXED     ok   a SETTINGS ACK as the preface is refused                     exit=0
```

Every other line of that file's 24 is identical between the two runs, including
the new control, which passes on both — it is there to catch a future
over-tightening, not this change.

### Acceptance controls

Run before the rejection test was written, and again after:

- **All 63 configs in `test/configs/`**, not a sample, under `--test` with both
  binaries: 39 accepted, 24 rejected, and the two verdict lists are
  byte-identical (`diff` empty). The 24 are the deliberately-bad fixtures
  (`bad-*`, `cert-badsig`, `cert-unknown-critical`, `truncated`, …).
- **`test/configs/doc_claims_test.py`**: 200 claims before, 200 after, "all
  claims hold" both times. The count is the part that matters — a block that
  stopped executing would still print the same last line.
- **`test/tls/prod_cert_check.sh`**: `ok /etc/linnea/certs/linnea.amberbio.com/
  fullchain.pem (3 certs): the whole chain parsed`, exit 0. This change touches
  no certificate, PEM or DER code — the gate is eight bytes into an HTTP/2 frame
  header — so this is a control, not a test of the change.

### What was run

- `./test/shards/run.sh tls/20-e2e.sh tls/40-http2.sh tls/50-e2e-teardown.sh`
  (20-e2e first for the proxy backend and `$U`, on which 40-http2 depends):
  **114 passed, 0 failed, 5 skipped** (the five are the fast-run soaks:
  multiplexing, fuzz, proxied-stream RST, error-body flow control, HPACK
  table). `PARTIAL RUN` by construction. `http2 connection errors carry the
  RFC's code` — the check that runs `h2_error_codes.py` — passes.
- `./test/shards/run.sh tls`, once, at the end, as the single directory-level
  acceptance control — the shard the changed code lives in: **602 passed, 0
  failed, 7 skipped** (the five above plus two h3 reaper waits). No `FAIL`
  lines. That is the run that says nothing else in the h2 frontend moved.

**The full suite was NOT run, and `LINNEA_SUITE=full` was NOT run.** Neither
gates this change; both are run separately before a deploy.
