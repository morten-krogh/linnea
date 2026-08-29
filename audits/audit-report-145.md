# Audit Report 145

Audited commit `b10d65c` (`audit 144: HTTP/2 accepts a SETTINGS acknowledgement as the client preface`), 2026-08-29.

This pass examined HTTP/1 request-header, conditional/range, and message-framing paths; HTTP/2 frame-state handling; TLS ClientHello record/handshake buffering; HTTP/3 request-stream sequencing and body capture; and configuration numeric limits. The HTTP/1, TLS, HTTP/3, and configuration areas came back clean on source review: HTTP/1 settles framing before routing and bounds both encoded and decoded bodies, TLS waits for whole bounded records before copying handshake fragments, HTTP/3 keeps an incomplete frame or field section bounded while it is reassembled, and configuration numbers are parsed across `u64` before their individual limits apply. The HTTP/2 frame dispatcher has the confirmed error-scope violation below. No source, test, or configuration file was changed in this audit; only this report was added.

## Finding 1 — A malformed HTTP/2 PRIORITY frame closes unrelated streams

**Severity:** Low  
**Confidence:** High  
**Status:** Open

RFC 9113 §6.3 requires a `PRIORITY` frame whose payload length is not five octets to be treated as a *stream* `FRAME_SIZE_ERROR`. Linnea's `.f_priority` handler instead sends it to `.goaway_frame_size`, closing the entire connection. This is observable even when the malformed frame names an otherwise idle stream and a separate, valid request is waiting behind it.

### Reproduction

From the repository root, start the existing HTTP/2 fixture. The Python client sends the mandatory preface and SETTINGS, a four-byte `PRIORITY` frame on idle stream 3, then a valid GET on stream 1. It prints received frames as `(type, flags, stream-id, payload-length, payload-hex)`.

```sh
set -e
logdir=$(mktemp -d /tmp/linnea-audit-145.XXXXXX)
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
s.settimeout(0.4)

def frame(typ, flags, sid, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([typ, flags]) + sid.to_bytes(4, "big") + payload

def literal(name, value):
    return b"\0" + bytes([len(name)]) + name + bytes([len(value)]) + value

block = b"".join((
    literal(b":method", b"GET"), literal(b":scheme", b"https"),
    literal(b":authority", b"localhost"), literal(b":path", b"/hello.txt"),
))
s.sendall(
    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0) +
    frame(2, 0, 3, b"\0\0\0\0") +  # PRIORITY must have five payload bytes
    frame(1, 5, 1, block)
)
buf = b""
try:
    while True:
        chunk = s.recv(65535)
        if not chunk:
            break
        buf += chunk
except TimeoutError:
    pass

frames, pos = [], 0
while pos + 9 <= len(buf):
    length = int.from_bytes(buf[pos:pos + 3], "big")
    payload = buf[pos + 9:pos + 9 + length]
    frames.append((buf[pos + 3], buf[pos + 4], int.from_bytes(buf[pos + 5:pos + 9], "big") & 0x7fffffff, length, payload.hex()))
    pos += 9 + length
print(frames)
PY
```

Observed output on `b10d65c`:

```text
[(4, 0, 0, 24, '000100001000000300000064000600002000000400400000'), (8, 0, 0, 4, '00410000'), (4, 1, 0, 0, ''), (7, 0, 0, 8, '0000000000000006')]
```

The final frame is `GOAWAY(last_stream=0, FRAME_SIZE_ERROR)`, and there are no `HEADERS` or `DATA` frames for valid stream 1. The required result is `RST_STREAM(stream=3, FRAME_SIZE_ERROR)` while stream 1 remains available to process its request.

### Impact

Any peer can turn a malformed frame scoped to an idle stream into a connection-wide failure, aborting unrelated multiplexed requests. This violates HTTP/2's mandated stream-error scope and gives a malformed low-priority input more blast radius than the protocol permits.

### Recommended fix

In `.f_priority`, route a wrong-length frame to the existing stream-error/RST emission path with `FRAME_SIZE_ERROR`, preserving the connection for other streams. Keep stream zero as the existing connection-level `PROTOCOL_ERROR` case, and add a control that a valid five-byte `PRIORITY` frame remains ignored and does not prevent a following request.

## Resolution (fix pass)

**Finding 1: FIXED** — reproduced verbatim on `b10d65c`, fixed in `.f_priority`,
and A/B'd: the new test fails 3/8 on the pre-fix binary and passes 8/8 on the
new one. The scope change is applied where RFC 9113 allows it to be applied; the
report's own idle-stream fixture is the one case where it cannot be, and that is
measured below rather than asserted.

### Reproduced

The report's script, run as written, printed exactly its stated output:

```text
(4, 0, 0, 24, '0001...'), (8, 0, 0, 4, '00410000'), (4, 1, 0, 0, ''),
(7, 0, 0, 8, '0000000000000006')      <- GOAWAY(last=0, FRAME_SIZE_ERROR)
```

No HEADERS or DATA for the valid request on stream 1. The diagnosis is right:
`.f_priority` jumped to `.goaway_frame_size` for any length but 5, and RFC 9113
§6.3 makes that a **stream** error — PRIORITY alters no connection state, so
§4.2's "frames that could alter the state of the entire connection" clause does
not reach it. The old code comment claiming §4.2 permission was wrong.

### The oracle disagreed with the report, and a real client disagreed with both

`openssl` has no verdict on frame scope, so the independent oracles here are the
two HTTP/2 stacks on this host.

**nginx 1.30.4** (same fixture, same probe, `http2 on`, TLSv1.3) replied
`(7, 0, 0, 8, '0000000000000006')` — GOAWAY, FRAME_SIZE_ERROR. nginx does for
*every* wrong-length PRIORITY exactly what linnea did. So "everyone else resets
the stream" is not true, and the report's required result is not universal
practice.

More decisively, **curl 8.15 / nghttp2 refuses an RST_STREAM naming an idle
stream**. I served the report's required response from a 40-line fixture
(`/tmp/idle_rst_server.py`) — RST_STREAM(stream 3, FRAME_SIZE_ERROR), then a
normal 200 on stream 1 — and A/B'd it against the identical server with that one
frame removed:

```text
no idle RST : IDLE-RST-OK          curl exit=0
with idle RST: curl: (16) nghttp2 recv error -902   curl exit=16
```

That is RFC 9113 §5.1 working as written: a peer receiving anything but HEADERS
or PRIORITY on an **idle** stream MUST treat it as a connection error. So for
the report's fixture — a malformed PRIORITY naming idle stream 3 — emitting
RST_STREAM(3) does not save the connection. It kills it just the same, only now
the violation is ours and the peer's error code names us.

### What was changed

`.f_priority` now splits on the target:

- **wrong length, stream the peer has opened** (odd id, `<= h2_last_stream`, so
  open or closed): RST_STREAM(that stream, FRAME_SIZE_ERROR) via the same
  13-byte emission `.f_window_rst` uses, then straight on to the next frame.
  This is the fix — the frames multiplexed beside it are served.
- **wrong length, idle target** (even id, or above the highest opened) **or
  stream 0**: the existing connection-level FRAME_SIZE_ERROR, unchanged, for the
  measurement above. §5.1 leaves no better option, and it is what nginx does.
- **valid 5-byte frame**: unchanged — ignored, stream 0 still PROTOCOL_ERROR.

The comment in the source records the curl measurement, so the carve-out is not
mistaken later for an oversight.

Stated plainly: **the report's literal reproduction still ends the connection.**
The blast radius for that input is unchanged by design. What is fixed is the
error scope itself, on every stream where a stream error is legal to send.

### Coverage

New `test/tls/h2_priority_scope.py`, wired into `test/shards/tls/40-http2.sh`
beside the other frame-validation checks. Four rejection assertions, four
paired acceptance controls, so a build that reset (or closed) everything fails:

| | pre-fix `b10d65c` | fixed |
|---|---|---|
| wrong-length PRIORITY on an open stream → RST_STREAM(1, FRAME_SIZE_ERROR) | FAIL (`RST: []`) | ok |
| ...and no GOAWAY | FAIL (`GOAWAYs: [6]`) | ok |
| ...and the request behind it (stream 3) completes | FAIL (`stream 3 frames: []`) | ok |
| control: valid 5-byte PRIORITY resets nothing | ok | ok |
| control: both streams served across a valid PRIORITY | ok | ok |
| idle target still a connection FRAME_SIZE_ERROR | ok | ok |
| PRIORITY on stream 0 still PROTOCOL_ERROR | ok | ok |
| control: a plain request on a clean connection is served | ok | ok |

The pre-fix column is a real run of the new file against a binary rebuilt from
`git checkout src/server/linnea_http2.asm` — not a prediction. The five controls
pass on both binaries, which is what makes the three failures mean something.

The existing `test/tls/h2_frame_validation.py` assertion "PRIORITY wrong length
rejected → GOAWAY FRAME_SIZE_ERROR" **still passes unchanged**: it sends the bad
frame on stream 1 with nothing opened, which is the idle case. That was not
adjusted to fit the fix.

### What was run

- `./test/shards/run.sh tls/20-e2e.sh tls/40-http2.sh` — 83s. Before the change:
  108 passed, 0 failed, 5 skipped. After: **109 passed, 0 failed, 5 skipped**
  (the same 5 slow/soak skips), the extra one being the new check.
- `./test/shards/run.sh tls` — the whole directory, once, as the acceptance
  control that nothing else in the TLS/h2/h3 surface moved: **603 passed, 0
  failed, 7 skipped** in 9m12s. That includes the backend-leg PRIORITY checks in
  `70-backend-tls-client.sh` (linnea's own h2 *client* validating an upstream's
  PRIORITY, a separate code path in `linnea_h2_client.asm`) — untouched and
  still green.
- The new file standalone against both binaries (the A/B table above).
- nginx 1.30.4 and curl/nghttp2 as oracles, as described.
- `test/tls/prod_cert_check.sh` was **not** run: this change touches only the
  HTTP/2 frame dispatcher — no certificate, PEM or DER code, and no parser that
  a certificate reaches.
- Doc claims unchanged: nothing in `docs/` states PRIORITY behaviour beyond
  `http2-plan.md:94` ("ignore PRIORITY"), which is still true — we act on none
  of them.

**The full suite was not run**, and neither was `LINNEA_SUITE=full`. Only the
two named shard files above plus the single whole-`tls`-directory control run; a
full run belongs to the pre-deploy pass, not this loop.
