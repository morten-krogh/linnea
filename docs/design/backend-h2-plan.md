# Backend HTTP/2 — implementation plan

Roadmap #1, Tier 1 (see [`backend-tls-h2.md`](backend-tls-h2.md)). Speak HTTP/2
*to* a backend. **Decided: single-stream first, multiplexing later.** At runtime
this depends on backend TLS (Tier 0) — h2 is negotiated by ALPN over TLS — but
the h2-client *wire mechanism* can be built and tested over **h2c (cleartext
prior-knowledge h2)** independently of the TLS client, then run over the kTLS
backend socket once Tier 0 lands. So this plan can proceed in parallel with the
TLS work.

## What single-stream-first is (and isn't)

One stream per backend h2 connection maps almost 1:1 onto the existing
per-request upstream leg — "one exchange per backend connection," exactly what
the h1 leg and the `linnea_h2p` slot already are. So the backend-h2 leg is an
**h2-framed variant of the current h1 leg**: reuse the slot lifecycle, the
io_uring arming discipline, and the upstream pool/health scaffolding, and replace
only the h1 request-build / response-parse with a minimal h2 wire on stream 1.
The odd-stream-id allocator degenerates to "always 1," there is no cross-stream
scheduler, and flow control is one stream window + one connection window.

**Be honest about the payoff:** single-stream is a **correctness milestone, not a
throughput win** — still one TCP+TLS connection per request, barely better than
h1-to-backend. What it buys: (a) reaching backends that speak **only** h2 (some
gRPC / modern app servers refuse h1), and (b) a proven h2-client wire protocol
(preface, SETTINGS, HEADERS/DATA, HPACK both ways, flow control, GOAWAY/RST) as
the base multiplexing is later built on. Throughput comes from Stage 2.

## Mine linnea-probe first (Stage 0)

linnea-probe is an HTTP/1/2/3 **client** and already speaks h2 to servers — it is
to backend h2 what its TLS client is to backend TLS: the **client-role skeleton
the server code lacks** (client preface, client SETTINGS, request-HEADERS
encoding, response decode incl. `:status`). Before building anything, read the
probe's h2 client path and take what transfers. The reuse/new split below is from
the *server* h2 code; the probe likely already implements several "new" rows as a
client and should shrink them. **Step 0: confirm what the probe's h2 client
already does, and lift it.**

## The toolbox (server h2 side — reuse/new)

All in `src/server/`. Calling conventions from the interface read.

**Reusable as-is:**
- **HPACK encode primitives** (`linnea_http2.asm`): `h2_enc_int`:5959,
  `h2_enc_hdr`:6069 (name-by-static-index + literal value), `h2_enc_hdr_lit`:5993
  (literal name + value). Convention: **dst cursor in `rdi`, returned advanced**;
  no length written (caller back-patches the frame header). **The encoder is
  entirely stateless** — only static-index refs + literal-without-indexing, *no
  encoder dynamic table anywhere*. So a request block needs **no new encoder
  state**. Build order (pseudo-headers first): `h2_enc_hdr(esi=2,method)`,
  `h2_enc_hdr(esi=6,scheme)`, `h2_enc_hdr(esi=4,path)`, `h2_enc_hdr(esi=1,
  authority)`, then regular headers (`include/linnea_hpack_data.inc:11-45` for the
  static indices). Cursor-threading template: the 200-builder at
  `linnea_http2.asm:1861-1928`.
- **Frame emitters:** `h2p_emit_window`:4251 (`rdi`=out,`esi`=sid,`edx`=inc →13),
  `h2p_emit_rst`:4273 (→13). Stream-agnostic; reusable directly.
- **HPACK decode engine:** `linnea_hpack_decode`:102 (`rdi`=block,`rsi`=len,
  `rdx`=`*req` → `rax`=0/err). Reusable — but see the two constraints below.
- **The preface bytes:** `h2_preface`:119 = the 24 bytes to *send* as a client.
- **SETTINGS values** from `linnea_h2_init`:139 (table size 4096, initial window
  4194304, max frame 16384) — values reusable; the function is server-role.
- **Flow-control algorithm** (`h2_schedule`:5526, `h2_apply_init_window`:6264) —
  the cwnd+swnd+`MAX_FRAME(16384)` clamp is exactly what a client body-sender
  needs, but both are wired to the server stream pool; reuse the *logic*, not the
  function.

**Two decisive constraints (the real new work):**
1. **No `:status` / response model.** `linnea_h2_req` (`include/linnea_hpack.inc:64`)
   is request-only — no status field. A backend leg reading a response needs a
   **new `linnea_h2_resp` struct** (`:status`, a header collection, content-length
   / transfer bookkeeping) fed by the decode engine. (The probe may already have
   an equivalent — Stage 0.)
2. **The HPACK decoder dynamic table is per-*client*-connection.** It lives in the
   `h2_dyn_pool` mmap keyed by `conn.index` (`linnea_http2.asm:2828-2843`,
   `h2_dyn_for`), *outside* `linnea_connection`, and is recycled by a `.gen`
   check. A backend h2 connection therefore needs its **own `linnea_hpack_dyn`
   allocation** for decoding the backend's responses (≈7.2 KB). Encoding needs
   none (constraint above). This is the single most load-bearing fact for memory
   and lifecycle.

**Not reusable (server-role):** `linnea_h2_handle`:214 (server receive loop),
`h2_queue_goaway`:6188 (bound to client `out_buf`/state — reuse the frame bytes,
not the side effects), `linnea_h2_init` (awaits a client preface), the `linnea_h2p`
slot (h1-backend-shaped throughout) — but its **scaffolding pattern** transfers:
tag→slot→conn user_data encode, the `.gen`/ZOMBIE staleness guard, and the
WANT-flag one-op-per-arming discipline (`linnea_uring_arm_h2p_ops`:4009,
`linnea_h2p_event`:3490, tags 11/12/13 in `include/linnea_uring.inc:55`).

## Stage 1 — single-stream exchange

**The leg, as a state machine over a connected byte socket** (h2c plaintext for
dev; the kTLS backend socket in production — identical framing either way):

1. **Open:** send the 24-byte client preface + a client SETTINGS frame + an
   initial connection WINDOW_UPDATE. Advertise a large receive window (like the
   server's 4 MiB) so inbound WINDOW_UPDATE is rare.
2. **Settle:** read the server's SETTINGS, apply it (record its
   INITIAL_WINDOW_SIZE for our stream-1 send window), ACK it; consume the server
   SETTINGS ACK. Record `MAX_FRAME`/table-size limits.
3. **Request:** build the HEADERS block on stream 1 with the encode primitives
   (pseudo-headers + headers), set END_HEADERS, and END_STREAM iff there is no
   body. Send it.
4. **Request body (if any):** the upload is already captured to a spill file
   before the backend is contacted ([[proxy-body-capture]]) — frame it into DATA
   frames clamped to `min(stream_window, conn_window, MAX_FRAME)`, waiting for
   WINDOW_UPDATE when a window hits zero (the reused flow-control logic). Final
   DATA carries END_STREAM.
5. **Response head:** read frames until the stream's HEADERS arrives; decode with
   the engine into the new `linnea_h2_resp` (its own dyn context). Normalize to
   the same (status, headers) shape the h1 leg produces.
6. **Response body:** consume DATA frames as body; send WINDOW_UPDATE
   (`h2p_emit_window`) as it is drained; END_STREAM ends the exchange.
7. **Control:** handle server RST_STREAM (fail the exchange → 502), GOAWAY
   (finish this stream if below last-stream, else 502), PING (ACK). Never
   half-succeed — an incomplete body must not become a clean 200
   ([[chunked-body-framing]]).

**Response normalization is the integration seam.** Unlike the h1 leg (which
relays raw h1 response bytes), the h2 leg must hand the client-facing path a
*normalized* response — status + headers + a body stream — which the client side
then re-serializes for whatever the browser speaks (h1/h2/h3). This is the same
normalized form the existing `h2p` path consumes in the other direction. Producing
it cleanly is where the leg connects to the rest of the proxy.

**Where it plugs in.** The leg is chosen when ALPN selects `h2` on a TLS backend.
Integration follows the two existing backend paths (from the backend-path map):
- **Stage 1a — h1/h3 clients** (the shared `up_fd` path). Reuse the arming
  choke points `linnea_uring.asm:3830`/`:3861` and add h2 sub-states to
  `proxy_state` (`include/linnea_connection.inc:30`), running the h2 framing in
  userspace over the (kTLS or plaintext) `up_fd`. Do this first — it covers two
  of three client protocols.
- **Stage 1b — h2 clients** (the `h2p` slot path). Extend that path to an h2
  backend leg, reusing the slot scaffolding but with the new h2 wire + response
  decode.

Model the leg on the `linnea_h2p` scaffolding (tag/gen/WANT-flag arming), as a new
leg type, not by overloading the h1-shaped slot.

## Config

h2-to-backend is meaningful only over TLS (ALPN). Two options:
- **ALPN-negotiated** (offer `h2,http/1.1`, use whichever the backend selects) —
  most flexible, needs both legs present and a runtime branch.
- **Explicit per-location `proxy_h2` flag** — offer only `h2`, and **fail (502)
  if the backend does not select it**, no silent h1 fallback. Simpler; a clear
  operator contract.

**Recommend the explicit flag for v1** (offer `h2`, require it), revisit
auto-negotiation with Stage 2. Config threads through the same touch-points as any
backend key (see [`backend-tls-h2.md`](backend-tls-h2.md) §Tier 0 config and the
config map): struct field, parser, docs/config.md, `doc_claims_test.py`.

## Memory & lifecycle

Per backend h2 leg (single-stream): its **own decoder dynamic table**
(`linnea_hpack_dyn`, ≈7.2 KB), a `linnea_h2_resp` struct, a header-block
reassembly + Huffman-decode scratch region (cf. `h2_hb_pool`, 24 KB/conn), and a
frame I/O buffer. Follow the existing pattern: a lazily-mapped per-leg mmap arena
keyed like `h2p_pool`/`h2_dyn_pool`, recycled by a `.gen` check, freed-by-recycle
rather than per-request. Single-stream keeps this to one context per leg; Stage 2
multiplexing is what would add a real stream table and scheduler.

## Testing

h2c decouples wire correctness from TLS:
- **Dev/unit:** run the leg over plaintext h2c against a known-good h2 server (an
  h2c-capable fixture, or linnea itself if given an h2c test listener). Assert a
  correct GET/POST round-trip, header fidelity, and body integrity.
- **Integration (self-hosted):** **linnea proxying to linnea over TLS+h2** — the
  natural fixture, no new dependency; pin the backend SPKI (Tier 0). Drive it
  from an h1, h2, and h3 client and confirm the normalized response reaches each.
- **Negatives:** backend sends GOAWAY mid-exchange, RST_STREAM, a flow-control
  stall (zero window then WINDOW_UPDATE — assert the body still completes and
  isn't silently truncated), oversized/again-malformed HEADERS, an incomplete
  body (must surface as an error, never a clean 200).
- Wire into the shard fixtures + `test/configs` per the config map; keep the build
  warning-free.

## Implementation approach (decided 2026-08-23, build start)

**The leg is an h1↔h2 translator around the existing normalized h1 form.** The
proxy already normalizes every client request (h1/h2/h3) to an **h1 request head**
in `up_buf` (what the h1 backend leg sends) and relays backend responses as **h1
response bytes** that the client-facing path re-serializes for h1/h2/h3. So the
h2 leg does not need a new response model wired through the whole proxy: it
**parses the h1 request head → HPACK HEADERS block** (+ DATA from the spill file),
and **synthesizes an h1 response head** (`HTTP/1.1 <status> \r\n` + header lines)
from the decoded h2 response, streaming DATA as the body. Everything downstream is
untouched. This is the "response normalization is the integration seam," made
concrete: normalize to h1 wire form, not a struct.

**Response HPACK decode reuses the hard primitives without touching the audited
request path.** `linnea_hpack_decode`/`emit_field` are request-shaped and heavily
audited; instead the new file carries its own block-walk (a faithful copy of the
`linnea_hpack_decode` control flow — indexed/literal/tsize, walk-on-after-fault,
scratch return) that calls the already-`global` primitives `hpack_int`/`hpack_str`
/`hpack_huffman` and the dyn-table helpers `hpack_dyn_get`/`hpack_dyn_insert`/
`hpack_dyn_evict` (newly exported, read-only reuse). **Register discipline is
inherited exactly**: `rbx` = a `linnea_h2_req` used purely as the scratch/dyn
carrier (those primitives read `[rbx+.scratch]`/`[rbx+.scratch_end]` and take the
carrier in `rdx`), `r12` = cursor, `r13` = end. The encoder is reimplemented
locally (trivial, stateless: static-index refs + literals, as the probe does) so
the new subsystem stays decoupled.

**Test lever: a pure-stdlib h2c server** (`test/h2/h2c_server.py`) — no h2 tooling
or Python h2 lib exists on the box — with a minimal HPACK codec covering exactly
the forms the leg emits/consumes (static table + literals + Huffman + one dynamic
insert/reference, raw and Huffman values). The blocking translator is tested over
plaintext h2c against it first (fast, TLS-decoupled), mirroring how the TLS client
was proven against `openssl s_server`. TLS+ALPN(`h2`) and the proxy wiring come
after, reusing the proven translator; the TLS client gains an ALPN-`h2` offer.

## Build status (2026-08-23) and the brick-3 plan

- **Brick 1 DONE** (`c172b96`): blocking `linnea_h2c_exchange`, proven over h2c
  (GET/POST/echo/large/flow-control/fragmented/GOAWAY/RST). The pure helpers
  (`h2c_build_headers`, `h2c_decode`, `h2c_compose`, `h2c_apply_settings`/
  `_window`, the HPACK encode/decode) are I/O-free and reused as-is by the driver.
- **Brick 2 DONE** (`d6a1011`): TLS client offers ALPN `h2` via `hs.alpn_sel`;
  `location.proxy_h2` field added; `.connect_tls` sets `alpn_sel` per connect.

- **Brick 3 DONE** (`522f77e` driver, `dccf9b7` wiring): **works end to end for h1
  clients** — curl(h1)→front(`proxy_h2`)→TLS+h2→linnea backend→200 (backend logs
  `"... HTTP/2"`); 200000 B intact, 30/30 concurrent, wrong pin→502; full fast
  suite 774/0, tls shard 218/0. The injection uses `out_ptr`/`out_rem` (head) +
  `file_ptr`/`file_rem` (body) so the existing client-send path is unchanged. v1
  scope = h1 clients (h3 client gated to 502; h2-client/request-body/streaming are
  follow-ups). Config `proxy_h2` requires `proxy_tls`. Trap: the request head is
  at `out_ptr`/`out_rem`, not `up_buf`/`up_head_len`.

- **Follow-ups DONE:** request bodies over h2 (`40ff960` — the driver's DATA
  path fed from `file_ptr`/`file_rem`; 500 B + 500000 B byte-exact, 15 concurrent
  POSTs) and **h3 clients** (`8138b7b` — synthesized response re-encoded through
  the QPACK path `linnea_h3_proxy_head`/`_body`/`_deliver`; real curl-h3, small +
  250000 B). tls shard 219/0.
- **Follow-ups REMAINING:** h2 CLIENTS (Stage 1b — the `h2p` slot path, the big
  one: run TLS+h2 inside the 285-line `linnea_h2p_event` slot machine, feed its
  RELAY; deserves a focused session; h2 client → 502 until then); response-body
  streaming (currently buffered ≤1 MiB); h3 + request body (spill sharing);
  connection reuse (Stage 2 multiplexing, deferred by design).

**Brick 3 (as designed) — resumable driver + proxy wiring.** Model
on the TLS-client driver. A per-leg h2 context (in a reused arena keyed by
conn.index, like the TLS handshake pool) holds the windows, an accumulate-in
buffer, a staged-out buffer, the reassembly buffers, the `linnea_h2_req` carrier
+ dyn table, and the request cursor. Interface:

- `h2c_drv_start(ctx, h1head, h1len, body, bodylen, scheme)` → stages
  preface+SETTINGS+HEADERS into `ctx.out`; state SEND_INIT. Caller arms a send.
- `h2c_drv_on_sent(ctx)` → advance `out_sent`; by state: SEND_INIT → (body ?
  SETTLE : RESP), WANT_RECV; SEND_BODY → stage next DATA up to the window, or
  WANT_RECV when the window is spent, or RESP when the body is done.
- `h2c_drv_on_recv(ctx, data, len)` → append to `ctx.in`; parse every COMPLETE
  frame (non-blocking `next_frame`: "need more" if short); apply
  SETTINGS/WINDOW/PING (staging ACKs/WINDOW_UPDATE into `ctx.out`), collect
  HEADERS/CONTINUATION → decode, DATA → body; returns WANT_SEND (drain `ctx.out`),
  WANT_RECV, DONE, or FAIL. On DONE the synthesized h1 response is in `ctx.resp`.

Return codes drive one io_uring op at a time (arm send of `ctx.out[out_sent..]`,
or arm recv into a scratch fed to on_recv), exactly like the TLS_HS branch.

**THE INTEGRATION SEAM (identified, not yet built).** After the kTLS handoff a
`proxy_h2` leg enters a new `proxy_state` LINNEA_PROXY_H2 (=11) instead of
SENDING. The driver runs to DONE, producing the h1 response **in a buffer, not
from a socket read** — so it must be injected into whatever consumes the h1
backend response head today (the `.head_data`/`.relay_recv` path). The open task
is to feed `ctx.resp` into that consumer as if it had been read from `up_fd`
(the normalization seam). Study `.head_data` (response head parse) and the relay
buffers before wiring. Body: v1 buffers the whole response body in `ctx`; a later
pass can stream it. Stage 1b (h2 clients / `h2p` path) follows Stage 1a.

## Sequencing / definition of done

0. **Read linnea-probe's h2 client**; lift the client preface / request-encode /
   response-decode skeleton.
1. `linnea_h2_resp` + a response HPACK decode path with its own dyn context;
   unit-tested over h2c.
2. Single-stream leg (Stage 1a, h1/h3 clients): preface→SETTINGS→HEADERS→(DATA)→
   response, wired into `proxy_state` on `up_fd`; self-hosted linnea→linnea over
   TLS+h2 green.
3. Stage 1b (h2 clients) on the `h2p` path.
4. Config (`proxy_h2` + require-h2), docs, doc-claims, shard fixtures; full suite
   green.

Stage 2 (multiplexing — a real backend-h2 connection object with a stream table,
shared across requests, and a scheduler) is deferred by decision. Done for Tier 1
= single-stream h2 to a pinned-TLS backend works for h1/h2/h3 clients, the
negatives reject cleanly, and the self-hosted linnea→linnea TLS+h2 fixture passes.
