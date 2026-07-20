# HTTP/2 arc — implementation plan

## Why / scope

Linnea speaks HTTP/1.1 over TLS 1.3 with kTLS. HTTP/2 keeps that
foundation: it still runs over TLS, so the kernel keeps doing record
encryption and userspace just speaks binary frames over the plaintext
socket instead of HTTP/1.1 text. We reuse the entire TLS/kTLS stack, the
io_uring loop, and the static-file and proxy backends. This is a
completeness pursuit, not a performance need — h1.1 already serves the
sites fine.

**In scope:** h2 over TLS (ALPN `h2`), full framing, HPACK, multiplexed
streams with flow control, static + proxy backends per stream, GOAWAY
integrated with drain (M11) and hot upgrade (M13).

**Out of scope:** h2c (cleartext h2 / Upgrade), h2-to-h2 proxying
(upstreams stay h1), WebSocket-over-h2 (RFC 8441), server push
(deprecated).

## The load-bearing design problem

Today `struc linnea_connection` is one fixed slot (~25 KB: in_buf 8192 +
out_buf 8512 + up_buf 8448) holding exactly **one** request/response.
HTTP/2 multiplexes N concurrent streams per connection. The codecs
(framing, HPACK) are tedious but bounded; the real design work is the
**per-stream memory model** — splitting the connection into a
connection-level frame I/O buffer plus a bounded pool of small stream
slots. Get that shape right (M18) and the rest is mechanical.

Memory discipline: keep stream state small (a header-assembly buffer +
bookkeeping, bodies *streamed* not buffered), cap
SETTINGS_MAX_CONCURRENT_STREAMS low (e.g. 32–100), and bound the total
stream pool like the connection pool. Bodies for static files stay
mmap+DATA (no per-stream copy); proxy bodies stream through.

## Milestones

### M14 — ALPN negotiation (prerequisite, small)
- Parse the ALPN extension (type `0x10`) in `parse_ch`: the
  ProtocolNameList; record which of `h2` / `http/1.1` the client offered
  (new `hs` field + flag bit, mirroring the SNI/PSK handlers).
- Selection policy behind a config flag (`"http2"`, default off for now):
  prefer `h2` when offered **and** enabled, else `http/1.1`.
- Emit the selected protocol as an ALPN extension in EncryptedExtensions
  (the empty-EE spot in `build_flight`, ~`linnea_tls.asm` EE block) — the
  EE extensions length stops being a constant.
- Plumb the selection to the connection (`conn.alpn`) at the kTLS handoff
  so the post-handoff path knows which protocol to speak.
- **Lands selecting only `http/1.1`** (h2 path doesn't exist yet): no
  client-visible change except a correctly-echoed ALPN. Test: `curl
  --http2` over TLS negotiates and reports `http/1.1`.

### M15 — h2 connection bring-up (framing, no requests yet)
- After handoff, `conn.alpn == h2` branches into an h2 connection handler
  instead of `linnea_http_handle`.
- Connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) read + validate.
- Frame layer: the 9-byte header (length24, type8, flags8, R+stream-id31),
  a reader that accumulates a whole frame, a writer.
- SETTINGS exchange (send ours, ACK theirs); handle PING (echo), GOAWAY,
  WINDOW_UPDATE, unknown-type ignore. Frame-size / stream-id validation.
- Connection stands up and stays alive; no stream serving yet.

### M16 — HPACK decoder + request assembly
- HPACK decode: integer (prefix-coded), string (Huffman table + raw),
  the 61-entry static table, the dynamic table (insert/evict, size
  accounting, dynamic-table-size-update). All five field
  representations.
- Assemble HEADERS(+CONTINUATION) on a stream into a request: `:method`,
  `:path`, `:scheme`, `:authority` → synthesize the same internal request
  shape the h1 path produces, so the existing location match / static /
  proxy handlers are reused unchanged. END_HEADERS / END_STREAM.
- Security: bound decoded header list size (HPACK-bomb guard), bound
  CONTINUATION frames per HEADERS (CONTINUATION-flood guard).

### M17 — response path + HPACK encoder + flow control (single stream)
- HPACK encode: start with literal-without-indexing (+ optional Huffman)
  for `:status` and headers — correctness first, ratio later.
- Serialize HEADERS + DATA frames; static body via mmap → DATA respecting
  max-frame-size and windows.
- Flow control: connection + per-stream windows; emit WINDOW_UPDATE as we
  consume; never exceed the peer's window when sending DATA.
- Serve one stream end-to-end (request → response); trivial scheduler.

### M18 — multiplexing + the memory-model redesign (the hard one)
- Per-connection stream table: a bounded pool of small stream slots, each
  with id, state (idle/open/half-closed/closed), request-assembly state,
  response progress (file_ptr/rem or a proxy handle), and flow window.
- Restructure the connection memory model: connection-level frame I/O
  buffer + the stream-slot pool (a second fixed pool, like the connection
  pool, with a hard cap).
- Write scheduler: interleave DATA across streams that have window;
  RST_STREAM, per-stream vs connection errors, priority (can start with
  round-robin and ignore PRIORITY).
- Security: bound concurrent + recently-reset streams (rapid-reset,
  CVE-2023-44487).
- Wire static + proxy backends per stream (proxy stays h1 upstream).

### M19 — flip h2 on, harden, conformance
- Default `"http2"` on; ALPN now selects `h2`.
- GOAWAY on drain (M11) and hot upgrade (M13): an h2 connection is
  drained by sending GOAWAY(last-stream-id) and finishing open streams —
  fold into the existing signalfd drain path.
- Conformance: `h2spec`. Interop: curl, nghttp2, real browsers.
- Fuzz the frame + HPACK parsers (mirror `test/tls/fuzz_clienthello.py`).
- Deadlock/edge audit: flow-control stalls, CONTINUATION flood, HPACK
  bomb, RST flood.

## Interactions with existing code
- **kTLS**: unaffected — frames ride the plaintext socket. ✓
- **Drain (M11) / upgrade (M13)**: add GOAWAY for h2 connections (M19).
- **Proxy**: h2 front, h1 back — the existing proxy path is reused per
  stream; upstream stays HTTP/1.1.
- **WebSocket**: stays h1-only (h2 negotiates, WS clients use h1).

## Rough sequencing
M14 first and standalone (a day, useful alone). M15–M17 build the
single-stream vertical slice. M18 is the redesign and the bulk of the
effort. M19 is hardening/conformance. Each milestone ends green in
`run_tests.sh` with new h2 tests (curl `--http2`, nghttp, h2spec subset).
