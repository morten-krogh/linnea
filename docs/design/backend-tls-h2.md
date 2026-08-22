# Backend TLS + HTTP/2 upstreams — design

Roadmap item #1 (see [`roadmap.md`](roadmap.md)). Today linnea proxies only
**plaintext HTTP/1.1 to loopback backends**. This scopes adding **TLS to
backends** and **HTTP/2 to backends**, grounded in a full read of the current
upstream, TLS, h2 and config code (2026-08-22).

The headline is the scoping decision, not the plumbing: done naïvely — "HTTPS to
arbitrary servers, like nginx" — this is one of the largest things linnea could
build and it multiplies the exact substrate risk the roadmap flags. Done the way
linnea actually deploys — proxying to backends the **operator controls** — it is
tractable and keeps the identity. The design below is **tiered** so we build the
identity-preserving version first and stop there unless the product goal changes.

## TL;DR

- **Authenticate by pinning, not a trust store.** Pin the backend's P-256 public
  key. This is both smaller *and* stronger than CA verification for a controlled
  backend, and it lets us skip the three things that dominate the effort: the
  general X.509 stack, a trust store + hostname matching, and RSA.
- **Use kTLS on the backend socket.** Run the handshake in userspace after
  `connect` (reusing linnea-probe's client handshake), hand the socket to kTLS,
  and the existing raw io_uring send/recv on the backend fd is **unchanged**.
  The plumbing cost is small; the crypto cost is one new primitive.
- **The one pivotal new primitive is ECDSA P-256 verify.** It does not exist
  (only sign does); its building blocks do. It unblocks all of Tier 0.
- **Backend TLS and backend h2 are two projects, not one.** h2 to a backend is
  negotiated by ALPN over TLS, so backend TLS is a hard prerequisite, and backend
  h2 is a whole new client-side h2 stack on top. Do TLS first.

## What already exists (reuse inventory)

Backend I/O today is entirely plaintext: raw `IORING_OP_CONNECT`/`SEND`/`RECV`
on the backend fd with no record layer or abstraction in between. But most of the
cryptographic substrate a client needs is already here and direction-neutral.

| Piece | Status | Where |
|---|---|---|
| X25519 (keygen + shared secret) | reuse as-is | `src/lib/linnea_x25519.asm:15` |
| AES-128-GCM (seal **and** open) | reuse as-is | `src/lib/linnea_aesgcm.asm:24` |
| SHA-256 / HMAC / HKDF | reuse as-is | `src/lib/linnea_sha256.asm:15` |
| TLS KDF (HKDF-Expand-Label, Derive-Secret) | reuse as-is (role-neutral) | `src/lib/linnea_tls_kdf.asm:15` |
| TLS record layer (seal/open, per-direction keys) | reuse as-is (role-neutral) | `src/lib/linnea_tls_record.asm:20` |
| kTLS installer (per-direction) | reuse — swap TX/RX secrets for the client role | `src/server/linnea_ktls.asm:298` |
| **A working TLS 1.3 client handshake** | reuse as skeleton | `src/probe/linnea_probe.asm:2685` (`tls_handshake`) — ClientHello `:3009`, ServerHello parse `:2954`, client key schedule `:2757`, client Finished `:2889` |
| HPACK **decode** engine (int/string/Huffman-decode/dyn table) | reuse for response decode | `src/server/linnea_hpack.asm:101` |
| HPACK **encode** primitives (int, literal-by-static-index, literal) | reuse to build a request block | `src/server/linnea_http2.asm:5961`, `:6072`, `:5996` |
| h2 frame **parsers** + WINDOW_UPDATE/RST/GOAWAY **emitters** | reuse (written neutrally) | `linnea_http2.asm:214`, `:4251`, `:4274`, `:6188` |
| Upstream scaffolding (select/health/idle-pool/failover, io_uring op arming) | reuse (transport-agnostic) | `src/server/linnea_upstream.asm`; `linnea_uring.asm:3786`, `:4009` |

## What is genuinely new

| Piece | Tier | Size |
|---|---|---|
| **ECDSA P-256 verify** (u1·G + u2·Q) — building blocks exist (`linnea_p256_point.asm:29/184`), routine absent | 0 | moderate, pivotal |
| **Targeted SPKI extraction** — pull the P-256 point out of the leaf cert (we control the cert shape; extend the DER length decoder to 0x82, cf. `linnea_pem.asm:239`) | 0 | small |
| **Client handshake wiring** into the upstream state machine + server-Finished verify (nobody verifies it today, even the probe: `linnea_probe.asm:2866`) | 0 | moderate |
| **Backend-side TLS config** (scheme/flag + pin) | 0 | small (templated on `cert`/`key`) |
| Full X.509 (general ASN.1, chain building, trust store, validity, hostname/SAN) | 2 | very large |
| **RSA** (bignum + modexp + PKCS#1 v1.5/PSS) | 3 | very large — X.509+RSA together exceed all of `src/lib/` combined |
| Client-side h2 stack (preface, odd-stream allocator, backend-h2 connection object, request-HEADERS encode, request-DATA send, response `:status` decode, client flow control, ALPN offer) | 1 | large |

## Decision 1 — authenticate by pinning, not a trust store

linnea proxies to backends the operator runs. For that relationship, **public-key
pinning is the right authentication model**, and it is strictly smaller than CA
verification:

- **It is stronger, not weaker.** A pin authenticates *this exact backend key*;
  a trust store authenticates *anything any CA in the store will vouch for*. For
  a fixed backend, the pin removes the whole CA as an attack surface.
- **It removes the largest components.** No chain building, **no trust store, no
  `notBefore`/`notAfter`, no hostname/SAN matching** (the pin *is* the identity),
  and — because the operator can put a **P-256** cert on the backend (linnea
  itself already generates and serves these) — **no RSA**.

What pinning still requires, and why:

- **CertificateVerify must still be verified.** The certificate is *public*;
  pinning its bytes proves nothing about who is on the other end unless we check
  that the peer holds the matching private key. That check is an **ECDSA verify**
  over the handshake transcript. Skipping it would let anyone who has seen the
  (public) pinned cert impersonate the backend. This is why ECDSA verify is
  non-negotiable for Tier 0.
- **The server Finished must be verified** (binds the handshake; a simple HMAC
  compare — done for the *client* Finished server-side today, never for the
  server Finished anywhere, so it is new but trivial).
- **A targeted SPKI parse** to locate the leaf cert's public key so we can (a)
  compare it to the pin and (b) feed it to the CertificateVerify check. Because
  we know the cert is P-256, this is a small fixed-shape DER walk, not a general
  X.509 parser.

Config carries the pin as the SHA-256 of the backend's SubjectPublicKeyInfo (or
the raw 65-byte point). Rotation = update the pin at reload (zero-downtime).

## Decision 2 — kTLS on the backend socket (keeps the plumbing small)

The client-facing socket already runs over kTLS: the handshake happens in
userspace, then the socket is handed to the kernel and bulk data moves as
plaintext to/from userspace. **Do exactly the same on the backend socket.** The
payoff is large: after the handshake and kTLS handoff, the existing raw
`IORING_OP_SEND`/`RECV` on the backend fd need **no change** — the kernel
encrypts and decrypts transparently.

Insertion (from the backend-path map):

- After `IORING_OP_CONNECT` completes — `.on_connect` at `linnea_uring.asm:2244`
  for h1/h3, `.ev_connect` in `linnea_h2p_event` (`linnea_http2.asm:3513`) for h2
  — a TLS backend enters a **new proxy state** (`LINNEA_PROXY_TLS_HS`) instead of
  going straight to `SENDING`. That state drives the userspace client handshake
  over the backend fd (a few send/recv round trips), verifies the pin +
  CertificateVerify + server Finished, then calls the (reused, secret-swapped)
  kTLS installer and falls through to `SENDING`.
- The existing byte-movement choke points then stay as they are:
  `linnea_uring.asm:3830`/`:3861` (h1/h3 send/recv), `:4065`/`:4116` (h2).

**Open risk — the pooled-connection liveness peek.** Idle backend reuse does a
`MSG_PEEK|MSG_DONTWAIT` recv at `linnea_upstream.asm:405`. kTLS RX support for
`MSG_PEEK` is not guaranteed across kernels and interacts with TLS record
framing. For TLS backends, the safe default is to **not** peek a pooled TLS
socket — either disable idle pooling for TLS backends in Tier 0 (simplest;
reconnect per exchange, as several proxies do for TLS upstreams), or gate it
behind a verified kernel capability. Decide this before implementation; it does
not block the handshake work.

Handshake records themselves are userspace (pre-kTLS), identical to how the
server already does its own handshake before the kTLS handoff.

## Tiered scope

- **Tier 0 — Backend TLS, ECDSA, pinned.** The recommended first deliverable.
  Client handshake + ECDSA verify + SPKI pin + kTLS handoff, wired into the
  existing h1/h3 upstream path. Unlocks: TLS to a controlled backend (e.g. across
  a machine boundary, or a backend that mandates TLS). Fits the identity.
- **Tier 1 — Backend HTTP/2**, over Tier-0 TLS via an ALPN `h2` offer. A whole
  new client-side h2 stack (see below). Separate, large; **depends on Tier 0**.
- **Tier 2 — Full ECDSA trust-store X.509** (optional). Write the general
  ASN.1/X.509 parser, chain building, validity and hostname/SAN. Still
  ECDSA-only. Only worth it for backends with CA-issued certs the operator does
  not want to pin.
- **Tier 3 — RSA (explicit NON-GOAL).** Do not build bignum modexp + PKCS#1 for
  arbitrary public HTTPS backends unless the product goal fundamentally changes.
  It is larger than the entire current crypto library and it is exactly the
  unmanaged-assembly-crypto surface the roadmap warns about. Mitigation for any
  real need: put a P-256 cert on the backend (linnea can generate it) and pin it.

## Tier 0 detail — backend TLS

**Config** (touch-points and template from the config map):

- Per-backend **scheme** in the proxy array: allow `https://ip:port` alongside
  the bare `ip:port`, parsed at the front of `.proxy_one`
  (`linnea_config_parse.asm:1258`), stored in a parallel `.bk_tls: resq
  LINNEA_MAX_BACKENDS` array (mirroring the existing per-backend `.bk_dead_at` /
  `.bk_fails` at `include/linnea_config.inc:98`). This lets a location mix
  plaintext and TLS backends; if uniform is acceptable, a per-location flag like
  `proxy_keepalive` (`:109`) is simpler.
- **Pin**, per-location: `proxy_pin` = SHA-256 hex of the backend SPKI (a value,
  not a path — no `genports.py` change). Validated under `--test`. A location
  with any `https://` backend must have a pin (both-or-neither, mirroring the
  cert/key rule at `linnea_config.asm:376`).
- Docs + tests: a row in `docs/config.md` (Location scope) and assertions in
  `test/configs/doc_claims_test.py`, or the config shard fails.

**Handshake path**: reuse `tls_handshake` from linnea-probe as the skeleton
(ClientHello with an ALPN offer of just `http/1.1` for Tier 0, ServerHello parse,
client key schedule, client Finished). Add: ECDSA verify of CertificateVerify
using the SPKI extracted from the (pinned-checked) leaf cert; server-Finished
HMAC verify; then the kTLS handoff (`linnea_ktls_enable` with TX←client-app,
RX←server-app). Everything after is the current plaintext path unchanged.

## Tier 1 detail — backend HTTP/2

Reuses the HPACK decode engine, the HPACK encode primitives (compose a request
block from the static-table pseudo-headers — `:method`, `:path`, `:scheme`,
`:authority` — no Huffman encoder needed; literals are legal), and the frame
parsers/emitters. New work, all of it the client role the server side never had:

- ALPN **offer** `h2` in the ClientHello and read the selection from
  EncryptedExtensions (server-side select/echo exists at `linnea_tls.asm:1172`/
  `:1936`; the client offer does not).
- A **backend-h2 connection object** — the current 100-slot stream table is
  welded to the browser-facing `linnea_connection.up_buf`
  (`include/linnea_http2.inc:82`), and the `linnea_h2p` slot models an *h1* leg,
  not an h2 connection. A backend h2 connection needs its own preface, SETTINGS,
  window state and stream table.
- Send the **client preface** + client SETTINGS; a **next-odd-stream-id**
  allocator (the server only ever validates peer ids, `linnea_http2.asm:383`).
- Encode + send **request HEADERS/DATA**; decode **response HEADERS** including a
  `:status` field model the request-only decoder lacks
  (`linnea_hpack.asm:1553`); client-side flow control.
- **Multiplexing choice**: one request per backend-h2 connection is far simpler
  and still gets TLS + h2 correctness; true multiplexing (many proxied requests
  over one backend connection) is the real efficiency win but a larger step.
  Start single-stream, revisit mux.

## Security considerations

- **Substrate risk is the dominant cost, not lines of code.** Every new crypto
  routine (ECDSA verify especially) is hand-written asm with no memory safety.
  ECDSA verify must be constant-shape against malformed inputs and must reject
  the classic failures (r/s out of range, point-not-on-curve, s==0). Fuzz the
  DER/SPKI parse against truncated and over-long inputs; prove the fuzzer reaches
  the verify. This is where the review effort goes.
- **CertificateVerify is mandatory even when pinning** — see Decision 1. A pin
  without CertVerify is cert-replay-vulnerable.
- **No silent downgrade.** A `https://` backend that fails the handshake, the pin
  check, or CertVerify must fail the exchange (502), never fall back to plaintext.

## Testing

- **Backend = linnea itself.** linnea is a TLS server with a P-256 cert, and can
  serve h2 — so the natural fixture is *linnea proxying to linnea over TLS*
  (Tier 0) and *over h2* (Tier 1), fully self-hosted, no new dependency. Pin the
  fixture backend's known SPKI. `linnea-probe` can also stand in as a check.
- A negative fixture per failure mode: wrong pin → 502; plaintext answer on a
  `https://` backend → 502; a backend that offers only `http/1.1` when `h2` was
  required (Tier 1) → defined fallback or 502.
- Suite integration per the config map: fixtures in `test/configs/`, a case in
  `test/shards/base/10-config.sh`, doc-claims assertions.

## Effort & sequencing

1. **ECDSA P-256 verify** — the pivotal primitive; unblocks everything. Build and
   fuzz it first, in isolation, before any TLS wiring.
2. **Tier 0 backend TLS** — SPKI parse + pin, client handshake wiring, kTLS
   handoff, config, tests. Resolve the pooled-peek question (likely: no idle pool
   for TLS backends in v1).
3. **Tier 1 backend h2** — only after Tier 0; the client-side h2 stack, starting
   single-stream.

Tiers 2 and 3 are deliberately deferred; Tier 3 (RSA) is a non-goal. Recommend
splitting the roadmap item into "backend TLS" and "backend h2" so #1 ships
without waiting on the larger h2 stack.
