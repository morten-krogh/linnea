# TLS-client handshake wiring — implementation plan

The remaining Tier 0 piece (see [`backend-tls-h2.md`](backend-tls-h2.md)),
between "ECDSA-P256 verify exists" ([`ecdsa-verify-plan.md`](ecdsa-verify-plan.md))
and "kTLS handoff, then the existing upstream send/recv path is unchanged." This
is the **async wiring** that runs a TLS 1.3 *client* handshake to a backend
through the io_uring loop. Pinning is decided; authentication is by pinned SPKI.

## Template + protocol source (the two halves)

Neither existing piece is sufficient alone; the client handshake is their
composition:

- **The async template is the server's own handshake driver.** After accept, the
  server runs its handshake over the accepted socket entirely through io_uring:
  `.tls_recv` (`linnea_uring.asm:1948-2027`) reassembles a flight, calls
  `linnea_tls_hs_input`, arms the reply flight; `.tls_on_send`
  (`:2029-2070`) drains it and re-arms recv; `.tls_handoff` (`:2072-2132`) enables
  kTLS and drops into normal serving. Routing is on a phase flag checked *before*
  any HTTP work: `tls_phase` (`include/linnea_connection.inc:279`) with
  `NONE/HS/KTLS` (`:76-84`). The client leg mirrors this loop on the backend fd.
- **The protocol body is linnea-probe's client handshake** (`src/probe/linnea_probe.asm:2687`,
  confirmed **blocking**, not io_uring): X25519 keypair (`:2698`), `build_clienthello`
  (`:3009`, one group = x25519), `parse_serverhello` (`:2954`), handshake-key
  derivation (`:2751-2815`), decrypt the server flight (`:2817-2868`), client
  Finished (`:2889-2924`), switch to app keys (`:2926-2932`). It supplies the
  *what-bytes* for each step but not the async wiring, and it **skips all peer
  authentication** — which we must add.

So: **probe's client protocol, driven through a client-role version of the
server's async loop, over the backend fd, with authentication added.**

## The five decisions the code forces

1. **A separate per-leg scratch arena — NOT up_buf.** The server overlays its
   `linnea_tls_hs` state on `up_buf`, safe only because "nothing is proxied during
   the handshake." On a backend leg the opposite holds: **`up_buf` already holds
   the rewritten request head** from connect until the first upstream send (built
   by `.proxy_conn_emit`, `linnea_http.asm:3028-3032`; `out_ptr/out_rem` and
   `up_head_len` all reference it), and `in_buf` holds the captured body cursors.
   So the client handshake state must live in its **own arena**, lazily mapped and
   keyed per leg (the `h2_dyn_pool`/`.gen`-recycle pattern, `linnea_http2.asm:2828`).
   Define a `linnea_tls_client_hs` struct mirroring `linnea_tls_hs`
   (`include/linnea_tls.inc:142-199`) minus the server-only fields
   (cert_list/key_priv, SNI-select hook, resumption) and plus the client-only ones
   (pinned SPKI, the SNI to *send*, a place to accumulate the leaf cert for the pin
   + CertVerify). It keeps the live transcript ctx, own ephemeral priv/srand, the
   peer share, the secrets, `wkeys/rkeys`, and a record-reassembly buffer.
2. **New handshake sub-states on the leg, checked before the proxy dispatch.**
   Add a `tls_phase`-equivalent to the backend leg and handshake sub-states
   (`CH_SENT/WAIT_SH/WAIT_FLIGHT/FIN_SENT/DONE/FAILED`, mirroring the server's
   `WAIT_CH/WAIT_FIN/DONE/FAILED` at `include/linnea_tls.inc:22-25`). Backend-fd
   completions route to the client-hs handler while mid-handshake, exactly as
   `tls_phase==HS` is checked before HTTP handling.
3. **Userspace records during the handshake → client-oriented kTLS handoff.**
   Reuse `linnea_tls_seal`/`linnea_tls_open`, `linnea_tls_keys_init`, the KDF and
   the transcript exactly as the probe does. Then reuse `linnea_ktls_enable`
   (`linnea_ktls.asm:240`) **with the directions swapped**: server maps TX←s_ap,
   RX←c_ap; a client maps **TX←c_ap, RX←s_ap**. Sequence numbers flip too: the
   client's TX seq starts at **0** (the client sends no app records in userspace —
   its Finished is a handshake record), and RX seq = the count of server app
   records drained in userspace before handoff (see the ticket wrinkle below).
   The kernel takes over on a record boundary, so `drain_early`'s
   refuse-partial-record rule (`linnea_tls.asm:2035-2049`) still applies.
4. **Authentication is the security core** (the part both sources skip). After the
   server flight is reassembled and decrypted under handshake read keys:
   - **Parse the leaf Certificate** → targeted SPKI extraction (per the
     ecdsa-verify plan's small DER walk).
   - **Check the pin:** SHA-256(SPKI) == the configured pin. Mismatch → fail.
   - **Verify CertificateVerify** over the handshake transcript using
     `linnea_p256_ecdsa_verify` with the SPKI's public key. This is why ECDSA
     verify is the prerequisite; without it the pin is cert-replayable.
   - **Verify the server Finished MAC** (the probe skips this; the server verifies
     only the *client* Finished at `linnea_tls.asm:551-580` — mirror it for the
     server direction).
   All mandatory; any failure → alert + fail the leg. **No plaintext fallback.**
5. **v1 simplifications that also cut risk:** **HRR is fatal** (we offer only
   x25519 — detect the HRR sentinel ServerHello random and fail cleanly rather
   than the probe's opaque `-1`); **parse inbound alerts** for a specific failure
   reason (both sources treat an alert as an opaque error); **no resumption/0-RTT**;
   and a **fresh handshake per exchange, no TLS connection pooling** — which also
   sidesteps the kTLS `MSG_PEEK` liveness-peek concern from the parent doc entirely.

## The state machine (client-role, over the backend fd)

Mirrors the server loop; the hooks are the connect-complete sites from the
backend-path map.

1. **Connect completes** — `.connect_ok` (`linnea_uring.asm:2244`) for h1/h3;
   `.ev_connect` (`linnea_http2.asm:3513`) for h2. If the backend is TLS: allocate
   + init the client-hs arena, generate the X25519 keypair, `build_clienthello`
   (ALPN = `http/1.1` for Tier 0, `h2` for Tier 1; SNI from config), write it to
   the leg's handshake send buffer, `arm_up_send`, set state `WAIT_SH`. **Do not**
   go to `PROXY_SENDING` yet.
2. **Backend recv while mid-handshake** → client-hs recv handler: accumulate into
   the arena's reassembly buffer (the server's record/message fragment-accumulator
   model, `linnea_tls.asm:255-343` — record-complete then message-complete checks;
   `consumed` lets successive recvs continue). On a complete ServerHello: parse it,
   **detect HRR → fail**, derive handshake keys. Continue accumulating the
   encrypted flight; `linnea_tls_open` each record under handshake read keys;
   absorb messages into the transcript; at Certificate do the **pin + SPKI**; at
   CertificateVerify do **ECDSA-verify**; at server Finished **verify the MAC** and
   derive app keys.
3. **Send client Finished** (`linnea_tls_seal`, inner type 22, client handshake
   write keys), `arm_up_send`, state `FIN_SENT`.
4. **On Finished-send drain** → client-oriented kTLS handoff (§decision 3): copy
   the app secrets out of the arena into per-leg fields (mirroring
   `conn.s_ap_secret`/`c_ap_secret`, `include/linnea_connection.inc:334-335`),
   `linnea_ktls_enable` swapped, set the leg's phase to KTLS, free/recycle the
   arena, then fall through to `PROXY_SENDING` — which sends the request head that
   has been waiting in `up_buf` the whole time, now over kTLS, **through the
   unchanged send/recv path**.

## Integration with the two backend paths

TLS establishment sits *below* the h1-vs-h2 backend distinction — it's "get TLS up
on the backend socket after connect," common to both. Structure it as one reusable
driver `(fd, arena, config)` invoked from both connect-complete hooks; the arming
differs (the `up_fd` helpers `arm_up_send`/`arm_up_recv` for h1/h3 vs the h2p
WANT-flag arming for h2). **Do the shared `up_fd` path first** (covers h1 + h3
clients), then the h2p path.

## Config

From the parent doc plus one addition:
- **TLS on/off** per backend (the `https://` scheme or a `proxy_tls` flag) and the
  **pin** (`proxy_pin`, SHA-256 of the SPKI) — both already scoped in
  [`backend-tls-h2.md`](backend-tls-h2.md).
- **SNI (new):** an optional per-location `proxy_sni` hostname to put in the
  ClientHello. Pinning handles *identity*, but many TLS servers select a cert by
  SNI, so a vhost backend needs it; IP-only single-cert backends can omit it.

## Post-handshake edge: kTLS control records

Once the backend socket is on kTLS RX, non-application records surface specially
(via the TLS cmsg record-type). The backend may send a **NewSessionTicket**
(type 22) as its first post-handshake record; since we don't resume, **skip it**,
but the recv path must recognize and drop it rather than feed it to the HTTP
parser. Also handle `close_notify` and KeyUpdate — the existing server-side kTLS
helpers (`linnea_ktls_key_update`, `linnea_ktls_close_notify`,
`linnea_ktls.asm:458/513`) are direction-parameterized and reusable. Simplest
operational mitigation: configure the (controlled) backend to not issue tickets;
still handle the record defensively.

## Error handling & failover

A linked idle-timeout on the handshake ops (as with connect). Any failure —
timeout, malformed ServerHello, **HRR**, pin mismatch, CertVerify fail, server
Finished fail, or a received **alert** (parsed for its description into the error
log) — marks the backend failed (`linnea_upstream_mark_fail`) and either fails
over to the next backend (reuse `linnea_uring_up_reconnect`) or returns **502** when
backends are exhausted. Never fall back to plaintext.

## Testing

- **Self-hosted integration:** linnea is a TLS server, so the natural fixture is
  **linnea proxying to linnea over TLS**, pinning the backend's known SPKI; drive
  it from h1, h2, and h3 clients. Also test against `openssl s_server` with a
  pinned P-256 cert.
- **Unit-test the auth step** via the selftest harness (feed a captured
  Certificate + transcript + CertificateVerify → accept/reject, and pin
  match/mismatch), so the security core is tested apart from the async wiring.
- **Negatives, each must fail to 502, never plaintext:** pin mismatch, tampered
  CertificateVerify, wrong server Finished, a backend that offers only a
  non-x25519 group (→ HRR → clean fail), a backend that sends a fatal alert, and a
  handshake timeout. Confirm the alert path logs a *specific* reason.
- Wire fixtures into the shard suite + `test/configs`; keep the build
  warning-free; prove any fuzzer over the ServerHello/flight parse reaches the
  code ([[verifying-changes]]).

## Sequencing / definition of done

0. ECDSA-P256 verify done (prerequisite).
1. `linnea_tls_client_hs` arena + struct; `build_clienthello` (adapt the probe) +
   ServerHello parse with **HRR detection**.
2. Flight decrypt + transcript + **authentication** (pin + SPKI, ECDSA-verify of
   CertificateVerify, server-Finished MAC). Unit-tested via the selftest harness.
3. Client Finished + **client-oriented kTLS handoff** (swapped directions/seqs),
   then fall through to the unchanged `PROXY_SENDING` path.
4. Wire into `.connect_ok` (h1/h3) with the new states; self-hosted
   linnea→linnea over TLS green for h1/h3 clients.
5. The h2p path (h2 clients).
6. Config (`proxy_sni`), alert parsing, timeout/failover, post-handshake ticket
   skipping; full suite green.

## Implementation status (2026-08-22, branch `tls-client`)

**Done, tested, and gated in the suite** (the authenticating client core — the
hard, novel, security-critical work):

- **ECDSA P-256 verify** (`linnea_p256_ecdsa_verify` + strict DER) — merged to
  master. CAVP-style KAT, off-curve rejection, OpenSSL interop, fuzz.
- **X.509 leaf key extraction** (`linnea_x509_find_spki`/`_spki_point`) — walks
  an untrusted cert to the SPKI, reads the prime256v1 point; pin = sha256(SPKI).
- **CertificateVerify** (`linnea_tls_client_verify_certverify`) — RFC 8446
  signed content + ECDSA verify.
- **The full authenticating handshake** (`linnea_tls_client_handshake`, blocking
  form) — ClientHello/ServerHello/key schedule/flight decrypt, with the SPKI
  pin, CertificateVerify, and server-Finished checks; HRR fatal. Proven against
  `openssl s_server` (`test/shards/tls/70-backend-tls-client.sh`): pin match
  completes and the server accepts our Finished; wrong pin and an unoffered-group
  HRR fail cleanly.

**Remaining (the async proxy integration — deep io_uring/serving-path work, best
done as one deploy-gated unit):**

1. **Async driver** — refactor the handshake into a completion-driven
   `linnea_tls_client_input(hs, in, inlen, out, outcap)` over a per-connection
   arena (mirroring the server's `linnea_tls_hs_input`), so many backend
   handshakes run concurrently. The blocking form above is the tested reference.
2. **io_uring wiring** — a per-leg scratch arena, new `proxy_state` sub-states,
   route backend-fd completions to the driver from `.connect_ok`, then the
   client-oriented **kTLS handoff** (TX=c_ap, RX=s_ap, seqs per §decision 3).
3. **Config** — `https://` backends (or a `proxy_tls` flag) + `proxy_pin` +
   `proxy_sni`, through the parser/validation/docs/doc_claims.
4. **Failover** + the self-hosted linnea→linnea-over-TLS integration test.

## Definition of done

**Done = Tier 0 complete:** linnea completes an authenticated, pinned TLS 1.3
handshake to a backend and proxies over kTLS for h1/h3 (then h2) clients; every
failure mode (pin/CertVerify/Finished/HRR/alert/timeout) rejects cleanly to 502
with no plaintext fallback; the self-hosted linnea→linnea TLS fixture and the
auth unit tests pass. With this and the ECDSA-verify plan, all of Tier 0 is
designed; the backend-h2 plan (Tier 1) builds on top.
