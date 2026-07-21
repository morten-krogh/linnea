# HTTP/3 (QUIC) arc — implementation plan

## Why / scope

linnea speaks HTTP/1.1 and HTTP/2 over TLS 1.3 on TCP, with the record
layer handed to the kernel (kTLS). HTTP/3 is a different foundation:
it runs over **QUIC** (RFC 9000) on **UDP**, and QUIC does its own
per-packet AEAD encryption and header protection (RFC 9001) — so kTLS is
left behind entirely. This is the project's largest frontier: a QUIC
transport, the TLS 1.3 handshake carried in QUIC CRYPTO frames, QPACK
header compression, and the HTTP/3 framing — all in x86-64 assembly.

**Reused from the existing stack:** the TLS 1.3 handshake *messages* and
crypto (ClientHello parse, the key schedule, x25519 / P-256 / ECDSA /
AES-128-GCM / SHA-256 / HKDF / HKDF-Expand-Label), the io_uring event
loop (UDP recvmsg/sendmsg instead of TCP), the config/vhost/static-file
machinery, and the QPACK-is-HPACK-shaped insight (advertise a zero-size
dynamic table so the decoder stays stateless).

**Left behind:** kTLS (QUIC encrypts in userspace, per packet), the TCP
accept/recv/send model (one UDP socket demultiplexes many connections by
connection ID), and TLS records (QUIC packets instead).

**In scope:** QUIC v1 (RFC 9000/9001), HTTP/3 (RFC 9114), QPACK (RFC
9204) with a static-only dynamic table, one AEAD suite (AES-128-GCM,
mandatory for Initial and sufficient throughout), static-file serving
over h3, ALPN `h3`, graceful close/drain.

**Out of scope (at least initially):** 0-RTT / early data, connection
migration, key update, retry/address validation tokens (may add a stateless
Retry for anti-amplification), ChaCha20-Poly1305, datagram extension,
proxy-over-h3, congestion control beyond a simple scheme.

## The load-bearing design problems

1. **UDP demultiplexing.** UDP is connectionless: one socket receives
   datagrams from every client. Connections are keyed by Destination
   Connection ID. The server picks its own connection IDs, so we encode
   the connection-pool index in the server CID — demux becomes O(1) (read
   the index out of the DCID) with no map.

2. **Per-packet crypto.** Every packet is individually protected: header
   protection (an AES-ECB block over a ciphertext sample masks the first
   byte + packet number) plus AEAD (AES-128-GCM, nonce = iv XOR packet
   number, AAD = the packet header). Three packet-number spaces (Initial,
   Handshake, 1-RTT) each have their own keys and numbering.

3. **Reliability without TCP.** QUIC reimplements ordered/reliable
   delivery: ACK frames, loss detection, retransmission, and flow control,
   all in userspace. A minimal but correct scheme (ACK everything, RTO
   retransmit for the handshake, simple flow-control windows) comes first;
   refinement later.

4. **Handshake transport swap.** The TLS 1.3 handshake messages are
   identical, but they ride QUIC CRYPTO frames (an ordered byte stream per
   packet-number space) instead of TLS records, and they derive QUIC
   packet keys via HKDF-Expand-Label with QUIC labels ("quic key", "quic
   iv", "quic hp") instead of kTLS record keys. QUIC transport parameters
   are a new TLS extension (0x39) the server must parse and emit.

## Milestones

### Q1 — QUIC packet + Initial crypto foundations (deterministic, no client)
- Variable-length integers (RFC 9000 16): encode/decode.
- Packet headers: long header (Initial/0-RTT/Handshake/Retry) and short
  header (1-RTT); connection IDs; truncated packet-number decode.
- Initial keys: `initial_secret = HKDF-Extract(initial_salt, client DCID)`,
  then client/server Initial secrets, then key/iv/hp via HKDF-Expand-Label
  ("quic key" / "quic iv" / "quic hp").
- Header protection: expose AES-128-ECB single-block encrypt (the AES
  machinery already lives in linnea_aesgcm); sample → mask; apply/remove.
- Packet protection: AES-128-GCM seal/open with the QUIC nonce and the
  header as AAD.
- **Test:** RFC 9001 Appendix A known-answer vectors in a self-test binary
  (given the client DCID, reproduce the keys, unprotect the sample client
  Initial, and recover its CRYPTO frame / ClientHello bytes). Fully
  deterministic — needs no UDP and no client.

### Q2 — UDP event loop + connection demux + Initial receive
- Bind a UDP socket; io_uring recvmsg (with the peer address) and sendmsg.
- A QUIC connection pool; demux incoming datagrams by DCID (server CID
  encodes the pool index); anti-amplification budget.
- Receive a real client Initial (from aioquic), remove protection, parse
  frames (CRYPTO, PADDING, ACK, PING, CONNECTION_CLOSE), reassemble the
  CRYPTO stream into the ClientHello.
- **Test:** point aioquic at the server; assert the server decrypts the
  Initial and logs a well-formed ClientHello (SNI, ALPN `h3`).

### Q3 — QUIC-TLS handshake to completion
- Run the TLS 1.3 handshake over CRYPTO frames, reusing the existing
  handshake: parse ClientHello, derive handshake + application secrets,
  emit ServerHello (Initial), then EncryptedExtensions (with QUIC
  transport parameters), Certificate, CertVerify, Finished (Handshake
  packets). Derive 1-RTT keys.
- Packet-number spaces, ACK generation/processing, CRYPTO ordering,
  transport-parameters extension (0x39).
- **Test:** aioquic completes the handshake (1-RTT keys established).

### Q4 — QUIC transport core (1-RTT, streams, flow control, loss)
- Short-header 1-RTT packets. STREAM frames, per-stream and connection
  flow control (MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS), stream state.
- ACK processing, RTO-based retransmission, a simple congestion window,
  CONNECTION_CLOSE, stateless reset (optional).
- **Test:** aioquic opens streams and exchanges bytes reliably.

### Q5 — HTTP/3 framing + QPACK
- H3 unidirectional control streams + SETTINGS; the request/response
  bidirectional stream; H3 frame layer (HEADERS / DATA).
- QPACK decode: static table (99 entries) + prefixed integers/strings;
  advertise dynamic-table capacity 0 so no dynamic table is kept (the
  HPACK trick). QPACK encode for responses.

### Q6 — serve static files over HTTP/3 (end to end)
- Wire an h3 request (method/path/authority from QPACK) into the existing
  static resolver, and stream the response as H3 HEADERS + DATA with QUIC
  stream/connection flow control.
- **Test:** aioquic (and, if available, a browser / curl-http3) GETs a
  file over h3 and gets the bytes intact.

### Q7 — advertise, harden, conformance
- Advertise h3 (ALPN `h3`; optionally Alt-Svc from the h1/h2 responses).
- Graceful close/drain integrated with the worker lifecycle.
- Fuzz the packet/frame/QPACK parsers; interop with aioquic and browsers;
  transport conformance checks.

## Interactions with existing code
- **kTLS:** unused on the h3 path (QUIC encrypts per packet in userspace).
- **TLS handshake crypto:** reused for the QUIC-TLS handshake.
- **io_uring:** reused, with a UDP recvmsg/sendmsg path beside the TCP one.
- **Static/serve path:** reused per request, as with h2.
- **Config:** a new listener kind (UDP/QUIC) or an "h3" flag per server.

## Rough sequencing
Q1 first and standalone — pure crypto against RFC vectors, no networking.
Q2–Q4 build the QUIC transport (the bulk of the effort). Q5–Q6 layer
HTTP/3 on top. Q7 hardens. Each milestone ends green in the test suite,
early ones against RFC known-answer vectors and later ones against
aioquic.
