# Architecture

How a zero-dependency web server works when it is written from `_start` up in
assembly. This is the map; the configuration reference is
[`config.md`](config.md), the proxy is [`proxying.md`](proxying.md), and how it
is built with AI is [`ai-development.md`](ai-development.md).

## The shape of the build

Linnea is `nasm` and `ld`, nothing else. There is no libc: the binary has its
own `_start`, makes syscalls directly, and links no external object. The source
is split into three parts:

- `src/lib/` — the shared library: the cryptographic primitives (X25519, P-256,
  AES-GCM, SHA-2), the TLS and QUIC record/key machinery, and string/format
  utilities. Both products below link it.
- `src/server/` — the server itself, with its own `_start`.
- `src/probe/` — `linnea-probe`, a standalone HTTP/1/2/3 compliance prober with
  its own `_start`, shipped as a product in its own right.

Each `.asm` file assembles to an ELF object; `ld` statically links them. The
result is a single static binary that depends on nothing but the Linux syscall
ABI. See [`building.md`](building.md).

## Process model: a master and reuseport workers

Linnea is multi-process. One **master** parses the configuration, loads the
certificates and keys, and binds the listening sockets — one `SO_REUSEPORT`
listener set **per worker**. It then forks `workers` workers (the config key;
the default is one per online CPU) and serves no traffic itself: it waits on its
workers and respawns any that die. Because the listening sockets live in the
master's file-descriptor table, a respawned worker resumes the very same
listeners.

Each **worker** accepts on its own reuseport listeners, so the kernel's
reuseport hash spreads incoming connections across workers rather than letting a
single accept loop win them all. Workers share nothing at runtime — no shared
memory, no locks on the hot path. Per-worker state (the connection pool, the
upstream keep-alive pool, rate-limit buckets) is exactly that: per worker. This
is why several tunables are documented as "per worker, times `workers`."

Every worker carries `PR_SET_PDEATHSIG(SIGTERM)`, so if the master goes the
workers go with it — no orphaned workers holding a port.

## The event loop: io_uring, everything

Each worker is a single `io_uring` submission/completion loop. Nearly every
operation the server performs is an io_uring request: `accept`, `recv`, `send`,
`connect` to a backend, file reads for static content, the UDP receive and send
for QUIC, and the timeouts that bound them all (submitted as linked timeout
requests). There is no thread pool and no blocking call on the hot path; the
worker submits work and reacts to completions.

Connections live in a fixed-size pool allocated once at startup
(`max_connections` per worker). A connection is a struct with its buffers inline;
there is no per-request allocation. A completion carries only indices, so a
late completion for a connection that has since closed is detected by a
generation counter on the slot and dropped rather than delivered to whoever
holds the slot now.

## Memory model: no allocator, no garbage

There is no `malloc` and nothing to garbage-collect. Buffers are fixed and sized
at build time from documented maxima — the request/response buffers, the TLS
record buffers, the QUIC receive buffers, the header-table scratch. A great deal
of the audit history is about exactly this: proving each buffer is large enough
for the largest input the configuration can produce, and that every copy into it
is bounded first. With no memory safety underneath, those bounds are the safety.

## TLS 1.3, and its own cryptography

TLS is [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446), version 1.3 only. The
profile is deliberately fixed to a single choice: the `TLS_AES_128_GCM_SHA256`
cipher suite, X25519 key exchange, and an ECDSA P-256 certificate. A TLS 1.2
client is refused; there is no RSA, no ChaCha20, no second curve. This is
minimalism, not an oversight — one path to get right instead of a matrix.

Every primitive under the handshake is in `src/lib/`: X25519, P-256 field and
scalar arithmetic and ECDSA, AES-GCM, SHA-256/384, the HKDF key schedule. After
the handshake, linnea hands the connection's keys to the kernel with **kTLS**,
so bulk records are encrypted and decrypted in the kernel rather than in the
worker.

That the cryptography is self-contained is a real property — no inherited
dependency vulnerabilities — and a real responsibility: it is far less
battle-tested than a mature library, and one MUST-level check (an all-zero
shared secret) was once missing from both handshake paths. See
[`security.md`](security.md).

## The protocol stack

One connection can be HTTP/1.1, HTTP/2 or HTTP/3, chosen by ALPN on TLS; plain
HTTP/1.1 is served on non-TLS listeners.

- **HTTP/1.1** — a streaming request parser, keep-alive, chunked and
  content-length framing, `Expect: 100-continue`, and the static/proxy handlers.
- **HTTP/2** — the connection preface and SETTINGS, HPACK header
  compression, up to 100 concurrent streams with per-stream and connection flow
  control, a round-robin stream scheduler, and rapid-reset defences.
- **HTTP/3 over QUIC** — the QUIC transport (packet protection, streams, flow
  control, loss detection and NewReno congestion control, RTT sampling, address
  validation and amplification limits, 0-RTT gated to safe methods), QPACK
  header compression, and the h3 framing layer. QUIC connections are steered to
  their owning worker by a one-byte index in the connection id through a **BPF
  reuseport map**, so a migrating client stays on the worker that holds its
  state. Without `CAP_BPF` this falls back to the kernel's 4-tuple hash, which
  cannot survive migration or a reload. HTTP/3 is served on one port; see
  [`config.md`](config.md).

The three share what should be shared — request routing, static-file selection,
the proxy — precisely once, so a rule holds identically across them. Where they
diverged was a recurring source of bugs (a fix landing on one of three twins),
which is why the shared paths exist.

## Static files

A `root` location serves files with byte-range requests (`206`), conditional
requests (ETag, Last-Modified, `If-Modified-Since`, `If-None-Match`,
`If-Range`), and precompressed variant selection: a request that accepts `br` or
`gzip` is served a neighbouring `.br`/`.gz` file when one exists and is not
older than its source. Content types come from a built-in extension table, and
`cache_control` is emitted per location.

## Reverse proxy

A `proxy` location forwards to one or more HTTP/1.1 backends with round-robin
selection, passive health and connect-time failover, and optional upstream
keep-alive shared across all three client protocols. Uploads are captured whole
before the backend is contacted, so a backend never sees a partial request. The
full design — and the reasoning behind connect-only failover and GET/HEAD-only
reuse — is in [`proxying.md`](proxying.md).

## Lifecycle: reload without dropping a connection

`systemctl reload` sends **SIGUSR2**. The master re-execs the new binary in
place — same PID, so systemd keeps tracking it. The new generation binds its own
reuseport listener group on the same ports (reuseport lets the two coexist),
runs the new binary in `--test` mode first and **refuses the reload if the
configuration or certificates are bad**, spawns its workers, then `SIGQUIT`s the
old workers to drain what they hold. No connection is dropped by a reload. A
plain stop is immediate; the distinctions are in [`shutdown.md`](shutdown.md).

## A note on the substrate

None of this has memory safety or a type system beneath it. Nothing crashes to
say a bound is wrong or a fix did nothing. That is the whole reason for the
verification discipline described in [`ai-development.md`](ai-development.md) —
the guarantees other servers get from their language, linnea has to get from
proof and testing.
