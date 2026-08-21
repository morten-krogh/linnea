# Linnea

**A from-scratch HTTP/1.1, HTTP/2 and HTTP/3 web server and reverse proxy,
written in x86-64 assembly — with its own TLS 1.3 and no dependencies at all.**

Linnea speaks HTTP over TLS to real browsers — Chrome, Firefox and Safari,
including HTTP/3 over QUIC — serves static files, and reverse-proxies to backend
services. It is built from nothing but `nasm` and `ld`: no libc, no OpenSSL, no
runtime, no third-party code. The TLS 1.3 stack and every cryptographic
primitive under it (X25519, P-256, AES-GCM, SHA-2) are part of the source tree.

It runs a live site on the public internet today.

## Written by AI — that is the point

Linnea is written mostly by **Claude, Anthropic's AI**, with some contributions
and audits by **Codex, OpenAI's coding agent** — all under the direction and
review of its author, **Morten Krogh**. The commits say so: they are
co-authored by the AI agent that wrote them.

This is not incidental to the project — it *is* the project. Linnea is a
standing demonstration that AI-assisted engineering can produce serious,
low-level systems software: a complete, from-scratch web server and reverse
proxy in hand-written assembly, with its own TLS 1.3 implementation, correct
enough to serve HTTP/3 to real browsers over the real internet, and hardened by
repeated adversarial audits — most of that audit work also carried out by AI.

It is not a single-model project by principle, only so far in practice:
**other AI agents and human contributors are welcome**, now and in the future.
Codex working alongside Claude is the first step of that, not the limit of it.
See [`CONTRIBUTING.md`](CONTRIBUTING.md).

We hold it to a matching standard of honesty. Assembly has no memory safety and
no type system, and linnea uses its own cryptography rather than a
battle-tested library — so the same audits that make it credible have also, more
than once, turned up subtle bugs that green test suites could not see. We write
those findings down rather than paper over them. If you are evaluating linnea,
read [`docs/ai-development.md`](docs/ai-development.md) and
[`docs/security.md`](docs/security.md) first: they describe how it was built,
what that process is good and bad at, and where the real risks are.

## What it does

- **HTTP/1.1, HTTP/2 and HTTP/3 (QUIC)** on one port, negotiated by ALPN, with
  Alt-Svc advertising h3. HTTP/3 works for Chrome, Firefox and Safari over the
  open internet — with congestion control, loss recovery, 0-RTT (gated to safe
  methods), and BPF connection-id steering across worker processes.
- **Its own TLS 1.3** (RFC 8446). A deliberately minimal, fixed profile:
  `TLS_AES_128_GCM_SHA256`, X25519 key exchange, an ECDSA P-256 certificate.
  No TLS 1.2, no RSA — see [Scope](#scope).
- **Static files** with precompressed `.br`/`.gzip` variant selection, byte-range
  requests, conditional requests (ETag, Last-Modified, `If-*`), and per-location
  `Cache-Control`.
- **Reverse proxy** to HTTP/1.1 backends: several backends per location with
  round-robin and passive health/failover, and optional upstream keep-alive —
  reused across HTTP/1, HTTP/2 and HTTP/3 clients alike. See
  [`docs/proxying.md`](docs/proxying.md).
- **WebSocket** tunnelling through the proxy.
- **Operations built in:** `io_uring` throughout, one reuseport worker per CPU,
  kTLS, a lossless hot upgrade (a config/binary reload that drops no connection),
  per-source connection and request-rate limits, and a slow-loris bound.

## Scope

Linnea is an honest specialist, not a drop-in nginx. It does a focused set of
things to a high standard and leaves a great deal out — on purpose, for now.
Notably it has **no** backend TLS or h2/gRPC upstreams (backends are plaintext
HTTP/1.1 over loopback), **round-robin only** load balancing, **passive-only**
health checks, no response cache, no auth/WAF/rewrite engine, and no metrics or
admin API. TLS is a single fixed cipher profile. It targets modern Linux on
x86-64 with `io_uring`. If you need the breadth of a general-purpose proxy,
reach for one; if you want a tiny, self-contained, QUIC-first edge server for a
site you control, linnea is built for exactly that.

## Dependencies

Linnea's only runtime requirements are the operating system and the processor:

- **Linux 5.19 or newer**, on an **x86-64** CPU.

That is the whole list. Linnea makes raw system calls and links nothing else:

- **No C runtime.** The binary has its own `_start`; there is no libc.
- **No libraries — not even for `io_uring`, cryptography, or networking.**
  `io_uring` is driven by hand through the raw syscall interface with no
  `liburing`; the TLS 1.3 stack and every primitive under it (X25519, P-256,
  AES-GCM, SHA-2) are in the source tree; the HTTP, QUIC and socket handling are
  all direct syscalls.
- **Statically linked.** The ELF binary depends only on the stable Linux syscall
  ABI. There is nothing to install alongside it and nothing to keep in version
  lockstep.

The 5.19 floor is set by the newest kernel feature linnea relies on — `io_uring`
multishot accept. It also uses kTLS, BPF reuseport steering for HTTP/3, and UDP
GRO, all of which landed in older kernels. Without `CAP_BPF` the HTTP/3 steering
falls back to the kernel's connection hash (see [`docs/config.md`](docs/config.md));
everything else is required.

**Building** additionally needs an assembler and a linker — **`nasm`** and
**`ld`** — and nothing to fetch. See [`docs/building.md`](docs/building.md).

**The tests** have their own dependencies, separate from the server: **`python3`**
(the fixtures and demo backends are Python) and **`curl`**. A few HTTP/3 tests
also need an HTTP/3-capable `curl` and the Python `aioquic`/`pylsqpack` packages;
tests needing them are skipped when they are absent rather than failed.

## Quick start

Requires `nasm` and a linker on Linux 5.19+/x86-64 — see
[Dependencies](#dependencies).

```sh
make                                    # nasm + ld; no dependencies to install

mkdir -p /tmp/linnea /var/www
echo '<h1>hello from linnea</h1>' > /var/www/index.html

cat > quickstart.json <<'JSON'
{
  "log": "/tmp/linnea/access.log",
  "servers": [
    { "host": "127.0.0.1", "port": 8080, "hostname": "localhost",
      "locations": [ { "prefix": "/", "root": "/var/www" } ] }
  ]
}
JSON

./bin/linnea --config quickstart.json
```

Then, from another shell:

```sh
curl http://127.0.0.1:8080/
```

For TLS, HTTP/3 and proxying, see the configuration reference below. `linnea
--test --config <file>` checks a configuration (and its certificates) and exits
without binding anything.

## Documentation

| Document | What it covers |
|---|---|
| [`docs/ai-development.md`](docs/ai-development.md) | How linnea is built with AI — the process, what it is good and bad at, the honesty policy |
| [`docs/architecture.md`](docs/architecture.md) | How a zero-dependency assembly server works: process model, `io_uring`, the protocol stack, TLS and crypto |
| [`docs/config.md`](docs/config.md) | The complete configuration reference — every key, scope, default and rule |
| [`docs/proxying.md`](docs/proxying.md) | Reverse proxy: backends, load balancing, health, failover, upstream keep-alive |
| [`docs/building.md`](docs/building.md) | Building from source, the toolchain, and running the tests |
| [`docs/deployment.md`](docs/deployment.md) | Running in production: systemd, TLS certificates, log rotation, the service model |
| [`docs/shutdown.md`](docs/shutdown.md) | Stopping, reloading and restarting — and what each does to open connections |
| [`docs/security.md`](docs/security.md) | Threat model, the self-contained crypto, the audit history, and how to report a vulnerability |

## Testing

Linnea ships with an extensive test suite and a standalone compliance prober.

```sh
make test                       # the fast suite
LINNEA_SUITE=full ./test/run_shards.sh   # the full, deploy-gating suite
```

`bin/linnea-probe` is a dependency-free HTTP/1, HTTP/2 and HTTP/3 conformance
prober that can be pointed at any server, including a live one. See
[`docs/building.md`](docs/building.md).

## Contributing

Contributions are welcome — and **AI-assisted and AI-reviewed contributions are
explicitly encouraged**, since that is how linnea itself is written. Please read
[`CONTRIBUTING.md`](CONTRIBUTING.md) for how to build, test, and submit changes,
and the conventions the codebase holds itself to.

## Security

Linnea implements its own TLS and cryptography and is written in unmanaged
assembly, so please treat security seriously. To report a vulnerability, see
[`docs/security.md`](docs/security.md) — do not open a public issue for it.

## License

MIT. See [`LICENSE`](LICENSE).
