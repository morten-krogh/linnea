# Changelog

All notable changes to linnea are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project will use
[semantic versioning](https://semver.org/) from its first tagged release.

## [1.0.0] — 2026-08-21

The first properly documented public release. Linnea is a from-scratch HTTP/1.1,
HTTP/2 and HTTP/3 web server and reverse proxy, written in x86-64 assembly with
its own TLS 1.3 and no dependencies, and written mostly by Claude with some
contributions and audits by Codex. It has been running a live site on the public
internet.

### Protocols
- HTTP/1.1, HTTP/2 and HTTP/3 (QUIC), negotiated by ALPN with Alt-Svc, on one
  port.
- TLS 1.3 (RFC 8446), a fixed profile: `TLS_AES_128_GCM_SHA256`, X25519, ECDSA
  P-256. All primitives implemented in-tree; kTLS for bulk records.
- HTTP/3 over QUIC with NewReno congestion control, loss recovery, RTT sampling,
  address validation and amplification limits, 0-RTT gated to safe methods, and
  BPF connection-id steering across workers.

### Serving
- Static files with precompressed `.br`/`.gz` variant selection, byte-range
  requests, and conditional requests (ETag, Last-Modified, `If-*`).
- Reverse proxy to HTTP/1.1 backends: multiple backends per location with
  round-robin and passive health/failover, and optional upstream keep-alive
  reused across all three client protocols. Uploads captured whole before the
  backend is contacted.
- WebSocket tunnelling.

### Operations
- One reuseport worker per CPU under a supervising master; `io_uring` throughout.
- Lossless hot upgrade (config and binary) via `SIGUSR2`, refusing a bad config.
- Per-source connection and request-rate limits; slow-loris bound.
- A standalone HTTP/1/2/3 compliance prober, `linnea-probe`.

### Documentation
- A full documentation set under `docs/`, and an honest account of how linnea is
  built with AI (`docs/ai-development.md`).

### Release binaries

The stripped x86-64 binaries shipped in `linnea-1.0.0-linux-x86_64.tar.gz` are
byte-for-byte reproducible from the `v1.0.0` source and hash to:

```
129d7fd7e9515dfe59fa2cf65e69053d16459a99b967cf6cac2779366c959920  linnea
6122814d9aa20f58c234bf4a03812753e2d1a400b732a7c0240edc0cef102996  linnea-probe
```

Reproduce and verify:

```sh
git checkout v1.0.0 && make && strip bin/linnea bin/linnea-probe
sha256sum bin/linnea bin/linnea-probe
```

The `strip` is required — the default build carries DWARF debug info that embeds
the build path, so only the stripped binaries hash identically everywhere.
