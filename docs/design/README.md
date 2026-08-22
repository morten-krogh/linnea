# Design notes

Internal design and implementation notes, kept for the record. These are **not**
user documentation — they are how parts of linnea were reasoned out while they
were being built, written for whoever works on the code next.

For using and deploying linnea, start at the top-level [`README.md`](../../README.md)
and the user docs in [`docs/`](..).

- [`roadmap.md`](roadmap.md) — the scope gaps vs a general-purpose proxy, and what not to trade away.
- [`backend-tls-h2.md`](backend-tls-h2.md) — design for TLS + HTTP/2 to backends (roadmap #1): the tiered, pin-not-trust-store scope.
- [`http2-plan.md`](http2-plan.md) — the HTTP/2 implementation arc.
- [`http3-plan.md`](http3-plan.md) — the HTTP/3 (QUIC) implementation arc.
- [`upload-window.md`](upload-window.md) — the HTTP/3 upload receive-window design.
