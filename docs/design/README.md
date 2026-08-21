# Design notes

Internal design and implementation notes, kept for the record. These are **not**
user documentation — they are how parts of linnea were reasoned out while they
were being built, written for whoever works on the code next.

For using and deploying linnea, start at the top-level [`README.md`](../../README.md)
and the user docs in [`docs/`](..).

- [`http2-plan.md`](http2-plan.md) — the HTTP/2 implementation arc.
- [`http3-plan.md`](http3-plan.md) — the HTTP/3 (QUIC) implementation arc.
- [`upload-window.md`](upload-window.md) — the HTTP/3 upload receive-window design.
