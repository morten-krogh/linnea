# audit-report-92 — the unix: backend work, self-audited

The Unix-socket backend series (`09f4332..9aef672`) shipped to production
without an adversarial pass. This is that pass. Two findings, one of them
security-relevant and **pre-existing** — not introduced by this work, but found
while auditing it.

---

## F1 — `proxy_pin` without `proxy_tls` is silently inert (SECURITY)

**Confirmed, fixed.** The both-or-neither rule between `proxy_tls` and
`proxy_pin` was enforced in **one direction only**. `proxy_tls` requires a pin;
a pin never required `proxy_tls`.

The consequence is not "a pin that goes unchecked". It is:

```json
{ "prefix": "/api", "proxy": "127.0.0.1:8080", "proxy_pin": "abab...ab" }
```

...accepted, and served over **plaintext**, unauthenticated, with no warning.
Measured: that location with a deliberately WRONG pin answered **200**, where
the same wrong pin plus `proxy_tls` gives 502. An operator who writes a pin and
forgets `proxy_tls` believes they have an authenticated TLS backend and has
neither.

The file's own comment already claimed the rule — *"a TLS backend must be
pinned (both-or-neither, like cert/key)"* — and only one half was ever checked.
`proxy_sni` had the same shape: a server name for a ClientHello that is never
sent.

This is the pattern already recorded from reports 10-21: **ask of any boundary
rule whether it is enforced in BOTH directions.** It was written down, and it
still took an audit to find the next instance.

Fix: `proxy_pin` requires `proxy_tls`, `proxy_sni` requires `proxy_tls`, each
with a message that says what the config would actually have done. Six new
rows in `doc_claims_test.py` — three refusals and three acceptances, so the
rule cannot widen and start rejecting legitimate combinations — plus both
`docs/config.md` rows.

**Not a regression from the unix: work**: it predates it and applies to TCP
backends equally. The unix: work is only how it was found.

---

## F2 — h2 and h3 clients to a unix: backend had no coverage

**Confirmed working, coverage added.** The `unix:` rows in `h1/30-proxying.sh`
drive **h1 clients only** — five curl calls, none with `--http2`/`--http3`.
Since `e78b131`, h2 and h3 clients are served through the h2p leg whatever the
backend speaks, so they reach a backend socket by a **different path** than an
h1 client. Nothing pinned that path for a unix: backend.

Tested by hand: h1, h2 and h3 clients all return the backend body over a unix:
socket, with zero connect failures. So this is a **test gap, not a defect** —
which is worth stating plainly rather than dressing up as a bug.

It is exactly the shape `upstream_failover.py`'s own header warns about:
*"h2 and h3 passed without executing a line of the paths they were meant to
cover."*

Fix: a TLS front on `P61734` whose `/api` is a unix: socket, driven by all
three client protocols, plus an assertion that **no** leg logged a connect
failure — there is no TCP backend to fall back to, so a silent fallback would
otherwise look like success.

---

## Checked and found sound

- **The 107-byte path boundary at RUNTIME**, not just at parse: a backend on a
  path of exactly 107 bytes is reached and answers. This is the `addrlen`
  arithmetic at its maximum (2 + 107 + 1 = 110 = `sizeof(sockaddr_un)`).
- **Slot reuse across a reload**: the slot is zeroed before the `sockaddr_un`
  is built, so a previous parse's longer path cannot survive in it.
- **`proxy_keepalive` with a unix: backend** parses and is accepted; the pool
  keys on (location, backend index), not on an address, so it is family-blind
  by construction.
- **Mixed families in one location**, both orders, which is what production
  now runs: `["127.0.0.1:7700", "unix:/run/linnea-api-2/api.sock"]`.
