# Roadmap — the gaps vs a general-purpose proxy

Captured 2026-08-22 from an honest comparison of linnea against nginx, Caddy,
Apache, HAProxy and Envoy. This is a **backlog of scope, not a bug list.** Every
item here is something linnea deliberately does *not* do today — the cost of
being a small, self-contained specialist rather than a general-purpose proxy.

Nothing on this list is required for linnea's actual deployment (a hardened,
dependency-free, QUIC-first edge terminator for a known site). Pursue an item
only if the goal shifts from *"the best possible edge for this site"* to *"a
general proxy others adopt."* Until then, breadth is not the objective and adding
it erodes the thing that makes linnea worth having.

## What stays the differentiator (do not trade this away)

Whatever we add, these are why linnea exists — a change that dilutes them is
probably the wrong change:

- **Self-contained.** No dependency CVE surface (no OpenSSL to patch), tiny
  binary, hermetic `nasm`+`ld` build. No mainstream proxy has this property.
- **First-class HTTP/3.** NewReno, RTT sampling, GRO receive, amplification
  limits, 0-RTT method gating, BPF CID steering, multi-address binding — working
  for Chrome, Firefox and Safari over the open internet.
- **Modern I/O and ops.** io_uring end to end, kTLS, reuseport workers, lossless
  hot upgrade.
- **Correctness discipline.** Adversarial audits, a standalone compliance prober
  (`linnea-probe`), RFC conformance work.

## The gaps

### Backend / upstream side — the thinnest area

- **Plaintext HTTP/1.1 to upstreams only.** No backend TLS, and no
  **h2 / h3 / gRPC to upstreams**. For most real reverse-proxy deployments
  (TLS to backends, gRPC, h2 upstream) this alone is disqualifying — the single
  biggest functional gap.
- **Load balancing is round-robin only.** No least-connections, weighted,
  consistent-hash or EWMA; no sticky sessions.
- **Health is passive only.** No active health checks, no outlier detection, no
  circuit breaking.

### Traffic features

- **No caching** — no proxy/response cache.
- **No request/response transformation** — no header add/rewrite, no URL
  rewriting.
- **No auth** — no basic / JWT / mTLS-client auth.
- **No WAF, no ACL / geo / IP allow-deny.**
- **No canary / mirroring / traffic-splitting.**
- **Rate limiting is minimal** — per-IP connection cap plus a global token
  bucket, nothing more granular.

### Observability & dynamic control

- **No metrics / Prometheus endpoint.**
- **No admin / runtime API, no tracing.**
- **No service discovery** (DNS / Consul / xDS).
- **Config is static JSON (~32 keys), reload-only.** No dynamic config plane;
  Envoy's xDS/filters have no analog here.

### Substrate risk (not a feature, but the standing backdrop)

Hand-written assembly with no memory safety and no type system; its own crypto is
far less battle-tested than BoringSSL; pinned to modern Linux/x86-64/io_uring;
realistically maintainable by about one expert. The audit history is a long list
of subtle bugs the discipline caught — and the concerning ones keep being the
*omissions* (e.g. the all-zero X25519 check was missing on **both** handshakes
and survived a 71-finding audit). Every item added below widens this surface;
weigh it accordingly.

## Priority order

If we narrow the gap for broader use, highest leverage first:

1. **Backend TLS + h2/gRPC upstreams.** The biggest functional gap; unlocks the
   largest set of real deployments. Scope this properly before touching code —
   backend TLS means a TLS *client* path (we only have the server path today),
   and h2 upstream means a client-side HTTP/2 that reuses connections.
2. **Metrics / stats endpoint.** Operability table stakes; comparatively cheap
   and immediately useful for the live deployment.
3. **Weighted LB + active health / outlier detection.** Builds on the existing
   passive-health upstream pool.

The rest (caching, transforms, auth, WAF, xDS, tracing, service discovery) is
lower priority and larger — take it on only under a deliberate decision to
become a general-purpose proxy.
