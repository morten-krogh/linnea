# Reverse proxy

A `proxy` location forwards requests to one or more backend services. This
covers how backends are chosen, what happens when one is down, and how upstream
connections are reused. The configuration keys themselves are in
[`config.md`](config.md); this is the behaviour and the reasoning.

## Backends

A backend is either a TCP address — `IPv4:port`, e.g. `127.0.0.1:8080` — or a
**Unix domain socket**, written `unix:` followed by an absolute path. A location
names one backend, or an array of them, and an array may mix the two:

```json
{ "prefix": "/api", "proxy": "127.0.0.1:8080" }
{ "prefix": "/api", "proxy": ["127.0.0.1:8080", "127.0.0.1:8081"] }
{ "prefix": "/api", "proxy": "unix:/run/linnea/api.sock" }
{ "prefix": "/api", "proxy": ["unix:/run/a.sock", "127.0.0.1:8080"] }
```

A Unix socket is reached over the filesystem rather than the loopback TCP
stack, so **who may reach it is a file permission** rather than "anything on
this host". That is the reason to prefer one for a local backend. The path must
be absolute and at most 107 bytes — `sun_path` is 108 including its NUL — and
the abstract namespace (`unix:@name`) is deliberately not supported, since it
has no filesystem permissions and that is the whole point.

**A `unix:` backend is HTTP/1.1 cleartext only.** `proxy_tls` is refused on a
location naming one, and `proxy_h2` with it, because backend TLS is kTLS and
the kernel's TLS ULP does not exist for `AF_UNIX`. The config is rejected
rather than every request failing at runtime. Nothing is lost by it: for a
socket on the same machine the file permission *is* the boundary.

linnea only ever **connects** to the socket. It never creates or unlinks one —
that belongs to the backend.

Routing to the location is by **longest matching prefix**, so `/api` and `/`
coexist and `/api/x` goes to `/api`. The client's protocol is independent of the
backend's: an HTTP/1.1, HTTP/2 or HTTP/3 client is served by the same HTTP/1.1
backend, with linnea translating.

> **Scope.** A location names its backends literally: there is no service
> discovery. Backend TLS (`proxy_tls`, pinned by SPKI) and HTTP/2 to a backend
> (`proxy_h2`) both exist for TCP backends; gRPC to upstreams does not. This is
> deliberate for linnea's role as an edge server in front of local services.

## Choosing a backend

With several backends, requests go round them in turn (round-robin). There is
one load-balancing policy; there is no weighting, least-connections or hashing.

## When a backend is down

Health is **passive**. Nothing is probed on a timer — no traffic exists that a
client did not ask for. Instead:

- A backend that **refuses a connection** is stepped over, **within the same
  request**, so the client is served by the next backend rather than shown an
  error. This is failover, and it is why more than one backend removes the
  brief unavailability of a single backend restarting.
- **Three consecutive connect failures** take a backend out of rotation for ten
  seconds; the first success after the cooldown puts it back. Being out of
  rotation only decides where a request *starts* — while any backend is up, no
  request fails because of the health state.

Failover happens **only on a refused connection**, never after the request has
been sent. Once the request head is on the wire, a backend that then goes quiet
may already have acted on it, and sending it again would invent a second request
the client made once. A backend that accepts and then hangs is a *slow* backend,
not an absent one, and is left to `proxy_timeout` (a 504).

A failover is invisible in the access log — the client was served, so the line
reads `200` and names no backend. The error log is the record:

```
upstream 127.0.0.1:8081 connect failed
upstream 127.0.0.1:8081 failed out of rotation
upstream 127.0.0.1:8081 back in rotation
```

## Upstream keep-alive

By default linnea opens one connection per proxied request and sends
`Connection: close` upstream. `proxy_keepalive: 1` keeps connections and reuses
them:

```json
{ "prefix": "/api", "proxy": "127.0.0.1:8080", "proxy_keepalive": 1 }
```

It is **off by default on purpose**. `Connection: close` is what makes a
close-delimited response terminate; turning keep-alive on is you asserting that
your backend delimits its responses (an exact `Content-Length`, or chunked
through its terminal chunk), which HTTP/1.1 requires but does not enforce. It is
the same reason nginx needs `proxy_http_version 1.1` before its `keepalive` does
anything.

A connection is kept only when **all** of these hold:

- the location opted in;
- the request method was `GET` or `HEAD`;
- the backend did not answer `Connection: close`;
- the response body was delimited and fully consumed.

The GET/HEAD restriction is load-bearing. A pooled socket can always lose a race
with the backend's own idle timeout — the backend may close it between the moment
linnea checks it for liveness and the moment linnea sends the next request into
it. The only sound answer to that race is to **send the request again on a fresh
connection**, which linnea does — once — but only for methods that may safely be
repeated. A `POST` may not be, so a `POST` is never sent over a pooled socket.

Operational details:

- A connection is parked for at most **five seconds**, and is checked for
  liveness before reuse. **Keep your backend's own idle timeout above five
  seconds**, or it will close first and every reuse will race its `FIN`.
- Each worker holds at most **32 idle upstream connections**, and they are
  counted against `max_upstream`. An idle pooled connection yields its slot to a
  request that needs to open a new one, so the pool never starves other traffic.
- All three client protocols reuse the same pool.

What keep-alive is worth depends on what your backend pays per connection, not on
TCP: large against a backend that forks or spawns a thread per connection, small
against one with a pre-forked pool.

## Authenticated client source identity

A proxy location may set `proxy_client_identity: 1` to replace any public
`Linnea-Client-Identity` field with exactly one Linnea-authored value. The
wire forms are `v1;ip4=` followed by eight lowercase network-order hex digits,
or `v1;ip6=` followed by 32. IPv4-mapped IPv6 is rendered as IPv4.

Trust comes from authenticating the backend transport, not from the field. A
private Unix socket checked with `SO_PEERCRED` is an intended consumer; a TCP
backend reachable by untrusted clients must treat the field as untrusted. This
metadata is suitable for a per-source rate key and carries no authorization.

### Restarting a keep-alive backend cleanly

Because failover is connect-only, a **single** backend has a sub-second window
during a restart where its listener is down and a fresh connect fails — with
nowhere to fail over, that surfaces as a `502`. Two backends close it: a connect
that fails on the restarting one moves to the other in the same request. Restart
them **one at a time** (wait for the first to be listening again before the
second) so they are never both down together.

## Uploads

A request body is captured **whole before the backend is contacted** — on
HTTP/1.1, HTTP/2 and HTTP/3 alike — so a backend never sees a partial or slow
request, and a client that abandons an upload costs the backend nothing. The
capture is as large as the body, up to `max_body`; `spill_dir` decides whether
it costs disk or RAM (see [`config.md`](config.md) — put it on a real disk).
