# Audit Report 41

Audited at `b2f8b5a`, 2026-08-24.

One backend HTTP/2 lifecycle defect remains open:

1. **Medium: `proxy_keepalive` parks a backend HTTP/2 connection in the
   HTTP/1 pool, so the next H2 request sends an HTTP/1 request on an H2 socket.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — `proxy_h2` connections can be reused through the HTTP/1 pool

Severity: **Medium (P2, repeat-request failure and avoidable backend churn)**  
Confidence: **High**  
Status: **Not reproduced as filed** (see Resolution) — the runtime half of its
recommended fix is nevertheless in, and looking where it pointed found two real
defects one path over.

The configuration parser permits `proxy_keepalive: 1` and `proxy_h2: 1` on the
same proxy location. It validates that `proxy_h2` has TLS, but does not reject
the combination or otherwise make the two options mutually exclusive
([src/server/linnea_config_parse.asm:1473](/home/linnea/linnea/src/server/linnea_config_parse.asm:1473)
through [:1496](/home/linnea/linnea/src/server/linnea_config_parse.asm:1496)).
The documentation says that H2 connection reuse and multiplexing are deferred
([docs/config.md:372](/home/linnea/linnea/docs/config.md:372)
through [:376](/home/linnea/linnea/docs/config.md:376)), but the accepted
configuration still enables the existing HTTP/1-style pool.

The H2-client slot marks a safe GET or HEAD request reusable solely from
`proxy_keepalive`. `h2p_finalize` does not inspect `proxy_h2` before setting
`.reusable = 1` and choosing the keep-alive branch
([src/server/linnea_http2.asm:3276](/home/linnea/linnea/src/server/linnea_http2.asm:3276)
through [:3305](/home/linnea/linnea/src/server/linnea_http2.asm:3305)). After
the H2 exchange completes, `h2p_release` uses that flag to call
`linnea_upstream_park`; its eligibility checks contain no
`LINNEA_H2P_F_PROXY_H2` or H2-state exclusion
([src/server/linnea_http2.asm:2960](/home/linnea/linnea/src/server/linnea_http2.asm:2960)
through [:2985](/home/linnea/linnea/src/server/linnea_http2.asm:2985)). The
parked descriptor is therefore a TLS socket whose peer is still speaking the
backend's HTTP/2 protocol.

On the next safe request to the same location and backend,
`h2p_open_upstream` takes that descriptor from the generic upstream pool and
sets the slot to `LINNEA_H2P_SENDING`
([src/server/linnea_http2.asm:3357](/home/linnea/linnea/src/server/linnea_http2.asm:3357)
through [:3375](/home/linnea/linnea/src/server/linnea_http2.asm:3375)). That
state is not an H2 driver state. The arming code consequently takes the normal
path and sends the slot's rewritten HTTP/1 request buffer
([src/server/linnea_uring.asm:4496](/home/linnea/linnea/src/server/linnea_uring.asm:4496)
through [:4527](/home/linnea/linnea/src/server/linnea_uring.asm:4527)). No
client preface, SETTINGS, or H2 HEADERS frame is produced for this pooled
attempt.

### Reproduction

Use a TLS backend that selects H2 by ALPN and a location like:

```json
{
  "prefix": "/api",
  "proxy": "127.0.0.1:8443",
  "proxy_tls": 1,
  "proxy_pin": "<backend SPKI pin>",
  "proxy_h2": 1,
  "proxy_keepalive": 1
}
```

Send two sequential safe requests over one frontend HTTP/2 connection. The
first request completes over a fresh TLS+H2 leg and parks that leg. The second
request takes it from the pool, sends an HTTP/1 request line as the first bytes
of the already-established H2 stream, and receives a backend protocol error or
waits for the upstream timeout. The pooled-retry path may eventually open a
fresh H2 leg and return 200, but it has already generated an invalid backend
exchange and adds failure latency; if the retry cannot be started, the request
surfaces as a gateway error.

This is not a cross-request data disclosure: the pool remains keyed by
location and backend. It is nevertheless a correctness and availability bug
for an explicitly accepted option combination, and it defeats the documented
single-stream H2 implementation by treating an H2 connection as an HTTP/1
keep-alive socket.

### Recommended fix

Until H2 connection reuse is implemented, make `proxy_h2` and
`proxy_keepalive: 1` incompatible at configuration time, with a clear parse
error. Independently, keep the runtime safe by forcing `.reusable = 0` for an
H2 backend leg before `h2p_release` can park it. Add a regression test that
uses two sequential frontend H2 requests with both options present and asserts
either the intended configuration error or two fresh TLS+H2 backend exchanges;
it must not observe an HTTP/1 request on the backend H2 connection.

## Verification

The finding is a source-level lifecycle trace across configuration validation,
H2 request finalization, upstream pooling, and io_uring send selection.
`make -j4` completed with no work required. Runtime socket tests could not be
executed in this restricted environment because the sandbox denies socket
creation; no source change was made that required executable verification.

## Resolution (2026-08-24) — Finding 1 does not reproduce; two real defects in the same code, FIXED

### Finding 1, as filed, cannot happen

The filed configuration, run against the audited binary (`b2f8b5a`), three
sequential safe requests over HTTP/2 clients:

```
request 1: BACKEND-OK [200]   backend: accepted connection from 127.0.0.1:56778
request 2: BACKEND-OK [200]   backend: accepted connection from 127.0.0.1:56792
request 3: BACKEND-OK [200]   backend: accepted connection from 127.0.0.1:56800
```

Three requests, three backend connections. The H2 leg is never parked, so no
later request takes an H2 socket out of the HTTP/1 pool, and no HTTP/1 request
line is ever written onto an H2 stream.

The trace is correct through `h2p_finalize` and into `h2p_release`, and stops
one line short of what decides it. Parking needs `.no_reuse == 0` as well as
`.reusable == 1` ([src/server/linnea_http2.asm:2969](/home/linnea/linnea/src/server/linnea_http2.asm:2969)),
and `.no_reuse` is set by `h2p_parse_head` for any response that says
`Connection: close`. Every `proxy_h2` response says exactly that:
`linnea_h2c_drv_head` appends `connection: close` to the HTTP/1 head it
synthesizes from the backend's HEADERS
([src/server/linnea_h2_client.asm:2521](/home/linnea/linnea/src/server/linnea_h2_client.asm:2521)).
The leg is closed, not parked.

That is a response header the driver happens to write, not a rule about
pooling — one edit to the synthesized head away from disappearing. So the
report's runtime recommendation is worth taking even though its failure is not
real, and taking it is what turned up the two below.

### The same class does happen — one path over

`proxy_tls` **without** `proxy_h2`, `proxy_keepalive: 1`, three sequential
requests from an **HTTP/3** client, again on `b2f8b5a`:

```
h3 request 1: BACKEND-OK [200]
h3 request 2: BACKEND-OK [200]
h3 request 3: BACKEND-OK [200]
backend: accepted connection from 127.0.0.1:44822
backend: request "GET /probe.txt HTTP/1.1" 200      <- all three
backend: request "GET /probe.txt HTTP/1.1" 200         requests on
backend: request "GET /probe.txt HTTP/1.1" 200         ONE connection
```

A kTLS socket, parked and taken back out. It answers correctly here, which is
the whole problem with leaving it: a linnea backend sends no post-handshake
records, so nothing ever hands this socket the control record that would expose
it. What the taker does with one is not decided by anything the pool knows —
`up_ktls` is set only at the kTLS handoff and cleared only in `.connect_tls`,
and a pooled take runs neither, so whether the reads are record-type-aware
depends on what the leg's connection slot happens to still hold. A backend that
sends a ticket, or closes with a `close_notify`, faults a plain `recv` with
`-EIO`.

The rule this breaks was already written down — once, on one of three paths.
The h1 leg has refused to pool a TLS backend leg since backend TLS landed
([src/server/linnea_http.asm:3050](/home/linnea/linnea/src/server/linnea_http.asm:3050)),
with the reasoning spelled out in a comment. The h2p and h3 legs never got it.
A rule enforced on one protocol's path is not a rule; it is a coincidence with
a comment on it.

### And looking there found the bigger one: an h2 client to a plain `proxy_tls` backend always 502s

Same `b2f8b5a`, a `proxy_tls` location with no `proxy_h2`, an HTTP/2 client:

```
front:   "GET /probe.txt HTTP/2" 502 16     upstream accepted but did not answer
backend: tls handshake failed, alert 10     (unexpected_message)
```

Every request, deterministically. `.ev_connect` started the backend TLS
handshake on `proxy_h2` rather than on `proxy_tls`, so for a plain TLS backend
the h2p leg skipped the handshake entirely and sent its rewritten HTTP/1 head in
cleartext to a socket expecting records. The backend read `G` as a record type.

This is step 5 of the backend-TLS plan ("the h2p path (h2 clients)",
`docs/design/tls-client-handshake-plan.md`) — never done, and nothing refuses
the configuration or logs that it cannot serve it. h1 and h3 clients to the same
location work, which is why the suite did not see it: every `proxy_tls` check
drives `curl` against a **plaintext** front, and curl speaks HTTP/1.1 there.

### The fixes

1. **The h2p leg runs the backend TLS handshake for any `proxy_tls` location**
   (`.ev_connect` → `.ev_connect_tls`), offering ALPN `h2` only when `proxy_h2`
   is set — the same `alpn_sel = proxy_h2` the h1/h3 leg uses. After the kTLS
   handoff a plain TLS backend rejoins the ordinary `SENDING`/`HEAD`/`RELAY`
   path instead of starting the h2 driver, and `F_PROXY_H2` is set only for an
   actual h2 backend.
2. **A kTLS leg reads records, not bytes.** `.ao_recv_norm` arms a RECVMSG when
   `F_KTLS` is set, and the recv completion asks `h2p_krx_rectype` what the
   record was: a backend's NewSessionTicket is skipped and re-read, an alert
   ends the message. Without this the first ticket faults the read with `-EIO`
   and 502s a response the backend did answer — the same defect `b2f8b5a` fixed
   for the h2 leg, on the leg that did not exist yet.
3. **No TLS backend leg is ever parked**, on the h2p leg (`h2p_finalize`) and
   the h3 leg (`linnea_h3_proxy.asm`), matching h1. `proxy_keepalive` on a
   `proxy_tls` location is now uniformly a no-op rather than a no-op on one path
   and an untracked kTLS socket on the others.

Not done: a configuration-time error for `proxy_h2` + `proxy_keepalive`, as the
report recommends. `proxy_tls` + `proxy_keepalive` has always been accepted and
ignored, and rejecting only the `proxy_h2` spelling of the same combination
would be an arbitrary line — one that fails a reload for a config that is now
demonstrably safe. `docs/config.md` states the exclusion instead, in the list of
conditions a connection must meet to be kept.

### Coverage, stated honestly

Nine new checks in `test/shards/tls/70-backend-tls-client.sh`, every one of them
also run against a binary built from the audited source before the fix:

```
pre-fix: an h2 client is served over a plain proxy_tls leg               FAIL
pre-fix: an h2 client receives a 200000-byte body over proxy_tls         FAIL
pre-fix: 20 concurrent h2 clients all 200 over proxy_tls legs            FAIL
pre-fix: a ticket-sending backend is relayed, not 502 (client --http2)   FAIL
pre-fix: proxy_keepalive parks no TLS leg (h2 client)                    FAIL
pre-fix: proxy_keepalive parks no TLS leg (h3 client)                    FAIL
pre-fix: a ticket-sending backend is relayed, not 502 (client --http1.1) PASS
pre-fix: a ticket-sending backend is relayed, not 502 (h3 client)        PASS
pre-fix: proxy_keepalive parks no h2 leg (proxy_h2)                      PASS  <- the filed finding
```

Six fail before the change, three pass. The last row is this report's Finding 1:
it passes before the fix as well as after, so it is a control, not new coverage.
Said plainly, because "nine new checks for audit-report-41" would claim the
filed finding was real.

The three `openssl s_server` rows put a **ticket-sending** backend behind the
front and drive it from HTTP/1.1, HTTP/2 and HTTP/3 clients. Every other proxy
check in the suite uses a linnea backend, and linnea sends no session tickets —
so nothing in the suite could see a leg mishandle one. That gap is not
hypothetical: an editing slip dropped fix 2 out of the tree mid-session and the
whole tls group still passed 227/0 without it. This check is what caught that,
which is why it is in the suite rather than in a scratch script.

`test/shards/lib/common.sh` gains `P61719`–`P61723`.

Full suite: **816 passed, 0 failed** (807 before; the nine are the difference).

## Verification (resolution)

Every claim above is a run, not a reading. Each defect was reproduced on a
binary built from the audited source, then re-run after the change; the pre-fix
control identifies which rows the fix is responsible for. The record-type skip
was A/B'd on its own — the same binary with only the RECVMSG conversion
neutered 502s the ticket-sending backend where the fixed one returns 200 with a
3707-byte body — because a check that passes for a reason other than the one
you think is worse than no check.
