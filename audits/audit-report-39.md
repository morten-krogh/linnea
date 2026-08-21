# Audit Report 39

Audited at `cb3e736`, 2026-08-21.

One upstream-pool capacity gap remains open:

1. **Medium: HTTP/2 and HTTP/3 refuse reusable upstream connections when
   `max_upstream` is full.** A parked connection is already included in that
   limit, so borrowing it cannot exceed the configured connection ceiling.

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — H2/H3 check the upstream ceiling before looking in the idle pool

Severity: **Medium (P2, avoidable 503 under configured capacity)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

`max_upstream` is documented as the maximum number of concurrent connections
to proxy backends, not the number of active requests
([docs/config.md:111](/home/linnea/linnea/docs/config.md:111)). Parked
keep-alive descriptors remain correctly included in the count: they are live
backend connections and must consume one of those slots. Reusing one does not
open another descriptor and therefore does not increase that count.

HTTP/1 implements precisely that ordering. It picks a backend, attempts
`linnea_upstream_take`, and consults `linnea_upstream_limit` only on the
fresh-socket path at
[src/server/linnea_http.asm:3045](/home/linnea/linnea/src/server/linnea_http.asm:3045)
through
[:3076](/home/linnea/linnea/src/server/linnea_http.asm:3076). Its adjacent
comment states the same invariant: the connection is already counted, so the
ceiling must not refuse the pool's own inventory.

HTTP/2 does the reverse. `h2p_open_upstream` returns its 503 path immediately
when the count equals the ceiling
([src/server/linnea_http2.asm:3331](/home/linnea/linnea/src/server/linnea_http2.asm:3331)
through [:3334](/home/linnea/linnea/src/server/linnea_http2.asm:3334)); its
otherwise-correct pool lookup is unreachable below at
[:3342](/home/linnea/linnea/src/server/linnea_http2.asm:3342) through
[:3353](/home/linnea/linnea/src/server/linnea_http2.asm:3353).

HTTP/3 has the same early refusal in the request-start routine
([src/server/linnea_h3_proxy.asm:193](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:193)
through [:199](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:199)), before
it reaches its pool lookup at
[:494](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:494) through
[:514](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:514).

### Reproduction

Configure one worker, one `proxy_keepalive` location, and `max_upstream: 1`.
Send a successful safe request so its upstream socket is parked. A subsequent
safe request to the same location has an immediately reusable descriptor:
`linnea_upstream_take` accepts an idle, matching descriptor and transfers its
ownership to the request without opening a connection
([src/server/linnea_upstream.asm:380](/home/linnea/linnea/src/server/linnea_upstream.asm:380)
through [:399](/home/linnea/linnea/src/server/linnea_upstream.asm:399)).

At that point HTTP/1 sends the second request over the parked socket. HTTP/2
and HTTP/3 instead observe `inflight == max_upstream` first and answer 503,
despite consuming no additional upstream capacity. It lasts until the five
second idle-pool expiry or another request path reaps the descriptor.

### Recommended fix

Move the count/limit check in `h2p_open_upstream` to the fresh-socket branch,
after its `linnea_upstream_take` miss. In HTTP/3, allocate the request leg as
needed, perform the matching pool lookup first, and apply the count check only
immediately before opening a new socket. Preserve the existing cleanup for a
leg allocated before a fresh-path 503.

Add a three-protocol test with `max_upstream: 1`: warm one pooled GET, issue a
second GET, assert 200 and no extra backend accept for HTTP/1, HTTP/2, and
HTTP/3. Also assert that a pool miss at that ceiling remains 503, so the
connection cap itself is not weakened.

## Resolution — FIXED (2026-08-21)

Confirmed, and the consequence is worse than the report estimates. Measured on a
fresh server, `max_upstream: 1`, one worker, four sequential GETs to the
keep-alive location:

```
h1   200 200 200 200      and 200 after the idle expiry
h2   200 503 503 503      and STILL 503 after it
h3   200 503 503 503      and STILL 503 after it
```

The report expects the refusal to last "until the five second idle-pool expiry
or another request path reaps the descriptor". **Neither happens.**
`linnea_upstream_take` is the ONLY thing that reaps an expired pool entry, and
it is exactly what the early ceiling check skips — so the descriptor is never
reclaimed and the count never falls. On a site served over h2/h3 alone there is
no other request path, and **one successful request wedges the location at 503
for the life of the worker.** That moves this from an avoidable 503 under
saturation to a self-inflicted outage under a configured ceiling.

### The fix

The check now sits beside the socket it governs. In h2 it moved into
`.ou_fresh`; in h3 it moved from the request-start routine down to `.st_fresh`,
which means a leg is already allocated when it fires — so a new `.st_busy` gives
the leg back before answering 503, the same shape `.st_nosock` has always had.

### The ceiling still refuses, which is half the fix

A cap that stopped capping would not be a repair. The saturation row asserts a
request that **cannot** borrow — a different location, no `proxy_keepalive`, its
single slot held by a backend that sleeps two seconds — is still 503 on all
three protocols. It is: `h1 503, h2 503, h3 503`.

### Why it was mine

h1 got this ordering deliberately when the pool landed, with a comment saying
the ceiling must not refuse its own inventory. h2 and h3 were taught to use the
pool afterwards and inherited the old ordering unchanged. **The rule was
reasoned about once and applied once**, which is the same shape as the wildcard
in report 36 and the staleness gate in `cb3e736` — the third time in three days
that a rule which had to hold in three translators held in one.

### Coverage

`test/tls/upstream_ceiling.py`, 15 rows over h1, h2 and h3: the ceiling still
refuses an unborrowable request; a keep-alive GET is served; three more are
served at a full ceiling; **no further backend connection is opened** (read from
the backend's own accept counter, since reuse is invisible from the client); and
the location recovers after the idle expiry — the row that would have stayed 503
forever before.

Six fail on a pre-fix binary, all h2 and h3. The h1 rows and both saturation
rows pass either way, which is what keeps the fix from over-applying.

Full suite: **786 passed, 0 failed**.

## Verification (resolution)

Measured, not traced: a live `max_upstream: 1` server on all three protocols,
before and after, including the post-expiry row that showed the wedge was
permanent rather than transient.

## Verification (as filed)

`make -j4` completed successfully. No executable test was run: the finding is
a source-level ordering trace against a configuration-specific saturation case
that the existing normal-capacity keep-alive coverage does not exercise.
