# Audit Report 76

Audited at `c16077b` (`proxy: an absolute-form target's authority replaces the
received Host`), 2026-08-26.

Audit report 75's authority replacement is present. The next absolute-form
gap is earlier, while splitting a target URI into its authority and its path:

1. **Low: an absolute-form HTTP URI with a query and an empty path is rejected
   as though its query were part of the authority.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — `http://host?query` is not parsed as an absolute URI

Severity: **Low (P3, a valid absolute-form request is rejected at a server or
proxy boundary, preventing the client from reaching the resource)**  
Confidence: **High**  
Status: **Confirmed by a live three-request comparison and source trace.**

An HTTP URI permits an empty path followed by a query:

```text
http-URI = "http" "://" authority path-abempty [ "?" query ]
```

Thus `http://one.test?x=1` has authority `one.test`, an empty path, and query
`x=1`; it is not an authority containing a question mark. The path and query
identify the resource within the origin
([RFC 9110 §4.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.1)).
HTTP/1.1 uses an absolute URI as the request-target when talking to a proxy,
and every server must accept absolute-form even though most direct clients send
origin-form ([RFC 9112 §3.2.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.2)).

`target_absolute` starts scanning at the authority and treats only `/` as its
terminator ([src/server/linnea_http.asm:3642](/home/linnea/linnea/src/server/linnea_http.asm:3642)
through [src/server/linnea_http.asm:3681](/home/linnea/linnea/src/server/linnea_http.asm:3681)).
For a target without a slash, it takes the `root` arm and returns all remaining
bytes as the authority ([src/server/linnea_http.asm:3691](/home/linnea/linnea/src/server/linnea_http.asm:3691)
through [src/server/linnea_http.asm:3698](/home/linnea/linnea/src/server/linnea_http.asm:3698)).
Consequently this valid request is parsed as:

```text
request-target:  http://one.test?x=1
actual authority: one.test
Linnea authority: one.test?x=1
Linnea path:      /
```

The request parser installs that extracted authority in its effective-authority
slots for an absolute-form target
([src/server/linnea_http.asm:1021](/home/linnea/linnea/src/server/linnea_http.asm:1021)
through [src/server/linnea_http.asm:1038](/home/linnea/linnea/src/server/linnea_http.asm:1038)).
It subsequently validates the same slot as an authority
([src/server/linnea_http.asm:1690](/home/linnea/linnea/src/server/linnea_http.asm:1690)
through [src/server/linnea_http.asm:1702](/home/linnea/linnea/src/server/linnea_http.asm:1702)).
That validator correctly rejects `?` as a non-host character
([src/server/linnea_hpack.asm:1845](/home/linnea/linnea/src/server/linnea_hpack.asm:1845)
through [src/server/linnea_hpack.asm:1855](/home/linnea/linnea/src/server/linnea_hpack.asm:1855)),
so the malformed split turns into `400 Bad Request` before vhost selection,
static service, or proxying.

The helper added for audit report 75 already stops an authority at `?`
([src/server/linnea_http.asm:744](/home/linnea/linnea/src/server/linnea_http.asm:744)
through [src/server/linnea_http.asm:761](/home/linnea/linnea/src/server/linnea_http.asm:761)).
It runs only while rebuilding a request for an upstream, however, and the
initial target parser rejects this request first.

### Reproduction

I ran the current binary as a loopback HTTP server with a `one.test` vhost and
a static `/` location, then sent all three HTTP/1.1 requests with
`Host: one.test` and `Connection: close`:

```text
GET http://one.test?x=1 HTTP/1.1    ->  HTTP/1.1 400 Bad Request
GET http://one.test HTTP/1.1        ->  HTTP/1.1 200 OK
GET http://one.test/?x=1 HTTP/1.1   ->  HTTP/1.1 200 OK
```

The first request differs from the second only by the valid query, and from
the third only by omission of the otherwise empty `/` path. Both controls are
accepted; only the valid empty-path form is refused. A query that contains a
slash, such as `http://one.test?next=/api/headers`, exercises the same bad
delimiter scan: the slash in query data is the first one the parser sees.

### Impact

This is an interoperability and availability failure rather than an authority
confusion issue. A client using Linnea as an HTTP proxy is supposed to use
absolute-form. Requests for perfectly ordinary query-only root resources — for
example a signed root URL or a search endpoint rooted at `/` — get a local 400
instead of reaching the configured origin. Direct callers using absolute-form
receive the same failure, despite the server acceptance requirement.

The reject occurs before any request is forwarded, so the current result is not
cross-vhost routing or a query leak. That containment is why this is Low, but
returning 400 for a valid request is still a protocol boundary defect.

### Recommended fix

Make the absolute-target scanner recognize `?` as the end of the authority as
well as `/`. Preserve the two different normalizations explicitly:

- `http://host` has normalized path `/`;
- `http://host?x=1` routes as `/` but forwards the combined path-and-query as
  `/?x=1`; and
- `http://host/path?x=1` continues to use `/path?x=1` unchanged.

Do not merely return `slash_target` when the scanner sees `?`. The parser
currently stores that returned length in the proxy request-target slot
([src/server/linnea_http.asm:1031](/home/linnea/linnea/src/server/linnea_http.asm:1031)
through [src/server/linnea_http.asm:1038](/home/linnea/linnea/src/server/linnea_http.asm:1038))
and the rewriter copies that span verbatim into its upstream request line
([src/server/linnea_http.asm:2822](/home/linnea/linnea/src/server/linnea_http.asm:2822)
through [src/server/linnea_http.asm:2835](/home/linnea/linnea/src/server/linnea_http.asm:2835)).
That superficial fix would turn a 400 into a successful request for `/` while
silently dropping `?x=1`. Carry an empty-path-with-query representation through
the target parser and serializer, or synthesize the leading slash during the
HTTP/1 rewrite and the equivalent `:path` construction for `proxy_h2`.

Add end-to-end rows for all three forms above, plus
`http://one.test?next=/api/headers` to prove a slash in query data is not used
as a path delimiter. The existing proxy test's query row is only
`http://one.test/api/headers?q=1`
([test/tls/h1_absolute_form.py:62](/home/linnea/linnea/test/tls/h1_absolute_form.py:62)
through [test/tls/h1_absolute_form.py:72](/home/linnea/linnea/test/tls/h1_absolute_form.py:72));
its real path hides this defect. Test both a direct static route and an HTTP/1
and HTTP/2 backend capture, requiring `/?x=1` in the upstream request-target
or `:path`, so acceptance cannot regress into query loss.

## Verification

`bin/linnea` was current for the audited source. The loopback reproduction
above used a temporary, single-vhost configuration and raw socket requests;
the front returned exactly the three status lines shown. Source inspection
traced the rejected question mark from `target_absolute` into the effective
authority validation, while the report-75 helper supplies a useful independent
control that does recognize the delimiter. The existing direct absolute-form
suite covers a no-path target but no query-only target, and the new proxy suite
puts its query after an actual slash. Temporary server processes, configuration,
and logs were removed afterward. No production source, configuration, or test
file was changed.

References:

- [RFC 9110 §4.2.1 — http URI Scheme](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.1)
- [RFC 9112 §3.2.2 — absolute-form](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.2)

## Resolution (2026-08-26) — CONFIRMED

### Reproduced

At the audited source, against a front with a proxied location, request lines
written raw:

```
empty path + query            GET http://target.test?x=1             400 Bad Request
query containing a slash      GET http://target.test?next=/api/...   400 Bad Request
no path (control)             GET http://target.test                 200 OK  -> GET /
explicit / + query (control)  GET http://target.test/?x=1            200 OK  -> GET /?x=1
```

The report's account of why is exact: `target_absolute` ended the authority
only at `/`, so the query became part of the authority and the authority
validator refused the `?`.

### The fix, and the half-fix the report warned about

`target_absolute` now recognises `?` as an authority terminator as well. That
alone would have been the *wrong* fix, and the report says so: the parser
stores the returned span as the proxy request-target, so returning the canned
`/` would have turned a 400 into a **successful request for the wrong
resource**, the query silently gone.

So the query comes back separately in `r10`/`r11`, is kept in two new frame
slots, and the proxy rewrite appends `?` and the query behind the target.
`/?x=1` cannot be a span: the `/` is synthesised and does not exist next to the
query anywhere in the head buffer.

The append is gated on the query **pointer**, not its length, so
`http://host?` — an empty query, which is not the same as no query — still
forwards `/?`.

### The frame slot I chose first crashed the worker

The first attempt used `[rsp+408]`/`[rsp+416]`. Both are taken: the frame map
comment in the source gives `[400]` to the Accept-Encoding scan index and
`[416]`/`[424]` to the version token kept for the access log. Overwriting the
version token gave

```
fatal: SIGSEGV addr=0x0000000000000000 rip=0x0000000000416f7b
```

and a respawned worker with no response at all. The frame is allocated once and
released once, so it grew 544 -> 560 and the pair lives at `[536]`/`[544]`,
listed in that same comment. That comment is the only map of this frame there
is, and I read it wrong once already.

### Coverage: three routes, because the query survives three different ways

The report asked for a static route, an HTTP/1 backend capture and an HTTP/2
one. They are not the same question: a static route only has to be *served*; an
h1 backend has to receive `/?x=1` in its request line; the h2 leg has to build
it as `:path`.

- **Static** (`test/shards/h1/25-http-semantics.sh`, 4 rows): the two query rows
  assert *which* index came back — `three.test` has its own root, so "sub index"
  proves the target's authority won and that a query containing `/` was not
  split at that slash. A status check would have passed on a wrong route.
- **h1 backend** (`test/tls/h1_absolute_form.py`, 4 new rows, 8 total): the
  assertion is the forwarded request line and the forwarded Host. This needed a
  vhost whose `/` is *proxied* — an empty path can only ever normalise to `/`,
  so no prefix-based location can ever see it — hence `qroot.test` in the suite
  config and a bare-`/` head echo in `test/proxy_backend.py`.
- **h2 leg** (`test/shards/tls/70-backend-tls-client.sh`, 3 rows): a plaintext
  `proxy_h2` front, because curl sends absolute-form only to a proxy and never
  through TLS, so the request line has to be written raw.
  `test/h2/h2c_server.py` reports the `:path` it received.

The h2 leg needed no server change: it is handed the rewritten h1 head
(`out_ptr`/`out_rem`) and translates that, so fixing the h1 rewrite fixed the
`:path` too — measured, not assumed.

**The first version of that h2 check failed on the fixed build, and the fixture
was the thing that was broken.** `h2c_server.py` splits the query off `:path`
into `q` before it dispatches, so my route was handed `/` and dutifully reported
`PATH=/` — for a leg that had in fact sent `/?x=1`. It failed exactly the two
rows the fix was for and passed the no-query control, which is precisely the
shape of a real defect. The fixture now keeps `raw_path` before the split and
the route reports that. Third time in this series that a "defect" was the test;
the tell each time is that the failure is too perfectly aligned with the thing
being tested.

Against binaries built from the audited source:

```
pre-fix: target: absolute-form with an empty path and a query        FAIL
pre-fix: target: an empty path with a query still routes by authority FAIL
pre-fix: target: a slash inside the query is not a path delimiter    FAIL
pre-fix: proxy replaces Host from an absolute-form target (8 rows)   FAIL  (2 of 8 rows)
pre-fix: backend h2 :path: an empty path keeps its query (/?x=1)     FAIL  (400 at the front)
pre-fix: backend h2 :path: a slash in the query is not a delimiter   FAIL  (400 at the front)
pre-fix: target: absolute-form with a path and a query               PASS  <- control
pre-fix: backend h2 :path: an empty path with no query is /          PASS  <- control
pre-fix: h1 rows: no-query and explicit-/-with-query                 PASS  <- controls
```

h1 shard pre-fix **411 passed, 4 failed**; tls shard pre-fix **596 passed, 2
failed**.

### What this does not cover, and why

An h2 or h3 **client** cannot ask this question: RFC 9113 8.3.1 requires a
non-empty `:path`, so there is no empty-path form for it to normalise. The
defect and the fix are both in the HTTP/1 request-line parser; the h2 leg is
reachable only because a client's h1 request is rewritten into an h1 head
first, and that head is what `linnea_h2c_drv_start` translates.

The query bytes are still validated. The request-line target is checked as one
token before `target_absolute` splits it, so a control character, DEL or a
non-ASCII byte in the query is still a 400 in every target form — measured
across all three, not assumed, because the canned `/` return does mean the
query never reaches the target validator a second time.

h1 shard **415 passed, 0 failed**; tls shard **598 passed, 0 failed**; full
suite **1182 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on a static route, an HTTP/1 backend and the HTTP/2 leg, each asserting
what was FORWARDED rather than the status. The pre-fix table names which rows
the fix is responsible for and which were already passing. The one row that
first failed on the fixed build was traced to the fixture and is recorded above
rather than quietly repaired.
