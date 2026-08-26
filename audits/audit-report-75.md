# Audit Report 75

Audited at `4809b2d` (`backend h2: content-length is not a trailer field`),
2026-08-26.

Audit report 74's trailer check is present. The next proxy-boundary defect is
in translating an HTTP/1 absolute-form request:

1. **Medium: the proxy routes an absolute-form request by its target authority,
   then forwards the ignored `Host` authority to the backend.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — an absolute-form target and `Host` select different backend authorities

Severity: **Medium (P2, a valid HTTP/1 proxy request can be sent to the
backend under an authority different from the one that selected the front-end
route)**  
Confidence: **High**  
Status: **Confirmed and reproduced on BOTH legs** — the h2 handoff was measured,
not traced: the backend reported `AUTHORITY=other.test`. Fixed by emitting `Host`
from the effective authority the parser already routes on.

For an HTTP/1 absolute-form request, the target URI — not the `Host` field —
identifies the resource. A proxy must replace `Host` with the target's authority
when it forwards the message ([RFC 9112 §3.2.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.2)).
That is important even though HTTP/1.1 requires a client to send `Host`: its
value can be stale or contradictory, and is specifically not the routing input
for absolute-form.

Linnea's HTTP/1 parser gets the first half right. It recognizes absolute-form,
replaces the request-target span with the extracted path, and puts the
extracted authority in its effective-host slots
([src/server/linnea_http.asm:948](/home/linnea/linnea/src/server/linnea_http.asm:948)
through [src/server/linnea_http.asm:966](/home/linnea/linnea/src/server/linnea_http.asm:966)).
The later parser deliberately keeps that target authority when it encounters the
actual `Host` line ([src/server/linnea_http.asm:1314](/home/linnea/linnea/src/server/linnea_http.asm:1314)
through [src/server/linnea_http.asm:1331](/home/linnea/linnea/src/server/linnea_http.asm:1331)).
Consequently, vhost and location selection follow the target URI as required.

The proxy rewriter then loses the same decision. It emits the normalized path
as the upstream request-target ([src/server/linnea_http.asm:2750](/home/linnea/linnea/src/server/linnea_http.asm:2750)
through [src/server/linnea_http.asm:2763](/home/linnea/linnea/src/server/linnea_http.asm:2763)),
but its field loop only removes or rewrites connection-specific fields. An
ordinary `Host` line falls through to the verbatim copy operation
([src/server/linnea_http.asm:2905](/home/linnea/linnea/src/server/linnea_http.asm:2905)
through [src/server/linnea_http.asm:2966](/home/linnea/linnea/src/server/linnea_http.asm:2966)).
It never writes a replacement from the target authority.

That already sends the wrong authority to an HTTP/1 backend. It is also the
exact head handed to a `proxy_h2` backend: the uring path passes the rewritten
`out_ptr`/`out_rem` bytes directly to `linnea_h2c_drv_start`
([src/server/linnea_uring.asm:2476](/home/linnea/linnea/src/server/linnea_uring.asm:2476)
through [src/server/linnea_uring.asm:2491](/home/linnea/linnea/src/server/linnea_uring.asm:2491)).
`h2c_build_headers` scans that head for `Host`, emits the request target as
`:path`, and emits the discovered `Host` value as `:authority`
([src/server/linnea_h2_client.asm:748](/home/linnea/linnea/src/server/linnea_h2_client.asm:748)
through [src/server/linnea_h2_client.asm:791](/home/linnea/linnea/src/server/linnea_h2_client.asm:791)).
The ordinary `Host` field is then omitted, so the H2 backend has no way to
recover the original target authority.

That violates the explicit HTTP/2 intermediary rule: `:authority` must be
constructed from the original request's control data, not assumed from `Host`
([RFC 9113 §8.3.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1)).
For an absolute-form HTTP/1 request, the control-data authority is the target
URI.

### Reproduction

I ran a one-shot local HTTP/1 backend behind the current Linnea frontend and
sent this valid proxy-form request:

```http
GET http://target.test/hello HTTP/1.1
Host: other.test
```

The request succeeded at the front, proving that `target.test` selected its
configured proxy location. The backend captured the head that Linnea actually
forwarded:

```http
GET /hello HTTP/1.1
Host: other.test
User-Agent: curl/8.15.0
Accept: */*
Via: 1.1 linnea
Connection: close
```

Thus the request's path is normalized correctly, but its authority is not. On
the `proxy_h2` handoff, the same captured head deterministically produces:

```text
:path       /hello
:authority  other.test
```

even though the request which selected the front-end vhost and proxy location
named `target.test`. The existing backend-H2 harness also confirms the encoder
uses exactly the supplied `Host` as `:authority`: nghttp2 records
`:authority: h2c.test` for its fixed `Host: h2c.test` test head.

### Impact

An HTTP/1 client that talks to Linnea as a proxy is expected to send
absolute-form. A conflicting `Host` must not alter the target, but it does at
the backend boundary here. A backend virtual-host router can therefore process
the request under `other.test` while Linnea selected its upstream, policy, and
front-end vhost from `target.test`.

The result ranges from an incorrect backend response to a cross-vhost policy
split when the selected backend serves more than one authority. It is not
limited to the H2 leg: the live capture shows the ordinary HTTP/1 backend has
the same wrong `Host`. `proxy_h2` makes the mapping especially direct because
the stale field becomes the sole `:authority` pseudo-header.

### Recommended fix

Retain an explicit `absolute-form` flag from request-target parsing through
the HTTP/1 proxy rewrite. When set:

- skip the received `Host` field in the copy loop;
- emit one replacement `Host` line from the target URI's extracted authority;
  and
- keep the normalized origin-form path already used for the upstream request
  line.

This gives the existing H2 encoder the right input: it will convert that
replacement Host to the required `:authority` and omit the ordinary field.
Do not apply this rewrite to origin-form requests, where `Host` remains the
authority source.

Add a backend-head capture test and a `proxy_h2` field-capture test for
`GET http://target.test/hello` plus `Host: other.test`. Both must observe
`/hello` and `target.test`, never `other.test`. Keep same-authority
absolute-form and ordinary origin-form cases as controls, and include an
absolute URI with a query and one with no path so target normalization and
authority replacement remain coupled.

## Verification

The worktree was clean before this report. The live local HTTP/1 proxy capture
above ran against `4809b2d` and demonstrates the deployed rewrite, including
the normalized path and unmodified conflicting `Host`. The backend-H2 driver
accepts that exact rewritten head from `out_ptr`/`out_rem`; its source trace
shows the same field is emitted as `:authority`. A direct H2 harness run
against verbose nghttp2 independently logged the encoder's fixed test Host as
`:authority: h2c.test`, matching the source mapping. Temporary local fixtures
and configurations were removed afterward. No production source,
configuration, or test file was changed.

References:

- [RFC 9112 §3.2.2 — absolute-form](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.2)
- [RFC 9113 §8.3.1 — Request Pseudo-Header Fields](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1)

## Resolution (2026-08-26) — CONFIRMED as filed, on both legs

### Reproduced

A backend that answers with the head it received, behind a front whose vhost is
`target.test`:

```
GET http://target.test/hello HTTP/1.1        ->   GET /hello HTTP/1.1
Host: other.test                                  Host: other.test
```

The path is normalised correctly and the authority is not: the request selected
its vhost and location as `target.test` and reached the backend claiming
`other.test`.

And on the `proxy_h2` leg, with the fixture reporting the pseudo-header it
received:

```
Host: other.test    ->  backend saw AUTHORITY=other.test
Host: target.test   ->  backend saw AUTHORITY=target.test
```

The stale field becomes the sole `:authority`, exactly as the report says.

### What was already right, and what the suite already covered

The parser routes on the target's authority, and the suite has said so for a
long time — `target: absolute-form authority beats Host` passes on the audited
binary, along with five other absolute-form rows. Every one of them asks what
the FRONT did. None asked what was FORWARDED, which is the whole of this
finding.

### The fix, and the wrong first attempt

My first version reused the parser's effective-authority slot on the theory that
no absolute-form flag was needed: for origin-form that slot *is* the Host value,
so emitting from it unconditionally should have been byte-identical.

It is not. That slot holds the routing host with the **port stripped** — right
for vhost selection, wrong for a Host line — so every proxied request lost its
port: `Host: 127.0.0.1:62080` became `Host: 127.0.0.1`. The suite caught it
immediately: `proxy forwards host` failed in the full run.

The report's own recommendation was right. The rewrite now re-reads the
authority from the original request line, which is still intact in the head
buffer, through a small `proxy_abs_authority` helper — absolute-form only, port
included. Origin-form copies the client's `Host` verbatim exactly as before, and
HTTP/1.0 without a `Host` still forwards none.

### Coverage

`test/tls/h1_absolute_form.py`, four rows: a conflicting Host, a target with a
query, a matching Host, and origin-form as the control. A port-bearing target
and a port-bearing origin-form Host were measured by hand after the first
attempt dropped both. It asserts the request
line **and** the Host the backend received, because the report's own capture
shows the path was always right — only checking the status would have seen
nothing. Against a binary built from the audited source the check fails; the six
existing absolute-form rows pass on both.

### One thing found beside it, not mine

The suite footer printed `run_tests.sh 16000000 file`. A `set --` in the h3
upload loop of `35-uploads.sh` overwrites the shard's positional parameters —
the same trap audit-report-70 hit in a check I had just written, here sitting in
committed code since before this series. It is one line, it makes the suite's
own instructions wrong, and it is fixed with the reason recorded.

Full suite **1175 passed, 0 failed**.

## Verification (resolution)

Reproduced against a live front on the audited binary with a head-echoing
backend, on the HTTP/1 leg and on `proxy_h2` with the fixture reporting
`:authority`, and re-measured after the change on both. Origin-form and
HTTP/1.0-without-Host were checked explicitly, because the fix rewrites a field
on every proxied request rather than only on absolute-form ones.
