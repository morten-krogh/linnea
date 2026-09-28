# Exact route request-body limits (proposal)

Status: implemented locally for HTTP/1 and HTTP/2 with an explicit global
HTTP/3 opt-out requirement. Not merged or deployed. Exact HTTP/3 enforcement
remains proposed.

Location `max_body` currently applies to the longest matching path prefix on
HTTP/1, HTTP/2, and HTTP/3. It cannot express a larger cap only for
`POST /projects/{id}/source`: a `/projects/` override also widens every other
project route, and a `/` override widens the entire Vefruna host.

Initial server-level `body_limits` array (currently one supported rule):

```json
"body_limits": [
  { "method": "POST", "path": "/projects/{project_id}/source",
    "max_body": 16777216 }
]
```

The `path` is a restricted template, not a general regular expression.
`{project_id}` matches exactly 34 ASCII characters: `project_` followed by 26
characters in Vefruna's lowercase project ID alphabet. The first encoded
character is restricted to `0`–`7`. There is no slash, query,
percent-decoding, or alternate target form.
The rule applies only to the named server's exact hostname and method. The
effective cap is the matching rule's `max_body`; otherwise the existing
location/global cap applies. Duplicate matching rules are rejected at config
parse time. Unsupported template syntax is rejected rather than treated as a
prefix match. The initial implementation accepts exactly one rule and caps its
`max_body` at Vefruna's 16,777,216-byte source-store limit.

Acceptance requires the same limit decision before body buffering on HTTP/1,
HTTP/2, and HTTP/3, including chunked/unknown-length streams and declared
`Content-Length`. Test exact 16 MiB acceptance and 16 MiB plus one byte `413`
on the upload route, and 12 KiB plus one byte `413` on adjacent project routes,
wrong methods, malformed project IDs, and other hosts. Preserve existing
location `max_body` behavior for configurations without `body_limits`.

Implementation is more than a location match change. HTTP/1 checks counted
bodies in `linnea_http.asm` and chunked capture in `linnea_spill.asm`. HTTP/2
checks declared lengths and arriving DATA in `linnea_http2.asm`. HTTP/3's QUIC
reassembly assigns `linnea_quic_ra.max_body` from the **largest cap on the SNI
vhost before QPACK decodes the method or path**, then may write DATA to a spill
file before `linnea_http3.asm` routes the request. An exact limit enforced only
in the HTTP/3 router would already have buffered an over-limit adjacent route.
The HTTP/3 path must decode and retain enough request headers before allowing
large body capture, or hold initial DATA under the default cap until it can
select the scoped limit. This change needs protocol-specific regression tests
for requests that send HEADERS and DATA in one packet and in separate packets.

The isolated branch now parses this one rule strictly and applies it before
HTTP/1 counted and chunked capture and HTTP/2 declared and DATA capture. The
method/path predicate reads the raw request target, so a query or percent
escape cannot gain the larger cap through routing normalization. Other rules
and multiple elements are rejected at startup. HTTP/3 exact-route enforcement
remains unresolved. Startup rejects a config containing `body_limits` unless
top-level `http3` is explicitly `0`. The global opt-out affects every host
served by that Linnea process, so deployment requires an explicit decision.
HTTP/3 otherwise keeps its previous default.

`test/pdf_source_body_limit.py` is a standalone HTTP/1 acceptance probe for an
isolated Linnea instance with the proposed Vefruna rule. It checks counted and
chunked source uploads above the ordinary cap, adjacent routes, wrong method,
malformed ID, query, percent escape and extra path, plus an oversized declared
source body without sending that body. `test/pdf_source_body_limit_h2.py` checks
HTTP/2 declared and no-Content-Length DATA paths, including adjacent routes
and path variants. `test/pdf_body_limits_config.py` checks accepted/rejected
config shapes. All passed against isolated local fixtures with an absent test
backend. `test/pdf_source_body_limit_fixture.py` runs both probes on isolated
instances with a 16 KiB scoped cap so exact-cap and cap-plus-one cases are
cheap to repeat. It confirms `http3: 0` leaves the TLS UDP port unbound and omits
`Alt-Svc` from HTTP/1.1 and HTTP/2 responses. An exact-route HTTP/3 probe
remains to be implemented with that feature.

A pure exact-route predicate exists in
`src/lib/linnea_pdf_source_route.asm`, with `make pdf-route-test` covering
method, path suffix, query, project ID alphabet and length, and the all-zero
identifier. The HTTP/1 and HTTP/2 handlers call it before body capture.

The interim control is top-level `http3: 0`, documented in
`docs/design/http3-opt-out.md`. It suppresses the QUIC listener and Alt-Svc
for the entire process. A hot reload can leave old workers' UDP listeners
active until they drain; a full stop and restart is required for immediate
exclusion. No live configuration has been changed here.
