# HTTP/3 exact route body cap design

Status: implemented and tested on Linnea master; deployed for Vefruna's exact
source-upload rule on 2026-09-28 with HTTP/3 enabled.
The startup guard was removed after the exact-route HTTP/3 protocol probe,
same-certificate authority and spill-size checks, and existing HTTP/3 body
regression checks passed. `http3: 0` remains a supported explicit setting.
Run `make pdf-h3-route-test` for the repeatable isolated acceptance fixture.

## Proposed internal interface (2026-09-28)

The implementation adds a callback to `linnea_h3_walk` which fires once after the first complete
HEADERS field section has been accumulated, before the walker enters DATA.
The callback receives the field section and its reassembly context, decodes it
with the existing bounded QPACK decoder into worker scratch, validates the
request, resolves `:authority` against the certificate, normalizes the path for
location matching, and selects a per-stream body cap. Its result is stored in
`linnea_quic_ra.max_body`; no decoded request pointers survive the callback.
The existing final decode still builds the full request for serving. QPACK's
current implementation requires Required Insert Count zero, so decoding the
same field section a second time does not advance a dynamic table. The
callback returns existing H3 error codes for malformed fields or oversized
field sections. Incomplete HEADERS keep only the initial small flow window;
the larger upload window is granted only after the callback succeeds.

The one-packet path uses the same cap selection on its decoded request before
body or route dispatch. The selected cap uses the validated serving vhost's
matching location and the exact raw method/path predicate. An unknown
authority can use the SNI vhost's ordinary cap, but cannot receive the scoped
source cap. The callback does not change config schema or public APIs.

## Previous sequence

Previously, when a QUIC request stream was allocated, `linnea_quic_server.asm`
set `linnea_quic_ra.max_body` to the largest body cap on the SNI vhost and any
coalescible same-certificate vhost. The walker held the first HEADERS field
section until the complete request was served. The body sink could write DATA
to a spill file before QPACK decoding, authority validation, and route
selection. A later route check could reject an adjacent request only after
oversized bytes had already been buffered. The one-packet path also used the
vhost maximum before selecting the route. Both paths now choose the cap from
validated headers before accepting the larger body.

## Required boundary

The first complete HEADERS section must be decoded and validated per stream
before DATA can be written or large flow credit granted. Keep a bounded
per-stream copy of the raw `:method`, raw `:path`, and `:authority` (or a
validated, stable request snapshot); the existing QPACK output and request
scratch are shared across streams. Resolve authority against the connection's
certificate before deciding which server's rule applies. Run the exact raw
method/path predicate, then store the selected cap in that stream's reassembly
context. DATA arriving in the same packet after HEADERS must wait for this
decision. Fragmented or QPACK-blocked HEADERS may not grant the larger cap.
The first accepted DATA byte and every later write must use the selected cap,
with subtraction before addition to avoid length overflow. Preserve the
Content-Length reconciliation and the 413/421/431/malformed-QPACK responses.

An implementation may stage a small bounded amount of DATA while HEADERS are
incomplete, but it must keep that amount under the ordinary cap and must not
open or write a spill file above that cap. Flow control must not deadlock a
client whose HEADERS require dynamic QPACK table updates on another stream.

## Protocol acceptance tests

- Valid upload at cap and cap plus one; adjacent route, wrong method, query,
  percent-encoded path, malformed project ID, and unknown authority at the
  ordinary cap. Repeat with and without Content-Length.
- HEADERS and DATA in one QUIC packet, in separate packets, fragmented across
  packets, and reordered. Confirm no over-limit DATA reaches the spill sink.
- Invalid dynamic QPACK references cause a connection-level decompression
  error. Linnea advertises dynamic-table capacity zero, so valid blocked
  field sections cannot occur under the current settings.
- Same-certificate coalesced origins, unknown SNI, and mismatched authority;
  the selected cap must belong to the validated serving vhost.
- Single-packet fast path and reassembled/spill path must agree on each status.
  Existing H3 proxy, framing, flow-control, and hot-reload suites must pass.

The global `http3: 0` control stays available for deployments that choose it;
the exact-route rule no longer requires it.

`make pdf-h3-route-test` runs the isolated exact-route acceptance fixture at
small caps. It covers one-datagram and separated HEADERS/DATA, fragmented
HEADERS, cap and cap-plus-one, no Content-Length, route variants, malformed
project IDs, invalid QPACK references, same-certificate origin coalescing,
and an adjacent-route capture bound. The full `make test` suite passed 1,270
checks after the implementation. Live configuration and external ingress
verification remain separate deployment work.
