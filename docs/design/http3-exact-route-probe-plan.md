# HTTP/3 exact-route acceptance probe plan

Status: test requirements only. These probes run against an isolated Linnea
instance after the HTTP/3 `body_limits` startup guard can be removed. They do
not authorize a live config change.

The existing `test/pdf_source_body_limit_h3.py` checks ordinary and source
caps, route variants, and HEADERS/DATA in one datagram or separate sends. Add:

1. Fragment the HEADERS frame header and QPACK field block at several byte
   boundaries. Send DATA before the final HEADERS bytes only where QUIC stream
   ordering still produces a valid H3 request. Compare the response to the
   unsplit request for source and adjacent routes, with and without
   Content-Length. A reassembled request must never gain the source cap until
   the complete field section is decoded.
2. Linnea advertises QPACK dynamic-table capacity zero and rejects nonzero
   Required Insert Count, so a conforming client cannot create a blocked
   field section. Send a malformed dynamic reference in first HEADERS, with
   DATA following, and require the RFC 9204 connection-level decompression
   error without a source-cap grant. If Linnea later permits dynamic QPACK entries, add
   a real blocked-stream/unblock case before removing the route guard.
3. Connect with one SNI name, then send requests for two configured vhosts
   sharing the same certificate. Give only one vhost the source rule. The same
   path must use that vhost's cap, regardless of SNI and request order. An
   authority outside the certificate must get 421 or an explicit rejection
   without gaining either vhost's source cap.
4. For an over-ordinary adjacent route, keep the request stream open while
   inspecting the worker's anonymous capture-file descriptors. No observed
   capture file may grow beyond the ordinary cap. A final 413 alone is
   insufficient evidence because it may arrive after oversized data was
   written. The descriptor sampler can miss a very short-lived write, so a
   source-level boundary review remains necessary before removing the guard.

Probe prerequisites must be explicit: H3 enabled, `body_limits` accepted, a
known absent backend (accepted bodies yield 502), two vhosts with a shared
certificate for the coalescing case, and a worker PID plus a unique spill
directory marker for capture inspection. The coalesced and capture checks
are enabled by `LINNEA_H3_COALESCED_AUTHORITY`, `LINNEA_H3_WORKER_PID`, and
`LINNEA_H3_SPILL_MARKER` respectively.
Until those are available, the tests remain standalone acceptance probes and
must not be put in the passing suite or reported as deployed coverage.
