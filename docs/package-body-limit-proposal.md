# Exact pattern package ingress limit

Status: documented before implementation, merged to Linnea main, and deployed
on 2026-09-28. The installed binary SHA-256 is
`4d43b6d3330057bcc3351a2a095a25993a869f8ec300c302472362c2a85a0b23`;
the installed config SHA-256 is
`3967257b54a485d382d7a9b425decde19281772187826fc6b88a7074321f9cbe`.
The matched rollback files are
`/usr/local/bin/linnea.pre-20260928-package-route` and
`/etc/linnea/linnea-tls.json.pre-20260928-package-route`.

Add a third optional `body_limits` rule for `POST
/projects/{project_id}/pattern-package`, with a maximum configured cap of
16,777,216 bytes. The deployment will use that cap. The existing source rule
retains its 16,777,216-byte ceiling, the PDF candidate confirmation rule its
262,144-byte ceiling, and unrelated requests the location's 12,288-byte cap.
Rules may appear in any order, each at most once. Other templates, methods,
duplicate rules, and caps above the route ceiling fail config validation.

The route predicate must match the same strict project ID syntax as the two
existing exact rules, and reject malformed IDs, queries, extra path segments,
and other methods. H1, H2, and H3 select the cap before accepting request body
data. An accepted request still goes to the existing application API; Linnea
does not alter package validation or publication state.

Acceptance: parser and predicate tests, plus isolated ingress probes on H1,
H2, and H3 where available. Probe the exact route at cap and cap-plus-one,
and an adjacent route above the ordinary cap. Production configuration adds
only the exact package rule to the Vefruna HTTPS server. Release requires a
matched binary/config backup, `linnea --test`, service restart, and live
probes. The code and config can be rolled back together.

The focused `make pdf-confirmation-ingress-test` suite passed parser,
predicate, and isolated HTTP/1.1, HTTP/2, and HTTP/3 boundary/adjacent-route
probes. The new binary validated the exact production config before install.
The broader `make test` run was interrupted after its TLS shard ran for more
than eight minutes without completion; an initial sandboxed run had unrelated
network-fixture failures. After deployment, fake-project requests of 12,289
bytes returned app HTTP 400 on the package, source, and confirmation routes
and Linnea HTTP 413 on the adjacent notes route, over all three protocols.
The authenticated private Peacock package attachment and reader journey
passed separately. HTTP/3 remains enabled. The Vefruna app's PDF import
semantics and package validation are unchanged by this ingress rule.
