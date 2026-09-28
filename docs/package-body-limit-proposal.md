# Exact pattern package ingress limit

Status: proposal for the Vefruna first private Peacock reader flow. This
document records the shared Linnea configuration contract before code changes.

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
