# Exact PDF candidate confirmation ingress limit

Status: local design before implementation. No live configuration or listener
changes are authorized by this document.

Extend each server's `body_limits` array to contain up to two distinct,
explicit route rules:

```json
[
  {"method":"POST","path":"/projects/{project_id}/source","max_body":16777216},
  {"method":"POST","path":"/projects/{project_id}/pdf-candidate-confirmations","max_body":262144}
]
```

Either rule may appear alone; duplicates and any other method or template
fail config validation. The source cap remains at most 16,777,216 bytes; the
confirmation cap remains at most 262,144 bytes. The path template uses the
same strict project ID alphabet as the existing source rule and rejects
queries, percent escapes, malformed IDs, and extra path segments. Each
protocol selects a rule only after validating the request authority for the
server, before checking Content-Length, accepting DATA, granting a larger H3
flow window, or writing a spill file. Nonmatching paths keep the location or
global cap, which is 12,288 bytes in the Vefruna deployment.

Acceptance: config parse tests for both orders, either rule alone, duplicates,
unsupported keys/templates and over-cap values; pure predicate tests; H1/H2/H3
fixture probes for 12,289-byte confirmation acceptance, 262,144-byte
acceptance, 262,145-byte 413, source route regression, adjacent route/method/
path variants at 12,289 bytes, and coalesced authorities where configured.
The isolated fixture uses an absent backend, so accepted requests yield 502.
No production deployment or Peacock publication follows from these tests.
