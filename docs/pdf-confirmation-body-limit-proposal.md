# Exact PDF candidate confirmation ingress limit

Status: implemented in an isolated Linnea branch and tested locally. No live
configuration, listener, or installed binary was changed by this work.

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

The prepared production config diff adds one object after the existing source
rule on the Vefruna HTTPS server, with `method: POST`, `path:
/projects/{project_id}/pdf-candidate-confirmations`, and `max_body: 262144`.
The global and Vefruna `/` location caps remain 12,288 bytes. The live source
rule remains 16,777,216 bytes. A temporary validation copy can replace the
protected live spill/log paths with `/tmp` paths while retaining the server
and body-limit JSON; do not deploy that test copy.

Rollback for a later approved deployment: restore the pre-change Linnea binary
and config backup together, validate that backup with `linnea --test`, and
restart Linnea so the restored binary and all HTTP/3 workers use the old
one-rule configuration. Recheck source ingress and the ordinary cap on the
confirmation route. Keep Vefruna's receipt API inaccessible through the
public proxy until a compatible exact-route Linnea version is active.
