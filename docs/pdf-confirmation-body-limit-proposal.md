# Exact PDF candidate confirmation ingress limit

Status: implemented on Linnea main, tested locally, and deployed on
2026-09-28 at 13:11:50 UTC. The deployed binary SHA-256 is
`6c7eb9302c5a7982e16832d4943938c87b65145059d16f3ba2216662839cade7`;
the config SHA-256 is
`e4358d0f7a0259de3aa1ef937f89c0e5a76fcc3a32281df54737529b99a57d9f`.
The Vefruna confirmation API was deployed later on 2026-09-28. Peacock
remains unpublished.

Live fake-project probes after reload exercised HTTP/1.1, HTTP/2, and HTTP/3
(the latter negotiated ALPN `h3`). The exact confirmation route returned 413
at 262,145 bytes and 502 at the 262,144-byte boundary; the adjacent notes
route returned 413 at 12,289 bytes and the source route returned 400 at that
size. The 502 showed the ingress accepted the body but the older deployed app
did not complete it. After the Vefruna app release at 13:18:34 UTC,
fake-project probes at 262,144 bytes no longer returned 502 on HTTP/1.1,
HTTP/2, or HTTP/3. The 262,145-byte request still returned 413. An
authenticated Vefruna API smoke test is still pending.

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

The deploy kept `/usr/local/bin/linnea.pre-20260928-pdf-confirm` and
`/etc/linnea/linnea-tls.json.pre-20260928-pdf-confirm` as a matched rollback
pair. To roll back, restore both, validate with `linnea --test`, restart
Linnea so the restored binary and all HTTP/3 workers use the old one-rule
configuration, and recheck source ingress and the ordinary cap on the
confirmation route. The Vefruna receipt API must not be deployed with that
older ingress pair.
