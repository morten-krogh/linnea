# Exact route request-body limits (proposal)

Status: proposal only. No parser, routing, or deployed configuration change.

Location `max_body` currently applies to the longest matching path prefix on
HTTP/1, HTTP/2, and HTTP/3. It cannot express a larger cap only for
`POST /projects/{id}/source`: a `/projects/` override also widens every other
project route, and a `/` override widens the entire Vefruna host.

Proposed server-level `body_limits` array:

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
parse time. The feature must reject unsupported template syntax instead of
falling back to a prefix match.

Acceptance requires the same limit decision before body buffering on HTTP/1,
HTTP/2, and HTTP/3, including chunked/unknown-length streams and declared
`Content-Length`. Test exact 16 MiB acceptance and 16 MiB plus one byte `413`
on the upload route, and 12 KiB plus one byte `413` on adjacent project routes,
wrong methods, malformed project IDs, and other hosts. Preserve existing
location `max_body` behavior for configurations without `body_limits`.

This proposal needs Linnea owner review before implementation because it
changes shared configuration syntax and all three public request paths.
