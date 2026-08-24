# Audit Report 44

Audited at `35c9416`, 2026-08-24.

Audit report 43's malformed-trailer fix is present, and informational blocks
before a final response are now handled correctly. One response-ordering gap
remains in that classifier:

1. **Low: a `1xx` HEADERS block received after the final response is accepted
   as informational, so DATA after the malformed block can complete the
   response.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — post-final informational responses are accepted

Severity: **Low (P3, malformed-upstream acceptance and response-ordering
violation)**  
Confidence: **High**  
Status: **Confirmed as filed** (see Resolution). Fixed, together with two more
malformed sequences the same classifier accepted — one of which silently
corrupted the response body.

HTTP/2 permits zero or more informational response HEADERS blocks before one
final response, followed optionally by a trailer section. Once the final
response has been received, a later HEADERS block is a trailer section; it
cannot become a new informational response. The backend classifier receives a
`have-final-head` flag, but checks the decoded status for `100..199` before it
checks that flag
([src/server/linnea_h2_client.asm:1909](/home/linnea/linnea/src/server/linnea_h2_client.asm:1909)
through [:1962](/home/linnea/linnea/src/server/linnea_h2_client.asm:1962)).

Consequently, after `hdr_done` is set, a later block containing
`:status = 103` is still classified as informational. With no END_STREAM on
that block, the classifier restores the already accepted final response and
returns the informational result
([src/server/linnea_h2_client.asm:1947](/home/linnea/linnea/src/server/linnea_h2_client.asm:1947)
through [:1957](/home/linnea/linnea/src/server/linnea_h2_client.asm:1957)). The
resumable dispatcher treats that result as harmless and continues receiving
([src/server/linnea_h2_client.asm:2428](/home/linnea/linnea/src/server/linnea_h2_client.asm:2428)
through [:2438](/home/linnea/linnea/src/server/linnea_h2_client.asm:2438)).

The following DATA is then accepted and can carry END_STREAM
([src/server/linnea_h2_client.asm:2463](/home/linnea/linnea/src/server/linnea_h2_client.asm:2463)
through [:2493](/home/linnea/linnea/src/server/linnea_h2_client.asm:2493)).
The proxy therefore relays the original final status and the concatenated body,
even though a pseudo-header appeared in a post-final trailer block and DATA
arrived after it. The blocking helper has the same classification order and
therefore accepts the same sequence
([src/server/linnea_h2_client.asm:1202](/home/linnea/linnea/src/server/linnea_h2_client.asm:1202)
through [:1221](/home/linnea/linnea/src/server/linnea_h2_client.asm:1221)).

### Reproduction

Have a `proxy_h2` backend send this stream-1 sequence:

```text
HEADERS  :status = 200, END_HEADERS
DATA     "body", no END_STREAM
HEADERS  :status = 103, link = </late>, END_HEADERS, no END_STREAM
DATA     "more", END_STREAM
```

The third frame is not a legal informational response: informational responses
must precede the final response, and a trailer section cannot contain a
pseudo-header. The current driver nevertheless drops the `103` block as if it
were an allowed early response, accepts the final DATA, and produces a 200
response with `bodymore`. A malformed backend response should instead fail at
the post-final HEADERS block.

This is not a client-controlled cross-request disclosure: the backend leg is
single-stream and the response body remains explicitly framed by DATA. It is
still inconsistent with the project's stated policy of refusing malformed
upstream responses
([docs/security.md:24](/home/linnea/linnea/docs/security.md:24)
through [:30](/home/linnea/linnea/docs/security.md:30)), and it leaves the
driver accepting a response sequence that downstream clients cannot represent
faithfully.

### Recommended fix

Check the final-response state before the informational-status branch. If the
final response is already present, classify every later completed block as a
trailer; then require no pseudo-headers and END_STREAM as report 43's fix does.
Only classify `100..199` as informational while no final response head has
been accepted. Apply the same rule in the blocking helper through the shared
classifier.

Add a fixture route with a final response followed by a `103` block and DATA,
and assert a gateway failure from H1, H2, and H3 frontend clients. Follow it
with an independent request to verify that rejecting the malformed backend
stream does not wedge the front. Retain `/interim` and `/interim-two` as
controls for legal informational responses before the final head.

## Verification

The finding is a source-level trace through the shared block classifier, the
resumable dispatcher, and the blocking backend-H2 oracle. `make -j4` completed
with no work required. Existing informational coverage exercises only 1xx
blocks before the final response
([test/h2/h2c_server.py:323](/home/linnea/linnea/test/h2/h2c_server.py:323)
through [:336](/home/linnea/linnea/test/h2/h2c_server.py:336)); it has no
post-final 1xx case. Runtime socket reproduction was not available in this
restricted environment, and no source change was made that required executable
verification.

## Resolution (2026-08-24) — CONFIRMED as filed; two more of the same family fixed alongside

### The finding reproduces exactly

At `35c9416`, the report's own sequence, on both the resumable driver and the
blocking oracle, and end to end through a `proxy_h2` front:

```
/interim-late    HEADERS :status=200, END_HEADERS
                 DATA "body", no END_STREAM
                 HEADERS :status=103, link: </late>, END_HEADERS, no END_STREAM
                 DATA "more", END_STREAM

HTTP/1.1 200 OK
content-length: 8
bodymore
```

The classifier asked *"is this block 1xx?"* before it asked *"has the final
response already arrived?"*, so a post-final `103` was dropped as though it were
an early response and the DATA behind it completed the exchange.

### The fix

The two questions swap places. Once the final head is in, **every** later block
is a trailer section — an informational response cannot follow the response it
informs about — so a late 1xx now meets the trailer rule, which admits no
pseudo-header, and is refused. `100..199` is only informational while no final
head has been accepted. The blocking oracle shares the classifier and follows.

The order of those two questions **is** the rule: what a block may be depends on
what has already arrived, not only on what is inside it. That is the same
mistake report 43 fixed from the other side, where "later block" was read as
"trailer" without asking whether it might be informational.

### Two more of the same family, not filed

Probing the rest of the classifier's state space rather than only the reported
case turned up two more malformed sequences it accepted. **These are beyond what
the report asked for**; both are one-line rules in the same function, and both
are recorded here so the change is reviewable as what it is.

```
/no-status    a response header section with NO :status
              -> HTTP/1.1 000 Status, content-length 8, "nostatus"

/data-first   DATA before any response header block
              -> HTTP/1.1 200 OK, content-length 9, "earlylate"
```

The first is caught downstream — the shared upstream-head validator refuses a
status below 100 — so end to end it was already a 502. It is fixed in the driver
anyway, because the driver has callers that do not run that validator, and
because "something else notices" is not the same as "refused". Notably, this is
the exact output audit-report-42 predicted for its own finding: `HTTP/1.1 000
Status`. It was the right symptom attached to the wrong cause.

The second is caught nowhere. DATA arriving before the response head was
appended to the body, so bytes that preceded the head were **prepended to what
the client received, under a 200** — a silently corrupted body rather than a
refused response. A response header section must now carry a `:status` in
`200..599` (1xx having already been routed away), and DATA before the head fails
the exchange.

### The classifier's state space, now enumerated

Three consecutive reports have found one hole each in this one function, so
here is the whole table rather than the next hole:

| block / frame | before the final head | after it |
|---|---|---|
| `1xx` HEADERS | informational: dropped, keep reading | **refused** (trailer, pseudo-header) |
| `1xx` with END_STREAM | **refused** | **refused** |
| `200..599` HEADERS | the response header section | **refused** (trailer, pseudo-header) |
| no `:status` | **refused** | **refused** (trailer rules apply) |
| no pseudo-header, END_STREAM | *(not the head: refused)* | a trailer section: dropped, response complete |
| no pseudo-header, no END_STREAM | *(not the head: refused)* | **refused** |
| DATA | **refused** | body |

Every cell is a check in the tls shard or a case in `test/h2/h2c_server.py`.

### Coverage

`test/h2/h2c_server.py` gains `/interim-late`, `/no-status` and `/data-first`.
Six new checks in the tls shard, against a binary built from the audited source:

```
pre-fix: a 1xx block after the final response is refused (h1 client)     FAIL
pre-fix: a 1xx block after the final response is refused (h2 client)     FAIL
pre-fix: a 1xx block after the final response is refused (h3 client)     FAIL
pre-fix: a response header block with no :status is refused              FAIL
pre-fix: DATA before the response head is refused, not prepended         FAIL
pre-fix: a refused post-final 1xx leaves the next request working        FAIL  (200 then 200)
```

All six fail at `35c9416` and pass after. `/interim` and `/interim-two` stay as
controls for legal informational responses, as the report asks, and `/status/204`,
`/status/404`, `/status/500` and `/status/599` were checked by hand so the new
status-range rule cannot be a rule against ordinary non-200 responses.

tls shard **247 passed, 0 failed**; full suite **833 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the resumable driver, on the blocking oracle, and end to end through
a real `proxy_h2` front from HTTP/1.1, HTTP/2 and HTTP/3 clients. The pre-fix
control identifies which rows the fix is responsible for. The two unfiled cases
were found by walking the classifier's state space, not by reading the report.
