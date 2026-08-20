# Audit Report 28

Audited at `5c39ab8`, 2026-08-20.

**Fixed in `a713363`**, verified against a pre-fix binary. The sharper
statement of the finding: one message written the two legal ways got two
different answers from one parser — `chunked, chunked` on one line was `501`
while the same thing on two lines was `200` and the body was decoded and routed.

One HTTP/1 request-framing gap remains open:

1. **Medium: repeated `Transfer-Encoding: chunked` request fields are accepted
   as one coding.** Repeated list-valued fields combine in order, so this is the
   forbidden chain `chunked, chunked`, not a harmless duplicate.

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — The request parser does not count `chunked` codings

Severity: **Medium (P2, malformed request framing accepted)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

The HTTP/1 request parser processes each `Transfer-Encoding` field line in
isolation. At [src/server/linnea_http.asm:1479](/home/linnea/linnea/src/server/linnea_http.asm:1479),
an exact `chunked` value only sets bit 4 in the framing word:

```asm
.te_header:
    ...
    call linnea_string_iequal
    test eax, eax
    jz .te_unsupported
    or qword [rsp + 136], 4
```

There is no counter or “already saw chunked” check. The later framing test at
[src/server/linnea_http.asm:1543](/home/linnea/linnea/src/server/linnea_http.asm:1543)
through [:1551](/home/linnea/linnea/src/server/linnea_http.asm:1551) detects
only the `Content-Length` plus `Transfer-Encoding` combination; a second
`chunked` field leaves the same bit set and reaches the ordinary chunk decoder.

HTTP list fields are combined in field-line order. Thus this request declares
`Transfer-Encoding: chunked, chunked`:

```text
POST /api/echo HTTP/1.1\r\n
Host: one.test\r\n
Transfer-Encoding: chunked\r\n
Transfer-Encoding: chunked\r\n
\r\n
4\r\nbody\r\n0\r\n\r\n
```

`chunked` may not be applied more than once. Linnea accepts the request,
decodes one layer, and routes the resulting body. The equivalent response-side
problem was identified and fixed in audit-report-13; its request-side parser
does not share that duplicate-coding guard.

### Impact

The listener accepts malformed message framing that a front proxy, WAF, or
other intermediary can reject or interpret as two transfer codings. That
creates an avoidable request-boundary differential. Although Linnea de-chunks
before proxying upstream, accepting the malformed outer request is enough for
an adjacent hop to disagree about whether the bytes constitute a valid request
and where a subsequent request begins.

### Recommendation

Count transfer codings across all `Transfer-Encoding` field lines, or parse the
combined list once. Reject a second `chunked` coding with 400 before invoking
either request chunk decoder. Preserve one exact `chunked` field as the valid
control and continue rejecting `Content-Length` plus any transfer coding.

Suggested regression coverage:

* Two `Transfer-Encoding: chunked` lines and `Transfer-Encoding: chunked,
  chunked` must return 400 and close.
* One `chunked` field remains accepted.
* Run each case below and above `LINNEA_CONN_IN_BUF`, so `chunked_decode` and
  `linnea_spill_chunked` cannot drift.
* Include `gzip, chunked` and `chunked, gzip` controls to confirm unsupported
  coding remains 501 rather than accidentally becoming a framing acceptance.

### Resolution — FIXED (2026-08-20)

Confirmed exactly as filed. The whole table, before:

```
  one chunked              200 OK                 <- the control
  two chunked lines        200 OK                 <- accepted, decoded, routed
  chunked, chunked         501 Not Implemented
  chunked then gzip        501 Not Implemented
  gzip then chunked        501 Not Implemented
  gzip, chunked            501 Not Implemented
  chunked, gzip            501 Not Implemented
  chunked + Content-Length 400 Bad Request
```

Repeated field lines are one comma-separated list in order (RFC 9110 5.3), so
rows two and three are **the same message**. The parser answered them
differently because it compared the whole field value against `chunked` and
never counted anything: one line was "a coding we cannot do", two lines were two
independent sightings of a coding we can.

The value is now walked as the list it is. Each element is OWS-trimmed and
compared; a second `chunked` sets a distinct flag, and that flag is a `400`
after the `501` check, because chunked applied twice is not an unimplemented
coding but an invalid message. After:

```
  one chunked              200 OK                 <- unchanged
  two chunked lines        400 Bad Request        <- was 200
  chunked, chunked         400 Bad Request        <- was 501, now agrees
  chunked then gzip        501 Not Implemented    <- unchanged
  gzip then chunked        501 Not Implemented    <- unchanged
  gzip, chunked            501 Not Implemented    <- unchanged
  chunked, gzip            501 Not Implemented    <- unchanged
  chunked + Content-Length 400 Bad Request        <- unchanged
```

The two spellings now agree, which is the property that was actually missing;
every unsupported-coding row keeps its `501`, as the report asks.

### The other three protocols, checked rather than assumed

* **The response side is already closed** and the report is right about where:
  `linnea_http_upstream_head_valid` counts `Transfer-Encoding` lines and
  requires the coding list to be exactly `chunked`, naming `chunked, chunked` in
  its own comment (audit-report-13). Only the request side lacked it.
* **HTTP/2 and HTTP/3 never reach this question.** `Transfer-Encoding` is a
  connection-specific field, which RFC 9113 8.2.2 and RFC 9114 4.2 make
  malformed outright; `linnea_hpack.asm` and `linnea_qpack.asm` both carry it in
  that list. So this was h1-only by construction, not by oversight.

### Coverage

`test/upload_chunked.py telist` drives all nine rows above at both body sizes,
so the head-level verdict cannot come to depend on which decoder would have read
the body. On a pre-fix binary it reports:

```
two chunked lines (buffered): b'HTTP/1.1 200 OK', wanted 400
```

Full suite: **778 passed, 0 failed**.

### Two things this cost, both worth writing down

**A control run that passed because the wrong binary was answering.** The first
`telist` control reported `OK` against what I believed was the pre-fix build.
The rig's previous server was still holding the port, so the new one never
bound and the *fixed* binary answered both halves of the A/B. The fix is to
confirm which build is serving before trusting either half — the raw probe
prints the whole table, and `two chunked lines` tells you immediately which one
you are talking to.

**A helper that silently reset the socket timeout.** The new case sends the head
and waits briefly to see whether the server answers before sending a body, since
every verdict here is reached from the head and a body still going out during a
refusal draws an RST that discards the response. Passing a 1 s timeout and then
calling `read_response` did not do that: `read_response` sets its own 20 s
timeout, so the wait ran past the server's body clock and the valid row came
back `408` instead of `200`. The wait is a bare `recv` now.

## Verification

No executable tests were run: this report makes no source change. The finding
is a source trace from per-line parsing through the sole request framing test.

## Conclusion

The server enforces `Content-Length`/`Transfer-Encoding` exclusivity, but it
does not enforce the single-use rule for `chunked` across repeated transfer
coding fields. Parsing the combined coding list closes that remaining request
framing differential.

It does now, and the shape is one this tree has met before: a rule written
against the field VALUE when the field is a LIST, so the same message said two
ways got two answers. `Content-Length` was already counted; `Transfer-Encoding`
was compared. **Ask of any field rule whether the field is a list, and whether
repeating the line is a legal way to say the same thing** — where it is, a rule
that never counts cannot be right.
