# Audit Report 14

Audited at `0f9d6ac` (`audit-report-13: both findings FIXED`), 2026-08-19.

**Both findings are fixed in `aacd172`**, verified against a pre-fix binary on
all three protocols. Finding 1 is a regression from report 10's own fix and is
owned as such below; fixing it took two changes rather than one, and the second
only became visible because the first was A/B'd rather than assumed.

Two upstream-response translation issues remain open:

1. **High: a `Connection` option can hide `Transfer-Encoding` from HTTP/1's
   framing parser.** HTTP/1 relays the raw chunk syntax as a close-delimited
   body, while HTTP/2 and HTTP/3 correctly de-chunk the same upstream response.
   Naming both `Transfer-Encoding` and `Content-Length` makes HTTP/1 serve it
   while the binary-protocol paths reject the framing conflict.
2. **Medium: HTTP/2 and HTTP/3 re-encode HTTP/1 optional whitespace as part of
   a downstream field value.** A valid HTTP/1 field such as
   `X-Note:\tvalue\t` becomes an invalid HTTP/2 field value; HTTP/3 also
   preserves bytes that are HTTP/1 framing whitespace rather than the field
   value.

No production source, configuration, or test files were changed in this audit.
Only this report was added.

This is a source-trace audit against the stated baseline. The reproduction
sections give exact backend fixtures and the control-flow outcomes they reach;
they are not presented as captures from a modified test backend.

## Finding 1 — Connection-option filtering runs before HTTP/1 reads response framing

Severity: **High (P1, response framing integrity and protocol consistency)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

`Connection` says which fields are specific to the immediate upstream hop; it
does not erase the semantics those fields have *on that hop*. RFC 9110 section
7.6.1 specifically lists `Transfer-Encoding` among fields an intermediary
should remove or replace after applying their semantics. Thus an upstream is
allowed to send the ordinary HTTP/1 pair:

```text
Connection: Transfer-Encoding
Transfer-Encoding: chunked
```

Linnea's HTTP/1 rewriter walks each field only once. It first removes the
fixed hop-by-hop fields at
[src/server/linnea_http.asm:4046](/home/linnea/linnea/src/server/linnea_http.asm:4046)
through [:4056](/home/linnea/linnea/src/server/linnea_http.asm:4056), then
removes every field named by `Connection` at
[:4057](/home/linnea/linnea/src/server/linnea_http.asm:4057) through
[:4092](/home/linnea/linnea/src/server/linnea_http.asm:4092). Only *after*
that early exit does it identify `Content-Length` or `Transfer-Encoding` and
set its private framing flags at [:4093](/home/linnea/linnea/src/server/linnea_http.asm:4093)
through [:4124](/home/linnea/linnea/src/server/linnea_http.asm:4124).

Consequently, a `Transfer-Encoding` field named in `Connection` is correctly
omitted from the downstream head but is incorrectly omitted from HTTP/1's own
upstream framing decision as well. The final response has neither local flag,
so the path selects `.until_eof` rather than its chunk decoder. It sends the
chunk size lines and terminator as ordinary response content, then closes the
downstream connection.

HTTP/2 and HTTP/3 have the opposite ordering. Both locate
`Transfer-Encoding` directly from the received head before their emitters
remove `Connection`-nominated fields:

- HTTP/2 chooses chunked framing at
  [src/server/linnea_http2.asm:4008](/home/linnea/linnea/src/server/linnea_http2.asm:4008)
  through [:4024](/home/linnea/linnea/src/server/linnea_http2.asm:4024), then
  drops a named field only while emitting at [:4562](/home/linnea/linnea/src/server/linnea_http2.asm:4562)
  through [:4571](/home/linnea/linnea/src/server/linnea_http2.asm:4571).
- HTTP/3 makes the same framing choice at
  [src/server/linnea_h3_proxy.asm:643](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:643)
  through [:661](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:661), and
  removes the field later in QPACK at
  [src/server/linnea_qpack.asm:883](/home/linnea/linnea/src/server/linnea_qpack.asm:883)
  through [:894](/home/linnea/linnea/src/server/linnea_qpack.asm:894).

The shared upstream-head gate intentionally sees the `Transfer-Encoding`
field despite `Connection`, so it accepts sole `chunked` and enforces its
status-specific rules. It does not supply the HTTP/1 rewriter's lost local
framing bit. This is therefore another placement defect: forwarding policy
was applied before receiving-hop message framing.

### Reproduction

An isolated upstream needs only return this normal one-layer chunked response:

```text
HTTP/1.1 200 OK\r\n
Connection: Transfer-Encoding\r\n
Transfer-Encoding: chunked\r\n
\r\n
4\r\n
body\r\n
0\r\n
\r\n
```

The expected downstream representation is `body` on every protocol, with
neither connection-specific field forwarded. The current source trace yields:

| Downstream protocol | Framing selected | Client-visible content |
| --- | --- | --- |
| HTTP/1.1 | close-delimited | literal `4\r\nbody\r\n0\r\n\r\n` |
| HTTP/2 | chunked, de-chunked | `body` |
| HTTP/3 | chunked, captured/de-chunked | `body` |

The conflict variant is a useful companion:

```text
Connection: Transfer-Encoding, Content-Length\r\n
Transfer-Encoding: chunked\r\n
Content-Length: 4\r\n
```

HTTP/2 and HTTP/3 detect both fields while selecting framing and take 502.
HTTP/1 filters both before setting either local flag, regards the response as
close-delimited, and can instead return a successful raw-chunk response. The
existing shared validator proves that each individual field is grammatically
valid but does not currently make this cross-field forwarding/framing decision.

### Impact

A backend, intermediary, or protocol fault upstream of Linnea can make the
body bytes depend on ALPN. In the simple case HTTP/1 users receive chunk syntax
as application data while HTTP/2 and HTTP/3 users receive the decoded body. In
the conflict case HTTP/1 accepts a response that the other two paths reject as
a response-splitting hazard.

This is particularly risky because the source already contains the right
security principle — `Connection`-nominated fields must not cross the next
hop — but conflates it with whether the current hop must obey their framing.
Removing a field from the message sent onward must happen *after* that field
has been used to delimit the message received.

### Recommendation

Separate HTTP/1's received-head framing classification from its forwarding
walk. Parse and retain `Content-Length` and `Transfer-Encoding` before any
`Connection`-nominated field is skipped; continue to omit them from the
downstream HTTP/1 head when `Connection` names them. Make the local
TE-plus-CL refusal use those retained flags, so it matches HTTP/2 and HTTP/3.

Add `/api/connte`, `/api/conncl`, and `/api/conntecl` to
`test/proxy_backend.py` and the three-protocol matrix. Require `connte` to
deliver exactly `body`, no `Connection` or `Transfer-Encoding`, everywhere;
require `conntecl` to produce 502 everywhere; and retain an ordinary chunked
response as the control. The `conncl` case should verify that an upstream
length is still used for the received hop while the nominated field is absent
from the forwarded response.

### Resolution — FIXED (2026-08-19, `aacd172`)

Correct, and it is my regression: `4bb11cb` added the dynamic `Connection` walk
to HTTP/1's field loop and placed it *before* the loop identifies
`Content-Length` and `Transfer-Encoding`. That is the same commit, and the same
class of mistake, as report 11's Finding 1 — a forwarding rule applied where a
receiving rule had not yet run.

Reproduced against a pre-fix binary:

```
/api/connte     h1 body = 4\r\nbody\r\n0\r\n\r\n     h2/h3 body = body
/api/conntecl   h1 200                              h2/h3 502
```

The field walk now classifies framing first and decides forwarding second, at
`.fwd`. A nominated `Content-Length` still frames this hop and still does not
travel.

**That was not sufficient on its own, and only the A/B showed it.** HTTP/1 does
not de-chunk; it relays chunked framing verbatim, which is correct *while the
`Transfer-Encoding` field travels with it*. Since that field is hop-nominated
and rightly dropped, the framing disappeared with it and the client still
received chunk syntax as content. So HTTP/1 now **states its own**
`Transfer-Encoding: chunked` when it relays a chunked body — the same treatment
`Connection` already gets, and correct for the same reason: transfer coding
describes one hop, and the hop it describes downstream is ours. `/api/chunked`
is byte-identical to pre-fix.

The report asked that `connte` deliver exactly `body` everywhere. It does, at
the representation level: HTTP/1 delimits it with chunked framing, which is
legal HTTP/1 and what HTTP/1 does for every chunked response, while HTTP/2 and
HTTP/3 de-chunk because their protocols have no chunked framing.

## Finding 2 — Binary-protocol emitters retain HTTP/1 optional whitespace

Severity: **Medium (P2, invalid downstream HTTP/2 field sections)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

HTTP/1 allows optional whitespace around a field value. The shared upstream
validator accepts SP and HTAB before and after that value; its parsing is
therefore correct for an upstream line such as:

```text
X-Note:\tvalue\t\r\n
```

Those bytes are field-line delimiters, not part of the semantic `X-Note`
value. HTTP/1 can safely relay the original line. HTTP/2 cannot: RFC 9113
section 8.2.1 says a field value **MUST NOT** start or end with SP or HTAB.

The HTTP/2 response emitter does not use the validator's normalized value
slice. At [src/server/linnea_http2.asm:4589](/home/linnea/linnea/src/server/linnea_http2.asm:4589)
through [:4609](/home/linnea/linnea/src/server/linnea_http2.asm:4609), it
removes only leading SP and then HPACK-encodes everything through the CR. A
leading HTAB and all trailing OWS are emitted to the downstream H2 peer. Thus
all of these legal HTTP/1 field lines produce a malformed H2 field value:

```text
X-Note:\tvalue\r\n
X-Note: value \r\n
X-Note: value\t\r\n
```

The HTTP/3 QPACK path repeats the same mistake at
[src/server/linnea_qpack.asm:895](/home/linnea/linnea/src/server/linnea_qpack.asm:895)
through [:915](/home/linnea/linnea/src/server/linnea_qpack.asm:915): it strips
leading SP only and encodes the rest. HTTP/3 does not carry HTTP/1 field-line
syntax, so forwarding those delimiter bytes is still an incorrect translation
of the received field value, even where an H3 peer tolerates it.

This was anticipated in report 7: its recommendation explicitly called for the
response-field emitters to trim their value slices. The subsequent fix changed
only framing lookups (`h2p_head_find` and `.ph_find`), which is why
`Content-Length` with HTAB works while a general extension field still reaches
the binary encoders with its surrounding OWS intact.

### Reproduction

Use a normal counted response whose only unusual field is whitespace-padded:

```text
HTTP/1.1 200 OK\r\n
Content-Length: 4\r\n
X-Note:\tvalue\t\r\n
\r\n
body
```

HTTP/1.1 may relay `X-Note` with its optional whitespace. HTTP/2 instead
HPACK-encodes the value as `\tvalue\t`; a compliant recipient must treat the
field section as malformed. HTTP/3 QPACK-encodes the same bytes rather than
the semantic value `value`. This is independent of the earlier
`Content-Length` whitespace cases: those fields are found by dedicated
framing helpers and are not emitted as ordinary extension fields.

### Impact

A fully valid HTTP/1 upstream response can cause HTTP/2 clients to reject the
response or terminate the connection, while HTTP/1 clients succeed. The defect
also produces a translation that different H3 clients may canonicalize or
preserve differently, undermining the goal of the shared gate: a proxy should
not turn legal upstream syntax into version-specific downstream bytes.

The common case is broader than `X-Note`: any end-to-end response field that
is not removed or regenerated by the proxy takes this emitter path, including
application metadata used by caches, browsers, and API clients.

### Recommendation

Create one bounded helper that returns a field value with both leading and
trailing SP/HTAB removed, then use it in the HTTP/2 and QPACK response
emitters. Do not alter internal whitespace. The helper should be used only
after the shared validator has established a well-formed CRLF-delimited line.

Add `/api/fieldows`, `/api/fieldsptrail`, and `/api/fieldtabtrail` to the
cross-protocol upstream-head matrix. On HTTP/2 and HTTP/3, decode the field
section and require the exact value `value` with no leading or trailing OWS;
on HTTP/1, either preserve the upstream spelling or make an explicit,
consistent normalization decision. Keep a field with internal whitespace such
as `value one` as the control.

### Resolution — FIXED (2026-08-19, `aacd172`)

Confirmed at exactly the stated boundary:

```
before   fieldows      h2/h3 = '\tvalue\t'    (HTAB kept at both ends)
         fieldsptrail  h2/h3 = 'value '        (leading SP stripped, trailing kept)
         fieldinner    h2/h3 = 'value one'     (already correct)
after    fieldows, fieldsptrail -> 'value'; fieldinner unchanged
```

One `linnea_string_trim_ows` in `linnea_string.asm` — which the QPACK test
harnesses already link, so it needs no new object anywhere — now serves both
binary emitters. Internal whitespace is untouched, and `/api/fieldinner` is the
control that keeps a trim from turning into a rewrite. HTTP/1 continues to relay
the upstream line as it stands, which is legal there.

The report is right that report 7 asked for this and that only the framing
lookups were changed then. That is why `Content-Length` with HTAB has worked
since, while every other field still reached the encoders with its delimiters
attached: the fields with dedicated helpers got the fix and the general path did
not.

## Verification

| route | before | after |
| --- | --- | --- |
| `/api/connte` | h1 relayed `4\r\nbody\r\n0\r\n\r\n` as content | `body` on all three |
| `/api/conncl` | `body` | unchanged — nominated CL frames the hop, does not travel |
| `/api/conntecl` | h1 `200`, h2/h3 `502` | `502` on all three |
| `/api/fieldows`, `/api/fieldsptrail` | h2/h3 kept the OWS | `value` exactly |
| `/api/fieldinner` | `value one` | unchanged — the control |
| `/api/chunked` | served | byte-identical |

Cross-protocol matrix: **126 checks green**, from 4 failures. Full suite
**767 passed, 0 failed**.

### Two mistakes of mine, recorded because both were nearly missed

Moving the framing block left `.cn_ask` falling straight into `.content_len`,
so every surviving field was parsed as a Content-Length value and the server
hung on **every** request, static included. A pile of leaked scratch server
processes made a tempting alternative explanation; running the *pre-fix* binary
on the same rig is what separated my code from the environment in one step.

The new assertion was wrong twice before it was right. It split on `": "`,
which HTTP/1's raw header lines do not contain, and the matrix helper formatted
its sections as `name: value` — a separator space of our own that made a genuine
leading-space value indistinguishable from a correct one. In that state the
check would have passed a broken server, which is the only kind of test bug that
really matters.

## Conclusion

Both are ordering and ownership errors at the HTTP/1-to-binary boundary, as the
report says. The first is worth restating in one line, because it is the third
report in a row to land on it: **removing a field from the message sent onward
must happen after that field has delimited the message received.**

## Conclusion (as filed)

The shared validator has made response-head grammar substantially more
consistent, but it cannot by itself determine every translation decision. The
first defect is caused by using a forwarding rule before the received message
is framed; the second by bypassing the validator's normalized field-value
boundaries during binary encoding. Both are small ordering/ownership errors at
the HTTP/1-to-HTTP/2/3 boundary, with client-visible effects that depend on the
protocol negotiated downstream.
