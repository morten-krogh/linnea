# Audit Report 21

Audited at `01b0d74` (`audit-report-20: FIXED`), 2026-08-19.

**Fixed in the commit below**, verified against a pre-fix binary on all three
protocols and on the request path as well.

One response/request-framing issue remains open:

1. **High: all three chunked decoders accept trailer lines that are not HTTP field lines.** They now reject embedded LF, but otherwise scan until CR without requiring a field-name/colon or rejecting control bytes. A colonless trailer or a NUL in a trailer value is therefore accepted by HTTP/2 and HTTP/3 and is silently dropped by the HTTP/1 request decoder.

No production source, configuration, or test files were changed in this audit. Only this report was added.

This is a source-trace audit against the stated baseline. The reproductions are
minimal fixtures and the control flow they reach; they are not presented as
captures from a modified backend.

## Finding 1 — Trailer scanners do not validate field-line syntax

Severity: **High (P1, malformed framing acceptance and protocol differential)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

The HTTP/2 trailer state now rejects LF, but it still treats every other byte
as part of a trailer line until CR:

```asm
.dec_trail_line:
    cmp r13, [rbx + linnea_h2p.len]
    jae .dec_save
    cmp byte [r12 + r13], 13
    je .dec_trail_cr
    cmp byte [r12 + r13], 10
    je .dec_bad
    inc r13
    jmp .dec_trail_line
```

at [src/server/linnea_http2.asm:4259](/home/linnea/linnea/src/server/linnea_http2.asm:4259) through
[:4274](/home/linnea/linnea/src/server/linnea_http2.asm:4274). There is no
colon check, field-name token check, or control-byte check. The later CRLF and
empty trailer line then complete the response at [:4275](/home/linnea/linnea/src/server/linnea_http2.asm:4275)
through [:4286](/home/linnea/linnea/src/server/linnea_http2.asm:4286).

HTTP/3's `LINNEA_CHUNK_TRAIL_LINE` state has the same shape at
[src/server/linnea_spill.asm:314](/home/linnea/linnea/src/server/linnea_spill.asm:314) through
[:337](/home/linnea/linnea/src/server/linnea_spill.asm:337): it rejects LF,
but every other byte is accepted until CR. The HTTP/1 request decoder likewise
only checks CR/LF framing at
[src/server/linnea_http.asm:4622](/home/linnea/linnea/src/server/linnea_http.asm:4622) through
[:4645](/home/linnea/linnea/src/server/linnea_http.asm:4645).

The project already has a strict upstream field-section validator. It requires
token field names, a colon, and values without forbidden control bytes at
[src/server/linnea_http.asm:3485](/home/linnea/linnea/src/server/linnea_http.asm:3485) through
[:3504](/home/linnea/linnea/src/server/linnea_http.asm:3504). That validator is
applied to response heads, but not to the trailer lines consumed by any of the
three chunked decoders.

### Reproduction

An upstream response can carry a colonless trailer line:

```text
HTTP/1.1 200 OK\r\n
Transfer-Encoding: chunked\r\n
\r\n
4\r\n
body\r\n
0\r\n
Not-A-Field\r\n
\r\n
```

Or it can carry a control byte in a nominal field value:

```text
0\r\n
X-Trail: ok\x00still\r\n
\r\n
```

Neither trailer section is an HTTP field section. Current source behavior is
that HTTP/2 and HTTP/3 de-chunk successfully and discard the trailer, while
HTTP/1's request decoder also accepts and discards it; the HTTP/1 response path
relays the raw trailer bytes to its client.

### Impact

The proxy's three transfer-coding boundaries accept bytes that are not legal
HTTP fields. For H2 and H3 the malformed metadata disappears and the client
receives a clean successful response, while H1 exposes the malformed section
to a downstream parser. This leaves acceptance dependent on ALPN and makes the
decoder's “valid trailer” state broader than the HTTP message grammar it claims
to consume.

The issue is separate from report 20: embedded LF is now rejected. A trailer
line containing no colon or a NUL still reaches the same completion state.

### Recommendation

Validate each non-empty trailer line before accepting its CRLF:

- require a field-name consisting only of HTTP token bytes followed by `:`;
- reject CTLs other than permitted HTAB/visible bytes in the value;
- retain the existing CRLF and empty-line checks.

Reuse the shared field-line validation rules where practical, or factor a
bounded trailer-line helper so the H2, H3, and H1 decoders cannot drift again.
Add colonless, control-byte, and valid-trailer fixtures to the matrix. H2/H3
should fail malformed trailer sections (502 before the head or reset after it),
while the valid trailer control remains a successful response.

### Resolution — FIXED (2026-08-19)

Confirmed: a colonless trailer, a non-token name, and a NUL in a value were all
accepted — `200` on HTTP/2 *and* HTTP/3 — while HTTP/1 relayed `Not-A-Field`
straight to its client.

The report's own sentence is the one worth keeping: rejecting embedded LF fixed
a **delimiter**, not the **grammar**. The scanners' "valid trailer" state was
broader than the HTTP message they claim to consume.

Each scanner is incremental with nowhere to buffer a line, so the check is made
byte by byte: a name/value split in each, judged against the **same `tchar`
bitmap the head validator uses**, exposed as `linnea_string_is_tchar`. One
bitmap, one rule, three callers — a fourth hand-rolled character class is how
this family of findings began.

The three decoders differ in one way that is now recorded in the code: HTTP/2
and HTTP/3 are resumable state machines and each needed a new state (`chunked`
9, `LINNEA_CHUNK_TRAIL_VAL`), whereas `chunked_decode` re-parses from the body
start on every call and needed none.

### The request path, checked directly

`chunked_decode` is the upload path, so it was exercised rather than left to the
suite:

```
no trailer / valid trailer / HTAB in value   200
no colon / NUL in value / bad name           400
```

`400` on the request side and `502` proxying — the right code for each, rather
than one rule producing a bad-gateway for a bad request.

`/api/chunktrailhtab` is a new control so that "reject control bytes" cannot
quietly become "reject whitespace": HTAB and internal spaces are legal in a
field value, and only the CTLs and DEL are not.

Control against a pre-fix binary: all three routes fail on all three protocols.
After: **241 checks green**. Full suite **767 passed, 0 failed**.

## Verification (as filed)

No executable tests were run: this report makes no source change. The finding
is traced from the three checked-in trailer scanners and the existing strict
upstream-head validator.

## Conclusion

Rejecting embedded LF fixed one trailer-line delimiter hole, but the scanners
still do not parse trailer lines as HTTP fields. Requiring a token name, colon,
and valid field-value bytes closes the remaining malformed-trailer acceptance
gap across the proxy's framing paths.
