# Audit Report 23

Audited at `4d7d3eb` (`chunked: sweep the grammar differentially`), 2026-08-19.

**Fixed in `9036b39`**, verified against a pre-fix binary on all three
protocols and on both HTTP/1 request decoders. The fix also corrected a
deviation in the opposite direction that the report does not mention: `4 ;a=b`
is *valid* — BWS before the `;` is in the grammar — and report 22's fix had
made it a 400.

One cross-protocol chunk grammar gap remains open:

1. **High: all chunk decoders accept syntactically invalid chunk extensions.**
   They reject line-breaking and control bytes, but do not require each
   extension to have a `token` name or constrain its value to `token` or a
   complete `quoted-string`.

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — Chunk extensions are scanned as byte classes, not parsed

Severity: **High (P1, malformed framing accepted)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

RFC 9112 defines `chunk-ext` as semicolon-prefixed components with a mandatory
`chunk-ext-name` (`token`) and an optional value (`token` or `quoted-string`).
The HTTP/1 request decoder instead enters `.cd_ext` after seeing `;` and accepts
every printable byte (plus HTAB) until CRLF:

```asm
.cd_ext:
    ...
    cmp byte [r14], 9
    je .cd_ext_next
    cmp byte [r14], 0x20
    jb .cd_bad
    cmp byte [r14], 0x7f
    je .cd_bad
```

at [src/server/linnea_http.asm:4597](/home/linnea/linnea/src/server/linnea_http.asm:4597)
through [:4616](/home/linnea/linnea/src/server/linnea_http.asm:4616). HTTP/2
uses the same byte-class scan at
[src/server/linnea_http2.asm:4217](/home/linnea/linnea/src/server/linnea_http2.asm:4217)
through [:4242](/home/linnea/linnea/src/server/linnea_http2.asm:4242), and the
captured HTTP/3/request path does likewise at
[src/server/linnea_spill.asm:260](/home/linnea/linnea/src/server/linnea_spill.asm:260)
through [:278](/home/linnea/linnea/src/server/linnea_spill.asm:278).
The comments acknowledge the token/quoted-string grammar, but no state tracks
the name, `=`, quote, escaping, or quote termination.

The differential corpus covers valid `4;a=b` and `4;note`, plus control-byte
and line-framing failures, but no empty-name, missing-name, or quoted-string
cases: [test/chunkfuzz/variants.py:24](/home/linnea/linnea/test/chunkfuzz/variants.py:24)
through [:48](/home/linnea/linnea/test/chunkfuzz/variants.py:48).

### Reproduction

These bodies are accepted as complete chunked messages by the three scanners,
although neither extension is valid:

```text
4;=bad\r\nbody\r\n0\r\n\r\n
4;name="unterminated\r\nbody\r\n0\r\n\r\n
```

The first has no extension name; the second has an unterminated quoted-string.
Other malformed forms include `4;=\r\n` and invalid quoted-string escapes.

### Impact

The server’s three chunk parsers accept a broader extension grammar than the
HTTP specification. A peer, intermediary, WAF, or downstream parser that
validates extension structure can reject or interpret these bytes differently,
creating a request/response framing differential. The current sweep reports
green while leaving this entire grammar dimension untested.

### Recommendation

Parse extensions in all three paths as `;` plus optional BWS, a required
`token` name, optional BWS/`=`/BWS, then either a `token` or a complete
`quoted-string` with valid escapes, followed by another extension or CRLF.
Reject empty names, bare `=`, unterminated quotes, and invalid quoted-pair
bytes. Add identical malformed fixtures and retain `4;a=b`, `4;note`, and a
valid quoted value as controls.

### Resolution — FIXED (2026-08-19)

Confirmed as filed, on every path. Nine malformed extension forms were served
as clean `200`s by both HTTP/1 request decoders and by both binary protocols:

```
                            before                 after
  4;=bad        (no name)   200 / 200 / 200        400 / 502 / 502
  4;            (no ext)    200 / 200 / 200        400 / 502 / 502
  4;a=          (no value)  200 / 200 / 200        400 / 502 / 502
  4;a="unterm   (open "   ) 200 / 200 / 200        400 / 502 / 502
  4;a=b"c                   200 / 200 / 200        400 / 502 / 502
  4;a="q"x                  200 / 200 / 200        400 / 502 / 502
  4;a b                     200 / 200 / 200        400 / 502 / 502
  4;a,b                     200 / 200 / 200        400 / 502 / 502
  4;a="x\                   200 / 200 / 200        400 / 502 / 502
                            (h1 request / h2 / h3)
```

The unterminated quote is the one with teeth. A parser that *does* track the
quoted-string keeps reading past the CRLF looking for the closing quote, so it
and a scanner that stops at the CR disagree about where the chunk data begins —
and that disagreement is the whole of request smuggling. `qdtext` excludes CR
and LF precisely so the line ending can never be swallowed, which is why the
grammar has to be parsed rather than approximated by a byte class.

### One function, because three decoders cannot each spell out one grammar

`linnea_chunk_ext_step(state, byte)` returns the next state, `-1` for malformed,
or `-2` for "this CR legally ends the extension". Nine states cover
`*( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )`, including the
quoted-string and its escapes. Each decoder keeps the state where it already
keeps its own, and the difference between them is why the shared piece is a
*step* rather than a scan:

* `chunked_decode` re-parses from the body start on every call — a register;
* `h2p_decode` re-scans the size line until the whole line is in hand — a
  register;
* `linnea_spill_chunked` resumes byte by byte — a new `chunk_ext` connection
  field, beside the `chunk_state` it already carries.

Only `0`, `-1` and `-2` mean anything to a caller. It lives in
`src/lib/linnea_string.asm` because that object is in every link set while the
three decoders sit in three that no single test harness links together — the
same constraint that put `linnea_string_is_tchar` there.

### Found beside it — report 22's fix was over-strict

`4 ;a=b` is valid: RFC 9112 7.1.1 puts BWS *inside* the repeated group, before
the `;`. Report 22 required `;` or CR immediately after the digits, so that
line became a 400 on all three protocols. Writing the ABNF out as states is
what surfaced it; a byte-class rule cannot express "a space is allowed only
when a `;` follows it", which is exactly the distinction between `4 ;a=b`
(valid) and `4 ` (malformed). Both are now fixtures, and they are the pair that
keeps the rule honest — a decoder that simply refused every extension would
pass all nine malformed rows above.

The same applies to `4;a="x;y"`: inside a quoted-string a semicolon is data,
not a separator. That is also a fixture.

### Coverage

* `test/chunkfuzz/variants.py` gains 15 rows (6 valid, 9 malformed) — 46 → 61.
  The sweep now reports `61 variants driven, 0 malformed served as a clean 200
  or valid rejected`; before the fix that line read `20`.
* The same 61 driven as HTTP/1 request bodies through **both** request decoders:
  `0 disagreements, 0 malformed accepted`.
* `test/upload_chunked.py sizeline` grows 12 → 27 size lines, each sent at both
  body sizes. Ten of the fifteen new rows are wrong on a pre-fix binary — nine
  malformed accepted and one valid refused.
* `test/proxy_backend.py` and `test/proxy_upstream_head.py` gain
  `chunkextnoname`, `chunkextunterm` (both `502`), and `chunkextquoted`,
  `chunkextbws` (both `200 body`) — 12 matrix checks that fail on the pre-fix
  binary (matrix exit 1 → 0).

Full suite: **769 passed, 0 failed**.

## Verification

No executable tests were run: this report makes no source change. The finding
is a source-trace audit of all three decoder states and the sweep’s fixture
boundary.

## Conclusion

The differential sweep closed delimiter, control-byte, trailer, and overflow
bugs, but its extension cases stop at byte-class validity. The parsers still
need to enforce the extension's name/value grammar rather than merely scan to
CRLF.

They do now, from one function rather than three transcriptions of it. The
report's framing is worth keeping: the earlier fixes asked which *bytes* may
appear, and this one asks what *shape* they must make — which is also how it
turned up a valid line the previous fix had started refusing.
