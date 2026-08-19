# Audit Report 22

Audited at `4d7d3eb` (`chunked: sweep the grammar differentially, and fix what it found`), 2026-08-19.

**Fixed in `11e7a81`**, verified against a pre-fix binary. A second
defect in the same decoder was found beside it and is fixed here too: the
accumulator's "a size no body could ever have" bound had never fired, and a
17-digit size wrapped to zero — which reads as the last chunk, so the body
ended early and the octets behind it were served as a **second request**.

One request-framing issue remains open:

1. **High: the HTTP/1 request chunk decoder still accepts bytes that cannot follow chunk-size digits.** After the first hexadecimal digit, it treats any non-LF byte other than CR as ignored extension data. Thus `4 `, `4g`, `4\0`, and control bytes are accepted as a size of four. The new differential sweep does not assert malformed HTTP/1 request outcomes, so this path is outside its coverage.

No production source, configuration, or test files were changed in this audit. Only this report was added.

This is a source-trace audit against the stated baseline. The reproductions are
minimal client fixtures and the control flow they reach; they are not presented
as captures from a modified backend.

## Finding 1 — HTTP/1 request chunk-size delimiters are too permissive

Severity: **High (P1, malformed request framing acceptance)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

The request-side `chunked_decode` recognizes the end of the hexadecimal size
run at `.cd_size_done`, but then enters `.cd_ext` without checking the byte
that caused the size scan to stop:

```asm
.cd_size_done:
    test rcx, rcx
    jz .cd_bad
.cd_ext:
    cmp r14, r13
    jae .cd_more
    cmp byte [r14], 13
    je .cd_size_crlf
    cmp byte [r14], 10
    je .cd_bad
    inc r14
    jmp .cd_ext
```

at [src/server/linnea_http.asm:4570](/home/linnea/linnea/src/server/linnea_http.asm:4570) through
[:4581](/home/linnea/linnea/src/server/linnea_http.asm:4581). The chunk grammar
allows only `;` to open a chunk extension or CR to end the size line. This code
accepts a space, a second letter such as `g`, NUL, DEL, and other control bytes
as extension contents. It only rejects LF.

The HTTP/3 incremental decoder has already been tightened to require `;` or CR
when its size scan ends at
[src/server/linnea_spill.asm:235](/home/linnea/linnea/src/server/linnea_spill.asm:235) through
[:251](/home/linnea/linnea/src/server/linnea_spill.asm:251), and it rejects
control bytes inside a valid extension at [:241](/home/linnea/linnea/src/server/linnea_spill.asm:241)
through [:251](/home/linnea/linnea/src/server/linnea_spill.asm:251). HTTP/2's
response decoder applies the same delimiter and control-byte rules at
[src/server/linnea_http2.asm:4205](/home/linnea/linnea/src/server/linnea_http2.asm:4205) through
[:4220](/home/linnea/linnea/src/server/linnea_http2.asm:4220).

The new sweep is blind to this request-side acceptance. `test/chunkfuzz/drive.py`
drives all variants through H1, H2, and H3 at [:20](/home/linnea/linnea/test/chunkfuzz/drive.py:20)
through [:23](/home/linnea/linnea/test/chunkfuzz/drive.py:23), but its malformed
and valid assertions iterate only over `http2` and `h3` at [:24](/home/linnea/linnea/test/chunkfuzz/drive.py:24)
through [:31](/home/linnea/linnea/test/chunkfuzz/drive.py:31). The H1 result is
used only in the disagreement tuple at [:32](/home/linnea/linnea/test/chunkfuzz/drive.py:32)
through [:33](/home/linnea/linnea/test/chunkfuzz/drive.py:33), and request
uploads are not exercised by that driver at all.

### Reproduction

Send an HTTP/1 request with a chunked body whose size is followed by junk:

```text
POST /api/echo HTTP/1.1\r\n
Host: example\r\n
Transfer-Encoding: chunked\r\n
\r\n
4g\r\n
body\r\n
0\r\n
\r\n
```

Equivalent fixtures are `4 \r\n`, `4\0\r\n`, and `4;note=ok\r\n` (the last
one is the valid control). The current HTTP/1 request decoder reads the first
three as a four-byte chunk with ignored extension data and proceeds to route
the request, rather than returning 400.

### Impact

The server accepts malformed HTTP/1 request framing that its response and
HTTP/3 decoders reject. Although the proxy strips the chunk syntax before
forwarding the decoded body, accepting invalid framing broadens the request
grammar and creates an avoidable parser differential at the HTTP/1 boundary.
Any component in front of or behind this listener that interprets the junk
after the size digits differently can disagree about where the body begins and
ends.

The sweep's 46 response fixtures and its H2/H3 checks do not establish that the
HTTP/1 upload parser is closed; they explicitly leave H1 unasserted and never
send these variants as client request bodies.

### Recommendation

At `.cd_size_done`, require the terminating byte to be either `;` or CR before
entering the extension state. Inside `.cd_ext`, mirror the binary decoders:
allow CR, reject LF and all controls except HTAB, reject DEL, and otherwise
consume extension bytes. Add direct HTTP/1 upload fixtures for `4g`, `4 `,
NUL/CTL/DEL extensions, valid `4;note=ok`, and a valid HTAB-containing
extension. Require malformed cases to return 400 while preserving the valid
controls.

### Resolution — FIXED (2026-08-19)

Confirmed exactly as filed. `4 `, `4g`, `4\0`, `4\x7f` and control bytes inside
a valid extension were all `200`; `4;note=ok` and an HTAB inside an extension
were `200` as well, and had to stay so.

The report frames this as a gap against HTTP/2 and HTTP/3, but the sharper
statement is that it is a gap **within HTTP/1**. A chunked upload is decoded by
`chunked_decode` while it fits in `in_buf` (17408 bytes) and by
`linnea_spill_chunked` above that, and only the first was permissive — so the
same bytes on the same listener were answered differently according to how large
the body was:

```
                 buffered (<17408)      captured (>17408)
  '4 '           200 OK                 400 Bad Request
  '4g'           200 OK                 400 Bad Request
  '4\0'          200 OK                 400 Bad Request
```

`.cd_size_done` now requires `;` or CR before entering the extension state, and
`.cd_ext` rejects every control byte but HTAB, and DEL — the same two rules
`linnea_spill_chunked` and the HTTP/2 response decoder already carried.

### Found beside it — the accumulator bound that never fired

The fix was verified by driving all 46 `test/chunkfuzz/variants.py` cases
through **both** request decoders and demanding they agree. Seven rows went
green; two more disagreed for a different reason:

```
  size-17-digit        buffered=EOF     captured=400 Bad Request   DISAGREE
  size-16-digit-huge   buffered=EOF     captured=400 Bad Request   DISAGREE
```

`.cd_accum` bounds the size at `0x0fffffffffffffff` twice, before and after the
shift. Both compares were written as immediates:

```
  413440: 48 83 fb ff    cmp $0xffffffffffffffff,%rbx
```

That constant does not fit the sign-extended `imm32` a `cmp r64, imm` carries,
so nasm truncated it to `0xff` and both tests became "above 2^64-1" — which
nothing is. The bound had been dead for as long as it had existed, and it
assembled with a warning every time. `linnea_spill_chunked` and `h2p_decode`
load the same constant into a register, which is why they were unaffected and
why the sweep saw a disagreement rather than nothing at all.

Dead bound, live consequence: a 17-digit size shifts one nybble past 64 bits and
wraps to **zero**, and a zero-size chunk is the last chunk. The body therefore
ended at the size line, and everything behind it was parsed as the next request
on the connection:

```
POST /api/echo HTTP/1.1 + Transfer-Encoding: chunked
10000000000000000\r\n\r\nGET /index.html HTTP/1.1 ...

  before:  2 responses to one request line   (200 for the POST, 200 for the GET)
  after:   1 response                        (400 Bad Request)
```

One request line in, two responses out — past any device in front of us that
read the same bytes as one message. Both compares now go through `r8`.

The build is the tripwire for the rest of this class: `make 2>&1 | grep warning`
had printed these two lines plus one more (an inert mask on the HTTP-version
compare, harmless only because `version_1x` is followed by an explicit zero
byte). All three now go through a register and **the build is warning-free**, so
the next truncated immediate is visible the moment it is assembled.

### Coverage

The report is right that the sweep was blind here: it drives *response* bodies,
the direction all three protocols share, and a request may be chunked over
HTTP/1 alone. The request side now has its own fixtures:

* `test/upload_chunked.py sizeline` — twelve size lines, each sent at both
  sizes, so the two decoders are asserted against **one** table. The three valid
  rows are the control: a decoder that refused every extension would pass the
  malformed rows on its own.
* `test/upload_chunked.py smuggle` — one request line must produce one response.

Both fail on a pre-fix binary (`sizeline`: `trailing space (buffered): 200 OK,
wanted 400`; `smuggle`: `2 responses to one request line`) and pass after. The
46-variant differential ends `0 disagreements, 0 malformed accepted`. Full
suite: **769 passed, 0 failed**.

## Verification (as filed)

No executable tests were run: this report makes no source change. The finding
is traced from the request decoder, the stricter H2/H3 counterparts, and the
differential sweep's assertion boundary.

## Conclusion

The new sweep closed several response-side grammar gaps, but it does not test
HTTP/1 chunked uploads. The request decoder still treats arbitrary bytes after
the size digits as an extension. Requiring the same delimiter and control-byte
grammar in this path removes the remaining request-side parser differential.

Both decoders now hold the same grammar, and the request side is swept the way
the response side already was. The finding as filed was a differential; the one
underneath it — an overflow bound the assembler had quietly disabled — was a
smuggling vector, and it was reachable only because the fix was checked by
asking two decoders the same 46 questions rather than the ten the report named.
