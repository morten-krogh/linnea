# Audit Report 17

Audited at `ec5cd7c` (`audit-report-16: FIXED`), 2026-08-19.

**Fixed in `3840c95`**, verified against a binary carrying the bug. The finding
is correct on both counts. Measuring it also turned up a **worse** defect beside
it, in HTTP/3 rather than HTTP/2, recorded below.

One response-framing issue remains open:

1. **High: HTTP/2 accepts malformed chunk-size lines that HTTP/3 rejects and HTTP/1 relays as malformed chunk syntax.** Its de-chunker permits leading whitespace before the first hexadecimal digit and shifts an unbounded hexadecimal accumulator until it wraps. A wrapped oversized size becomes zero, so HTTP/2 can complete a successful empty response at the first invalid chunk line.

No production source, configuration, or test files were changed in this audit. Only this report was added.

This is a source-trace audit against the stated baseline. The reproduction sections give minimal backend fixtures and the control flow they reach; they are not presented as captures from a modified backend.

## Finding 1 — HTTP/2's chunk-size parser accepts whitespace and integer overflow

Severity: **High (P1, response framing integrity and protocol differential)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

The shared upstream-head gate accepts a sole `Transfer-Encoding: chunked` and
leaves the body decoder to establish whether the chunk syntax is valid. The
three downstream paths do not apply the same grammar.

HTTP/2's decoder starts a size line at
[src/server/linnea_http2.asm:4154](/home/linnea/linnea/src/server/linnea_http2.asm:4154).
Before it has seen a digit, it explicitly accepts a space:

```asm
test r8d, r8d
jnz .dec_size_digit
cmp al, ' '
je .dec_size_next
```

at [:4167](/home/linnea/linnea/src/server/linnea_http2.asm:4167) through
[:4180](/home/linnea/linnea/src/server/linnea_http2.asm:4180). HTTP chunk
grammar starts with `1*HEXDIG`; optional whitespace is not a chunk-size
delimiter.

The same loop accumulates a digit with:

```asm
shl rdx, 4
or rdx, rax
```

at [:4172](/home/linnea/linnea/src/server/linnea_http2.asm:4172) through
[:4177](/home/linnea/linnea/src/server/linnea_http2.asm:4177), with no bound
before the shift. A 17-digit size such as `10000000000000000` therefore shifts
the valid 60-bit value one more nybble and wraps `rdx` to zero. `.dec_size_eol`
then treats it as the terminal chunk at [:4197](/home/linnea/linnea/src/server/linnea_http2.asm:4197)
through [:4205](/home/linnea/linnea/src/server/linnea_http2.asm:4205), sets
`LINNEA_H2P_F_BODY_DONE`, and the caller emits a normal completed response at
[:3197](/home/linnea/linnea/src/server/linnea_http2.asm:3197) through [:3203](/home/linnea/linnea/src/server/linnea_http2.asm:3203).

HTTP/3 uses `linnea_spill_chunked`, whose size state starts at
[src/server/linnea_spill.asm:208](/home/linnea/linnea/src/server/linnea_spill.asm:208).
It treats a leading space as a non-digit before any digit and returns malformed
at [:235](/home/linnea/linnea/src/server/linnea_spill.asm:235) through [:239](/home/linnea/linnea/src/server/linnea_spill.asm:239). Before each shift it
also rejects a value beyond `0x0fffffffffffffff` at [:224](/home/linnea/linnea/src/server/linnea_spill.asm:224)
through [:231](/home/linnea/linnea/src/server/linnea_spill.asm:231). The
HTTP/1 request decoder has the same strict rules at
[src/server/linnea_http.asm:4544](/home/linnea/linnea/src/server/linnea_http.asm:4544)
through [:4569](/home/linnea/linnea/src/server/linnea_http.asm:4569), including
the pre-shift limit at [:4559](/home/linnea/linnea/src/server/linnea_http.asm:4559)
through [:4564](/home/linnea/linnea/src/server/linnea_http.asm:4564).

The proxy's HTTP/1 response path does not decode chunks at all: it restates its
own `Transfer-Encoding: chunked` and relays the upstream bytes. Thus a
downstream HTTP/1 parser sees the malformed size line, HTTP/3 fails the capture
with 502, and HTTP/2 alone converts it into a clean successful response.

### Reproduction

An upstream needs only return either of these responses:

```text
HTTP/1.1 200 OK\r\n
Transfer-Encoding: chunked\r\n
\r\n
 4\r\n
body\r\n
0\r\n
\r\n
```

or the overflow form:

```text
HTTP/1.1 200 OK\r\n
Transfer-Encoding: chunked\r\n
\r\n
10000000000000000\r\n
```

The expected result is refusal of the malformed upstream framing. Current
source behavior is:

| Downstream protocol | Leading-space form | Overflow form |
| --- | --- | --- |
| HTTP/1.1 | relays invalid chunk syntax | relays invalid chunk syntax |
| HTTP/2 | `200`, body `body` | completed `200`, empty body after wrap-to-zero |
| HTTP/3 | 502 | 502 |

The overflow variant is not merely a large-body limit. The declared size never
causes a capacity decision in HTTP/2 because it becomes zero before the decoder
chooses data mode.

### Impact

A malformed upstream response has materially different client-visible meaning
by ALPN. HTTP/2 turns invalid framing into application data or an ordinary
empty success; HTTP/3 refuses it; HTTP/1 delegates the malformed transfer
coding to the client. The wrap case is especially dangerous because it makes a
nonzero chunk line indistinguishable from end-of-message inside the HTTP/2
proxy, truncating the response without a protocol error.

The server already treats malformed chunk framing as a gateway failure when
`h2p_decode` reaches `.dec_bad`. These two forms bypass that existing failure
path solely because the parser is more permissive than the project’s other two
chunk decoders.

### Recommendation

Make `h2p_decode` use the same size grammar and overflow limit as
`linnea_spill_chunked` and `chunked_decode`:

- remove the leading-space branch; require the first byte to be hexadecimal;
- before `shl rdx, 4`, reject `rdx > 0x0fffffffffffffff`.

Keep chunk extensions as the existing policy permits, but do not treat invalid
bytes before the extension delimiter as whitespace. Add `/api/chunkspace` and
`/api/chunkoverflow` to the upstream-head matrix. Require HTTP/2 and HTTP/3 to
fail the exchange rather than return `200`; retain ordinary chunked and
mixed-case/OWS `Transfer-Encoding: Chunked` heads as controls. For HTTP/1,
either validate before emitting the response head or explicitly document that
it streams the upstream's chunk syntax verbatim and closes on the malformed
message; it must not be used as evidence that the malformed response was
accepted.

### Resolution — FIXED (2026-08-19, `3840c95`)

Both halves confirmed. `h2p_decode` now uses the same grammar as
`linnea_spill_chunked` and the HTTP/1 request decoder: hexadecimal from the
first byte, no leading-space branch, and the `0x0fffffffffffffff` bound tested
**before** the shift rather than after.

The wrap case is as described and worth restating, because it is the dangerous
one: the accumulator reaching zero makes a nonzero size line indistinguishable
from end-of-message *inside the proxy*, so the response completes — successful
and truncated, with no protocol error anywhere.

### Two things measurement added

**`/api/chunkbig`** — `1fffffffffffffff`, sixteen digits — reversed the roles
the report predicts:

```
chunkbig    h2 = 502    h3 = 200
```

The bound is tested before each shift, so a 16-digit value never trips it.
HTTP/3 accepted it as a size, the upstream closed, and HTTP/3 called that a
success. A "too large" size is not the same test as "wraps", and only the
second was covered.

**`/api/chunktrunc`** — `4\r\nbo`, then close — is the worse one:

```
chunktrunc  h3 = 200, body = "bo"     <- a truncated response, delivered as complete
```

A chunked body ends at its terminal chunk, never at a closed socket. But it
arrives at the EOF path with `body_rem = -1`, which is also how a legitimately
close-delimited body arrives, so the two were indistinguishable there. HTTP/3
now requires `LINNEA_CHUNK_DONE` before it will call a chunked capture complete.

This matters most on HTTP/3 for a structural reason: **HTTP/3 buffers the whole
body before it sends anything, so it is the only one of the three that can still
refuse.** HTTP/1 and HTTP/2 have already sent their `200` by then and can only
close or reset the stream. Being able to refuse is precisely why it must.

### Verification

| route | with the bugs | fixed |
| --- | --- | --- |
| `/api/chunkspace` | h2 `200` body `body` | h2/h3 `502` |
| `/api/chunkoverflow` | h2 `200`, empty, wrapped to zero | h2/h3 `502` |
| `/api/chunkbig` | h2 `502`, **h3 `200`** | h2/h3 `502` |
| `/api/chunktrunc` | **h3 `200` + `bo`** | h3 `502`, h2 resets the stream |
| `/api/chunked`, `/api/tepad` | served | unchanged |

Control against a binary carrying both bugs: **4 chunk routes fail**. After:
**205 checks green**. Full suite **767 passed, 0 failed**.

### On the HTTP/1 question the report raises

The report asks that HTTP/1 either validate before emitting the head or be
documented as streaming the upstream's chunk syntax verbatim. It is the latter,
and the test now says so in `STREAMED_BODY`: HTTP/1 has already sent its `200`
before any chunk line is read, so it can only relay and close. That is not
laxity, it is the order in which the bytes exist — and it is recorded as a
per-protocol expectation rather than an exemption, because after report 16 an
exemption is exactly the shape a defect hides in.

## Verification (as filed)

No executable tests were run: this report makes no source change. The finding
is traced from the three checked-in chunk-size parsers and their distinct body
completion paths.

## Conclusion

All three proxy protocols receive the same upstream HTTP/1 chunk syntax, so
they need one acceptance boundary. HTTP/2 currently has a whitespace exception
and an unchecked arithmetic step that the other decoders deliberately avoid.
Mirroring their strict grammar and pre-shift bound makes malformed transfer
framing fail rather than become a successful HTTP/2 response.
