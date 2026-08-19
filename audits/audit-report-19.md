# Audit Report 19

Audited at `819df62` (`audit-report-18: FIXED`), 2026-08-19.

**Fixed in the commit below**, verified against a pre-fix binary. The finding is
correct. Since it is the third consecutive report in this one decoder, the three
neighbouring states were probed as well — all were already right, which is
recorded below so the surface is known to be closed rather than assumed.

One response-framing issue remains open:

1. **High: HTTP/2 accepts a bare LF inside an upstream chunk extension.** Its extension scanner skips every byte until a later CR, whereas the HTTP/3 and HTTP/1 chunk parsers reject LF before that CR. HTTP/2 therefore turns malformed transfer coding into a completed `200` response that HTTP/3 rejects and HTTP/1 relays as malformed syntax.

No production source, configuration, or test files were changed in this audit. Only this report was added.

This is a source-trace audit against the stated baseline. The reproduction is a
minimal backend fixture and the control flow it reaches; it is not presented as
a capture from a modified backend.

## Finding 1 — HTTP/2's chunk-extension scanner permits bare LF

Severity: **High (P1, response framing integrity and protocol differential)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

`h2p_decode` moves to `.dec_size_ext` at the semicolon that starts a chunk
extension. That state stops only at CR and otherwise advances unconditionally:

```asm
.dec_size_ext:
    cmp byte [r12 + rcx], 13
    je .dec_size_eol
    inc rcx
    jmp .dec_size_ext
```

at [src/server/linnea_http2.asm:4205](/home/linnea/linnea/src/server/linnea_http2.asm:4205) through
[:4212](/home/linnea/linnea/src/server/linnea_http2.asm:4212). A LF in the
extension is consequently consumed as ordinary extension data. When a later
CRLF arrives, `.dec_size_eol` accepts the line and starts copying the declared
chunk at [:4213](/home/linnea/linnea/src/server/linnea_http2.asm:4213) through
[:4226](/home/linnea/linnea/src/server/linnea_http2.asm:4226).

The HTTP/3 capture path calls `linnea_spill_chunked` at
[src/server/linnea_h3_proxy.asm:980](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:980) through
[:989](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:989). Its matching
extension state explicitly rejects a LF before the CR:

```asm
cmp byte [r12], 10
je .bad
```

at [src/server/linnea_spill.asm:241](/home/linnea/linnea/src/server/linnea_spill.asm:241) through
[:247](/home/linnea/linnea/src/server/linnea_spill.asm:247). The HTTP/1 request
decoder applies the same rule at
[src/server/linnea_http.asm:4570](/home/linnea/linnea/src/server/linnea_http.asm:4570) through
[:4578](/home/linnea/linnea/src/server/linnea_http.asm:4578).

This is not merely a request-side comparison. The response paths use these
different decoders for the same upstream bytes: HTTP/2 sets
`F_BODY_DONE` and services the exchange when de-chunking succeeds at
[src/server/linnea_http2.asm:3197](/home/linnea/linnea/src/server/linnea_http2.asm:3197) through
[:3203](/home/linnea/linnea/src/server/linnea_http2.asm:3203), while HTTP/3
maps the spill decoder's negative result to a gateway failure. HTTP/1 relays
the upstream transfer coding verbatim rather than decoding it.

### Reproduction

An upstream needs only return this response:

```text
HTTP/1.1 200 OK\r\n
Transfer-Encoding: chunked\r\n
\r\n
4;note\ncontinued\r\n
body\r\n
0\r\n
\r\n
```

The LF after `note` is not part of a CRLF line ending. A chunk-extension is
terminated by CRLF; the later CRLF does not make an embedded LF valid.

| Downstream protocol | Current result |
| --- | --- |
| HTTP/1.1 | relays malformed chunk syntax |
| HTTP/2 | completed `200`, body `body` |
| HTTP/3 | 502 |

### Impact

The same invalid transfer coding has different client-visible meaning by ALPN.
HTTP/2 silently normalizes it to an ordinary successful response, while HTTP/3
refuses it and HTTP/1 leaves it for a downstream parser to reject. A malicious
or faulty backend can therefore choose whether malformed response framing is
accepted simply by which protocol the client negotiated.

This is adjacent to reports 17 and 18 but distinct from their repaired states:
the size digits, arithmetic, data CRLF, and trailer terminator may all be valid.
The unchecked byte is in the size-line extension scan, before the decoder
commits to consuming the body.

### Recommendation

Make `.dec_size_ext` mirror `linnea_spill_chunked` and `chunked_decode`: after
the CR check, reject byte `10` before advancing. Retain the existing final
CRLF check and the project’s current policy of ignoring otherwise valid chunk
extensions.

Add `/api/chunkextlf` to the upstream-head matrix, with the fixture above.
HTTP/2 and HTTP/3 should fail the malformed exchange (a 502 if no response
head has been emitted, otherwise an HTTP/2 reset); HTTP/1 may remain documented
as the raw streaming path. Keep a chunk with a normal extension such as
`4;note=ok\r\nbody\r\n0\r\n\r\n` as the control.

### Resolution — FIXED (2026-08-19)

Confirmed as traced, and the fix is the recommended two instructions:
`.dec_size_ext` rejects byte `10` before advancing, exactly as
`linnea_spill_chunked` and `chunked_decode` do. The existing final CRLF check
and the policy of ignoring otherwise valid extensions are unchanged.

The report's framing of the principle is the durable part: **a chunk extension
may be ignored as metadata, but its line framing may not.**

### The neighbouring states, probed rather than assumed

This is the third consecutive finding in `h2p_decode`, so the rest of its
LF handling was measured instead of trusted:

| fixture | position of the bare LF | result |
| --- | --- | --- |
| `/api/chunkextlf` | inside the chunk extension | h2 `200` → **`502`** — the finding |
| `/api/chunkdatalf` | where the data's CRLF belongs | `502` / `502`, already correct |
| `/api/chunktraillf` | where a trailer line starts | h2 resets, h3 `502`, already correct |
| `/api/chunkext` | none — a valid extension | `200` / `200`, untouched |

So the extension scan was the last hole. The size line already rejects non-hex,
the data CRLF is checked, and the trailer states added for report 18 already
reject a bare LF. All four are fixtures now, so the whole LF-in-chunk-framing
surface is covered rather than the single byte position that happened to be
reported — and `/api/chunkext` is the control that stops the rule becoming
"reject extensions".

Control against a pre-fix binary: exactly one route fails. After: **226 checks
green**. Full suite **767 passed, 0 failed**.

## Verification (as filed)

No executable tests were run: this report makes no source change. The finding
is traced from the three checked-in chunk-extension parsers and their response
completion paths.

## Conclusion

Chunk extensions may be ignored as metadata, but their line framing cannot be.
HTTP/2 currently skips an embedded LF that the other two decoders deliberately
reject, converting malformed upstream bytes into a completed response. Giving
the extension scan the same LF rejection restores the shared acceptance
boundary.
