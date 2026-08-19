# Audit Report 20

Audited at `088a502` (`audit-report-19: FIXED`), 2026-08-19.

**Fixed in the commit below**, verified against a pre-fix binary. The finding is
correct, and so is its criticism of report 19's neighbourhood probe — that
criticism is recorded below, because the testing lesson outlasts the two-line
fix.

One response-framing issue remains open:

1. **High: the HTTP/2 and HTTP/3 de-chunkers accept a bare LF embedded in a non-empty trailer line.** Both trailer-line scanners skip all bytes until a later CR, so an invalid trailer section is accepted as a completed response. HTTP/1 relays those malformed bytes rather than validating them.

No production source, configuration, or test files were changed in this audit. Only this report was added.

This is a source-trace audit against the stated baseline. The reproduction is a
minimal backend fixture and the control flow it reaches; it is not presented as
a capture from a modified backend.

## Finding 1 — Trailer-line scanners skip embedded LF

Severity: **High (P1, response framing integrity and protocol differential)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

After a zero-size chunk, HTTP/2 enters its trailer states. A non-empty trailer
line reaches `.dec_trail_line`, which searches only for CR and advances over
every other byte:

```asm
.dec_trail_line:
    cmp byte [r12 + r13], 13
    je .dec_trail_cr
    inc r13
    jmp .dec_trail_line
```

at [src/server/linnea_http2.asm:4259](/home/linnea/linnea/src/server/linnea_http2.asm:4259) through
[:4265](/home/linnea/linnea/src/server/linnea_http2.asm:4265). It does not
test for byte `10`. A later CRLF is accepted at [:4266](/home/linnea/linnea/src/server/linnea_http2.asm:4266)
through [:4277](/home/linnea/linnea/src/server/linnea_http2.asm:4277), and the
subsequent empty line sets `F_BODY_DONE` at [:4278](/home/linnea/linnea/src/server/linnea_http2.asm:4278)
through [:4286](/home/linnea/linnea/src/server/linnea_http2.asm:4286).

HTTP/3 uses `linnea_spill_chunked`. Its matching `LINNEA_CHUNK_TRAIL_LINE`
state has the same scan-until-CR rule at
[src/server/linnea_spill.asm:314](/home/linnea/linnea/src/server/linnea_spill.asm:314) through
[:322](/home/linnea/linnea/src/server/linnea_spill.asm:322), before accepting
the following LF and eventually setting DONE at [:323](/home/linnea/linnea/src/server/linnea_spill.asm:323)
through [:334](/home/linnea/linnea/src/server/linnea_spill.asm:334). The
HTTP/1 request-side `chunked_decode` has the same omission at
[src/server/linnea_http.asm:4622](/home/linnea/linnea/src/server/linnea_http.asm:4622) through
[:4636](/home/linnea/linnea/src/server/linnea_http.asm:4636).

The `/api/chunktraillf` control added with report 19 does not exercise this
case. Its body ends `0\r\n\n`: the lone LF is followed by EOF, so both
incremental decoders remain in their unfinished trailer-line state and fail at
EOF. It proves completion is not triggered by that byte alone; it does not
prove the scanner rejects it. Placing a later CRLF after the LF lets the code
above consume the LF as ordinary trailer data and complete normally.

HTTP/2 services a decoder-success response at
[src/server/linnea_http2.asm:3197](/home/linnea/linnea/src/server/linnea_http2.asm:3197) through
[:3203](/home/linnea/linnea/src/server/linnea_http2.asm:3203). HTTP/3 treats a
successful spill decode as a complete response at
[src/server/linnea_h3_proxy.asm:980](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:980) through
[:992](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:992). HTTP/1's
response path does not de-chunk and relays the raw transfer coding until close
at [src/server/linnea_uring.asm:2451](/home/linnea/linnea/src/server/linnea_uring.asm:2451) through
[:2455](/home/linnea/linnea/src/server/linnea_uring.asm:2455).

### Reproduction

An upstream needs only return:

```text
HTTP/1.1 200 OK\r\n
Transfer-Encoding: chunked\r\n
\r\n
4\r\n
body\r\n
0\r\n
X-Trail: one\n
continued\r\n
\r\n
```

The LF after `one` is embedded in a trailer field line; it is not a CRLF line
ending. A trailer section consists of HTTP field lines, so an embedded LF makes
the upstream chunked message malformed even if a later CRLF occurs.

| Downstream protocol | Current result |
| --- | --- |
| HTTP/1.1 | relays malformed chunk syntax |
| HTTP/2 | completed `200`, body `body` |
| HTTP/3 | completed `200`, body `body` |

### Impact

The proxy converts an invalid HTTP/1 transfer-coded response into successful
HTTP/2 and HTTP/3 responses, while HTTP/1 leaves the invalid syntax exposed to
the downstream parser. The accepted bytes are in discarded trailer metadata,
but they still delimit the message the proxy is validating; accepting them
breaks the one upstream acceptance boundary established by reports 17–19.

It also shows why the report-19 neighbourhood probe was insufficient: checking
only an LF followed by EOF tests truncation, whereas checking an LF followed by
a later CRLF tests the parser's character-class rule.

### Recommendation

Make each trailer-line scan reject byte `10` before advancing:

- `.dec_trail_line` in `h2p_decode`;
- `.s_trail_line` in `linnea_spill_chunked`;
- `.cd_trailer_line` in `chunked_decode`.

Also consider validating trailer lines as HTTP field lines (at least a token
name, colon, and no forbidden control bytes) before dropping them, so the
proxy's acceptance rule is not limited to CRLF shape alone.

Add `/api/chunktrailinlinelf` with the fixture above. HTTP/3 should answer 502;
HTTP/2 should reset after its already-emitted head; HTTP/1 should remain marked
as raw streaming. Keep `/api/chunktrailer` as the valid non-empty-trailer
control, and retain `/api/chunktraillf` as the distinct EOF/truncation control.

### Resolution — FIXED (2026-08-19)

Confirmed, and it reaches further than reports 17–19 did: those were HTTP/2
only, whereas `/api/chunktrailinlinelf` was accepted by **HTTP/2 and HTTP/3
alike** (`200` / `200`). Three scanners shared the omission and all three now
reject byte `10` before advancing — `.dec_trail_line`, `.s_trail_line`, and
`.cd_trailer_line`.

The third is the **request** path, so it was checked directly rather than left
to the suite: a chunked upload with no trailer gives `200`, with a valid trailer
`200`, and with an embedded LF `400` — a malformed request rather than a bad
gateway, which is the right code on that side.

`chunktraillf` moves from `PROTOCOL_SPECIFIC` to `STREAMED_BODY`, because HTTP/2
now refuses it before emitting a head and no longer needs the reset-based
assertion.

### The testing lesson, which outlasts the fix

The report is right that report 19's probe was insufficient, and right about
why. I wrote that the LF surface was "known-closed rather than assumed" — but
`/api/chunktraillf` is `0\r\n\n`, an LF followed by **EOF**. Both incremental
decoders stayed in an unfinished trailer state and failed on *truncation*. The
fixture passed, which is exactly why I trusted the probe.

```
LF then EOF           tests TRUNCATION       -- a decoder that ignores LF still fails
LF then a later CRLF  tests the CHARACTER CLASS -- only this reaches the scanner
```

Both fixtures now exist, and each is labelled with the property it proves. The
general form: **when testing that a parser rejects a byte, the byte must be
followed by input that would otherwise be valid.** Terminating the input instead
tests the error path you did not mean to test, and passes.

Control against a pre-fix binary: both routes fail, `chunktrailinlinelf` on all
three protocols. After: **229 checks green**. Full suite **767 passed, 0
failed**.

## Verification (as filed)

No executable tests were run: this report makes no source change. The finding
is traced from the checked-in HTTP/2, HTTP/3, and HTTP/1 trailer parsers and
their response completion paths.

## Conclusion

The trailer states now wait for a trailer section, but their non-empty-line
scanners still accept LF as field data. Rejecting embedded LF in all three
decoders makes malformed trailer framing fail instead of becoming a completed
HTTP/2 or HTTP/3 response.
