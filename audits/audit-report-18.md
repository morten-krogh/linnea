# Audit Report 18

Audited at `6d4bbb1` (`audit-report-17: FIXED, plus a worse h3 defect found beside it`), 2026-08-19.

**Fixed in the commit below**, verified against a pre-fix binary. The finding is
correct, including its note about why the defect survived normal fixtures — that
note is now a permanent control.

One response-framing issue remains open:

1. **High: HTTP/2 treats the zero-size chunk line itself as the end of a chunked upstream response.** It does not require the terminating empty trailer line and does not consume trailer bytes. A backend can therefore close after `0\r\n` (or send malformed trailer bytes), and HTTP/2 emits a clean completed response while HTTP/3 refuses the same incomplete message.

No production source, configuration, or test files were changed in this audit. Only this report was added.

This is a source-trace audit against the stated baseline. The reproduction is a
minimal backend fixture and the control flow it reaches; it is not presented as
a capture from a modified backend.

## Finding 1 — HTTP/2 completes before the chunked trailer section

Severity: **High (P1, response framing integrity and protocol differential)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

The HTTP/2 upstream decoder says that phase 4 is for “trailers/end” at
[src/server/linnea_http2.asm:4141](/home/linnea/linnea/src/server/linnea_http2.asm:4141), but no parser exists for that phase. After parsing a zero-size
line, `.dec_last` simply switches `chunked` to phase 4 and sets
`LINNEA_H2P_F_BODY_DONE`:

```asm
.dec_last:
    mov qword [rbx + linnea_h2p.chunked], 4
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_BODY_DONE
```

at [:4211](/home/linnea/linnea/src/server/linnea_http2.asm:4211) through
[:4214](/home/linnea/linnea/src/server/linnea_http2.asm:4214). On the next
decode call, phase 4 goes straight to `.dec_save` at
[:4145](/home/linnea/linnea/src/server/linnea_http2.asm:4145) through
[:4153](/home/linnea/linnea/src/server/linnea_http2.asm:4153); it neither
waits for nor validates the trailer section's final empty line.

The event path treats `F_BODY_DONE` as sufficient to service the response at
[:3197](/home/linnea/linnea/src/server/linnea_http2.asm:3197) through
[:3203](/home/linnea/linnea/src/server/linnea_http2.asm:3203). The H2 scheduler
then marks the client stream ended as soon as all decoded body bytes have been
framed, including with an empty final DATA frame if necessary, at
[:5042](/home/linnea/linnea/src/server/linnea_http2.asm:5042) through
[:5055](/home/linnea/linnea/src/server/linnea_http2.asm:5055).

HTTP/3 uses the incremental `linnea_spill_chunked` decoder through
[src/server/linnea_h3_proxy.asm:980](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:980) through
[:989](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:989). Its zero-size
line enters `LINNEA_CHUNK_TRAIL`, not DONE, at
[src/server/linnea_spill.asm:253](/home/linnea/linnea/src/server/linnea_spill.asm:253) through
[:264](/home/linnea/linnea/src/server/linnea_spill.asm:264). Only an empty
trailer line reaches `LINNEA_CHUNK_DONE` at [:330](/home/linnea/linnea/src/server/linnea_spill.asm:330)
through [:334](/home/linnea/linnea/src/server/linnea_spill.asm:334). At EOF,
the HTTP/3 leg explicitly requires that DONE state for a captured chunked body
and otherwise answers 502 at
[src/server/linnea_uring.asm:2389](/home/linnea/linnea/src/server/linnea_uring.asm:2389) through
[:2394](/home/linnea/linnea/src/server/linnea_uring.asm:2394).

HTTP/1 does not de-chunk upstream responses. It relays a chunked body as raw
bytes and considers the connection close the end of its own relay at
[src/server/linnea_uring.asm:2451](/home/linnea/linnea/src/server/linnea_uring.asm:2451) through
[:2455](/home/linnea/linnea/src/server/linnea_uring.asm:2455), leaving its
client to discover that the chunked syntax is incomplete.

### Reproduction

An upstream needs only return this response and close immediately after the
last shown byte:

```text
HTTP/1.1 200 OK\r\n
Transfer-Encoding: chunked\r\n
\r\n
4\r\n
body\r\n
0\r\n
```

`0\r\n` is the zero-size chunk line; it is not the end of the chunked message.
The required empty trailer line (`\r\n`) is missing. The same issue occurs if
the backend sends a malformed or partial trailer after that line, because H2
has already declared the body complete.

| Downstream protocol | Current result |
| --- | --- |
| HTTP/1.1 | relays the incomplete chunk syntax, then closes |
| HTTP/2 | completed `200`, body `body` |
| HTTP/3 | 502 |

### Impact

The proxy accepts an incomplete transfer-coded response on HTTP/2 and changes
it into a normal end-of-stream. That is the same fundamental failure mode as
the truncated-body defects resolved in report 17: a client sees a successful,
complete representation even though the upstream response has not reached its
message boundary. It also leaves the three ALPN paths with incompatible
acceptance rules for the same upstream bytes.

The defect is particularly easy to miss because a normal `0\r\n\r\n` fixture
passes: H2 stops one CRLF too early and simply ignores the bytes that happen to
make the fixture valid.

### Recommendation

Give `h2p_decode` explicit trailer states equivalent to
`linnea_spill_chunked`:

- after the zero-size line, require a CRLF-terminated trailer section;
- set `F_BODY_DONE` only after the empty trailer line;
- reject a bare LF and an EOF in every unfinished trailer state.

Add upstream fixtures for `/api/chunknoterm` (`4\r\nbody\r\n0\r\n`, then
close) and a partial/malformed trailer. HTTP/3 should remain 502; HTTP/2 should
fail before its response head is emitted or reset the stream after it, never
end it cleanly. Keep normal empty and non-empty trailer sections as controls.

### Resolution — FIXED (2026-08-19)

Confirmed as traced. `h2p_decode` now has real trailer states, mirroring
`linnea_spill_chunked` — the decoder HTTP/3 uses, and the one that was already
right: at the start of a trailer line, inside one, the LF after it, the LF that
ends the whole body, done. `F_BODY_DONE` is set only at the last of those.

```
                     before                  after
chunknoterm          h2 200, clean end       h2 200 + RST_STREAM,  h3 502
chunkpartialtrail    h2 200, clean end       h2 200 + RST_STREAM,  h3 502
chunktrailer         h2 200                  h2 200 (unchanged)
```

**The EOF half needed no change, which is itself worth recording.** HTTP/2
already routes `chunked != 0` at EOF to `.ev_bad_gateway`, with a comment from
Finding 31 describing this precise hazard. It simply never had a state that
*stayed* unfinished, because phase 4 meant "done". Giving the phases their real
meaning made the existing guard start working — a guard that cannot fire looks
exactly like a guard that passes.

`/api/chunktrailer` — a complete message carrying an actual trailer field — is a
permanent control rather than a regression test: it passes before and after. The
report's own explanation of why the defect survived is the reason it must exist.
A normal `0\r\n\r\n` body passes either way, because the decoder stopped one CRLF
early and ignored the very bytes that made the fixture valid.

`chunknoterm` and `chunkpartialtrail` join `chunktrunc` in the matrix's
`PROTOCOL_SPECIFIC` set and are asserted on their own terms: HTTP/3 must answer
502, HTTP/2 must **reset** the stream rather than end it cleanly. HTTP/2 has
already sent its head by the time the truncation is knowable, so a 502 is not
available to it — that is protocol, not laxity.

Control against a pre-fix binary: both new routes fail with `h2_reset=False`.
After: **214 checks green**. Full suite **767 passed, 0 failed**.

## Verification (as filed)

No executable tests were run: this report makes no source change. The finding
is traced from the checked-in HTTP/2 decoder, HTTP/3 capture decoder, and their
completion paths.

## Conclusion

A zero-size chunk starts the trailer section; it does not complete a chunked
message by itself. HTTP/2 currently collapses those two boundaries, converting
an incomplete upstream response into a clean end-of-stream. Matching the
existing HTTP/3 state machine restores one acceptance boundary across the
de-chunking paths.
