# Audit Report 25

Audited at `b5ae900` (`audit-report-24: FIXED`), 2026-08-19.

**NOT REPRODUCIBLE.** The relay path does call the validator, in
`src/server/linnea_uring.asm` rather than `linnea_http.asm`, carrying
`resp_chunk_state` across every later read. Measured rather than argued: the
whole 61-variant corpus was driven through HTTP/1 cut at **every byte offset of
the response** — 4057 splits — and not one malformed body became a clean,
complete 200. The report's own reproduction is a valid extension.

No production change was needed. The report's test recommendation was worth
taking, and the split-write fixtures it asks for are now permanent.

One response-validation bypass remains open:

1. **High: HTTP/1 chunked-response validation stops after the initial buffered
   read.** Later upstream reads enter the normal relay path without calling the
   chunk decoder.

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — Later response reads bypass chunk validation

Severity: **High (P1, malformed response framing forwarded)**  
Confidence: **High**  
Status: **Not reproducible** (see Resolution)

### Evidence

The response-head path records the first body bytes and invokes
`linnea_spill_chunked` in validate mode at
[src/server/linnea_http.asm:4464](/home/linnea/linnea/src/server/linnea_http.asm:4464)
through [:4483](/home/linnea/linnea/src/server/linnea_http.asm:4483). If that
call returns `0` (the chunk line is incomplete and more bytes are needed), the
code nevertheless falls through to `.leftover_ok`, sets `proxy_state` to
`LINNEA_PROXY_RELAY` at [:4484](/home/linnea/linnea/src/server/linnea_http.asm:4484)
through [:4491](/home/linnea/linnea/src/server/linnea_http.asm:4491), and begins
forwarding the original bytes.

The subsequent relay state has no second call to the validator: the only
`LINNEA_CHUNK_VALIDATE` call in the HTTP/1 response implementation is the one
at [:4480](/home/linnea/linnea/src/server/linnea_http.asm:4480). The decoder’s
state is carried in `resp_chunk_state`, but that state is therefore never
advanced for bytes arriving after the first read.

### Reproduction

Have an upstream send the response head and only the beginning of a valid
chunk line, flush it, then send the malformed continuation later:

```text
HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n
4;a=
```

followed in a later write by:

```text
bad\r\nbody\r\n0\r\n\r\n
```

The first validation pass returns “need more”, but the relay has already been
selected. The later bytes are copied to the client without the shared
chunk-extension parser seeing them. The same applies to a bad trailer or data
CRLF split across reads.

### Impact

Whether malformed upstream framing is rejected depends on TCP/read packetization
rather than message bytes. A backend that writes its head and body together is
judged, while one that flushes the head or an incomplete chunk line first can
send the malformed response through HTTP/1. This reopens the cross-protocol and
timing differential that audit-report-24 attempted to close.

### Recommendation

Keep HTTP/1 response relay in a validating state until the terminal chunk and
trailers have been consumed. Every later upstream read must pass through
`linnea_spill_chunked` with the carried `resp_chunk_state` before any bytes are
made client-visible; only validated bytes may be forwarded. Add a split-write
fixture that places the malformed extension, trailer, and data delimiter in a
second upstream write.

### Resolution — NOT REPRODUCIBLE (2026-08-19)

#### The second call exists

```
$ grep -rn LINNEA_CHUNK_VALIDATE src/
src/server/linnea_http.asm:4480:    mov r8d, LINNEA_CHUNK_VALIDATE
src/server/linnea_uring.asm:2501:    mov r8d, LINNEA_CHUNK_VALIDATE
```

The second is in `.relay_data`, the steady-state relay the report describes,
and it runs before any byte of that read is forwarded:

```asm
    cmp qword [r12 + linnea_connection.resp_chunked], 0
    je .relay_framed
    push r15                   ; the completion's byte count
    mov rdi, r12
    lea rsi, [r12 + linnea_connection.up_buf]
    mov edx, r15d
    lea rcx, [r12 + linnea_connection.resp_chunk_state]
    mov r8d, LINNEA_CHUNK_VALIDATE
    call linnea_spill_chunked
    pop r15
    cmp eax, -1
    je .relay_chunk_bad
```

The relay loop lives in `linnea_uring.asm`, not in `linnea_http.asm`, which is
where "the only `LINNEA_CHUNK_VALIDATE` call in the HTTP/1 response
implementation" came from. `.relay_data` and the head-adjacent leftover are the
only two paths that make chunked upstream bytes client-visible on HTTP/1; the
others (`.tunnel_up_recv`, `.closing_u2c`) belong to the post-101 tunnel, which
carries opaque bytes and no chunked framing.

#### The reproduction as filed is a valid message

`4;a=` followed by `bad` reassembles to `4;a=bad`. `chunk-ext-val = token /
quoted-string` (RFC 9112 7.1.1) and `bad` is a token, so that extension is
**valid** and serving it is correct:

```
  /api/asis      HTTP/1.1 200 OK          complete=True   body=b'4;a=bad\r\nbody\r\n0\r\n\r\n'
```

The malformed sibling the report was presumably reaching for — `4;=` then
`bad`, an extension with no name — is refused, and refused as a `502`, because
`4;=` is already malformed in the first write:

```
  /api/noname    HTTP/1.1 502 Bad Gateway complete=False  body=b''
```

#### Measured across every read boundary there is

The interesting case is neither of those: it is a malformation whose first half
is a *valid prefix*, so the decoder must have carried its state out of the head's
read. Three of those, and the valid control beside them, against the binary the
report audited and against the current one:

```
                    before report 24                       now
  chunksplitok    4;a=bad\r\nbody\r\n0\r\n\r\n      4;a=bad\r\nbody\r\n0\r\n\r\n   (valid: whole)
  chunksplitext   4;a,b\r\nbody\r\n0\r\n\r\n        4;a
  chunksplittrail 4\r\nbody\r\n0\r\nNotAField\r\n\r\n 4\r\nbody\r\n0\r\nNot
  chunksplitdata  4\r\nbody\n0\r\n\r\n              4\r\nbody
```

Each now stops at the last valid byte: the malformed continuation is never
forwarded and the message never terminates. That is only possible if the state
crossed the read boundary.

And then exhaustively — every variant in `test/chunkfuzz/variants.py`, cut at
every byte offset of the response including inside the head, with a pause
between the two writes so the halves really do land in separate reads:

```
4057 splits driven, 0 wrong
```

"Wrong" is both directions: a malformed body arriving as a clean complete 200,
or a valid body not arriving whole.

#### What was worth taking from the report

The recommendation. "Add a split-write fixture that places the malformed
extension, trailer, and data delimiter in a second upstream write" was a real
gap in the *tests* — report 24's fixture split the head from a whole body, not
the malformation itself. So:

* `/api/chunksplitext`, `/api/chunksplittrail`, `/api/chunksplitdata` place the
  malformation across the boundary, and `/api/chunksplitok` — this report's own
  bytes — is the control, because a guard that refused every split chunk line
  would pass the other three and fail it.
* `test/h1_chunk_relay.py` drives all four; they fail on a pre-report-24 binary.
* `test/chunkfuzz/splitback.py` and `splitdrive.py` make the exhaustive sweep
  repeatable. The pause between the two writes is the load-bearing part: without
  it both halves arrive as one read on loopback and the sweep silently never
  crosses a boundary.

Full suite: **770 passed, 0 failed**.

#### One thing this cost, worth writing down

The first run of the exhaustive sweep reported 422 failures, all on VALID
variants. The server was right and the driver was wrong: it tested completeness
with `body.endswith(b"0\r\n\r\n")`, which is false for every valid body that
carries a trailer or an extension on its last chunk. **A completeness test that
is really a suffix test will accuse a correct server**, and at that size it
accuses it hundreds of times, which reads like a finding. The driver decodes the
chunked framing properly now.

## Verification

No executable tests were run: this report makes no source change. The finding
is a control-flow trace of the only validator call and the transition into the
steady-state relay loop.

## Conclusion

The report-24 fix protects the common head-plus-body case, but its validator is
one-shot. A chunked response that crosses a read boundary can still bypass the
grammar entirely after the first incomplete pass.

It is not one-shot: the second call is in the relay loop, one file over. The
finding does not stand, and the reproduction it offers is a valid message. What
does stand is the test it asked for — the earlier fixture split the head from a
whole body and never split the malformation itself, so the state carried across
a read boundary was working but unasserted. It is asserted now, at four fixed
points and across all 4057 of them.
