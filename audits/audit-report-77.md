# Audit Report 77

Audited at `3510ab3` (`proxy: an absolute-form target may have an empty path and a query`), 2026-08-27.

Audit report 76's absolute-form query fix is present. The next QUIC boundary is the final-size invariant on already-completed request streams:

1. **Medium: the copy-free HTTP/3 request path forgets a stream's final size after dispatch.**

No production source, configuration, or test files were changed in this audit. Only this report was added.

## Finding 1 — completed offset-0+FIN streams bypass QUIC final-size validation

Severity: **Medium (P2, a peer can send a contradictory FIN or data beyond a previously declared final size without the required connection error)**  
Confidence: **High**  
Status: **Confirmed by source trace; a hand-built 1-RTT packet reproducer is provided below.**

RFC 9000 §4.5 requires an endpoint to fix a stream's final size when it first receives a FIN. A later FIN naming a different size, or stream data extending past that size, is a `FINAL_SIZE_ERROR` transport error. This applies to retransmissions received under new packet numbers as well as to ordinary frames ([RFC 9000 §4.5](https://www.rfc-editor.org/rfc/rfc9000.html#section-4.5)).

Linnea enforces those comparisons only in the HTTP/3 reassembly context. The reassembly path stores `fin`/`final` and checks both repeat FINs and data past the final size ([src/server/linnea_quic_server.asm:2980](/home/linnea/linnea/src/server/linnea_quic_server.asm:2980) through [src/server/linnea_quic_server.asm:3022](/home/linnea/linnea/src/server/linnea_quic_server.asm:3022)).

An offset-0 STREAM frame carrying FIN bypasses that context entirely: `.client_bidi` sends it directly to `.serve_bidi` ([src/server/linnea_quic_server.asm:2612](/home/linnea/linnea/src/server/linnea_quic_server.asm:2612) through [src/server/linnea_quic_server.asm:2639](/home/linnea/linnea/src/server/linnea_quic_server.asm:2639)). Before parsing, `.serve_bidi` checks the served-stream watermark and exits through `.ra_more` when the stream was already dispatched ([src/server/linnea_quic_server.asm:3458](/home/linnea/linnea/src/server/linnea_quic_server.asm:3458) through [src/server/linnea_quic_server.asm:3519](/home/linnea/linnea/src/server/linnea_quic_server.asm:3519)). That duplicate exit occurs before any comparison of the new frame's `offset + length` or FIN final size. The inline path never stores the first frame's final size, so there is no state left against which to validate it.

### Reproduction

Complete one ordinary HTTP/3 GET in a single offset-0 STREAM frame with FIN. Then, using the established 1-RTT send keys, inject a fresh-packet-number STREAM frame for the same stream ID:

```text
1. STREAM(off=0, data=<valid H3 request>, FIN)       -> request is served
2. STREAM(off=0, data=<same request>, FIN)            -> silently ignored
```

For the second packet, change the payload length while retaining FIN (a different final size), or send `STREAM(off=<first final>, data=X, no FIN)`. The server again takes the already-served exit and emits no `FINAL_SIZE_ERROR` (`0x06`). The existing `test/quic/h3_dup_served.py` already supplies the raw fresh-packet-number injection machinery; extending its reinjection frame to one of those two variants reproduces the missing close.

### Impact

The endpoint violates a mandatory transport invariant and diverges from the peer's stream state. A malicious or faulty client can inject arbitrary post-final bytes on every completed request stream without the connection error required by QUIC. Although the duplicate bytes are not dispatched a second time, silently accepting them undermines protocol state validation and can conceal packet/stream corruption from clients and monitoring.

### Recommended fix

Retain receive-side final-size state for the copy-free path (for example in a bounded served-stream record), and run the same `offset + length`/FIN-equality checks before the `req_served_known` early exit. A conflicting FIN or post-final data must close the connection with transport error `0x06`.


## Resolution (2026-08-27) — CONFIRMED, with the scope widened and the severity corrected

### Reproduced

At the audited source, against a live h3 server, injecting a hand-built 1-RTT
packet with the connection's own send keys after an ordinary GET completed:

```
inline: identical retransmission (control)   no close      <- correct
inline: second FIN, smaller final size       no close      <- wanted 0x06
inline: second FIN, larger final size        no close      <- wanted 0x06
inline: data past the final size             no close      <- wanted 0x06
```

The report's source trace is exact: `.serve_bidi` takes the already-served exit
before any offset or FIN comparison, and the copy-free path never stored a final
size to compare against.

### The report calls this a MUST. It is not one

RFC 9000 4.5 ends:

> Once a final size for a stream is known, it cannot change. If a RESET_STREAM
> or STREAM frame is received indicating a change in the final size for the
> stream, an endpoint **SHOULD** respond with an error of type
> FINAL_SIZE_ERROR... A receiver **SHOULD** treat receipt of data at or beyond
> the final size as an error of type FINAL_SIZE_ERROR, even after a stream is
> closed. **Generating these errors is not mandatory**, because requiring that
> an endpoint generate these errors also means that the endpoint needs to
> maintain the final size state for closed streams, which could mean a
> significant state commitment.

So "violates a mandatory transport invariant" (Impact) and "requires ... a
FINAL_SIZE_ERROR transport error" (opening) overstate it: both rules are SHOULD,
and the RFC names this exact scenario -- state for CLOSED streams -- as the
reason. That does not make the finding wrong. It makes it a conformance gap
worth closing rather than a violation, and it decides the shape of the fix.

### ...and it is not the copy-free path

The finding is filed against the copy-free path, and the recommended fix is "for
the copy-free path". Measured on the audited source, a request delivered in TWO
STREAM frames -- reassembled, never near that path -- fails identically:

```
reassembled: second FIN, smaller final size  no close
reassembled: second FIN, larger final size   no close
reassembled: data past the final size        no close
```

The reassembly context does hold `fin`/`final` and does enforce both rules, but
it is released the moment the request is dispatched, taking the only copy of the
final size with it. The defect is not "the copy-free path forgets", it is **a
COMPLETED stream forgets, whichever path received it** -- so the fix belongs
with the served-stream record, which both paths already reach, and not in
`.client_bidi`.

### The fix

A bounded ring on the connection: `fin_sid[16]` / `fin_size[16]`, written once
per stream at the point it is committed to dispatch (the inline path takes the
size from the frame in hand, a reassembled one from the context that is about to
be released), and read by `req_final_check` at the two places a later frame for
that stream can arrive:

- `.serve_bidi`, ahead of every silent exit it has, for an offset-0-with-FIN
  frame; and
- `.ra_alloc`, for anything else -- which is exactly the shape of "data past the
  final size", and where such a frame used to CLAIM a reassembly context for a
  stream that could never finish. A legal partial retransmission now gets acked
  without one.

Sixteen entries, not all of them, deliberately: the RFC makes this a SHOULD
precisely to avoid unbounded per-closed-stream state, so the most recent streams
are checked and older ones are acked exactly as before. 264 bytes per
connection, 66 KB per worker.

### The probe was measuring the wrong party, and said the fix did nothing

The first version of `test/quic/h3_final_size.py` fed the server's replies to
aioquic's connection and waited for a `ConnectionTerminated` event. With the fix
in, every violating row still reported "no close" -- the measurement did not move
at all, which is the signature of a dead check, so I went looking for one. It
was not dead. Tracing each exit of `.client_bidi` showed the duplicate reaching
`.serve_bidi`; instrumenting the ring showed the size stored (24) and found (24);
instrumenting the verdict showed 2, the violation; instrumenting the close showed
`emit_1rtt` returning success. Decrypting the datagrams by hand then showed what
had been on the wire the whole time:

```
32 bytes -> 02 06 00 00 02        an ACK
31 bytes -> 1c 06 08 00           CONNECTION_CLOSE, error 0x06, frame 0x08
```

aioquic had received that packet and reported `ConnectionIdIssued` and nothing
else. The test now decrypts with aioquic's receive keys but does NOT hand the
datagram to its state machine: what is being asserted is what linnea put on the
wire, and asking the client library "were you told?" is asking the wrong party.

One other blind alley worth recording: a probe that padded the injected packet
to a distinctive length, to find it in the server's `qrx` log, appeared to show
that even a VALID injected request was ignored. That was the padding's own
doing, not the server's -- an unpadded injection of the same request was served.
A diagnostic that changes the thing it is measuring is worse than no diagnostic.

### The name I picked was already taken

The new probe went in as `test/quic/h3_final_size.py` -- which already existed,
and which I overwrote. It covers the same RFC section for a stream that is still
being REASSEMBLED: it deliberately holds a gap at offset 0 so the context stays
alive, because the context is where `fin`/`final` live. That is the complement
of this finding, not a duplicate of it, and it is wired into the quic shard.
Restored, and the new one is `h3_final_size_closed.py` -- the two names now say
which side of the serve each is about. `git status` calling the file *modified*
rather than *untracked* is the only reason I noticed.

Their close detection differs, and the difference is real: the existing test's
`ConnectionTerminated` check works because the stream there is still open and
aioquic is still tracking it. Once the request has completed, the same library
receives the same close packet and reports nothing.

### Coverage

Twelve rows, six per receive path, driven from the h3 shard. Against a binary
built from the audited source:

```
pre-fix: inline: second FIN, smaller final size        FAIL
pre-fix: inline: second FIN, larger final size         FAIL
pre-fix: inline: data past the final size              FAIL
pre-fix: reassembled: second FIN, smaller final size   FAIL
pre-fix: reassembled: second FIN, larger final size    FAIL
pre-fix: reassembled: data past the final size         FAIL
pre-fix: inline/reassembled: identical retransmission  PASS  <- controls
pre-fix: inline/reassembled: partial retransmission    PASS  <- controls
```

Half the rows are controls, and they carry the risk. A fix of this kind fails
by being too eager: a peer whose ack was lost retransmits a completed request,
in whole or in part, and that is legal (RFC 9000 13.3). Closing the connection
on it would break real clients far more thoroughly than the gap being fixed
ever could. The partial-retransmission rows are also the only coverage of the
`.ra_alloc` site's non-error path.

tls shard **599 passed, 0 failed**; full suite **1183 passed, 0 failed**.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on BOTH receive paths -- the copy-free one the report names and the
reassembled one it does not -- with the close read off the wire as decrypted
bytes (`1c 06 08 00`) rather than taken from a client library's event stream,
which in this scenario reports nothing. The pre-fix table names which rows the
fix is responsible for; half the rows are legal retransmissions that must NOT
close, which is the failure mode a fix like this actually has.
