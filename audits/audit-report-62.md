# Audit Report 62

Audited at `a2eace6`, 2026-08-26.

Audit report 61's HPACK dynamic-table placement check is now present in the
backend response decoder. The next response-semantics gap is the prohibited
HTTP/2 status code `101`:

1. **Low: a backend HTTP/2 response containing `:status 101` is accepted as
   an informational response and discarded instead of being rejected.**

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — backend HTTP/2 accepts the forbidden 101 Switching Protocols status

Severity: **Low (P3, a malformed upstream response is silently normalized)**  
Confidence: **High**  
Status: **Confirmed as filed and reproduced.** Fixed. A neighbour surfaced
while probing — `content-length` in a 1xx — is measured, has no consequence
here, and is deliberately left accepted; see Resolution.

HTTP/2 does not support the `101 (Switching Protocols)` informational status
code. RFC 9113 §8.6 states that its semantics do not apply to a multiplexed
protocol, and §8.8.5 expressly describes informational responses as 1xx
statuses *other than* 101. A backend that sends `:status 101` on an HTTP/2
stream therefore sends a response that this intermediary must not accept or
translate.

The backend response classifier currently treats every status from 100 through
199 identically. After decoding a completed response field block, it checks
only whether a final response has already arrived, then accepts any status in
that range as informational when the opening HEADERS frame does not carry
END_STREAM ([src/server/linnea_h2_client.asm:2527](/home/linnea/linnea/src/server/linnea_h2_client.asm:2527)
through [:2573](/home/linnea/linnea/src/server/linnea_h2_client.asm:2573)).
There is no `101` exception before the `100..199` branch.

The status emitter has already validated that `:status` is exactly three
digits, but that is only syntax and range preparation; it does not reject the
HTTP/2-prohibited value ([src/server/linnea_h2_client.asm:1924](/home/linnea/linnea/src/server/linnea_h2_client.asm:1924)
through [:1971](/home/linnea/linnea/src/server/linnea_h2_client.asm:1971)).
Consequently, a validly encoded `:status 101` reaches the classifier as the
integer 101.

This is a backend-leg omission, not a claim that every Linnea HTTP/2 path
misses the rule. The frontend HTTP/2 response parser already rejects an
upstream HTTP/1 status of 101 before treating other 1xx values as interim
([src/server/linnea_http2.asm:4824](/home/linnea/linnea/src/server/linnea_http2.asm:4824)
through [:4835](/home/linnea/linnea/src/server/linnea_http2.asm:4835)). The
separate H2 client used by `proxy_h2` and by the backend-H2 harness does not
share that status gate; it uses `h2c_classify_block` through both its blocking
and resumable response drivers.

### Reproduction

Have the backend send a legal connection preface and this stream-1 sequence:

```text
HEADERS  END_HEADERS, no END_STREAM, :status 101
HEADERS  END_HEADERS, no END_STREAM, :status 200,
         content-length: 4
DATA     END_STREAM, payload = "body"
```

The first HEADERS block is invalid solely because its status is 101. The
current classifier sees 101 in the 100..199 interval, confirms that it does
not end the stream, restores/discards that block, and continues reading. It
then accepts the final 200 and relays the body as if the backend had sent a
legal informational sequence.

The same result occurs if the 101 field block is fragmented across
HEADERS/CONTINUATION, because the classifier runs after the combined block is
decoded. A 103-then-200 control must remain legal. A 101 block with
END_STREAM happens to fail through the generic “1xx cannot end the stream”
check, but that does not cover the prohibited and otherwise well-formed
non-END_STREAM form above.

### Impact

This is not a client-controlled status injection: the backend supplies the
response. It is nevertheless a protocol-boundary failure. Linnea silently
removes a status code that a strict HTTP/2 peer would reject, then exposes the
later response as the result. A faulty or compromised backend can therefore
make an invalid response sequence appear to be a legal interim-response
chain, and any backend-side observer disagrees with the response Linnea
relays.

If the backend intended an HTTP/1 upgrade, accepting and dropping the 101 is
especially misleading: HTTP/2 has no Upgrade-based protocol switch on this
stream, and the backend-H2 leg cannot turn that status into the HTTP/1 tunnel
path. It should fail the exchange rather than silently continue.

### Recommended fix

In the shared `h2c_classify_block` status classification, reject exactly 101
before the general 1xx informational branch. Keep the existing END_STREAM
check for the other informational statuses and preserve the legal 100, 103,
and other non-101 interim cases.

Add backend fixtures for a 101 block without END_STREAM followed by a 200, a
101 block split across CONTINUATION, a 101 block with END_STREAM, and legal
103-then-200 and single-200 controls. Assert failure in the blocking harness,
the resumable driver, and end to end through `proxy_h2`; verify that no
client-facing final response is produced for either 101 shape.

## Verification

The finding is a source-level trace through the backend `:status` emitter,
the common response classifier, and both backend-H2 drivers, contrasted with
the existing frontend HTTP/2 101 rejection. The classifier's informational
range still has no special case for 101. `make -j4` completed with no work
required. No production source, configuration, or test file was changed in
this audit.

References:

- [RFC 9113 §8.6 — The Upgrade Header Field](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.6)
- [RFC 9113 §8.8.5 — Informational Responses](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.8.5)

## Resolution (2026-08-26) — CONFIRMED as filed

### Reproduced

Both parsers, at the audited commit:

```
/interim-101       101 (no END_STREAM), then 200 + body  ->  200 OK
/interim-101-cont  the same 101 split across CONTINUATION ->  200 OK
/interim-101-es    101 WITH END_STREAM                    ->  H2C-FAIL
/interim           103, then 200                          ->  200 OK  <- control
/interim-two       103, 100, then 200                     ->  200 OK  <- control
```

Exactly as filed, including the report's own caveat: the END_STREAM form was
already refused, by the generic "a 1xx cannot end the stream" rule rather than
by anything about 101. Right outcome, wrong reason — it is a control here, and
the row that proves this fix is `/interim-101`, where the block is otherwise
perfectly well formed.

### The reference client, and the error class

nghttp2 1.66.0 as a client, given `:status 101` in a response:

```
[ERROR] Invalid HTTP header field was received: ... name: [:status], value: [101]
        error_code=PROTOCOL_ERROR(0x01)
```

and it serves 103 normally.

### The fix

One comparison in `h2c_classify_block`, ahead of the 100..199 branch. The
frontend has refused the same status from an h1 upstream since its own Finding
30, and the comment there already says why in almost these words: "101 has no
meaning over an h2 proxy". This is the seventh report running whose root is a
rule this server enforces in one direction and not the other.

### A neighbour, measured and deliberately NOT fixed

While putting 103 to nghttp2 I sent a `content-length` alongside it, and
nghttp2 refused *that* — RFC 9110 8.6 says a server must not send
`content-length` in a 1xx. So I measured our leg:

```
/interim-clen   103 + content-length: 6, then 200 + 20 bytes
                -> 200 OK, content-length: 20     (both parsers)
```

We accept it, and the interim's declaration is correctly discarded — the final
response's own length is what is relayed, because report 58's per-block save
and restore already keeps a non-final block's `content-length` away from the
assertion. There is no measured consequence.

Refusing it would be a strictness decision, not a defect fix: it would make a
backend that attaches a harmless `content-length` to a 103 unusable, and the
rule it breaks is addressed to the sender. It is left accepted, with the
fixture route kept so the behaviour is pinned and a later change has to mean
it. Naming it here rather than silently fixing or silently ignoring it.

### Coverage

Twelve rows: three refusals and two legality controls on each parser, plus two
end to end. Against a binary built from the audited source, **5 fail and 7 pass
as controls**.

Full suite **1056 passed, 0 failed**, including the 8 h1 WebSocket rows — 101 remains
correct where it belongs, on the HTTP/1 upgrade path, which is a different leg
entirely.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the blocking oracle and the resumable driver, and end to end through
a real `proxy_h2` front. The rule and its error class were put to nghttp2 as a
client. The legal interim rows are asserted on both parsers, so a fix that
rejected 1xx generally rather than 101 specifically fails the controls.
