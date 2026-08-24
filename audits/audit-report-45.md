# Audit Report 45

Audited at `10e9ac9`, 2026-08-24.

Audit report 44's response-block ordering fix is present, including refusal of
post-final informational blocks, missing `:status`, and DATA before the
response head. One frame-level backend HTTP/2 validation gap remains:

1. **Low: the backend driver accepts `CONTINUATION` without a preceding open
   header block, and accepts interleaved frames while a block is open.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — backend header-block frame sequencing is not enforced

Severity: **Low (P3, malformed-upstream acceptance)**  
Confidence: **High**  
Status: **Confirmed as filed** (see Resolution) — both sequences reproduce.
Fixed with an explicit header-block-open state in both dispatchers.

HTTP/2 requires a CONTINUATION frame to immediately follow a HEADERS or prior
CONTINUATION frame whose header block has not yet carried END_HEADERS, on the
same stream. No other frame may be interleaved
([RFC 9113 §6.10](https://www.rfc-editor.org/rfc/rfc9113#section-6.10)).

The backend driver has no state recording that a header block is open. Its
HEADERS path appends a fragment and simply returns when END_HEADERS is absent
([src/server/linnea_h2_client.asm:2419](/home/linnea/linnea/src/server/linnea_h2_client.asm:2419)
through [:2445](/home/linnea/linnea/src/server/linnea_h2_client.asm:2445)). The
CONTINUATION path unconditionally appends its payload and, on END_HEADERS,
passes the accumulated bytes to the response classifier
([src/server/linnea_h2_client.asm:2458](/home/linnea/linnea/src/server/linnea_h2_client.asm:2458)
through [:2480](/home/linnea/linnea/src/server/linnea_h2_client.asm:2480)). It
never checks whether a HEADERS/CONTINUATION sequence is in progress, whether
the stream matches an opener, or whether the previous frame was allowed to be
followed by CONTINUATION.

The blocking helper has the same unconditional `.cont` branch
([src/server/linnea_h2_client.asm:1178](/home/linnea/linnea/src/server/linnea_h2_client.asm:1178)
through [:1243](/home/linnea/linnea/src/server/linnea_h2_client.asm:1243)).
Because its main loop also dispatches PING before CONTINUATION
([src/server/linnea_h2_client.asm:1147](/home/linnea/linnea/src/server/linnea_h2_client.asm:1147)
through [:1177](/home/linnea/linnea/src/server/linnea_h2_client.asm:1177), a
PING can be accepted between an unfinished HEADERS block and its continuation.
The resumable parser dispatches every complete frame in arrival order without
an equivalent sequencing gate
([src/server/linnea_h2_client.asm:2247](/home/linnea/linnea/src/server/linnea_h2_client.asm:2247)
through [:2306](/home/linnea/linnea/src/server/linnea_h2_client.asm:2306)).

### Reproduction

Send this malformed response on backend stream 1, where the CONTINUATION
payload is a complete HPACK response header block:

```text
CONTINUATION  END_HEADERS, payload = :status 200 + content-type
DATA          END_STREAM, payload = "body"
```

The driver appends the first frame's payload, classifies it as the final
response header section because `hdr_done` is still clear, then accepts the
DATA and returns a successful 200 response. A CONTINUATION without an open
header block must instead fail the backend exchange.

A second malformed sequence demonstrates the interleaving gap:

```text
HEADERS       no END_HEADERS, payload = first half of :status block
PING          valid eight-byte payload
CONTINUATION  END_HEADERS, payload = remaining header block
DATA          END_STREAM
```

The PING is acknowledged and the continuation is still joined to the prior
fragment, even though RFC 9113 requires the CONTINUATION to be the immediately
following frame. The existing backend fixture only emits legal HEADERS and
CONTINUATION sequences. The frontend-side frame test does cover this rule for
client input — it explicitly asserts “CONTINUATION not preceded by HEADERS”
([test/tls/h2_error_codes.py:128](/home/linnea/linnea/test/tls/h2_error_codes.py:128)
through [:132](/home/linnea/linnea/test/tls/h2_error_codes.py:132) — but there
is no equivalent backend-response check.

This is not a client-controlled cross-request disclosure: the backend leg is
single-stream and a normal configured backend is expected to speak valid H2.
It is nevertheless a protocol-validation defect that lets malformed upstream
frames become a response the client believes was valid, contrary to the
project's stated policy of refusing malformed upstream responses
([docs/security.md:24](/home/linnea/linnea/docs/security.md:24)
through [:30](/home/linnea/linnea/docs/security.md:30)).

### Recommended fix

Track an explicit per-leg `header_block_open` state and opener stream. Set it
when a stream-1 HEADERS frame lacks END_HEADERS; while set, require the next
frame to be a stream-1 CONTINUATION and reject every interleaved frame. Clear
it when END_HEADERS arrives. Reject CONTINUATION when the state is clear, and
never classify its payload as a response block on its own.

Apply the same state machine to the blocking helper. Add backend-fixture cases
for CONTINUATION-first and HEADERS/PING/CONTINUATION interleaving, asserting a
gateway failure and a working subsequent request. Keep the legal fragmented
trailer and informational controls unchanged.

## Verification

The finding is a source-level trace through both backend-H2 response loops and
the resumable frame dispatcher. `make -j4` completed with no work required.
Existing backend coverage exercises legal fragmented trailers only and has no
CONTINUATION-first or interleaving case; the frontend frame suite's matching
negative case does not exercise this backend client. Runtime socket reproduction
was not available in this restricted environment, and no source change was
made that required executable verification.

## Resolution (2026-08-24) — CONFIRMED as filed, both sequences

### Both reproduce

At `10e9ac9`, on the resumable driver, on the blocking oracle, and end to end
through a `proxy_h2` front:

```
/cont-first        CONTINUATION END_HEADERS (a whole header block), then DATA
                   -> HTTP/1.1 200 OK, "body"

/cont-interleaved  HEADERS (block left open), PING, CONTINUATION END_HEADERS, DATA
                   -> HTTP/1.1 200 OK, "body"
```

A CONTINUATION arriving out of nowhere was decoded as though it were the
response header section, because `hdr_done` was still clear and nothing else
distinguishes "the first completed block" from "a block that was never opened".
And a PING between a HEADERS and its continuation was answered and stepped over,
because the driver had no state saying a block was in progress at all.

### Two more sequences, already refused — but by accident

Probing the rest of the rule found two the driver already rejected:

```
/cont-data-between   HEADERS (open), DATA, CONTINUATION, DATA   -> refused
/cont-wrong-stream   HEADERS (open) on 1, CONTINUATION on 3     -> refused
```

Neither was refused *for being a framing violation*. The first is caught by
audit-report-44's rule that DATA before the response head fails; the second
because a CONTINUATION on another stream is ignored, leaving the block
unfinished so the eventual DATA hits that same rule. Right outcome, wrong
reason — which is why they go in as **controls** rather than as coverage for
this fix, and why they pass on a pre-fix binary.

### The fix

An explicit `hdr_open` on the leg (and its global twin for the oracle), set when
a stream-1 HEADERS arrives without END_HEADERS and cleared when END_HEADERS
does. Both dispatchers gate on it before looking at the frame type at all:

* block open → the frame **must** be a CONTINUATION on stream 1; anything else,
  for any stream, fails the exchange — a PING, a SETTINGS, a WINDOW_UPDATE;
* block not open → a CONTINUATION fails the exchange.

The gate goes at the top of the dispatcher rather than inside the CONTINUATION
branch, because the rule is about **what may arrive**, not about what a
CONTINUATION may contain. Putting it in the branch would have caught
`/cont-first` and missed every interleaving.

`/trailers-frag` — a legal trailer split across HEADERS + CONTINUATION — is the
case that proves the gate does not simply ban continuations, and it still
answers 200 on both paths.

### Coverage

Four new checks. Against a binary built from the audited source:

```
pre-fix: /cont-first is refused          FAIL
pre-fix: /cont-interleaved is refused    FAIL
pre-fix: /cont-data-between is refused   PASS   <- control (refused already)
pre-fix: /cont-wrong-stream is refused   PASS   <- control (refused already)
```

Two fail and two pass, which is the honest split: this fix is responsible for
two of the four. `test/h2/h2c_server.py` gains all four routes, and the legal
fragmented-trailer and informational controls are unchanged.

tls shard **251 passed, 0 failed**; full suite **837 passed, 0 failed**.

### Where this sat relative to report 44

Report 44's resolution left a state table for `h2c_classify_block` and the note
that a further report in *that* function would mean the table was incomplete.
This finding is not in it: the table covers what a completed block may be, and
this is the layer below — which frames may arrive, and in what order, for a
block to be completed at all. The table stands; it simply never claimed this.
The frame layer now has its own rule, stated once, at the top of both
dispatchers.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the resumable driver, on the blocking oracle, and end to end through
a real `proxy_h2` front. The pre-fix control identifies which rows the fix is
responsible for, and names the two that were already refused so they are not
counted as its work.
