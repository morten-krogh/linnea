# Audit Report 34

Audited at `7707973`, 2026-08-20.

**Fixed in `73a92e8`**, verified against a pre-fix binary. The finding is
mine from yesterday: I applied the singleton-duplicate rule to eight fields and
not to the one I was adding. One row is worse than the report states — with
`1` then `0` **all three** answer locally and forward nothing, so field order
decides whether the request leaves this server at all.

One proxy hop-count gap remains open:

1. **High: repeated `Max-Forwards` values are accepted and rewritten
   inconsistently.** The field is singular; HTTP/1 emits every duplicate with
   the last value decremented, while HTTP/2 and HTTP/3 emit one value.

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — Duplicate Max-Forwards creates a protocol-dependent upstream request

Severity: **High (P1, proxy request-routing differential)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

HTTP/1 parses each `Max-Forwards` field line, stores its value in one slot, and
does not check whether the field was already present:

```asm
    call linnea_string_to_u64
    test edx, edx
    jnz .resp_400
    mov [rsp + 528], rax
    or qword [rsp + 136], 64
```

at [src/server/linnea_http.asm:1302](/home/linnea/linnea/src/server/linnea_http.asm:1302)
through [:1321](/home/linnea/linnea/src/server/linnea_http.asm:1321). A later
line overwrites the first.

The HTTP/1 proxy rewriter scans every original header line. For each
`Max-Forwards` line on an OPTIONS request, it emits a new header using that one
stored value minus one at [src/server/linnea_http.asm:2747](/home/linnea/linnea/src/server/linnea_http.asm:2747)
through [:2786](/home/linnea/linnea/src/server/linnea_http.asm:2786). It does
not suppress subsequent occurrences.

The shared binary collector has the same overwrite at
[src/server/linnea_hpack.asm:612](/home/linnea/linnea/src/server/linnea_hpack.asm:612)
through [:637](/home/linnea/linnea/src/server/linnea_hpack.asm:637), but keeps
the field out of the rebuilt head and emits exactly one replacement in the H2
proxy builder. Thus the malformed input becomes different upstream messages.

### Reproduction

Send to a proxy location:

```text
OPTIONS /api/echo HTTP/1.1\r\n
Host: one.test\r\n
Max-Forwards: 0\r\n
Max-Forwards: 1\r\n
\r\n
```

The two values contradict each other; `Max-Forwards` is `1*DIGIT`, not a
list-valued field. Linnea chooses the final `1` for its local decision.

* HTTP/1 forwards **two** `Max-Forwards: 0` fields.
* HTTP/2 and HTTP/3 forward **one** `Max-Forwards: 0` field.

Reversing the lines makes all paths treat the request as final locally, so a
client controls whether contradictory hop counts are forwarded merely by field
order.

### Impact

Max-Forwards is specifically a routing-control field for OPTIONS and TRACE.
Accepting contradictory values lets the request’s forwarding behavior depend on
downstream protocol and on backend duplicate-header policy. An upstream proxy
or service can reject, merge, or choose among the duplicate zero values
differently, defeating the deterministic hop limit this field is meant to
provide.

### Recommendation

Treat a second `Max-Forwards` occurrence as malformed in H1, H2, and H3 before
routing or request rebuild. Reuse the singleton-field duplicate policy adopted
for Range and conditional date/validator fields; do not choose a first or last
value. Keep single `0` (local OPTIONS response) and single positive values
(one decremented upstream field) as controls.

Suggested tests:

* `0` then `1`, and `1` then `0`, must be rejected consistently on all three
  protocols.
* Two equal values must also be rejected; singleton duplication is still
  ambiguous framing.
* Single `0` and `1` OPTIONS requests retain the existing local/forwarded
  behavior, and non-OPTIONS preserves a valid Max-Forwards unchanged.

### Resolution — FIXED (2026-08-20)

Confirmed, with one row the report reasons about rather than measures. Two
`Max-Forwards` lines on an `OPTIONS` to a proxy location, before:

```
  0 then 1   h1 200, TWO "Max-Forwards: 0" upstream
             h2 200, ONE                     h3 200, ONE
  1 then 0   all three 200, and NOTHING forwarded -- answered here
  2 then 2   h1 200, TWO "Max-Forwards: 1"   h2/h3 200, ONE
```

The middle row is the sharp one: the last value wins for the local decision, so
**a client chooses by field order whether the request is forwarded at all**.
The first and third then differ by protocol in what goes upstream, because the
HTTP/1 rewriter emits a decremented line per original occurrence while the
binary builders emit exactly one.

`Max-Forwards` is `1*DIGIT`, not a list. Two of them are two answers to one
question, so a second line is refused — the same policy and the same shapes as
the singleton conditionals of report 32: `400` on HTTP/1, a stream error on the
binary protocols. Equal values are refused too, which is where this differs from
a duplicate `Content-Length`: two identical lengths describe the same body and
can be reconciled, whereas two identical hop counts still make the field a list
the grammar does not allow.

```
  0 then 1 / 1 then 0 / 2 then 2   400  000  000
  a single 0                       200  200  200   answered here, not forwarded
  a single 3                       200  200  200   backend sees 2
```

### What this one is really about

I added `Max-Forwards` yesterday, in a session whose previous five reports were
all the same rule: **a field that may appear once may not appear twice.** I had
just applied it to eight response fields and, an hour earlier, to four request
ones. Then I introduced a new singleton and did not ask the question of it.

Adding a field is exactly when the question is cheapest to answer and easiest to
forget, because attention is on making the field *work*. The check belongs in
the act of adding one: **is this field a list or a singleton, and what happens
when it arrives twice?**

### Coverage

`test/tls/max_forwards_trace.py` gains three rows — both orders and the equal
pair — across all three protocols. All three fail on a pre-fix binary; the
single-value rows beside them are unchanged, so the rule cannot become "refuse
the field".

Full suite: **781 passed, 0 failed**.

## Verification

No executable tests were run: this report makes no source change. The finding
is a source trace from the one-slot collectors to the differently shaped H1 and
binary rewriters.

## Conclusion

The new hop-count logic is correct for one field but not for a repeated
singleton. Refusing duplicates prevents order-dependent forwarding and ensures
one request has one upstream hop-limit meaning.

It does now. The lesson is not about Max-Forwards: **a rule learned from six
reports was not applied to the field being added in the same session that
learned it.** A rule only holds if it is asked of new code as well as old, and
the moment of adding a field is when it is least likely to be asked.
