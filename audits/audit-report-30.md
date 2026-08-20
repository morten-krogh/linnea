# Audit Report 30

Audited at `05c19bc`, 2026-08-20.

**Fixed in `d750db6`**, verified against a pre-fix binary on all three
protocols. It is not an HTTP/1 defect: **h1 kept the FIRST occurrence and h2 and
h3 kept the LAST**, so the three protocols disagreed with the specification in
opposite directions and with each other. Every ordering of a legal two-line list
was wrong on some protocol.

One conditional-request semantics gap remains open:

1. **Medium: HTTP/1 evaluates only the first `If-Match` and `If-None-Match`
   field line.** Both are list-valued fields, so repeated lines must be treated
   as one combined entity-tag list.

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — Repeated ETag preconditions are not combined

Severity: **Medium (P2, cache and precondition integrity)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

The HTTP/1 parser explicitly keeps only the first occurrence of each ETag
precondition:

```asm
.ifm_header:                   ; first occurrence wins, as for Host
    cmp qword [rsp + 312], 0
    jne .header_next
    ...
.inm_header:                   ; first occurrence wins, as for Host
    cmp qword [rsp + 176], 0
    jne .header_next
```

at [src/server/linnea_http.asm:1281](/home/linnea/linnea/src/server/linnea_http.asm:1281)
through [:1304](/home/linnea/linnea/src/server/linnea_http.asm:1304). The
static responder subsequently calls the ETag match helpers over that sole
stored span at [src/server/linnea_http.asm:1993](/home/linnea/linnea/src/server/linnea_http.asm:1993)
through [:2024](/home/linnea/linnea/src/server/linnea_http.asm:2024).

`If-Match` and `If-None-Match` use an entity-tag list grammar. Repeated
list-field lines combine in field order, rather than using Host’s
single-occurrence rule. The parser’s first-line policy therefore changes the
meaning of a legal request.

### Reproduction

For a current entity tag `"E"`, these are equivalent list spellings:

```text
If-None-Match: "miss", "E"\r\n
```

```text
If-None-Match: "miss"\r\n
If-None-Match: "E"\r\n
```

The first must produce `304 Not Modified`; the second is evaluated as only
`"miss"` and produces a full `200` response. The inverse affects `If-Match`:
the combined list `"miss", "E"` must pass, whereas retaining only `"miss"`
returns `412 Precondition Failed`.

### Impact

Client caches can be needlessly bypassed, and conditional update/read semantics
depend on whether a client or intermediary serialized a legal ETag list on one
line or multiple lines. This can cause false 200s and false 412s, undermining
cache validation and optimistic-concurrency guarantees. Proxy locations forward
the individual fields, so the inconsistency is specifically between Linnea’s
static origin behavior and a conforming downstream/upstream interpretation.

### Recommendation

Store several spans or walk the request head for every `If-Match` and
`If-None-Match` occurrence, stopping when any entity tag matches. Preserve `*`
semantics and the existing strong-versus-weak comparison choices. Do not reuse
the Host duplicate rule for these list-valued fields.

Suggested tests:

* Compare one-line and two-line spellings of `"miss", <current-etag>` for both
  fields; they must yield identical 304/200 and pass/412 results.
* Reverse field order and include three field lines.
* Exercise HTTP/1, HTTP/2, and HTTP/3 static serving to ensure their header
  collectors agree.

### Resolution — FIXED (2026-08-20)

Confirmed on HTTP/1 exactly as filed, then measured on the other two, which the
report asks for and which changes the finding:

```
  If-None-Match: <current tag>       h1 304    h2 200    h3 200
  If-None-Match: "miss"

  If-None-Match: "miss"              h1 200    h2 304    h3 304
  If-None-Match: <current tag>
```

**h1 keeps the first occurrence, h2 and h3 keep the last.** So a client
revalidating with a two-line list is answered a full 200 on at least one
protocol however it orders the list, and the `If-Match` direction turns the same
disagreement into a 412 on a request that must pass. The h1 collector said
`; first occurrence wins, as for Host` — Host's rule, applied to a field that
may repeat, where Host is a field that may not.

### The mechanism was already here

`Accept-Encoding` has recorded one span per line since h1-14, with the reason
written out at `.ae_header`:

> RFC 9110 5.3: repeated field lines of a list-based field are equivalent to the
> comma-joined value... Record each line as its own (ptr,len) span instead; the
> negotiation below tries them all, which is the same answer as joining them
> without having to copy the values anywhere.

That is exactly this fix, on a different field. Both preconditions now keep up
to three spans on all three protocols and try them in turn: on h1 an array in
the request frame counted by the slots that used to hold the first pointer, on
h2 and h3 an array in `linnea_h2_req`. Nothing is copied and no length limit is
introduced, so a single long list behaves as it always did. A fourth line is
ignored, which can only cost a 304 or earn a 412 — never serve a stale
representation.

Two build-time guards fired on the way and were worth having: `h2_build_request
stack frame (sub rsp,408) too small for req + locals`, which exists because the
`priority` fields once silently overwrote the stream id, and h3's frame needed
the matching epilogue.

### Coverage

`test/tls/etag_list_lines.py` drives nine rows — the tag on the first, second
and third line, the one-line spelling, and the negatives for both fields —
across h1, h2 and h3, and requires all three to give the same answer. Five of
the nine fail on a pre-fix binary, and the failures show the split:

```
FAIL INM tag on line 1: want 304, got {'http1.1': '304', 'http2': '200', 'h3': '200'}
FAIL INM tag on line 2: want 304, got {'http1.1': '200', 'http2': '304', 'h3': '304'}
FAIL INM tag on line 3: want 304, got {'http1.1': '200', 'http2': '304', 'h3': '304'}
FAIL IM  tag on line 2: want 200, got {'http1.1': '412', 'http2': '200', 'h3': '200'}
FAIL IM  tag on line 1: want 200, got {'http1.1': '200', 'http2': '412', 'h3': '412'}
```

Full suite: **779 passed, 0 failed**.

## Verification

No executable tests were run: this report makes no source change. The finding
is a source trace from first-occurrence collection through the static ETag
decisions.

## Conclusion

ETag preconditions are parsed as singular headers on HTTP/1, even though their
grammar is a combined list. Combining all occurrences restores consistent
conditional-request behavior.

This is the third report in a row on the same rule — `Transfer-Encoding` in 28,
`Connection` in 29, the ETag preconditions here — and the third field where the
code applied a per-line policy to a list. Two things are worth carrying: the
tree had **already** written the correct treatment down, at `.ae_header`, and
applied it to one field only; and a comment reading *"first occurrence wins, as
for Host"* is the whole defect in six words, because Host's rule is for a field
that may not repeat. **When a policy is borrowed from another field, the thing
to check is whether the two fields have the same cardinality.**
