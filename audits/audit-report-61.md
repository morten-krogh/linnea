# Audit Report 61

Audited at `6c497d0`, 2026-08-26.

Audit report 60's response field-name and field-value validation is now
present in the shared backend-H2 emitter. The next gap is in the response
HPACK decoder:

1. **Low: a backend response can put a dynamic-table-size update after a
   response field, and the decoder accepts it instead of reporting a
   compression error.**

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — late HPACK dynamic-table updates are accepted in backend responses

Severity: **Low (P3, malformed upstream compression state is accepted)**  
Confidence: **High**  
Status: **Confirmed as filed and reproduced.** Fixed in the response decoder,
with one case the report does not name — a late update after a literal WITH
indexing — which my first attempt would have let through.

RFC 7541 §4.2 requires a Dynamic Table Size Update to occur at the beginning
of the first header block following a change to the permitted table size.
Equivalently, once a header-field representation has been decoded in a block,
a later table-size update in that same block is invalid. RFC 9113 §4.3 says a
field-block decoding error is a connection error of type `COMPRESSION_ERROR`.

The request-side HPACK decoder already implements the needed state machine. It
has a per-block `dec_field_seen` flag and marks indexed fields before decoding
them ([src/server/linnea_hpack.asm:94](/home/linnea/linnea/src/server/linnea_hpack.asm:94)
through [:97](/home/linnea/linnea/src/server/linnea_hpack.asm:97), and
[:137](/home/linnea/linnea/src/server/linnea_hpack.asm:137)
through [:142](/home/linnea/linnea/src/server/linnea_hpack.asm:142)). The
decoder's table-size arm rejects the update once that flag is set
([src/server/linnea_hpack.asm:268](/home/linnea/linnea/src/server/linnea_hpack.asm:268)
through [:287](/home/linnea/linnea/src/server/linnea_hpack.asm:287)).

The backend response decoder is a separate implementation in
`linnea_h2_client.asm`. It dispatches every byte whose `0x20` prefix identifies
a table-size update directly to `.tsize`, but has no per-block field-seen
state ([src/server/linnea_h2_client.asm:1681](/home/linnea/linnea/src/server/linnea_h2_client.asm:1681)
through [:1692](/home/linnea/linnea/src/server/linnea_h2_client.asm:1692)).
Indexed fields and literal fields both continue to `.next` after emission
([src/server/linnea_h2_client.asm:1693](/home/linnea/linnea/src/server/linnea_h2_client.asm:1693)
through [:1719](/home/linnea/linnea/src/server/linnea_h2_client.asm:1719),
and [:1797](/home/linnea/linnea/src/server/linnea_h2_client.asm:1797)
through [:1804](/home/linnea/linnea/src/server/linnea_h2_client.asm:1804)).
The `.tsize` arm therefore accepts the late update, writes the new maximum
into the response decoder's dynamic table, evicts entries, and loops back
without checking whether a field was already decoded
([src/server/linnea_h2_client.asm:1805](/home/linnea/linnea/src/server/linnea_h2_client.asm:1805)
through [:1817](/home/linnea/linnea/src/server/linnea_h2_client.asm:1817)).

This is not only a dead helper. `h2c_init_carrier` installs the private
response dynamic table and `h2c_do_decode` passes every reassembled response
field block to this decoder ([src/server/linnea_h2_client.asm:282](/home/linnea/linnea/src/server/linnea_h2_client.asm:282)
through [:292](/home/linnea/linnea/src/server/linnea_h2_client.asm:292),
and [:1661](/home/linnea/linnea/src/server/linnea_h2_client.asm:1661)
through [:1666](/home/linnea/linnea/src/server/linnea_h2_client.asm:1666)).
The blocking response parser and the resumable proxy driver both reach the
same decoder after reassembling HEADERS and CONTINUATION fragments, so neither
parser enforces the placement rule independently.

### Reproduction

Have the backend send a legal connection preface and this stream-1 response:

```text
HEADERS END_HEADERS,
        HPACK block = 88 20 0f 10 0a "text/plain"
DATA    END_STREAM, payload = "body"
```

Here `88` is the static `:status: 200` representation. `20` is a Dynamic
Table Size Update setting the maximum to zero, but it occurs after the
`:status` field and is therefore illegal. The remaining bytes encode a
`content-type: text/plain` field without indexing.

The current decoder emits `:status`, accepts `20`, emits `content-type`, and
completes the response as 200 with a body. A conforming HTTP/2 endpoint must
reject the field block with `COMPRESSION_ERROR`; it must not relay the
synthesized HTTP/1 response.

The same malformed block can be split after `88` into a HEADERS frame and a
CONTINUATION frame. The placement rule applies to the logical reassembled
field block, not to each frame, so this variant must fail too. A control with
the update before all fields — `20 88 ...` — must remain valid. A later
update in a new, separate response field block is a different case and must be
judged at that block's beginning.

### Impact

The immediate consequence is permissive acceptance of malformed backend
traffic. More importantly, the update is applied to the live response HPACK
dynamic table before the rest of the field block is decoded. A backend can
therefore change eviction behavior in the middle of a block and make the
decoder's compression state follow an instruction that a conforming peer must
never send there. If later fields use incremental indexing or dynamic
references, the resulting interpretation can differ from a strict endpoint's
and can affect which response fields cross the backend-to-HTTP/1 boundary.

This is a backend-controlled malformed-response issue rather than a direct
client-controlled injection. It nevertheless violates the compression
boundary's fail-closed requirement and makes the blocking and resumable
backend paths accept a field block that a strict HTTP/2 implementation would
terminate with a connection error.

### Recommended fix

Give `h2c_decode` a per-field-block `field_seen` bit, cleared immediately
before each completed HEADERS/CONTINUATION block is decoded. Set it whenever
an indexed or literal field representation is successfully recognized. The
`.tsize` arm must fail if the bit is already set, before changing the dynamic
table. Keep multiple size updates legal at the beginning of the same block,
and retain the existing maximum-size bound and eviction call.

The bit must live across HEADERS and all of its CONTINUATION fragments, but be
cleared between completed response blocks. Add blocking and resumable cases
for a late update in one frame, a late update split across CONTINUATION, a
valid beginning-of-block update, and a normal response without an update.
Assert that malformed cases do not produce a client-facing response through a
real `proxy_h2` front.

## Verification

The finding is a source-level comparison of the already-fixed request HPACK
decoder with its response-direction copy, plus a trace through both backend
response drivers. The response decoder's `.tsize` branch has no equivalent of
`dec_field_seen`; it mutates the live table and returns to `.next` after any
earlier field. `make -j4` completed with no work required. No production
source, configuration, or test file was changed in this audit.

References:

- [RFC 7541 §4.2 — Maximum Table Size](https://www.rfc-editor.org/rfc/rfc7541.html#section-4.2)
- [RFC 9113 §4.3 — Compression](https://www.rfc-editor.org/rfc/rfc9113.html#section-4.3)

## Resolution (2026-08-26) — CONFIRMED as filed

### Reproduced

Both parsers, at the audited commit, with hand-built blocks — the point is the
byte order, `0x88` being the static `:status: 200` and `0x20` an update to a
maximum of zero:

```
/hp-late       88 20 <fields>              -> 200 OK      (a field, then an update)
/hp-late-cont  88 | 20 <fields>            -> 200 OK      (split across CONTINUATION)
/hp-early      20 88 <fields>              -> 200 OK      <- control, legal
/hp-two-early  20 20 88 <fields>           -> 200 OK      <- control, legal
/hp-none       88 <fields>                 -> 200 OK      <- control
```

Exactly as filed, on both paths, including the CONTINUATION variant: the rule
is about the reassembled field block, not the frame that carried the bytes.

### The reference client names the error class

nghttp2 1.66.0 as a client, through `probe_h2.py`:

```
hplate   send GOAWAY frame ... error_code=COMPRESSION_ERROR(0x09)
hpearly  send GOAWAY frame ... error_code=NO_ERROR
normal   send GOAWAY frame ... error_code=NO_ERROR
```

That is the rule and the error type RFC 9113 §4.3 specifies, from the
implementation h2spec is written against.

### The fix, and the case that caught my first attempt

A per-block `h2c_field_seen` bit, cleared at the decoder's entry — which is
exactly the right lifetime, because this decoder runs once per *completed*
block, after HEADERS and all its CONTINUATIONs are reassembled — set when a
field representation is recognized, and checked in `.tsize` before the table
is touched. Several updates in a row at the beginning stay legal: an encoder
signals a shrink and a restore that way, so the bound is the first field, not
a count.

My first version marked `.indexed` and the fall-through literal form, and
missed `.lit_inc` — literal **with** incremental indexing, `0x40`, which is the
form an encoder actually emits. Both literal forms converge on one label, so
the mark belongs there. `/hp-late-inc` is not in the report; it is the row that
found this, and it is in the suite for that reason.

### Coverage

Fourteen rows: three malformed placements and three legal ones on each parser,
plus two end to end. Against a binary built from the audited source, **7 fail
and 7 pass as controls** — an unusually even split, because half of this
report's surface is about what must *keep* working.

Full suite **1044 passed, 0 failed**, nginx interop included.

## Verification (resolution)

Reproduced on a binary built from the audited source and re-run after the
change, on the blocking oracle and the resumable driver, and end to end through
a real `proxy_h2` front. The rule and its error class were put to nghttp2 as a
client before the fix was written. The three legal placements are asserted on
both parsers, so a fix that rejected table-size updates outright — or bounded
them by a count rather than by the first field — fails the controls.
