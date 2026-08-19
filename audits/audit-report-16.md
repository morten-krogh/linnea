# Audit Report 16

Audited at `180f0e2` (`audits directory`), 2026-08-19.

**Fixed in `88a10c2`.** The finding is correct in every particular, including
why it was not obvious, and it is a regression from report 14's own fix. It was
measured against a binary carrying the bug before anything was changed.

One upstream-response translation issue remains open:

1. **High: HTTP/1 forwards an upstream `Connection` field after the framing-first rewrite, including options that re-scope Linnea's own response headers.** HTTP/2 and HTTP/3 correctly remove the field. In the security-policy case fixed by report 15, the HTTP/1 wire response contains Linnea's configured HSTS field but also forwards `Connection: Strict-Transport-Security`, telling a compliant client to treat that very field as hop-specific and remove it.

No production source, configuration, or test files were changed in this audit. Only this report was added.

This is a source-trace audit against the stated baseline. The reproduction gives a minimal backend fixture and the exact code path it reaches; it is not presented as a capture from a modified backend.

## Finding 1 — HTTP/1 loses the `Connection` field name before forwarding policy runs

Severity: **High (P1, response-hop integrity and security-policy bypass)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

An upstream `Connection` field is specific to the upstream-to-Linnea hop. RFC 9110 section 7.6.1 requires an intermediary to remove it, and all fields it names, before forwarding the response. This is particularly important after report 15: a field that the upstream names in `Connection` is correctly discarded, so Linnea adds its configured replacement policy.

HTTP/1's rewriter intends to recognize `Connection` at [src/server/linnea_http.asm:4099](/home/linnea/linnea/src/server/linnea_http.asm:4099) through [:4109](/home/linnea/linnea/src/server/linnea_http.asm:4109). Its name calculation is:

```asm
mov rax, r8
sub rax, rcx
lea rdi, [r14 + rcx]
```

That requires `r8` to be the colon offset and `rcx` to be the line-start offset. Neither is reliably true after the new framing classification:

- For ordinary fields, the `Transfer-Encoding` comparison immediately above passes `ecx = 17` to `linnea_string_iequal` at [src/server/linnea_http.asm:4080](/home/linnea/linnea/src/server/linnea_http.asm:4080) through [:4089](/home/linnea/linnea/src/server/linnea_http.asm:4089). The helper preserves that argument register, not the original line cursor.
- For `Content-Length`, `.content_len` repurposes `r8` as the first value byte at [:4222](/home/linnea/linnea/src/server/linnea_http.asm:4222), walks `rcx` to the CR, then jumps back to `.fwd` at [:4281](/home/linnea/linnea/src/server/linnea_http.asm:4281).

Thus an actual `Connection` field normally fails the first comparison and falls through. One accidental case masks it: the first field after the common `HTTP/1.1 200 OK` line begins at byte 17, so the stale `rcx = 17` happens to be its correct start offset. Put any ordinary field before `Connection`, or use a status line of a different length, and the check is wrong again. The fixed hop-by-hop table intentionally does not include `connection` — it expects this first check to remove the field — and the later dynamic helper is asked whether a `Connection` value names the *field name* `Connection`, rather than whether the field being forwarded is `Connection` itself. An ordinary `Connection: close` or `Connection: Strict-Transport-Security` value does not name `connection`, so it reaches `.copy_line` at [src/server/linnea_http.asm:4192](/home/linnea/linnea/src/server/linnea_http.asm:4192) through [:4196](/home/linnea/linnea/src/server/linnea_http.asm:4196).

HTTP/2 and HTTP/3 do not share this defect. Their respective fixed drop tables include `connection` at [src/server/linnea_http2.asm:5754](/home/linnea/linnea/src/server/linnea_http2.asm:5754) through [:5777](/home/linnea/linnea/src/server/linnea_http2.asm:5777) and [src/server/linnea_qpack.asm:84](/home/linnea/linnea/src/server/linnea_qpack.asm:84) through [:109](/home/linnea/linnea/src/server/linnea_qpack.asm:109). The bug is therefore an HTTP/1 regression introduced by the framing-first placement from report 14.

The existing `/api/hopnamed` fixture already has the triggering order — `Content-Length`, then `Connection: X-Backend-Only` — but its assertion checks only that `X-Backend-Only` was dropped. It deliberately exempts HTTP/1 `Connection` fields on the assumption that the only one present is Linnea's own generated line, so this leaked upstream line is not observed.

### Reproduction

Use the TLS proxy vhost with its configured policy and an upstream response:

```text
HTTP/1.1 200 OK\r\n
Content-Length: 4\r\n
Connection: Strict-Transport-Security\r\n
Strict-Transport-Security: max-age=0\r\n
\r\n
body
```

The correct downstream HTTP/1 response removes both upstream fields, then adds Linnea's configured end-to-end policy:

```text
Strict-Transport-Security: max-age=31536000
Content-Length: 4
Via: 1.1 linnea
Connection: keep-alive
```

The current HTTP/1 control flow instead copies the upstream connection option and, because the named HSTS field is dropped, appends Linnea's configured HSTS:

```text
Connection: Strict-Transport-Security
Strict-Transport-Security: max-age=31536000
Content-Length: 4
Via: 1.1 linnea
Connection: keep-alive
```

A compliant downstream peer applies the first line to the next hop and removes the configured HSTS field as connection-specific. HTTP/2 and HTTP/3 remove the upstream `Connection` line and retain the configured HSTS field.

`Connection: close` after any ordinary first field is a simpler control: HTTP/1 forwards it and then appends its own `Connection: keep-alive`, while HTTP/2 and HTTP/3 omit it. The two instructions describe different hops; forwarding the upstream one can make a client close a connection Linnea intends to reuse.

### Impact

The defect violates the hop boundary independently of the named option, but its interaction with report 15's fix turns it into a direct security-policy bypass. An upstream can name `Strict-Transport-Security` or `X-Content-Type-Options` in `Connection`; Linnea correctly replaces the discarded backend field with its configured policy, then incorrectly forwards the option that tells the client to discard that replacement.

Other options cause protocol-dependent behavior: HTTP/1 clients receive an upstream `close` instruction or an extension option for a field Linnea already removed, whereas HTTP/2 and HTTP/3 do not. The current matrix checks only that the named field is absent on HTTP/1; it intentionally exempts HTTP/1's `Connection` field, assuming that field is Linnea's own. That lets this upstream copy pass the test beside the proxy-generated one.

### Recommendation

Restore the header-line cursor immediately before the first `.fwd` comparison: load `rcx` from `[rsp + 24]` and derive the name length from `r13` (the saved colon offset), exactly as the later fixed-hop and dynamic-connection checks already do. Do not rely on `r8` or the argument registers after framing classification.

Extend the proxy-head matrix with a route that returns `Connection: Strict-Transport-Security` and a nominated HSTS field. Require all protocols to emit exactly one configured HSTS field and no upstream `Connection` field. Also add `Connection: close` as a control and require HTTP/1 to contain only Linnea's final connection decision. The assertions must inspect every HTTP/1 `Connection` line, not merely exempt that field because Linnea normally emits one.

### Resolution — FIXED (2026-08-19, `88a10c2`)

Correct, and mine: report 14 moved framing classification ahead of the
forwarding walk and left this check reading registers that framing no longer
preserves. `linnea_string_iequal` takes its length in `ecx`, and `.content_len`
repurposes `r8` as a value cursor. The two checks below it had always reloaded
from the stack frame; this one had never needed to, because it used to run
first.

The accidental-survival account is exact. `Connection` as the **first** field
still worked, because the stale `ecx = 17` coincides with the offset just past
`HTTP/1.1 200 OK\r\n`. `/api/connfirst` is now a fixture so no fix can pass by
handling only the other position.

Measured before and after:

```
before   Connection: Strict-Transport-Security     <- upstream's, forwarded
         Strict-Transport-Security: max-age=...    <- ours, which that line discards
         Connection: close                         <- and ours as well
after    Content-Length, Via, the configured policy, one Connection: close
```

The fix is the report's recommendation: reload the line start from `[rsp + 24]`
and take the colon from `r13`, exactly as the fixed-hop and dynamic-connection
checks already do.

#### The half worth more than the fix

The report notices that `/api/hopnamed` already had the triggering order and
still passed, because the assertion exempts HTTP/1 `Connection` fields. That is
my exemption, from report 10, and it was load-bearing in the wrong direction.

Against a binary carrying the bug, the replacement invariant fails on **six**
routes — and four of them predate this report entirely:

```
hopnamed        Connection: X-Backend-Only              + Connection: close
hopnamedmulti   Connection: x-one,X-Two / close,X-Three + Connection: close
earlyhop        Connection: X-Hint-Only                 + Connection: close
upgrade200      Connection: Upgrade                     + Connection: close
connsts         Connection: Strict-Transport-Security   + Connection: close
connclose       Connection: close                       + Connection: close
```

All six were leaking and all six were passing. **An exemption in a test is a
place where a defect can live**, and this one had four tenants before today's
finding moved in.

The exemption is now a rule, checked on every route: HTTP/1 emits exactly one
`Connection` line and its value must be `close` or `keep-alive`; HTTP/2 and
HTTP/3 emit none. An upstream `Connection` value reaching a client is a
hop-boundary break whatever it happens to name.

## Verification

| route | with the bug | fixed |
| --- | --- | --- |
| `/api/connsts` | upstream option forwarded beside our policy | option gone, policy intact |
| `/api/connclose` | two `Connection: close`, different hops | one, ours |
| `/api/connfirst` | correct by accident | correct by rule |
| `/api/hopnamed`, `hopnamedmulti`, `earlyhop`, `upgrade200` | leaking, and passing | clean |

Cross-protocol matrix: **6 failures** against the buggy build, **193 checks
green** after. Full suite **767 passed, 0 failed**.

## Conclusion (resolution)

Two lessons, and the second is the durable one. A block moved past code that
consumes caller-saved registers leaves every later reader of those registers
wrong — reconstruct from the frame, as the neighbouring checks already did. And
a test that exempts a field because "we emit one of those ourselves" stops
testing that field entirely; the exemption must be replaced by a rule that says
what the correct number and value are.

## Verification (as filed)

No executable tests were run: this report makes no source change. The finding is traced from the checked-in HTTP/1 register flow and contrasted with the existing HTTP/2 and HTTP/3 drop tables.

## Conclusion

The report-14 fix put framing in the correct place, but left the forwarding block dependent on caller-saved cursor registers that framing no longer preserves. Reconstructing the name from the rewriter's stack frame closes the regression and ensures the policy fields added by report 15 remain end-to-end on HTTP/1 as well as HTTP/2 and HTTP/3.
