# Audit Report 29

Audited at `45e5b4a`, 2026-08-20.

**Fixed in `2ff4642`**, verified against a pre-fix binary. A second
defect of the same shape was found beside it: `Connection: close` followed by
`Connection: keep-alive` was answered `Connection: keep-alive` and the socket
held, against a client that had already said close.

One HTTP/1 proxy header-smuggling gap remains open:

1. **High: only the last `Connection` field line controls hop-by-hop field
   removal.** Earlier field values are overwritten even though repeated
   list-valued fields combine in order.

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — Repeated `Connection` fields can bypass nominated-field removal

Severity: **High (P1, proxy header-smuggling)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

`Connection` is a list-valued field. An intermediary must remove the
`Connection` fields themselves and every field name listed by any of their
values. During request parsing, however, each encountered `Connection` line
overwrites the one connection-owned span:

```asm
    ; keep the value: every token in it names a field the proxy must not forward
    mov rax, [rsp + 72]
    mov [rbx + linnea_connection.conn_opts], rax
    mov rax, [rsp + 80]
    mov [rbx + linnea_connection.conn_opts_len], rax
```

at [src/server/linnea_http.asm:1164](/home/linnea/linnea/src/server/linnea_http.asm:1164)
through [:1168](/home/linnea/linnea/src/server/linnea_http.asm:1168). There is
one pointer/length pair in the connection layout, not a collection of values:
[include/linnea_connection.inc:235](/home/linnea/linnea/include/linnea_connection.inc:235).

When rewriting a proxied request, each otherwise-forwardable header is tested
only against that retained final value by `http_conn_option_named` at
[src/server/linnea_http.asm:2720](/home/linnea/linnea/src/server/linnea_http.asm:2720)
through [:2728](/home/linnea/linnea/src/server/linnea_http.asm:2728). That
helper scans exactly one span, loaded from `conn_opts` at
[src/server/linnea_http.asm:703](/home/linnea/linnea/src/server/linnea_http.asm:703)
through [:709](/home/linnea/linnea/src/server/linnea_http.asm:709).

### Reproduction

Send a proxied request containing two `Connection` field lines:

```text
GET /api/echo HTTP/1.1\r\n
Host: one.test\r\n
Connection: X-Auth-Bypass\r\n
Connection: keep-alive\r\n
X-Auth-Bypass: 1\r\n
\r\n
```

The combined connection-option list nominates `X-Auth-Bypass` as hop-by-hop,
so that field must not reach the upstream. Linnea stores the first value, then
replaces it with `keep-alive`; the proxy copy loop consequently does not match
`X-Auth-Bypass` and forwards it.

The existing single-line test correctly covers
`Connection: X-Auth-Bypass`, but does not cover the repeated-field spelling:
[test/tls/h1_proxy_hop_by_hop.py:77](/home/linnea/linnea/test/tls/h1_proxy_hop_by_hop.py:77)
through [:78](/home/linnea/linnea/test/tls/h1_proxy_hop_by_hop.py:78).

### Impact

A client can mark a header as connection-specific to one hop while causing
Linnea to forward it as an end-to-end field to the backend. Backends commonly
treat private headers as routing, identity, or feature-control inputs; this
permits precisely the header-smuggling condition the proxy’s Connection filter
is intended to prevent. The bypass depends only on legal repeated list-field
syntax, so it is also likely to disagree with intermediaries that correctly
combine the lines.

### Recommendation

Retain and scan every `Connection` field value, or parse their combined token
list while reading headers. The proxy rewriter must remove a header if it is
nominated by *any* Connection occurrence. Preserve the existing upgrade
exception deliberately, but apply it after combining all values.

Suggested tests:

* `Connection: X-Auth-Bypass` followed by `Connection: keep-alive` must remove
  `X-Auth-Bypass` upstream.
* Reverse the order; add `close` and `upgrade` controls to ensure local
  persistence/upgrade behavior remains correct.
* Include multiple names split across three Connection fields and verify none
  reaches the backend.

### Resolution — FIXED (2026-08-20)

Confirmed exactly as filed. What the backend received, before:

```
  Connection: X-Auth-Bypass                     -> nothing leaked
  Connection: X-Auth-Bypass / Connection: keep-alive  -> x-auth-bypass LEAKED
  Connection: keep-alive / Connection: X-Auth-Bypass  -> nothing leaked
  three lines naming X-One and X-Two, then keep-alive -> BOTH leaked
```

The third row is the one that makes it a bypass rather than a bug: the same
request, with the same two lines in the other order, removes the field. **A
client could therefore choose whether its own hop-by-hop marking was honoured,
by writing the list in the order that suited it.**

The removal test now walks the whole request head with
`linnea_http_head_conn_named`, the helper the response direction has used since
report 10, which re-walks per field precisely so that repeated `Connection`
lines "work without being thought about". Its own comment claimed the request
direction "has had the real rule since `http_conn_option_named`" — which is
what a claim in a comment is worth. `http_conn_option_named` and the
`conn_opts` span it read are deleted rather than left available for reuse: a
mechanism that can only ever hold the last line is not one to keep.

### Found beside it — `close` undone by a later line

```
  Connection: close                                    -> Connection: close
  Connection: close / Connection: keep-alive           -> Connection: keep-alive
  Connection: keep-alive / Connection: close           -> Connection: close
```

A value that was entirely `close` was short-circuited before the token loop, and
the shortcut cleared keep-alive **without** the "close is final" flag the loop
sets. So a later `keep-alive` line put persistence back on and the socket was
held. Report 10 had already made `close` sticky *within* a line
(`Connection: close, keep-alive` is close); the shortcut existed only to skip
the loop that knows this. It is deleted, and the loop handles a lone `close`
correctly — the same defect as Finding 1, one field over: a rule applied per
LINE to a field whose lines are one list.

### The exception the fix broke, and what it should have been

`linnea_http_head_conn_named` is deliberately generic — it matches `upgrade`
like any other name — so switching to it stripped the client's `Upgrade` field
and the existing control failed at once:

```
FAIL Connection: upgrade does not strip the Upgrade field
```

The old helper skipped the `upgrade` TOKEN globally. Report 11 showed why that
form is wrong on the response side, where it leaked `Upgrade: websocket` out of
an ordinary 200. The exception is back in the narrower form: **this field,
given that the client asked to upgrade** — the one case where the server is a
participant in the tunnel rather than a bystander, and the wish is already
recorded during parsing.

### Coverage

`test/tls/h1_proxy_hop_by_hop.py` gains four cases (a name on an earlier line,
on a later one, three lines at once, and `upgrade` on its own line), and
`test/tls/connection_close_token.py` learns to send its list as separate field
lines and gains four more. Four of the eight fail on a pre-fix binary:

```
FAIL a name on an earlier Connection line is still removed: X-Auth-Bypass reached the backend
FAIL names spread across three Connection lines all go: X-One, X-Two reached the backend
FAIL 'close / keep-alive' on separate lines was answered Connection: 'keep-alive', want close
FAIL 'TE / close / keep-alive' on separate lines was answered Connection: 'keep-alive', want close
```

`keep-alive / close` passes before and after: that ordering always worked, which
is exactly why the defect survived a test file written one line at a time.

Full suite: **778 passed, 0 failed**.

## Verification

No executable tests were run: this report makes no source change. The finding
is traced from the per-line overwrite to the sole connection-option scan in the
proxy rewriter.

## Conclusion

The proxy handles a single `Connection` list correctly, but loses prior lists
when the legal repeated-field form is used. Combining all occurrences before
header removal closes the bypass.

Two reports in a row have now found the same shape — report 28 on
`Transfer-Encoding`, this one on `Connection` — and both were fields already
understood as lists, handled a line at a time. The question worth carrying
forward is not about either field: **for every list-valued field, is repeating
the line a legal way to say the same thing, and does the code see it that way?**
Where the answer is no, the test file will usually look thorough, because it was
written in the spelling that works.
