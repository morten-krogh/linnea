# Audit Report 26

Audited at `757956a`, 2026-08-20.

**Fixed in the commit below**, measured against a pre-fix binary. The impact is
worse than the report states: with a backend that holds its connection open, the
response was not merely delayed — **the 200 it had already served never reached
the access log at all**, and the connection was closed 10 s later as `upstream
timeout`.

One chunked-response completion gap remains open:

1. **High: HTTP/1 relay does not finish when the chunk decoder reaches DONE.**
   The steady-state read loop tests `body_rem` only; chunked responses carry no
   finite Content-Length there.

No production source, configuration, or test files were changed in this
audit. Only this report was added.

## Finding 1 — A terminal chunk can leave the relay waiting for upstream EOF

Severity: **High (P1, completed response not completed)**  
Confidence: **High**  
Status: **Fixed** (see Resolution)

### Evidence

Each upstream read is validated by `linnea_spill_chunked`; a terminal chunk
advances `resp_chunk_state` to `LINNEA_CHUNK_DONE`. The relay then sends the
bytes and enters `.relay_next`. That path decides whether the response is
finished solely from `body_rem`:

```asm
.relay_next:
    cmp qword [r12 + linnea_connection.body_rem], 0
    je .proxy_finish
    ...
    call linnea_uring_arm_up_recv
```

at [src/server/linnea_uring.asm:2526](/home/linnea/linnea/src/server/linnea_uring.asm:2526)
through [:2535](/home/linnea/linnea/src/server/linnea_uring.asm:2535). The
EOF path does check `resp_chunk_state == LINNEA_CHUNK_DONE` at
[src/server/linnea_uring.asm:2475](/home/linnea/linnea/src/server/linnea_uring.asm:2475),
but that check is too late when the upstream keeps its HTTP connection alive.

### Reproduction

Have an upstream send a complete response in one exchange and keep the socket
open:

```text
HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n
4\r\nbody\r\n0\r\n\r\n
```

The validator reaches `LINNEA_CHUNK_DONE`, but `body_rem` remains the
close-delimited sentinel rather than zero. The relay arms another upstream
receive instead of completing the response immediately, so the client can wait
for EOF even though the chunked message is already complete.

### Impact

A valid keep-alive backend can make completed chunked responses hang until its
idle timeout or connection close. This defeats the framing purpose of the
terminal chunk, wastes an upstream/client connection, and can turn otherwise
healthy responses into timeouts. It also makes completion depend on backend
connection policy rather than the message bytes.

### Recommendation

In `.relay_next`, check `resp_chunked` and
`resp_chunk_state == LINNEA_CHUNK_DONE` before arming another upstream read;
route directly to `.proxy_finish` (or the normal response-completion path).
Add a keep-alive upstream fixture that sends the terminal chunk and then waits
without closing, and require the client response to complete without waiting
for EOF.

### Resolution — FIXED (2026-08-20)

Confirmed as filed, and measured rather than argued. Two backends, both sending
the same complete chunked response; one closes afterwards, the other holds its
socket open:

```
                 before                                  after
  /api/close   terminal chunk 0.001s, EOF 0.001s   terminal chunk 0.0s, EOF 0.0s
  /api/keep    terminal chunk 0.000s, EOF 10.0s    terminal chunk 0.0s, EOF 0.0s
```

Ten seconds is `proxy_timeout` exactly. The client had its whole body in under a
millisecond and the exchange sat there for the rest of it.

#### The part the report did not reach

The log for those two requests, before:

```
  request one.test ... "GET /api/close HTTP/1.1" 200 14
  closed connection ... (fd 7): close after response
  accepted connection ... (fd 7)
  closed connection ... (fd 7): upstream timeout
```

The second request has **no access-log line at all**. A 200 that was served,
complete and correct, is simply absent from the record, and the only trace is a
close reason blaming an upstream that had done nothing wrong. After the fix both
requests are logged as `200 14` and closed with `close after response`.

That is the same shape as the defects this tree keeps finding: a reason
attributed to the wrong cause, and an event that happened leaving no evidence
that it did.

#### Why a `Connection: close` policy hid it

linnea sends `Connection: close` on every upstream request — one request per
upstream connection — so a conforming backend closes as soon as it has answered
and `.relay_eof` finishes the response a microsecond later. The bug was
invisible for every backend that obeys the header we send, which is nearly all
of them. It needed a backend that ignores it to show at all.

The check the EOF path has carried since report 24 was the right check in the
wrong place: reaching it depends on the upstream doing something. `.relay_next`
now asks the same question before arming another read:

```asm
    cmp qword [r12 + linnea_connection.resp_chunked], 0
    je .relay_read_on
    cmp qword [r12 + linnea_connection.resp_chunk_state], LINNEA_CHUNK_DONE
    je .proxy_finish
```

`body_rem`'s `-1` means both "close-delimited" and "chunked", and only the first
of those ends at the close — the same conflation report 24 untangled at EOF,
still live one branch away.

#### Coverage

`/api/chunkkeepalive` sends a complete chunked response and then holds its
socket for three seconds — longer than the check waits, shorter than any timeout
it could hit. `test/h1_chunk_relay.py` requires the exchange to be over in under
1.5 s and the body to be terminated, and the shard greps the access log for the
line that used to be missing entirely. On the immediately preceding build
(`757956a`, which has report 24's validator but not this check) it reports:

```
keep-alive backend: the response was complete but the exchange took 3.0s
  -- it waited for the upstream
```

Full suite: **777 passed, 0 failed**.

#### Not done, and deliberately

A chunked response is self-delimiting, so once the relay finishes at the
terminal chunk the CLIENT connection could be kept alive rather than closed —
`.until_eof` still clears `keep_alive` for every chunked proxied response. That
is a behaviour change of its own and is not what this report asked for.

## Verification

No executable tests were run: this report makes no source change. The finding
is a control-flow trace of the terminal state and the subsequent read decision.

## Conclusion

Split-read validation now carries state correctly, but completion still follows
the old Content-Length/EOF logic. The chunk decoder's DONE state must terminate
the relay itself.

It does now. The lesson is where the old check sat: report 24 put it on the EOF
path, which is correct and unreachable until the upstream acts — so the
invariant held only because linnea asks every backend to close and nearly all of
them oblige. **A check that depends on the other side doing something is not a
check on our own behaviour**, and the one backend that ignored the request
header was enough to show it.
