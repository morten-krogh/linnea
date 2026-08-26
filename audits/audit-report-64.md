# Audit Report 64

Audited at `835e72b` (`audit-report-63: HEAD responses reject DATA and retain
the declared representation length`), 2026-08-26.

Audit report 63's HEAD-response fix is present in both backend-H2 paths. The
next response-transport gap is receive-side HTTP/2 flow control:

1. **Low: the backend HTTP/2 client accepts DATA beyond its advertised stream
   or connection receive window.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — backend HTTP/2 does not enforce inbound flow-control windows

Severity: **Low (P3, a malformed or misbehaving backend can exceed the
advertised receive window and still produce a successful response)**  
Confidence: **High**  
Status: **NOT CONFIRMED as filed — rejected.** RFC 9113 6.9.1 makes the
receiver's flow-control error a MAY, and nghttp2 accepts the same overrun with
NO_ERROR. But the report's own aside is a real defect and is fixed: the leg
advertised a 4 MiB stream window while retaining 1 MiB.

HTTP/2 flow control has two independent receive limits for DATA: one for the
stream and one for the connection. The initial value of both is 65,535 octets.
The receiver may restore credit with WINDOW_UPDATE, but the sender must not
send a DATA frame whose payload is larger than the available space in either
window. A receiver must account for received DATA against the connection
window. These are RFC 9113 §§5.2 and 6.9.1 rules.

The client advertises a 4 MiB `SETTINGS_INITIAL_WINDOW_SIZE` to the backend
([include/linnea_h2_client.inc:70](/home/linnea/linnea/include/linnea_h2_client.inc:70)
through [:72](/home/linnea/linnea/include/linnea_h2_client.inc:72)). That
changes the stream-level receive window after the backend processes the
SETTINGS. It does **not** change the connection-level window: the client sends
no initial connection `WINDOW_UPDATE`, and RFC 9113 explicitly says that the
connection window can only be changed by `WINDOW_UPDATE`.

The blocking implementation initializes only the request/send-side windows,
not receive-side windows ([src/server/linnea_h2_client.asm:157](/home/linnea/linnea/src/server/linnea_h2_client.asm:157)
through [:164](/home/linnea/linnea/src/server/linnea_h2_client.asm:164)). Its
response DATA branch then:

1. appends the frame payload to the response body;
2. sends a connection-level WINDOW_UPDATE equal to the frame length; and
3. sends a stream-level WINDOW_UPDATE equal to the frame length

([src/server/linnea_h2_client.asm:1703](/home/linnea/linnea/src/server/linnea_h2_client.asm:1703)
through [:1737](/home/linnea/linnea/src/server/linnea_h2_client.asm:1737)).
There is no decrement of a receive window before the append and no check that
the frame fits in either window. `h2c_send_window` only serializes and sends a
WINDOW_UPDATE; it does not maintain receive-window state
([src/server/linnea_h2_client.asm:1161](/home/linnea/linnea/src/server/linnea_h2_client.asm:1161)
through [:1182](/home/linnea/linnea/src/server/linnea_h2_client.asm:1182)).

The resumable driver has the same omission. Its context contains
`stream_win` and `conn_win`, but those are explicitly the stream-1 and
connection **SEND** windows used while uploading the request
([include/linnea_h2_client.inc:120](/home/linnea/linnea/include/linnea_h2_client.inc:120)
through [:124](/home/linnea/linnea/include/linnea_h2_client.inc:124)). There
are no receive-window fields. In `d_dispatch`, a DATA frame is appended and
then two WINDOW_UPDATE frames are staged without any receive-window check or
accounting ([src/server/linnea_h2_client.asm:3376](/home/linnea/linnea/src/server/linnea_h2_client.asm:3376)
through [:3414](/home/linnea/linnea/src/server/linnea_h2_client.asm:3414)).
`d_stage_window` likewise only constructs bytes for the control frame
([src/server/linnea_h2_client.asm:2461](/home/linnea/linnea/src/server/linnea_h2_client.asm:2461)
through [:2481](/home/linnea/linnea/src/server/linnea_h2_client.asm:2481)).

The body buffer is bounded at 1 MiB, so this is not an unbounded write
([src/server/linnea_h2_client.asm:1531](/home/linnea/linnea/src/server/linnea_h2_client.asm:1531)
through [:1552](/home/linnea/linnea/src/server/linnea_h2_client.asm:1552)).
That bound is a separate memory limit; it does not implement the protocol's
per-connection and per-stream flow-control rules. In fact, the 4 MiB stream
window advertised to the backend is larger than the body that this client can
retain.

### Reproduction

After the request is sent, have the backend write its legal SETTINGS preface,
then a response HEADERS frame, then five legal 16,384-byte DATA frames in one
burst, with the last frame carrying END_STREAM. The backend must write the
burst before reading the client's WINDOW_UPDATE frames. The response declares
an 81,920-byte content length so the message framing itself is otherwise
consistent.

At the point the burst is sent, the connection receive window is still the
default 65,535 bytes. The first four DATA payloads total 65,536 bytes, already
one byte beyond that connection window; the fifth makes the violation
unambiguous. The stream window is large because the client advertised
`SETTINGS_INITIAL_WINDOW_SIZE = 4,194,304`.

The current blocking trace accepts each DATA frame, appends all 81,920 bytes,
and only afterward sends WINDOW_UPDATE frames. It completes the response. The
resumable trace does the same thing: `linnea_h2c_drv_on_recv` parses every
complete frame and `d_dispatch` appends the payload before staging credit
([src/server/linnea_h2_client.asm:3033](/home/linnea/linnea/src/server/linnea_h2_client.asm:3033)
through [:3094](/home/linnea/linnea/src/server/linnea_h2_client.asm:3094), and
[:3376](/home/linnea/linnea/src/server/linnea_h2_client.asm:3376) through
[:3414](/home/linnea/linnea/src/server/linnea_h2_client.asm:3414)). A conforming
receiver must reject the over-window DATA with a flow-control error; a sender
is allowed to transmit the later frames only after it has received sufficient
credit.

### Existing coverage

The fixture's normal response path sends DATA in chunks of at most 16,384
bytes ([test/h2/h2c_server.py:516](/home/linnea/linnea/test/h2/h2c_server.py:516)
through [:528](/home/linnea/linnea/test/h2/h2c_server.py:528)). Its `/big` route
creates 100,000 bytes ([test/h2/h2c_server.py:1181](/home/linnea/linnea/test/h2/h2c_server.py:1181)
through [:1186](/home/linnea/linnea/test/h2/h2c_server.py:1186)), and the
end-to-end shard separately checks a 200,000-byte response
([test/shards/tls/70-backend-tls-client.sh:138](/home/linnea/linnea/test/shards/tls/70-backend-tls-client.sh:138)
through [:142](/home/linnea/linnea/test/shards/tls/70-backend-tls-client.sh:142)).

Those controls verify body buffering and multi-frame relay, not flow-control
compliance. The fixture sends its entire response without waiting for the
client's WINDOW_UPDATE frames. Its comment says that the client's large
initial window prevents throttling ([test/h2/h2c_server.py:516](/home/linnea/linnea/test/h2/h2c_server.py:516)
through [:518](/home/linnea/linnea/test/h2/h2c_server.py:518)), but
`SETTINGS_INITIAL_WINDOW_SIZE` enlarges only the stream window; it does not
enlarge the connection window. No test sends enough DATA before credit to
assert that either parser refuses an over-window response.

### Impact

The immediate peer controls the malformed bytes, so this is an upstream
protocol-validation failure rather than direct client input injection. The
missing check nevertheless permits a backend to exceed the receive capacity
that the client advertised and to have the extra response content treated as a
valid exchange. A buggy backend can therefore bypass the intended connection
flow-control boundary, consume the response buffer up to its 1 MiB cap, and
return content that should have caused a flow-control failure. Across many
backend legs this removes the protocol's intended protection against a fast
upstream overwhelming a constrained receiver.

### Recommended fix

Track separate signed receive windows for the connection and stream 1 in both
the blocking globals and the resumable context:

- initialize the stream receive window from the client's advertised
  `INITIAL_WINDOW_SIZE` and the connection receive window to 65,535;
- before accepting every DATA frame, subtract its full payload length (padding
  included) from both windows and fail with a flow-control error if either
  becomes negative;
- after consuming and retaining DATA, restore credit with WINDOW_UPDATE while
  keeping the tracked windows synchronized; and
- do not advertise a stream window larger than the response-buffer policy
  unless the implementation can stream or otherwise retain that amount.

The blocking and resumable paths should share the same accounting helper so a
future response-frame fix cannot update only one reader. Add a test that sends
four 16,384-byte DATA frames before reading any client WINDOW_UPDATE, plus a
control that reads each update before sending the next frame. Test both the
blocking oracle and the resumable driver, and retain the existing large-body
relay test as a legal, credit-aware multi-frame case.

## Verification

The finding is a source-level trace through both backend response DATA
handlers. Both code paths append the payload and issue credit, but neither has
a receive-window counter or an overrun check; the only relevant window fields
are for request upload. The existing large-response fixture confirms buffering
only and is not a valid flow-control control. `make -j4 bin/linnea-h2client`
completed with no work required. A local socket reproduction was unavailable
under the restricted audit environment, so no runtime result is claimed. No
production source, configuration, or test file was changed in this audit.

References:

- [RFC 9113 §5.2 — Flow Control](https://www.rfc-editor.org/rfc/rfc9113.html#section-5.2)
- [RFC 9113 §6.9.1 — The Flow-Control Window](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9.1)
- [RFC 9113 §6.9.2 — Initial Flow-Control Window Size](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9.2)

## Resolution (2026-08-26) — NOT CONFIRMED as filed; a real defect in its aside

### The filed rule is MAY, not MUST

RFC 9113 §6.9.1: *"A receiver MAY respond with a stream error or connection
error of type FLOW_CONTROL_ERROR if it is unable to accept a frame."* The MUST
in that area governs a **sender** ("A sender MUST NOT send a flow-controlled
frame with a length that exceeds the space available"), and the MUST for a
receiver governs a WINDOW_UPDATE that overflows 2^31-1 — a different rule. The
report states that "a conforming receiver must reject the over-window DATA";
that is not what the section says.

The reference implementation agrees. A server that bursts two frames past the
client's advertised connection window — the window read off the client's own
WINDOW_UPDATEs rather than assumed — against nghttp2 1.66.0 as a client:

```
polite (waits for credit)   send GOAWAY ... error_code=NO_ERROR(0x00)
over   (ignores the window) send GOAWAY ... error_code=NO_ERROR(0x00)
```

nghttp2 accepts the overrun. Implementing the finding would add strictness the
RFC makes optional, diverge from the implementation h2spec is written against,
and risk refusing a legal burst depending on whether credit is accounted when an
update is staged or when it is flushed.

Our behaviour is unchanged and now pinned: `/fc-burst` and `/fc-polite` carry the
same 81,920 bytes, one obeying the window and one not, and both are accepted on
both parsers.

### The real defect is the report's own aside

The report notes in passing that "the 4 MiB stream window advertised to the
backend is larger than the body that this client can retain." That is the
finding, and it has a measured consequence:

```
advertised SETTINGS_INITIAL_WINDOW_SIZE : 4194304
response body the driver can retain     : 1048576
a 2 MiB response, well inside the window we granted:
    direct client   H2C-FAIL
    through a real proxy_h2 front   502, 0 bytes
```

A backend that believes us sends 2 MiB and is cut off after spending the
bandwidth. This is the same defect as the one recorded in the comment
immediately below `INITWIN` in the header — where staying silent on
`MAX_HEADER_LIST_SIZE` said "any size" while the buffers enforced far less, "and
nginx, entitled to believe us, sent an 18188-byte block and was refused". One
field over, and the lesson was already written in the file.

### The fix

`LINNEA_H2C_INITWIN` is now `LINNEA_H2C_D_BODY_CAP` rather than a number, so the
promise cannot drift from the buffer, and `linnea_h2_client.asm` **refuses to
assemble** if it ever does:

```
src/server/linnea_h2_client.asm:83: error: advertised stream window exceeds the
    response body the driver retains
```

That was verified by raising the window and watching the build fail, rather than
trusting the guard because it is written down.

The boundary was measured rather than assumed: both parsers accept a body of
exactly 1048576, and the production path relays all 1048576 bytes to an h1
client. The advertisement is that number.

### Coverage

Eleven rows: the promise, the boundary and the ceiling on each parser, the
burst/polite pair on each parser, and one end to end. Against a binary built
from the audited source, **2 fail and 9 pass as controls** — a narrow fix, and
the control half says so: 1 MiB always relayed and 2 MiB was always refused, so
only the promise was ever wrong.

The `/fc-adv` row is the one that states the finding: the **backend** reports
the window it was promised, so the check is made from the side that has to
believe it.

Full suite **1120 passed, 0 failed**.

## Verification (resolution)

The rule was put to nghttp2 1.66.0 as a client through a probe that tracks the
client's connection window from its own WINDOW_UPDATEs and deliberately
overruns it. The mismatch was measured on both parsers and end to end through a
real `proxy_h2` front. The assembly-time guard was proven by breaking it. No
receive-window accounting was added, and the decision not to add it is pinned by
two checks rather than left to a comment.
