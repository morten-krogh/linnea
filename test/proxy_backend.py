#!/usr/bin/env python3
"""Test backend for linnea's proxy locations.

Serves one request per connection (linnea always sends "Connection: close")
and answers with whatever framing the route name asks for, so the relay can
be tested against counted, chunked, close-delimited and truncated bodies.
Routes match on the path suffix: linnea does not strip location prefixes,
so the backend sees "/api/simple" and friends.
"""
import os
import base64
import hashlib
import socket
import sys
import threading
import time

_PB = int(__import__("os").environ.get("LINNEA_TEST_PORT_BASE", 61000))
_p = lambda n: _PB + n - 61000   # the suite's port rule, one base per run

HOST, PORT = "127.0.0.1", _p(61100)
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
SEEN = os.path.join(os.environ.get("LINNEA_TEST_RUNDIR", "/tmp"),
        "linnea_backend_seen.log")


def read_request(conn):
    """Read one request head plus any Content-Length body. Bytes past the
    body (a client's early tunnel bytes) come back as extra."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(65536)
        if not chunk:
            return None, b"", b""
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    while len(rest) < length:
        chunk = conn.recv(65536)
        if not chunk:
            break
        rest += chunk
    return head, rest[:length], rest[length:]


def ws_handshake(head):
    """The 101 response for a well-formed websocket upgrade, else None."""
    key = b""
    upgrade_ok = connection_ok = False
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        name, value = name.strip().lower(), value.strip()
        if name == b"sec-websocket-key":
            key = value
        elif name == b"upgrade" and value.lower() == b"websocket":
            upgrade_ok = True
        elif name == b"connection" and b"upgrade" in value.lower():
            connection_ok = True
    if not (key and upgrade_ok and connection_ok):
        return None
    accept = base64.b64encode(hashlib.sha1(key + WS_GUID).digest())
    return (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept
            + b"\r\n\r\n")


def respond(conn, head, body, extra=b""):
    request_line = head.split(b"\r\n")[0]
    method, target = request_line.split(b" ")[0], request_line.split(b" ")[1]
    path = target.split(b"?")[0]

    # A record of everything that actually reached a backend, so a test can
    # assert the negative: an upload the client abandoned must appear NOWHERE
    # in here, not even truncated.
    with open(SEEN, "a") as f:
        f.write(f"{method.decode()} {path.decode()} {len(body)}\n")

    if path.endswith(b"/ws-echo"):
        # tunnel echo: whatever arrives after the 101 goes straight back,
        # starting with any bytes the client sent ahead of the handshake
        hs = ws_handshake(head)
        if hs is None:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        conn.sendall(hs)
        data = extra
        while True:
            if data:
                conn.sendall(data)
            data = conn.recv(65536)
            if not data:
                break
    elif path.endswith(b"/ws-push"):
        # the first tunnel bytes ride in the same write as the 101 head;
        # then a second push, then the backend hangs up
        hs = ws_handshake(head)
        if hs is None:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        conn.sendall(hs + b"push-one")
        time.sleep(0.1)
        conn.sendall(b"push-two")
    elif path.endswith(b"/ws-tick"):
        # one-way traffic slower than the idle timeout, but never fully
        # idle: the silent client direction must keep re-arming
        hs = ws_handshake(head)
        if hs is None:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        conn.sendall(hs)
        for n in (1, 2, 3, 4):
            time.sleep(1)
            conn.sendall(b"tick-%d" % n)
    elif path.endswith(b"/ws-silent"):
        # nothing after the 101 in either direction: linnea should tear
        # the idle tunnel down, which surfaces here as EOF
        hs = ws_handshake(head)
        if hs is None:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        conn.sendall(hs)
        conn.recv(65536)
    elif path.endswith(b"/ws-reject"):
        # the app declines the upgrade: an ordinary response instead
        conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 10\r\n\r\nno upgrade")
    elif path.endswith(b"/101"):
        # a 101 nobody asked for: linnea must refuse to tunnel
        conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                     b"Connection: Upgrade\r\n\r\n")
    elif path.endswith(b"/simple"):
        payload = b"backend body"
        if method == b"HEAD":
            # A correct HEAD reply: Content-Length, but no body at all.
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n")
        else:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s"
                         % (len(payload), payload))
    elif path.endswith(b"/echo"):
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s"
                     % (len(body), body))
    elif path.endswith(b"/target"):
        # Echo the request target, to prove the query string is forwarded.
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s"
                     % (len(target), target))
    elif path.endswith(b"/headers"):
        # Echo the request head, to prove headers are forwarded.
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s"
                     % (len(head), head))
    elif path.endswith(b"/hopresp"):
        # Hop-by-hop fields in a RESPONSE. They describe the backend's
        # connection to us, not ours to the client, so none may be relayed on.
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n"
                     b"Keep-Alive: timeout=5, max=100\r\n"
                     b"TE: gzip\r\n"
                     b"Trailer: X-Late\r\n"
                     b"Proxy-Connection: keep-alive\r\n"
                     b"Proxy-Authenticate: Basic realm=\"backend\"\r\n"
                     b"X-Kept: yes\r\n\r\nbody")
    elif path.endswith(b"/hopnamed"):
        # RFC 9110 7.6.1: Connection is the EXTENSIBILITY mechanism -- an
        # intermediary must drop every field the peer NAMES there, not only the
        # names it happens to know. /hopresp above proves the fixed list and
        # cannot prove this one, because the field it preserves is never
        # nominated (audit-report-10 Finding 2). X-Kept is the control: an
        # ordinary field that must still arrive.
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n"
                     b"Connection: X-Backend-Only\r\n"
                     b"X-Backend-Only: leaked\r\n"
                     b"X-Kept: yes\r\n\r\nbody")
    elif path.endswith(b"/hopnamedmulti"):
        # Two Connection lines, several tokens, OWS and mixed case -- the shape
        # the token walk has to survive. close is a token too and is not a field.
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n"
                     b"Connection:  x-one ,\tX-Two\r\n"
                     b"Connection: close, X-Three\r\n"
                     b"X-One: a\r\nX-Two: b\r\nX-Three: c\r\n"
                     b"X-Kept: yes\r\n\r\nbody")
    elif path.endswith(b"/earlyhop"):
        # ...and the same rule on an INTERIM head, which has its own rewriter on
        # every protocol and so is exactly where a rule drifts.
        conn.sendall(b"HTTP/1.1 103 Early Hints\r\n"
                     b"Connection: X-Hint-Only\r\n"
                     b"X-Hint-Only: leaked\r\n"
                     b"Link: </a.css>; rel=preload\r\n\r\n"
                     b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nvalid")
    elif path.endswith(b"/205body"):
        # RFC 9110 15.3.6: a server MUST NOT generate content in a 205. Unlike
        # 204, a 205 MAY carry Content-Length -- but only to say zero, so a
        # nonzero one is a contradiction the proxy must not relay
        # (audit-report-10 Finding 1).
        conn.sendall(b"HTTP/1.1 205 Reset Content\r\nContent-Length: 4\r\n\r\nbody")
    elif path.endswith(b"/205zero"):
        # The legal spelling, and the control that stops the fix from becoming
        # "refuse every 205".
        conn.sendall(b"HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n")
    elif path.endswith(b"/205bare"):
        # No framing at all: also legal, also no content.
        conn.sendall(b"HTTP/1.1 205 Reset Content\r\n\r\n")
    elif path.endswith(b"/upgrade200"):
        # RFC 9110 7.8: a sender of Upgrade names it as a Connection option so
        # intermediaries do not forward it. On a response that is NOT a protocol
        # switch it is ordinary hop-by-hop metadata and must be dropped. Report
        # 10's Connection walk exempted `upgrade` unconditionally so the 101
        # tunnel could complete, which was broader than its purpose
        # (audit-report-11 Finding 1). The client here asked for no upgrade.
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n"
                     b"Connection: Upgrade\r\n"
                     b"Upgrade: websocket\r\n\r\nbody")
    elif path.endswith(b"/tegzip"):
        # RFC 9112 6.1's own example: content gzipped, THEN chunk-framed.
        # Removing the chunk framing does not undo the gzip, so a proxy that
        # de-chunks and then calls the result identity content is handing the
        # client bytes that are not the response (audit-report-11 Finding 2).
        import gzip as _gz
        member = _gz.compress(b"transfer-coded payload")
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
                     + ("%x\r\n" % len(member)).encode() + member + b"\r\n0\r\n\r\n")
    elif path.endswith(b"/tegzipbare"):
        # ...and the same coding without chunked at all: close-delimited, so
        # nothing even hints that a transformation is outstanding.
        import gzip as _gz
        member = _gz.compress(b"transfer-coded payload")
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n" + member)
        conn.close()
    elif path.endswith(b"/chunkhexsize"):
        # A chunk size using a hex LETTER. h2p_hexval clobbered AL with its own
        # `sub eax, '0'` and then re-read it, so 'a' arrived at the letter path
        # as 0x31 and was rejected: h2 refused EVERY chunked response whose size
        # contained a-f -- any chunk of 10-15 bytes, and most real ones -- while
        # h1 and h3 served it. Long-standing, and invisible because every chunk
        # fixture in this file used sizes 0-9 (sweep after audit-report-21).
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"a\r\nbodybody!!\r\n0\r\n\r\n")
    elif path.endswith(b"/chunkhexsizeupper"):
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"A\r\nbodybody!!\r\n0\r\n\r\n")
    elif path.endswith(b"/chunksizetrailsp"):
        # chunk = chunk-size [ chunk-ext ] CRLF: only ';' or CR may follow the
        # digits. h3 treated ANY non-hex byte as ending the size and fell into
        # its extension state, so this was a size of 4 with junk after it.
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4 \r\nbody\r\n0\r\n\r\n")
    elif path.endswith(b"/chunksizejunk"):
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4g\r\nbody\r\n0\r\n\r\n")
    elif path.endswith(b"/chunkextnul"):
        # An extension is token / quoted-string with BWS: HTAB may appear there,
        # no other control byte may. Rejecting LF (report 19) left NUL, CTL and
        # DEL accepted as extension data by BOTH binary protocols.
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4;a\x00b\r\nbody\r\n0\r\n\r\n")
    elif path.endswith(b"/chunklatebad"):
        # The head first, then -- after the relay has certainly forwarded it --
        # a malformed chunk. HTTP/1 cannot answer 502 by then, so this is the
        # other half of the rule: it must decline to FINISH. The client is left
        # a 200 whose chunked body never terminates, rather than the malformed
        # framing relayed verbatim inside a clean, complete message
        # (audit-report-24). Every other chunk route here writes head and body
        # together, which lands the same judgement while the head is unsent.
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        time.sleep(0.3)
        conn.sendall(b"4;=bad\r\nbody\r\n0\r\n\r\n")
    elif path.endswith(b"/chunklategood"):
        # ...and the control for it, split exactly the same way: a VALID body
        # arriving after the head must still be relayed whole.
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        time.sleep(0.3)
        conn.sendall(b"4\r\nbody\r\n0\r\n\r\n")
    elif path.endswith(b"/chunkextnoname"):
        # chunk-ext-name is a token and it is not optional. The scanners asked
        # only which BYTES an extension may contain, never what shape they must
        # make, so this was a well-formed chunk header (audit-report-23).
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4;=bad\r\nbody\r\n0\r\n\r\n")
    elif path.endswith(b"/chunkextunterm"):
        # An unterminated quoted-string. This is the one that matters: a parser
        # that DOES track the quotes keeps looking for the closing one past the
        # CRLF, so it and a scanner that stops at the CR disagree about where
        # the chunk data begins -- and that disagreement is request smuggling.
        # CR is not qdtext, so the quote can never swallow the line ending.
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b'4;a="unterminated\r\nbody\r\n0\r\n\r\n')
    elif path.endswith(b"/chunkextquoted"):
        # A VALID quoted-string value carrying a semicolon: the control for the
        # rule above, and proof that ';' inside quotes does not start a second
        # extension.
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b'4;a="x;y"\r\nbody\r\n0\r\n\r\n')
    elif path.endswith(b"/chunkextbws"):
        # BWS before the ';' IS in the grammar (RFC 9112 7.1.1), so this is
        # valid -- while /api/chunksizetrailsp, a space with no ';' behind it,
        # stays malformed. The pair is the point: "reject junk after the
        # digits" must not become "reject the whitespace the grammar allows".
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4 ;a=b\r\nbody\r\n0\r\n\r\n")
    elif path.endswith(b"/chunktrailemptyname"):
        # A field line needs at least one name byte. Report 21 required token
        # bytes before the colon but not that there be ANY.
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4\r\nbody\r\n0\r\n: v\r\n\r\n")
    elif path.endswith(b"/chunktrailhtab"):
        # A VALID trailer whose value contains HTAB and internal spaces: the
        # control for the value grammar, so "reject control bytes" cannot
        # quietly become "reject whitespace" (audit-report-21).
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4\r\nbody\r\n0\r\nX-T: \ta b\r\n\r\n")
    elif path.endswith(b"/chunktrailnocolon"):
        # A trailer section is a section of HTTP FIELD LINES. This line has no
        # colon, so it is not one (audit-report-21).
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4\r\nbody\r\n0\r\nNot-A-Field\r\n\r\n")
    elif path.endswith(b"/chunktrailnul"):
        # ...and a NUL inside what is otherwise a field value.
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4\r\nbody\r\n0\r\nX-Trail: ok\x00still\r\n\r\n")
    elif path.endswith(b"/chunktrailbadname"):
        # A field NAME that is not a token.
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4\r\nbody\r\n0\r\nBad Name: x\r\n\r\n")
    elif path.endswith(b"/chunktrailinlinelf"):
        # A bare LF INSIDE a trailer field line, followed by a later CRLF. This
        # is the test /api/chunktraillf is not: an LF then EOF leaves an
        # incremental decoder in an unfinished state and it fails on
        # truncation, which proves nothing about the character class. Only a
        # valid continuation after the LF exercises the scanner's rule
        # (audit-report-20).
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4\r\nbody\r\n0\r\nX-Trail: one\ncontinued\r\n\r\n")
    elif path.endswith(b"/chunkextlf"):
        # A chunk-extension is terminated by CRLF. A bare LF inside it is not a
        # line ending, and a later CRLF does not retroactively make it one
        # (audit-report-19).
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4;note\ncontinued\r\nbody\r\n0\r\n\r\n")
    elif path.endswith(b"/chunkext"):
        # An ordinary extension, ignored as metadata but validly framed: the
        # control that keeps the LF rule from becoming "reject extensions".
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4;note=ok\r\nbody\r\n0\r\n\r\n")
    elif path.endswith(b"/chunktraillf"):
        # A bare LF where a trailer line should start.
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4\r\nbody\r\n0\r\n\n")
    elif path.endswith(b"/chunkdatalf"):
        # A bare LF where the CRLF after chunk data should be.
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4\r\nbody\n0\r\n\r\n")
    elif path.endswith(b"/chunknoterm"):
        # "0\r\n" is the zero-size chunk LINE; it starts the trailer section and
        # does not end the message. The empty trailer line that would end it
        # never arrives (audit-report-18).
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4\r\nbody\r\n0\r\n")
        conn.close()
    elif path.endswith(b"/chunktrailer"):
        # A COMPLETE chunked message that carries a trailer field. The control:
        # a decoder that stops at the zero-size line passes this by ignoring the
        # very bytes that make it valid, so it has to be here.
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4\r\nbody\r\n0\r\nX-Trail: a\r\n\r\n")
    elif path.endswith(b"/chunkpartialtrail"):
        # ...and the same trailer section cut off before its terminator.
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4\r\nbody\r\n0\r\nX-Trail: a\r\n")
        conn.close()
    elif path.endswith(b"/chunkspace"):
        # RFC 9112 7.1: chunk-size is 1*HEXDIG. A space before the first digit
        # is not a delimiter, and h2's decoder alone accepted one
        # (audit-report-17).
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b" 4\r\nbody\r\n0\r\n\r\n")
    elif path.endswith(b"/chunkoverflow"):
        # 17 hex digits: one nybble past 64 bits. Shifted without a bound the
        # accumulator wraps to ZERO, which the decoder then reads as the
        # terminal chunk -- a nonzero size line becoming end-of-message, so the
        # response completes successfully and truncated.
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"10000000000000000\r\n")
    elif path.endswith(b"/chunkbig"):
        # The bound itself: 0fffffffffffffff is the largest the other two
        # decoders accept, so this must fail on SIZE rather than on wrapping.
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"1fffffffffffffff\r\n")
    elif path.endswith(b"/chunktrunc"):
        # A chunked body that simply stops: the declared 4 bytes never arrive
        # and no terminal chunk does either. Half a response is not one that can
        # be delivered as a success.
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4\r\nbo")
        conn.close()
    elif path.endswith(b"/connsts"):
        # Connection names the ORIGIN's policy field. Report 15 makes linnea
        # replace the discarded backend field with its configured policy -- and
        # if the upstream Connection line is then forwarded too, a compliant
        # client removes that replacement as hop-specific. The option must not
        # travel (audit-report-16). An ordinary field comes FIRST, which is what
        # moves Connection off the one offset that accidentally works.
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n"
                     b"Connection: Strict-Transport-Security\r\n"
                     b"Strict-Transport-Security: max-age=0\r\n\r\nbody")
    elif path.endswith(b"/connclose"):
        # The simpler control: an upstream close instruction describes the
        # upstream hop and must not become ours.
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n"
                     b"Connection: close\r\nX-Kept: yes\r\n\r\nbody")
    elif path.endswith(b"/connfirst"):
        # Connection as the FIRST field -- the position that happened to work
        # by accident, kept so a fix cannot pass by only handling the other one.
        conn.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n"
                     b"Content-Length: 4\r\nX-Kept: yes\r\n\r\nbody")
    elif path.endswith(b"/sechop"):
        # The upstream NAMES its own security fields as connection-specific, so
        # they must not reach the client -- and therefore must not count as
        # "the backend supplied a policy" when linnea decides whether to add
        # its configured one (audit-report-15 Finding 2).
        conn.sendall(b"HTTP/1.1 200 OK\r\n"
                     b"Connection: Strict-Transport-Security, X-Content-Type-Options\r\n"
                     b"Strict-Transport-Security: max-age=0\r\n"
                     b"X-Content-Type-Options: bogus\r\n"
                     b"Content-Length: 4\r\n\r\nbody")
    elif path.endswith(b"/secown"):
        # An ordinary backend policy that DOES survive: it wins, and linnea must
        # not add a second copy. The control for the fix.
        conn.sendall(b"HTTP/1.1 200 OK\r\n"
                     b"Strict-Transport-Security: max-age=99\r\n"
                     b"X-Content-Type-Options: nosniff\r\n"
                     b"Content-Length: 4\r\n\r\nbody")
    elif path.endswith(b"/connte"):
        # Connection says a field is specific to THIS hop; it does not unsay
        # what the field MEANS on this hop. RFC 9110 7.6.1 lists
        # Transfer-Encoding among the fields an intermediary removes AFTER
        # applying their semantics (audit-report-14 Finding 1).
        conn.sendall(b"HTTP/1.1 200 OK\r\nConnection: Transfer-Encoding\r\n"
                     b"Transfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n")
    elif path.endswith(b"/conncl"):
        # The same for a nominated Content-Length: it must frame this hop and
        # must not travel onward.
        conn.sendall(b"HTTP/1.1 200 OK\r\nConnection: Content-Length\r\n"
                     b"Content-Length: 4\r\n\r\nbody")
    elif path.endswith(b"/conntecl"):
        # Both nominated: still a framing conflict, and must be refused on every
        # protocol rather than served by whichever one stopped noticing.
        conn.sendall(b"HTTP/1.1 200 OK\r\n"
                     b"Connection: Transfer-Encoding, Content-Length\r\n"
                     b"Transfer-Encoding: chunked\r\nContent-Length: 4\r\n"
                     b"\r\n4\r\nbody\r\n0\r\n\r\n")
    elif path.endswith(b"/fieldows"):
        # HTTP/1 OWS around a field value is a field-line DELIMITER, not part of
        # the value. RFC 9113 8.2.1: an h2 field value MUST NOT start or end
        # with SP or HTAB (Finding 2). HTAB leading, HTAB trailing.
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n"
                     b"X-Note:\tvalue\t\r\n\r\nbody")
    elif path.endswith(b"/fieldsptrail"):
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n"
                     b"X-Note: value \r\n\r\nbody")
    elif path.endswith(b"/fieldinner"):
        # Internal whitespace is part of the value and must NOT be touched: the
        # control that keeps a trim from becoming a rewrite.
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n"
                     b"X-Note: value one\r\n\r\nbody")
    elif path.endswith(b"/status099"):
        # RFC 9110 15: a status code is a three-digit integer in 100..599.
        # Three digits alone is necessary but not sufficient, and 099 is not an
        # informational status a proxy must forward -- it is outside the
        # namespace. The trailing 200 exists only to make h1's unintended
        # interim classification visible (audit-report-13 Finding 1).
        conn.sendall(b"HTTP/1.1 099 Invalid\r\nX-Interim: should-not-pass\r\n\r\n"
                     b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfinal")
    elif path.endswith(b"/status600"):
        # ...and the upper half, which no protocol checked at all.
        conn.sendall(b"HTTP/1.1 600 Nope\r\nContent-Length: 4\r\n\r\nbody")
    elif path.endswith(b"/status299"):
        # In range but unregistered: MUST still be forwarded. The control that
        # stops the range check becoming an allowlist of known statuses.
        conn.sendall(b"HTTP/1.1 299 Extension\r\nContent-Length: 4\r\n\r\nbody")
    elif path.endswith(b"/tedupe"):
        # Repeated list-valued field lines combine in order, so this states
        # "chunked, chunked" -- two chunk layers, which RFC 9112 6.1 forbids and
        # which the single layer below does not satisfy. Distinct from the legal
        # duplicate Content-Length of report 6, where both lines describe the
        # same body (audit-report-13 Finding 2).
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                     b"Transfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n")
    elif path.endswith(b"/204te"):
        # RFC 9112 6.1: a server MUST NOT send Transfer-Encoding in any 1xx or
        # 204 response. Distinct from report 10's 205 rule -- a 205 MAY use
        # transfer framing to make its zero-length termination unambiguous;
        # 1xx and 204 may not carry the field at all (audit-report-12 Finding 1).
        conn.sendall(b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n"
                     b"\r\n5\r\nbody!\r\n0\r\n\r\n")
    elif path.endswith(b"/204tezero"):
        # The same head with an empty chunk: it is the FIELD that is forbidden,
        # not the bytes behind it.
        conn.sendall(b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n"
                     b"\r\n0\r\n\r\n")
    elif path.endswith(b"/earlyte"):
        # ...and on an interim head, where h2 used to relay a scrubbed 103
        # before discovering the error -- telling the client early metadata was
        # valid when the upstream response is malformed.
        conn.sendall(b"HTTP/1.1 103 Early Hints\r\nTransfer-Encoding: chunked\r\n"
                     b"Link: </a.css>; rel=preload\r\n\r\n0\r\n\r\n"
                     b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nvalid")
    elif path.endswith(b"/name64"):
        # A 64-byte field name: the boundary that already worked everywhere.
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-" + b"a" * 62
                     + b": kept\r\n\r\nbody")
    elif path.endswith(b"/name65"):
        # 65 bytes -- one past an ENCODER SCRATCH BUFFER, not any HTTP limit.
        # h1 forwarded it, h2 and h3 silently erased it, so an extension field
        # survived or vanished depending on ALPN (audit-report-12 Finding 2).
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-" + b"a" * 63
                     + b": kept\r\n\r\nbody")
    elif path.endswith(b"/namebig"):
        # Past the documented limit: must be refused the same way everywhere,
        # rather than served by one protocol and scrubbed by two.
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-" + b"a" * 300
                     + b": kept\r\n\r\nbody")
    elif path.endswith(b"/cegzip"):
        # The RIGHT layer for compressed bytes: Content-Encoding is a property of
        # the REPRESENTATION and is end-to-end, so it rides through a proxy
        # untouched and the client decompresses it. Transfer-Encoding is a
        # property of the HTTP/1 message on ONE hop. Refusing the latter must not
        # disturb the former (audit-report-11 Finding 2).
        import gzip as _gz
        # mtime pinned: gzip stamps the clock by default, and the three
        # protocols are three separate requests, so the bytes would differ and
        # "all three delivered the same body" could never be asserted.
        member = _gz.compress(b"transfer-coded payload", mtime=0)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n"
                     b"Content-Type: text/plain\r\nContent-Length: "
                     + str(len(member)).encode() + b"\r\n\r\n" + member)
    elif path.endswith(b"/tepad"):
        # The legal spelling with OWS and case, which must still be SERVED: the
        # control that stops "refuse anything that is not exactly chunked".
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding:  Chunked \r\n\r\n"
                     b"5\r\nplain\r\n0\r\n\r\n")
    elif path.endswith(b"/205chunked"):
        # A 205 that frames content the other way. RFC 9110 15.3.6 does allow a
        # zero-length chunked section here, so refusing this is deliberately
        # stricter than the letter: the proxy cannot know the section is empty
        # without reading it, and the alternative is relaying content on a
        # status that must have none. Documented, not accidental.
        conn.sendall(b"HTTP/1.1 205 Reset Content\r\nTransfer-Encoding: chunked\r\n"
                     b"\r\n4\r\nbody\r\n0\r\n\r\n")
    elif path.endswith(b"/chunked"):
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"7\r\nchunked\r\n5\r\n body\r\n0\r\n\r\n")
    elif path.endswith(b"/eof"):
        # No Content-Length and no chunking: the close is the framing.
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
                     b"eof delimited body")
    elif path.endswith(b"/truncated"):
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
    elif path.endswith(b"/badname"):
        # a field name containing a space is not a token (audit Finding 34)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nBad Name: x\r\n\r\nbody")
    elif path.endswith(b"/badvalue"):
        # a NUL (control byte) in a field value
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-Test: va\x00ue\r\n\r\nbody")
    elif path.endswith(b"/nocolon"):
        # a header line with no colon at all
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nNoColonHere\r\n\r\nbody")
    elif path.endswith(b"/clconflict"):
        # two Content-Length values that disagree -> contradictory framing
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 7\r\n\r\nhello")
    elif path.endswith(b"/cldupe"):
        # two Content-Length values that agree -> normalize, still serve
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello")
    elif path.endswith(b"/chunktrunc"):
        # A chunked response cut off mid-stream: the head and one full chunk are
        # flushed with a pause between each, so the proxy forwards the response
        # HEADERS to the client before the socket closes with no terminating
        # 0-chunk. De-chunked, the client is handed a complete-looking body with
        # no length to check -- so the proxy must be the one to notice the
        # truncation and reset the stream (audit Finding 31). Without the pauses
        # the proxy would see the whole (short) response in one read and fail it
        # with a 502 before any head went out.
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        time.sleep(0.4)
        conn.sendall(b"5\r\nhello\r\n")
        time.sleep(0.4)
    elif path.endswith(b"/early"):
        # 103 Early Hints as a separate write (the real pattern: hints early,
        # the final response once it is ready), then the final 200. A proxy must
        # relay the 103 as an interim HEADERS block without END_STREAM and still
        # deliver the 200 (audit Finding 30).
        conn.sendall(b"HTTP/1.1 103 Early Hints\r\n"
                     b"Link: </style.css>; rel=preload; as=style\r\n\r\n")
        time.sleep(0.3)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nfinal-reply")
    elif path.endswith(b"/early-atonce"):
        # The interim and the final response in a single write, then close. The
        # proxy must not treat the 103 as final, and must not hang waiting for a
        # final head that is already buffered.
        conn.sendall(b"HTTP/1.1 103 Early Hints\r\n"
                     b"Link: </a.js>; rel=preload; as=script\r\n\r\n"
                     b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nfinal-reply")
    elif path.endswith(b"/multi-early"):
        # Several informational responses before the final one, in one write.
        conn.sendall(b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n"
                     b"HTTP/1.1 103 Early Hints\r\nLink: </b.css>; rel=preload\r\n\r\n"
                     b"HTTP/1.1 100 Continue\r\n\r\n"
                     b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nfinal-reply")
    elif path.endswith(b"/upgrade101"):
        # 101 has no meaning over an h2 proxy; it must be rejected (502), not
        # relayed as an HTTP/2 response.
        conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\n"
                     b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        time.sleep(0.3)
    elif path.endswith(b"/linger"):
        # A backend that takes long enough for the client to give up first, but
        # not so long that it trips a proxy timeout. What that leaves behind is
        # an upstream exchange whose answer nobody is waiting for any more,
        # which the proxy has to notice rather than send to whichever
        # connection holds that slot by then.
        time.sleep(1.5)
        payload = b"linger body"
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s"
                     % (len(payload), payload))
    elif path.endswith(b"/big"):
        # A body larger than any single relay buffer, to exercise the loop.
        payload = b"x" * 40000
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s"
                     % (len(payload), payload))
    elif path.endswith(b"/bighead"):
        filler = b"X-Filler: " + b"y" * 200 + b"\r\n"
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
                     + filler * 50 + b"\r\n")
    elif path.endswith(b"/slow"):
        time.sleep(4)          # longer than the test config's 2s timeout
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nslow")
    elif path.endswith(b"/garbage"):
        conn.sendall(b"NOT AN HTTP RESPONSE\r\n\r\n")
    elif path.endswith(b"/tecl"):
        # Contradictory framing: a response-splitting vector, not a response.
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                     b"Content-Length: 5\r\n\r\n7\r\nchunked\r\n0\r\n\r\n")
    elif path.endswith(b"/cljunk"):
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 12 34\r\n\r\nhello world!")
    elif path.endswith(b"/clpad"):
        # Legitimate optional whitespace around the value.
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length:   5  \r\n\r\nvalid")
    elif path.endswith(b"/cltab"):
        # OWS is SP *or* HTAB (RFC 9110 5.6.3), and the tab spelling is the one
        # the framing lookups missed: they trimmed spaces only, so h2 and h3
        # answered 502 to this while h1 served it (audit-report-7 Finding 2).
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length:\t5\t\r\n\r\nvalid")
    elif path.endswith(b"/cltablead"):
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length:\t5\r\n\r\nvalid")
    elif path.endswith(b"/cltabtrail"):
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\t\r\n\r\nvalid")
    elif path.endswith(b"/expect"):
        # Answers 100 Continue if asked; linnea must never ask, since it
        # has the whole body buffered before it connects.
        if b"xpect: 100-continue" in head:
            conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nreal")
    elif path.endswith(b"/301"):
        conn.sendall(b"HTTP/1.1 301 Moved Permanently\r\n"
                     b"Location: /elsewhere\r\nContent-Length: 0\r\n\r\n")
    elif path.endswith(b"/204"):
        # No body despite the Content-Length, as 204 requires. RFC 9110 8.6 also
        # says a server MUST NOT send Content-Length on a 204 at all, so this is
        # a forbidden field the proxy must drop rather than relay
        # (audit-report-9 Finding 2).
        conn.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 12\r\n\r\n")
    elif path.endswith(b"/204clean"):
        # ...and the same 204 without it: the control that separates "the proxy
        # relays a forbidden field" from "h3 cannot do bodiless responses".
        conn.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
    elif path.endswith(b"/earlycl"):
        # A 103 carrying Content-Length -- forbidden on 1xx by the same rule --
        # then the real response. The interim relay must strip it and still
        # deliver the 200.
        conn.sendall(b"HTTP/1.1 103 Early Hints\r\nContent-Length: 7\r\n"
                     b"Link: </a.css>; rel=preload\r\n\r\n"
                     b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nvalid")
    elif path.endswith(b"/badstatuscr"):
        # A bare CR ends nothing in HTTP/1: a CR only ends a line when an LF
        # follows (RFC 9112 2.2). "HTTP/1.1 200\rX-Fold: ..." is not a status
        # line, and lenient parsing here is a response-splitting primitive
        # (audit-report-9 Finding 1).
        conn.sendall(b"HTTP/1.1 200\rX-Fold: accepted\r\n"
                     b"Content-Length: 5\r\n\r\nvalid")
    elif path.endswith(b"/http10"):
        conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 6\r\n\r\nold hi")
    elif path.endswith(b"/badversion"):
        # RFC 9112 2.3: HTTP-version is HTTP-name "/" DIGIT "." DIGIT, so
        # "HTTP/x.y" is not a status line at all. h1 refused it; h2 and h3
        # checked only "HTTP", the slash, the space and three digits, and
        # manufactured a downstream 200 from the digits (audit-report-8 F1).
        conn.sendall(b"HTTP/x.y 200 OK\r\nContent-Length: 5\r\n\r\nvalid")
    elif path.endswith(b"/bigearly"):
        # Two LEGAL 103 Early Hints, each head 4040 bytes -- under the 6144
        # per-head cap -- then the final 200, all in one write. Each fits on its
        # own; their QPACK-encoded sum plus the final head does not fit the one
        # 8192-byte staging buffer, so h3 answered 502 to an exchange h1 and h2
        # served (audit-report-8 F2).
        # SIX hints of 1300 bytes, not two of 4000. What overran the old 8192
        # reserve is the AGGREGATE (6 x ~1490 encoded = ~8900), and spreading it
        # over more, smaller heads keeps two other bounds happy: the whole
        # exchange still fits LINNEA_CONN_UP_BUF (8448), and no single field
        # section is bigger than pylsqpack will decode -- a 2700-byte one is
        # not, which made the test client fail on a response curl-h3 handles
        # perfectly. Sizing it this way keeps the fixture about the server
        # rather than about the test's decoder. Six is also under the
        # LINNEA_H3_PROXY_IMAX cap of 8, so this is the buffer being tested and
        # not the count.
        hint = (b"HTTP/1.1 103 Early Hints\r\nX-Filler: " + b"x" * 1300
                + b"\r\n\r\n")
        conn.sendall(hint * 6
                     + b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nvalid")
    elif path.endswith(b"/manyearly"):
        # NINE interim responses, one past LINNEA_H3_PROXY_IMAX. Tiny ones:
        # bounding the raw bytes cannot bound the ENCODED size, because every
        # head however small encodes to a field section carrying its own via,
        # date and server -- which is why the cap counts heads. h3 must refuse
        # the chain while parsing, before capturing a body it could not send.
        conn.sendall(b"HTTP/1.1 103 Early Hints\r\n\r\n" * 9
                     + b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nvalid")
    else:
        conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(16)
    while True:
        conn, _ = srv.accept()
        # One thread per connection: a long exchange (a websocket tunnel, or
        # the deliberately slow route) must not stop the backend answering
        # anything else. HTTP/2 clients open several upstream connections at
        # once, so a serial backend would make their timing depend on
        # unrelated traffic.
        threading.Thread(target=serve_one, args=(conn,), daemon=True).start()


def serve_one(conn):
    try:
        head, body, extra = read_request(conn)
        if head:
            respond(conn, head, body, extra)
    except (BrokenPipeError, ConnectionResetError, ValueError, IndexError,
            OSError):
        pass
    finally:
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        conn.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
