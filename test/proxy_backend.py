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
