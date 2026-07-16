#!/usr/bin/env python3
"""Test backend for linnea's proxy locations.

Serves one request per connection (linnea always sends "Connection: close")
and answers with whatever framing the route name asks for, so the relay can
be tested against counted, chunked, close-delimited and truncated bodies.
Routes match on the path suffix: linnea does not strip location prefixes,
so the backend sees "/api/simple" and friends.
"""
import base64
import hashlib
import socket
import sys
import time

HOST, PORT = "127.0.0.1", 47100
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


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
    elif path.endswith(b"/chunked"):
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"7\r\nchunked\r\n5\r\n body\r\n0\r\n\r\n")
    elif path.endswith(b"/eof"):
        # No Content-Length and no chunking: the close is the framing.
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
                     b"eof delimited body")
    elif path.endswith(b"/truncated"):
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
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
        # No body despite the Content-Length, as 204 requires.
        conn.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 12\r\n\r\n")
    elif path.endswith(b"/http10"):
        conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 6\r\n\r\nold hi")
    else:
        conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(16)
    while True:
        conn, _ = srv.accept()
        try:
            head, body, extra = read_request(conn)
            if head:
                respond(conn, head, body, extra)
        except (BrokenPipeError, ConnectionResetError, ValueError, IndexError):
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
