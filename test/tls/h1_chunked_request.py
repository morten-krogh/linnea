#!/usr/bin/env python3
"""Chunked request bodies (RFC 9112 7.1).

"A server MUST be able to receive and decode the chunked transfer coding."

Nothing here could. Any Transfer-Encoding at all was answered 501 and the
connection closed, so every client that sends a body of unknown length up front
was refused outright: curl -T -, fetch() with a ReadableStream, and most
libraries when handed a stream rather than a buffer. The streaming-upload path
that already existed worked only when the client could declare a Content-Length.

The body is now decoded in place on the way in, so downstream it is
indistinguishable from one that arrived with a length — which is also what the
backend is told, since a Transfer-Encoding forwarded to it would promise a
framing that is no longer there.

The cases that must NOT change are in here too: an unsupported coding is still
501, Transfer-Encoding alongside Content-Length is the classic smuggling setup
and RFC 9112 6.1 makes it 400, and an ordinary Content-Length body still works.

usage: h1_chunked_request.py <port>
"""
import socket
import sys
import time

port = int(sys.argv[1])
HOST = b"one.test"


def exchange(req, keep=False):
    s = socket.create_connection(("127.0.0.1", port), timeout=6)
    s.settimeout(4)
    s.sendall(req)
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    s.close()
    return out


def status(resp):
    return resp.split(b"\r\n", 1)[0].decode("latin1") if resp else "<nothing>"


def body(resp):
    return resp.partition(b"\r\n\r\n")[2]


def chunked(*pieces, trailer=b"", ext=b""):
    out = b""
    for p in pieces:
        out += (b"%x" % len(p)) + ext + b"\r\n" + p + b"\r\n"
    return out + b"0\r\n" + trailer + b"\r\n"


fails = 0


def case(label, ok):
    global fails
    print(f"{'ok  ' if ok else 'FAIL'} {label}")
    fails += not ok


# --- the decode itself ------------------------------------------------------
r = exchange(b"POST /api/echo HTTP/1.1\r\nHost: " + HOST +
             b"\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked(b"hello", b" world"))
case(f"two chunks reassemble ({status(r)}, {body(r)!r})",
     b"200" in status(r).encode() and body(r) == b"hello world")

r = exchange(b"POST /api/echo HTTP/1.1\r\nHost: " + HOST +
             b"\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked())
case(f"an empty chunked body ({status(r)})", b"200" in status(r).encode())

many = [bytes([0x61 + (i % 26)]) * 37 for i in range(40)]
r = exchange(b"POST /api/echo HTTP/1.1\r\nHost: " + HOST +
             b"\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked(*many))
case(f"forty chunks reassemble in order ({len(body(r))} bytes)",
     body(r) == b"".join(many))

r = exchange(b"POST /api/echo HTTP/1.1\r\nHost: " + HOST +
             b"\r\nTransfer-Encoding: chunked\r\n\r\n" +
             chunked(b"hello", ext=b";name=value", trailer=b"X-Checksum: abc\r\n"))
case(f"chunk extensions and a trailer are ignored ({body(r)!r})",
     body(r) == b"hello")

# --- what the backend is told -----------------------------------------------
r = exchange(b"POST /api/headers HTTP/1.1\r\nHost: " + HOST +
             b"\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked(b"hello"))
saw = body(r).decode("latin1").lower()
case("the backend gets a Content-Length for the decoded body",
     "content-length: 5" in saw)
case("...and no Transfer-Encoding, which would promise a framing that is gone",
     "transfer-encoding" not in saw)

# --- the cases that must not change -----------------------------------------
r = exchange(b"POST /api/echo HTTP/1.1\r\nHost: " + HOST +
             b"\r\nTransfer-Encoding: gzip\r\n\r\n")
case(f"an unsupported coding is still 501 ({status(r)})", "501" in status(r))

r = exchange(b"POST /api/echo HTTP/1.1\r\nHost: " + HOST +
             b"\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n" +
             chunked(b"hello"))
case(f"Transfer-Encoding with Content-Length is 400 ({status(r)})",
     "400" in status(r))

r = exchange(b"POST /api/echo HTTP/1.1\r\nHost: " + HOST +
             b"\r\nContent-Length: 5\r\n\r\nhello")
case(f"an ordinary Content-Length body still works ({body(r)!r})",
     body(r) == b"hello")

# --- malformed framing ------------------------------------------------------
for label, tail in (
        ("a non-hex chunk size", b"zz\r\nhello\r\n0\r\n\r\n"),
        ("a chunk not followed by CRLF", b"5\r\nhelloXX0\r\n\r\n"),
        ("a size with no digits at all", b"\r\nhello\r\n0\r\n\r\n")):
    r = exchange(b"POST /api/echo HTTP/1.1\r\nHost: " + HOST +
                 b"\r\nTransfer-Encoding: chunked\r\n\r\n" + tail)
    case(f"{label} is 400 ({status(r)})", "400" in status(r))

# --- arrival pattern: a body comes in as many reads as the network likes -----
# This is what a real streaming client looks like, and it is what caught the
# first version of the decoder: it slid chunks down as it walked, so a body that
# arrived in pieces was half-decoded when the parse asked for more, and the
# retry read the wreckage and called it malformed. The walk now measures first
# and moves nothing until the terminating chunk has actually been seen.
def in_pieces(label, pieces, delay=0.1):
    global fails
    s = socket.create_connection(("127.0.0.1", port), timeout=8)
    s.settimeout(5)
    try:
        for piece in pieces:
            s.sendall(piece)
            time.sleep(delay)
        out = b""
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except (socket.timeout, BrokenPipeError, ConnectionResetError):
        out = locals().get("out", b"")
    s.close()
    ok = b"200" in out.split(b"\r\n", 1)[0] and body(out) == b"streamed body"
    case(f"{label} ({status(out)}, {body(out)!r})", ok)


head = (b"PUT /api/echo HTTP/1.1\r\nHost: " + HOST +
        b"\r\nTransfer-Encoding: chunked\r\n\r\n")
whole = b"d\r\nstreamed body\r\n0\r\n\r\n"
in_pieces("head and body in one write", [head + whole])
in_pieces("head, then the whole body", [head, whole])
in_pieces("head, then a chunk, then the terminator",
          [head, b"d\r\nstreamed body\r\n", b"0\r\n\r\n"])
in_pieces("a byte at a time", [head] + [bytes([c]) for c in whole], delay=0.005)

# --- a static location must reject the method, not the coding ---------------
r = exchange(b"POST / HTTP/1.1\r\nHost: " + HOST +
             b"\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked(b"hello"))
case(f"chunked to a static location is 405, not 501 ({status(r)})",
     "405" in status(r))

sys.exit(1 if fails else 0)
