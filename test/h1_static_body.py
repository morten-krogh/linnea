#!/usr/bin/env python3
"""A static location does not accept request content, and a request that stops
short is told so.

Two halves, both of which used to fail silently.

*Content.* A static location serves a file. It never reads request content, and
content on GET or HEAD has no defined semantics anyway (RFC 9110 9.3.1) -- so
serving the file regardless means discarding bytes the client announced, which
is the request-smuggling shape 9.3.1 names. h1 already refused the half it
happened to notice: a body too large to sit in in_buf streams, and the static
path turns that into a 413. A body that FIT was ignored and the file served, so
the same request was refused or served depending on how it compared with a
buffer size nobody configured.

*The answer.* h1 waits for a declared body BEFORE it routes, and on a byte
stream a body that stops short is indistinguishable from one that is merely
slow -- so waiting is right and the timeout is the only answer h1 can give. It
just never gave it: the connection was dropped in silence, so a client could not
tell a server that gave up from a network that ate the connection. RFC 9110
15.5.9 names 408 for exactly this.

That 408 is also the first line this server ever logs for a request that never
ROUTED, and the access logger dereferenced conn.vhost without a null check --
a SIGSEGV that killed the worker. A 408 arriving at all is what pins that.

usage: h1_static_body.py [port]
"""
import os
import socket
import sys
import time

_PB = int(os.environ.get("LINNEA_TEST_PORT_BASE", 61000))
_p = lambda n: _PB + n - 61000     # the suite's port rule, one base per run

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else _p(61080)
HOST = "127.0.0.1"

fails = 0


def exchange(raw, budget=8.0):
    """Send raw bytes and read until the peer closes or goes quiet.

    -> (whole response bytes, seconds waited). A stalled request is answered
    only when the server's clock fires, so the budget must outlast it; the
    fixture's timeout is 2s.
    """
    start = time.time()
    try:
        s = socket.create_connection((HOST, PORT), timeout=budget)
    except OSError as e:
        return b"", time.time() - start
    s.sendall(raw)
    s.settimeout(budget)
    buf = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
    except (socket.timeout, OSError):
        pass
    s.close()
    return buf, time.time() - start


def status(resp):
    if not resp:
        return "no reply"
    line = resp.split(b"\r\n", 1)[0].decode("latin1")
    return line.split(" ", 1)[1] if " " in line else line


def check(name, ok, detail=""):
    global fails
    if ok:
        print(f"ok   {name}{detail}")
    else:
        print(f"FAIL {name}{detail}")
        fails += 1


G = b"GET /hello.txt HTTP/1.1\r\nHost: one.test\r\n"

# --- content on a static location is refused --------------------------------
#
# The pipelined second request is the point of this shape, not decoration: with
# the body discarded and the connection kept alive it used to be answered, so
# the old expectation here was TWO 200s. Refusing means the connection goes, and
# what must never happen either way is the body's own bytes being parsed as a
# request line -- so the assertion is one 400 and no 200 anywhere.
resp, _ = exchange(G + b"Content-Length: 5\r\n\r\nXXXXX" + G + b"Connection: close\r\n\r\n")
check("a static GET carrying content is refused",
      status(resp).startswith("400") and b"200 OK" not in resp,
      f" ({status(resp)}, {resp.count(b'200 OK')} x 200)")

resp, _ = exchange(G + b"Content-Length: 5\r\nConnection: close\r\n\r\nXXXXX")
check("...whether or not it is pipelined behind", status(resp).startswith("400"),
      f" ({status(resp)})")

# Transfer-Encoding is the same content by another framing, and refusing only
# the declared kind would be bypassed by chunking it.
resp, _ = exchange(G + b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                   b"5\r\nXXXXX\r\n0\r\n\r\n")
check("...and a chunked body is content too", status(resp).startswith("400"),
      f" ({status(resp)})")

# --- controls: what a static location still serves ---------------------------
resp, _ = exchange(G + b"Connection: close\r\n\r\n")
check("control: a plain static GET is served", status(resp).startswith("200"),
      f" ({status(resp)})")

resp, _ = exchange(G + b"Content-Length: 0\r\nConnection: close\r\n\r\n")
check("control: content-length 0 is not content", status(resp).startswith("200"),
      f" ({status(resp)})")

resp, _ = exchange(G + b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n")
check("control: a chunked body of no chunks is not content",
      status(resp).startswith("200"), f" ({status(resp)})")

# The refusal is the STATIC location's, not the server's: a proxy location has a
# backend that may well define semantics for the content, and still takes it.
resp, _ = exchange(b"POST /api/echo HTTP/1.1\r\nHost: one.test\r\n"
                   b"Content-Length: 5\r\nConnection: close\r\n\r\nhello")
check("control: a proxy location still takes a body",
      status(resp).startswith("200") and resp.endswith(b"hello"),
      f" ({status(resp)})")

# --- a request that stops short is answered, not dropped --------------------
#
# Declared 5, sent 3. h1 cannot tell this from a slow client, so it waits; when
# its clock fires the answer is 408 (RFC 9110 15.5.9), and 15.5.9's SHOULD is
# that the answer announces the close. "no reply" here is the old behaviour --
# and is also what a worker that died mid-timeout looks like.
resp, secs = exchange(G + b"Content-Length: 5\r\n\r\nXXX")
check("a body that stops short is answered 408, not dropped",
      status(resp).startswith("408"), f" ({status(resp)} after {secs:.1f}s)")
check("...and the 408 announces the close (15.5.9)",
      b"Connection: close" in resp, f" ({status(resp)})")

# The same for a head that stops mid-way: no blank line ever arrives.
resp, secs = exchange(b"GET /hello.txt HTTP/1.1\r\nHost: one.test\r\n")
check("a head that stops short is answered 408 too",
      status(resp).startswith("408"), f" ({status(resp)} after {secs:.1f}s)")

# ...but a connection that is merely IDLE between requests is owed silence, not
# a complaint: it is legitimate and may sit for a long time. Send a complete
# request, read its response, then hold the keep-alive connection open past the
# clock and expect the close to carry nothing.
resp, secs = exchange(G + b"\r\n")          # keep-alive: no Connection: close
check("an idle keep-alive connection is closed in silence, not 408",
      b"200 OK" in resp and b"408" not in resp,
      f" (served, then closed after {secs:.1f}s with nothing further)")

# The worker has to have survived all of that: the 408 is the first access line
# for a request with no vhost, and the logger read one unguarded.
resp, _ = exchange(G + b"Connection: close\r\n\r\n")
check("the worker is still serving after the timeouts",
      status(resp).startswith("200"), f" ({status(resp)})")

sys.exit(1 if fails else 0)
