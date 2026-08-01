#!/usr/bin/env python3
"""`Expect: 100-continue` must be answered (RFC 9110 10.1.1).

    "A server that receives a 100-continue expectation in an HTTP/1.1 request
     MUST either respond with 100 (Continue) and continue to read from the input
     stream, or respond with a final status code."

Neither happened. The field was never inspected — hn_expect existed only so the
proxy rewriter could strip it — so the server waited for a body the client was
deliberately withholding while the client waited for permission to send it. curl
breaks the deadlock with its own one-second timeout; a client without that
fallback gets nothing until the connection dies.

The timing is the test. A client that gets its 100 sends the body immediately; a
client that gets nothing waits out its own timer, so a pass and a fail differ by
about a second even though both eventually produce a response.

usage: expect_continue.py <port>
"""
import socket
import sys
import time

port = int(sys.argv[1])
HOST = b"one.test"
BODY = b"hello-body"


def exchange(expect=True, path=b"/api/echo", body=BODY, budget=4.0):
    """Send a head, wait for an interim response, then the body.

    -> (interim status or None, seconds waited, final status)
    """
    s = socket.create_connection(("127.0.0.1", port), timeout=budget)
    s.settimeout(1.5)
    head = (b"POST " + path + b" HTTP/1.1\r\nHost: " + HOST + b"\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n")
    if expect:
        head += b"Expect: 100-continue\r\n"
    head += b"Connection: close\r\n\r\n"
    s.sendall(head)

    start = time.time()
    interim = None
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            d = s.recv(65536)
            if not d:
                break
            buf += d
        if buf.startswith(b"HTTP/1.1 1"):
            interim = int(buf.split()[1])
    except socket.timeout:
        pass
    waited = time.time() - start

    # the body goes out whether or not permission arrived, as a real client
    # would after its own timeout
    try:
        s.sendall(body)
    except OSError:
        pass
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
    except (socket.timeout, OSError):
        pass
    s.close()

    final = None
    for chunk in buf.split(b"\r\n\r\n"):
        if chunk.startswith(b"HTTP/1.1 ") and not chunk.startswith(b"HTTP/1.1 1"):
            final = int(chunk.split()[1])
            break
    return interim, waited, final


fails = 0

interim, waited, final = exchange(expect=True)
if interim == 100:
    print(f"ok   Expect: 100-continue is answered 100, after {waited:.2f}s")
else:
    print(f"FAIL Expect: 100-continue got no interim response "
          f"(waited {waited:.2f}s, final {final}) — the client is left holding "
          f"a body the server is waiting for")
    fails += 1

if final == 200:
    print(f"ok   ...and the body is then accepted ({final})")
else:
    print(f"FAIL the exchange finished {final}, want 200")
    fails += 1

# a request WITHOUT the expectation must not draw an interim response
interim, waited, final = exchange(expect=False)
if interim is None:
    print(f"ok   no expectation, no interim response (final {final})")
else:
    print(f"FAIL a request that did not ask got {interim}")
    fails += 1

# ...and the second request on a fresh connection gets its own 100, so the
# once-per-request flag is actually cleared
interim, _, _ = exchange(expect=True)
if interim == 100:
    print("ok   a later request gets its own 100")
else:
    print(f"FAIL a later request got {interim!r} — the flag is not cleared")
    fails += 1

sys.exit(1 if fails else 0)
