#!/usr/bin/env python3
"""Send one request per HTTP version, so the access log can be checked against
what was actually on the wire.

The log used to write a fixed " HTTP/1.1" for every HTTP/1 request. A 1.0
request was therefore recorded as 1.1, and the one status that is ABOUT the
version told the reader nothing: an HTTP/2 connection preface, "PRI *
HTTP/2.0", is correctly answered 505 and was logged as `"PRI * HTTP/1.1" 505`
-- a line this server cannot produce, because that literal request is a 400.
It surfaced from a production 5xx alert where the log line was the only
evidence available and it described a message nobody had sent.

Prints OK; the shard greps the log for each line.
"""
import socket
import sys

PORT = int(sys.argv[1])

# (request line, what the status should be) -- the statuses are asserted here
# so a wrong one cannot be mistaken for a logging problem later
LINES = [
    (b"GET /hello.txt HTTP/1.0", b"200"),
    (b"GET /hello.txt HTTP/1.2", b"200"),
    (b"PRI * HTTP/2.0",          b"505"),
    (b"GET /hello.txt HTTP/3.0", b"505"),
    (b"GET /api/simple HTTP/1.0", b"200"),   # the proxy logger, a second copy
]


def send(line):
    s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    try:
        s.sendall(line + b"\r\nHost: one.test\r\n\r\n")
        s.settimeout(10)
        buf = b""
        while b"\r\n" not in buf:
            d = s.recv(65536)
            if not d:
                break
            buf += d
    except OSError:
        return b""
    finally:
        s.close()
    return buf.split(b"\r\n")[0]


def main():
    for line, want in LINES:
        got = send(line)
        if got.split(b" ")[1:2] != [want]:
            return f"{line.decode()}: {got!r}, wanted {want.decode()}"
    return "OK"


try:
    print(main())
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
