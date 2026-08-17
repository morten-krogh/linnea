#!/usr/bin/env python3
"""max_body must be honoured for a body that FITS in the request buffer, not
only one large enough to stream (audit Finding 3 for h1). With max_body set
below the ~17 KiB in_buf, a body of max_body bytes must be served and one byte
over must be 413 -- for counted and for chunked framing alike, and the refused
body must never reach the backend.

Usage: max_body_small.py <port> <max_body>.  Prints OK or the first failure.
"""
import socket
import sys

PORT = int(sys.argv[1])
CAP = int(sys.argv[2])


def status(body, chunked):
    s = socket.create_connection(("127.0.0.1", PORT), timeout=8)
    s.settimeout(8)
    if chunked:
        req = (b"POST /api/echo HTTP/1.1\r\nHost: one.test\r\n"
               b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
               + b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n")
    else:
        req = (b"POST /api/echo HTTP/1.1\r\nHost: one.test\r\n"
               b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body)) + body
    s.sendall(req)
    data = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            data += d
    except socket.timeout:
        pass
    s.close()
    return data.split(b"\r\n", 1)[0]


def main():
    for chunked in (False, True):
        tag = "chunked" if chunked else "counted"
        at = status(b"A" * CAP, chunked)
        if b"200" not in at:
            return f"{tag} body of exactly max_body ({CAP}) was not 200: {at!r}"
        over = status(b"A" * (CAP + 1), chunked)
        if b"413" not in over:
            return f"{tag} body of max_body+1 ({CAP + 1}) was not 413: {over!r} (bypass)"
    print("OK")
    return 0


if __name__ == "__main__":
    r = main()
    if r != 0:
        print(r)
        sys.exit(1)
