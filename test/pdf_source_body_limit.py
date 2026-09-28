#!/usr/bin/env python3
"""Acceptance probe for a scoped Vefruna source cap on an isolated Linnea.

Usage: pdf_source_body_limit.py <port> [host] [ordinary_cap] [source_cap]

The configured server must proxy all Vefruna paths. A 502 from an intentionally
absent test backend means the request passed ingress; only the 413 decision is
being tested here. This probe is intentionally not part of the passing suite
until Linnea can express the exact rule.
"""

import socket
import sys


PORT = int(sys.argv[1])
HOST = (sys.argv[2] if len(sys.argv) > 2 else "vefruna.test").encode()
ORDINARY_CAP = int(sys.argv[3]) if len(sys.argv) > 3 else 12288
SOURCE_CAP = int(sys.argv[4]) if len(sys.argv) > 4 else 16777216
PROJECT_ID = b"project_" + b"0" * 25 + b"1"
SOURCE = b"/projects/" + PROJECT_ID + b"/source"


def status(method, path, size, *, host=HOST, chunked=False, declared_only=False):
    with socket.create_connection(("127.0.0.1", PORT), timeout=8) as client:
        client.settimeout(8)
        head = (method + b" " + path + b" HTTP/1.1\r\nHost: " + host +
                b"\r\nConnection: close\r\n")
        if chunked:
            head += b"Transfer-Encoding: chunked\r\n\r\n"
            body = b"%x\r\n" % size + b"A" * size + b"\r\n0\r\n\r\n"
        else:
            head += b"Content-Length: %d\r\n\r\n" % size
            body = b"" if declared_only else b"A" * size
        client.sendall(head + body)
        return client.recv(4096).split(b"\r\n", 1)[0]


def main():
    adjacent = b"/projects/" + PROJECT_ID + b"/notes"
    malformed = b"/projects/not-a-project/source"
    cases = [
        ("source counted above ordinary cap", b"POST", SOURCE,
         ORDINARY_CAP + 1, False, False, False),
        ("source chunked above ordinary cap", b"POST", SOURCE,
         ORDINARY_CAP + 1, True, False, False),
        ("adjacent project route", b"POST", adjacent,
         ORDINARY_CAP + 1, False, False, True),
        ("adjacent project route chunked", b"POST", adjacent,
         ORDINARY_CAP + 1, True, False, True),
        ("wrong method", b"PUT", SOURCE,
         ORDINARY_CAP + 1, False, False, True),
        ("malformed project ID", b"POST", malformed,
         ORDINARY_CAP + 1, False, False, True),
        ("source path with query", b"POST", SOURCE + b"?other=1",
         ORDINARY_CAP + 1, False, False, True),
        ("source path with extra segment", b"POST", SOURCE + b"/extra",
         ORDINARY_CAP + 1, False, False, True),
        ("source above exact cap before body", b"POST", SOURCE,
         SOURCE_CAP + 1, False, True, True),
    ]
    failures = []
    for name, method, path, size, chunked, declared_only, want_413 in cases:
        result = status(method, path, size, chunked=chunked,
                        declared_only=declared_only)
        is_413 = b" 413 " in result
        if not result.startswith(b"HTTP/1.1 ") or is_413 != want_413:
            failures.append(f"{name}: {result!r}, expected " +
                            ("413" if want_413 else "non-413"))
    if failures:
        print("\n".join(failures))
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
