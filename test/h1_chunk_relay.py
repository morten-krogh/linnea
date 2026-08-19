#!/usr/bin/env python3
"""What the client is left with when a chunked upstream response goes wrong
AFTER its head has been relayed.

HTTP/1 relays a chunked body byte for byte, so by the time a chunk line is read
the 200 is already gone and 502 is not available -- which is why h1 was exempt
from the chunk-framing rows of the cross-protocol matrix for so long. The
exemption never justified FORWARDING the malformed framing: a bad extension
arrived inside a clean, complete 200 while h2 and h3 answered 502 to the same
upstream bytes (audit-report-24).

What h1 can do is decline to finish. This asserts exactly that, and its control
-- the same split write carrying a VALID body -- because "refuses the malformed
one" is worth nothing if it also broke the ordinary one.
"""
import socket
import sys

PORT = int(sys.argv[1])


def fetch(path):
    s = socket.create_connection(("127.0.0.1", PORT), timeout=15)
    s.sendall(b"GET %s HTTP/1.1\r\nHost: one.test\r\n\r\n" % path.encode())
    s.settimeout(15)
    buf = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
    except OSError:
        pass
    s.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    return head, body


def main():
    head, body = fetch("/api/chunklategood")
    if b" 200 " not in head.split(b"\r\n")[0]:
        status = head.split(b"\r\n")[0]
        return f"valid split body: not 200: {status!r}"
    if not body.endswith(b"0\r\n\r\n"):
        return f"valid split body: no terminating chunk: {body!r}"

    head, body = fetch("/api/chunklatebad")
    first = head.split(b"\r\n")[0]
    if b" 200 " not in first and b" 502 " not in first:
        return f"malformed split body: unexpected status: {first!r}"
    if b" 200 " in first:
        # the head was already gone: the message must not complete
        if body.endswith(b"0\r\n\r\n"):
            return f"malformed split body: relayed as a complete message: {body!r}"
        if b";=bad" in body:
            return f"malformed split body: the bad framing was forwarded: {body!r}"
    return "OK"


try:
    print(main())
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
