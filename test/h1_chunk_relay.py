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

It also asserts the harder half, which audit-report-25 read the source as
missing: a malformation that STRADDLES the read boundary. "4;a", "0\r\nNot" and
"4\r\nbody" are all valid prefixes; only the second write makes them wrong, so
the decoder has to have carried its state out of the head's read and into the
relay's. Its control is report 25's own reproduction, "4;a=" then "bad", which
reassembles to a valid token value and must arrive whole.
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

    head, body = fetch("/api/chunksplitok")
    if b" 200 " not in head.split(b"\r\n")[0]:
        status = head.split(b"\r\n")[0]
        return f"split-but-valid extension: not 200: {status!r}"
    if not body.endswith(b"0\r\n\r\n") or b"4;a=bad" not in body:
        return f"split-but-valid extension: not relayed whole: {body!r}"

    for route, junk in (("chunklatebad", b";=bad"),
                        ("chunksplitext", b",b"),
                        ("chunksplittrail", b"AField"),
                        ("chunksplitdata", b"\n0")):
        head, body = fetch("/api/" + route)
        first = head.split(b"\r\n")[0]
        if b" 200 " not in first and b" 502 " not in first:
            return f"{route}: unexpected status: {first!r}"
        if b" 502 " in first:
            continue               # caught while the head was still unsent
        # the head was already gone: the message must not complete, and the
        # bytes that made it malformed must not have travelled
        if body.endswith(b"0\r\n\r\n"):
            return f"{route}: relayed as a complete message: {body!r}"
        if junk in body:
            return f"{route}: the bad framing was forwarded: {body!r}"
    return "OK"


try:
    print(main())
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
