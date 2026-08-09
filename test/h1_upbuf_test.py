#!/usr/bin/env python3
"""Walk a proxied request head across the up_buf boundary.

up_buf holds the rewritten upstream head and .append is an unchecked rep movsb,
so one up-front bound in .proxy_build guards the whole rewrite. That bound has
to cover everything the rewrite adds over the client's head — a Via line
always, a Content-Length when a chunked one was dropped, and our Connection
line — and it does, with about 24 bytes to spare. This is what notices if a
future line spends that margin: the overrun would run off the end of up_buf
into the next connection's slot, which is not a failure that announces itself.

So the assertion is not a size. It is that EVERY size is either forwarded or
refused 431 — never anything else, and never a silent success that corrupted
the slot next door.

Usage: h1_upbuf_test.py <linnea port>
"""
import socket
import sys

PORT = int(sys.argv[1])
bad = []


def send(pad, chunked, body=b"hello"):
    extra = b"X-Pad: " + b"p" * pad + b"\r\n"
    if chunked:
        req = (b"POST /api/echo HTTP/1.1\r\nHost: one.test\r\n"
               b"Transfer-Encoding: chunked\r\n" + extra + b"\r\n"
               + b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n")
    else:
        req = (b"POST /api/echo HTTP/1.1\r\nHost: one.test\r\n"
               b"Content-Length: %d\r\n" % len(body) + extra + b"\r\n" + body)
    s = socket.create_connection(("127.0.0.1", PORT), timeout=6)
    s.sendall(req)
    d = b""
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            d += c
    except socket.timeout:
        d += b"<timeout>"
    s.close()
    return len(req), (d.split(b"\r\n")[0] if d else b"<no response>"), d


for chunked in (False, True):
    label = "chunked" if chunked else "counted"
    served = refused = 0
    for pad in range(8100, 8600, 20):
        n, status, full = send(pad, chunked)
        if status.startswith(b"HTTP/1.1 200"):
            served += 1
            # a forwarded one must come back intact, not truncated by an
            # overrun that happened to stay inside the arena
            if b"hello" not in full:
                bad.append("%s head of %d bytes: 200 but the body did not "
                           "survive" % (label, n))
        elif status.startswith(b"HTTP/1.1 431"):
            refused += 1
        else:
            bad.append("%s head of %d bytes -> %s"
                       % (label, n, status.decode(errors="replace")))
    print("%-8s %d forwarded, %d refused 431" % (label, served, refused))
    if not served or not refused:
        bad.append("%s never crossed the boundary (%d/%d) — the padding range "
                   "no longer straddles it" % (label, served, refused))

print()
if bad:
    for b in bad:
        print("FAIL", b)
    sys.exit(1)
print("OK")
