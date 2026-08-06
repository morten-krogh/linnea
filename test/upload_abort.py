#!/usr/bin/env python3
"""Abandon an upload mid-body.

Declares a body far too large to buffer with the head, sends part of it, and
then vanishes. Since linnea captures a body in full before forwarding any of
it, the backend must never hear of this request at all -- the caller asserts
that against the backend's own record. Before capture, the same client left
the backend holding a truncated POST it could not tell from a complete one.
"""
import socket
import time

DECLARED = 500000
SENT = 200000                       # well past in_buf, well short of DECLARED

s = socket.create_connection(("127.0.0.1", 47080), timeout=5)
s.sendall(b"POST /api/abandoned HTTP/1.1\r\nHost: one.test\r\n"
          b"Content-Length: %d\r\n\r\n" % DECLARED)
s.sendall(b"X" * SENT)
time.sleep(0.3)                     # let the capture take what was sent
s.close()
print(f"abandoned after {SENT} of {DECLARED} bytes")
