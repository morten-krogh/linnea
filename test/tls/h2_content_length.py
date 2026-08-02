#!/usr/bin/env python3
"""content-length must equal the DATA actually sent (RFC 9113 8.1.1).

    "A request or response that is defined as having content when it has a
     Content-Length header field that does not equal the sum of the DATA frame
     payload lengths ... is malformed."

Two halves, and only one was checked. A body that OVERRAN the declared length
was already refused. A body that stopped SHORT was not noticed at all: the
streaming path never looked at END_STREAM, so the request simply never
completed — it sat holding an upstream slot until the body clock timed it out at
408, several seconds later, reporting a timeout for what was a framing fault the
server could see immediately. The collecting path did not know the declared
length at all: it measured what arrived and forwarded that, quietly rewriting
the client's own framing on the way to the backend.

usage: h2_content_length.py <cafile> <port>
"""
import socket
import ssl
import struct
import sys
import time

ca, port = sys.argv[1], int(sys.argv[2])
FT_DATA, FT_HEADERS, FT_SETTINGS = 0x0, 0x1, 0x4
FLAG_END_STREAM, FLAG_END_HEADERS = 0x1, 0x4


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def estr(b):
    return bytes([len(b)]) + b


def hdr(n, v):
    return b"\x00" + estr(n) + estr(v)


def exchange(declared, body, path=b"/api/echo", budget=8.0):
    """POST with a declared content-length and a body that may disagree.

    -> (status, seconds) — the status the client eventually saw.
    """
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                        server_hostname="localhost")
    assert s.selected_alpn_protocol() == "h2"
    block = (hdr(b":method", b"POST") + hdr(b":scheme", b"https")
             + hdr(b":authority", b"localhost") + hdr(b":path", path)
             + hdr(b"content-length", str(declared).encode()))
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(FT_SETTINGS, 0, 0)
              + fr(FT_HEADERS, FLAG_END_HEADERS, 1, block)
              + fr(FT_DATA, FLAG_END_STREAM, 1, body))
    s.settimeout(budget)
    start, buf, status = time.time(), b"", None
    try:
        while status is None:
            d = s.recv(65536)
            if not d:
                break
            buf += d
            while len(buf) >= 9:
                ln = int.from_bytes(buf[:3], "big")
                if len(buf) < 9 + ln:
                    break
                ftype, body_b = buf[3], buf[9:9 + ln]
                buf = buf[9 + ln:]
                if ftype == FT_HEADERS:
                    # :status is a literal with an indexed name; the value is
                    # the last three digits in the block for our own encoder
                    for i in range(len(body_b) - 2):
                        chunk = body_b[i:i + 3]
                        if chunk.isdigit():
                            status = int(chunk)
                            break
    except (socket.timeout, OSError):
        pass
    s.close()
    return status, time.time() - start


fails = 0

# the honest case still works
status, secs = exchange(5, b"hello")
if status == 200:
    print(f"ok   a body matching its content-length is served ({status})")
else:
    print(f"FAIL a matching body gave {status}")
    fails += 1

# ...and one that stops short is refused promptly, not timed out
status, secs = exchange(10, b"hello")
if status == 400 and secs < 5:
    print(f"ok   a body shorter than declared is refused ({status}) in {secs:.2f}s")
elif status == 408 or secs >= 5:
    print(f"FAIL a short body gave {status} after {secs:.2f}s — that is the body "
          f"clock timing out, not the framing fault being detected")
    fails += 1
else:
    print(f"FAIL a short body gave {status} after {secs:.2f}s, want 400")
    fails += 1

# a body that overruns was already refused; keep it pinned
status, secs = exchange(2, b"hello")
if status in (400, 413):
    print(f"ok   a body longer than declared is refused ({status})")
else:
    print(f"FAIL an over-long body gave {status}")
    fails += 1

sys.exit(1 if fails else 0)
