#!/usr/bin/env python3
# RFC 9113 8.2.3 (audit Finding 32): an HTTP/2 client may split Cookie into
# several fields for compression, but an intermediary MUST join them, in order,
# with "; " before forwarding to a non-HTTP/2 hop. This sends split cookie
# fields through the proxy to the /api/headers backend, which echoes the request
# head it received, and checks the backend saw exactly one "; "-joined Cookie
# line -- not several, and not a comma-folded value.
#
# Usage: h2_cookie.py <ca> <port>.  Prints ok/FAIL lines; exits non-zero on any.
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
    return b"\x00" + estr(n) + estr(v)          # literal name, literal value


def fetch(cookies, path=b"/api/headers"):
    """GET path with one cookie field per entry in `cookies`; return the
    response body (the request head the backend echoes back)."""
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                        server_hostname="localhost")
    assert s.selected_alpn_protocol() == "h2"
    block = (hdr(b":method", b"GET") + hdr(b":scheme", b"https")
             + hdr(b":authority", b"localhost") + hdr(b":path", path))
    for c in cookies:
        block += hdr(b"cookie", c)
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(FT_SETTINGS, 0, 0)
              + fr(FT_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, block))
    s.settimeout(6.0)
    buf, body, done = b"", b"", False
    try:
        while not done:
            d = s.recv(65536)
            if not d:
                break
            buf += d
            while len(buf) >= 9:
                ln = int.from_bytes(buf[:3], "big")
                if len(buf) < 9 + ln:
                    break
                ftype, flags, payload = buf[3], buf[4], buf[9:9 + ln]
                buf = buf[9 + ln:]
                if ftype == FT_DATA:
                    body += payload
                    if flags & FLAG_END_STREAM:
                        done = True
    except (socket.timeout, OSError):
        pass
    s.close()
    return body


def cookie_lines(head):
    return [ln for ln in head.split(b"\r\n") if ln.lower().startswith(b"cookie:")]


fails = 0


def check(name, cond):
    global fails
    print(("ok   " if cond else "FAIL ") + name)
    if not cond:
        fails += 1


# two split cookie fields -> one "; "-joined line, in order
head = fetch([b"session=abc", b"prefs=xyz"])
lines = cookie_lines(head)
check(f"two split cookies -> one line ({len(lines)})", len(lines) == 1)
check("two split cookies joined in order",
      lines == [b"cookie: session=abc; prefs=xyz"] or
      lines == [b"Cookie: session=abc; prefs=xyz"])

# three split cookie fields -> one line, order preserved
head = fetch([b"a=1", b"b=2", b"c=3"])
lines = cookie_lines(head)
check(f"three split cookies -> one line ({len(lines)})", len(lines) == 1)
check("three split cookies joined in order",
      any(ln.endswith(b"a=1; b=2; c=3") for ln in lines))

# a single cookie field passes through unchanged (control)
head = fetch([b"only=one"])
lines = cookie_lines(head)
check(f"single cookie -> one line ({len(lines)})", len(lines) == 1)
check("single cookie value intact",
      any(ln.endswith(b"only=one") for ln in lines))

print("ok" if fails == 0 else f"FAIL ({fails})")
sys.exit(0 if fails == 0 else 1)
