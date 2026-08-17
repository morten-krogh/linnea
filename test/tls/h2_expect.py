#!/usr/bin/env python3
# RFC 9110 10.1.1 (audit Finding 33): a client may send request HEADERS with
# "expect: 100-continue" and withhold the body until it receives an interim 100
# (or a final response). The h2 proxy buffers the body before contacting the
# upstream, so it must answer the expectation itself -- an immediate local 100 --
# rather than leaving the client stalled until the request-body timeout. This
# sends the HEADERS, requires a 100 within a tight deadline, then sends the body
# and requires exactly one final 200 carrying the backend's echo.
#
# Usage: h2_expect.py <ca> <port>.  Prints ok/FAIL lines; exits non-zero on any.
import socket
import ssl
import struct
import sys
import time

ca, port = sys.argv[1], int(sys.argv[2])
FT_DATA, FT_HEADERS = 0x0, 0x1
FT_SETTINGS = 0x4
FLAG_END_STREAM, FLAG_END_HEADERS = 0x1, 0x4


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def estr(b):
    return bytes([len(b)]) + b


def hdr(n, v):
    return b"\x00" + estr(n) + estr(v)


def statuses_and_body(buf, out):
    """Parse whole frames from buf; append (status, end_stream) for each HEADERS
    and body bytes for each DATA into out. Returns unconsumed tail."""
    while len(buf) >= 9:
        ln = int.from_bytes(buf[:3], "big")
        if len(buf) < 9 + ln:
            break
        ftype, flags, payload = buf[3], buf[4], buf[9:9 + ln]
        buf = buf[9 + ln:]
        if ftype == FT_HEADERS:
            st = None
            for i in range(len(payload) - 2):
                c = payload[i:i + 3]
                if c.isdigit():
                    st = int(c)
                    break
            out["status"].append((st, bool(flags & FLAG_END_STREAM)))
            if st and st >= 200 and (flags & FLAG_END_STREAM):
                out["ended"] = True
        elif ftype == FT_DATA:
            out["body"] += payload
            if flags & FLAG_END_STREAM:
                out["ended"] = True
    return buf


ctx = ssl.create_default_context(cafile=ca)
ctx.check_hostname = False
ctx.set_alpn_protocols(["h2"])
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                    server_hostname="localhost")
assert s.selected_alpn_protocol() == "h2"

block = (hdr(b":method", b"POST") + hdr(b":scheme", b"https")
         + hdr(b":authority", b"localhost") + hdr(b":path", b"/api/echo")
         + hdr(b"content-length", b"5") + hdr(b"expect", b"100-continue"))
# HEADERS only -- no END_STREAM, and crucially no DATA yet: we wait for the 100.
s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(FT_SETTINGS, 0, 0)
          + fr(FT_HEADERS, FLAG_END_HEADERS, 1, block))

out = {"status": [], "body": b"", "ended": False}
buf = b""
fails = 0


def check(name, cond):
    global fails
    print(("ok   " if cond else "FAIL ") + name)
    if not cond:
        fails += 1


# an interim 100 must arrive quickly, before we send any body
s.settimeout(2.5)
start = time.time()
got100 = False
try:
    while time.time() - start < 2.5:
        d = s.recv(65536)
        if not d:
            break
        buf += d
        buf = statuses_and_body(buf, out)
        if any(st == 100 for st, _ in out["status"]):
            got100 = True
            break
except (socket.timeout, OSError):
    pass
elapsed = time.time() - start
check(f"interim 100 received before the body ({elapsed:.2f}s)", got100)
check("100 was interim (no END_STREAM)",
      any(st == 100 and not es for st, es in out["status"]))

# now release the body and require exactly one final 200 with the echo
s.sendall(fr(FT_DATA, FLAG_END_STREAM, 1, b"hello"))
s.settimeout(5.0)
try:
    while not out["ended"]:
        d = s.recv(65536)
        if not d:
            break
        buf += d
        buf = statuses_and_body(buf, out)
except (socket.timeout, OSError):
    pass
s.close()

finals = [st for st, _ in out["status"] if st and st >= 200]
hundreds = [st for st, _ in out["status"] if st == 100]
check(f"exactly one final response ({finals})", finals == [200])
check(f"exactly one 100, no duplicate ({len(hundreds)})", len(hundreds) == 1)
check(f"backend echo returned (body={out['body']!r})", out["body"] == b"hello")

print("ok" if fails == 0 else f"FAIL ({fails})")
sys.exit(0 if fails == 0 else 1)
