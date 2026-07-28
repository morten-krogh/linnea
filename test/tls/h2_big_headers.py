#!/usr/bin/env python3
# Q121: an oversized h2 header block answers THE STREAM with 431 — it used to
# kill the whole connection with GOAWAY, so a browser with a big cookie load
# lost every stream in flight. Also: the server must advertise
# SETTINGS_MAX_HEADER_LIST_SIZE (8192, the decoder's real bound) so a
# conforming client trims instead of discovering the limit the hard way.
#
#   1. server SETTINGS carries MAX_HEADER_LIST_SIZE = 8192
#   2. a ~12 KB cookie: :status 431 on that stream, no GOAWAY
#   3. the SAME connection then serves a normal request (200)
#   4. a ~5 KB cookie fits the raised limits and is served 200
# Usage: h2_big_headers.py <cafile> <port>
import socket
import ssl
import struct
import sys

ca, port = sys.argv[1], int(sys.argv[2])
ctx = ssl.create_default_context(cafile=ca)
ctx.check_hostname = False
ctx.set_alpn_protocols(["h2"])
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                    server_hostname="localhost")
assert s.selected_alpn_protocol() == "h2"
s.settimeout(10)


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def estr(b):
    return bytes([len(b)]) + b if len(b) < 128 else None


def hdr(n, v):
    # literal, never-indexed, 7-bit lengths are too small for the big cookie:
    # use the HPACK multi-byte length for the value
    out = b"\x00" + bytes([len(n)]) + n
    ln = len(v)
    if ln < 127:
        out += bytes([ln]) + v
    else:
        rest = ln - 127
        enc = b"\x7f"
        while rest >= 128:
            enc += bytes([(rest & 0x7f) | 0x80])
            rest >>= 7
        enc += bytes([rest])
        out += enc + v
    return out


def rd():
    h = b""
    while len(h) < 9:
        d = s.recv(9 - len(h))
        if not d:
            return None
        h += d
    ln = int.from_bytes(h[:3], "big")
    p = b""
    while len(p) < ln:
        d = s.recv(ln - len(p))
        if not d:
            break
        p += d
    return h[3], h[4], int.from_bytes(h[5:9], "big") & 0x7fffffff, p


s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(4, 0, 0))

# 1. the server's SETTINGS must advertise MAX_HEADER_LIST_SIZE = 8192
t, fl, sid, p = rd()
assert t == 4, "expected the server SETTINGS first"
settings = {}
for i in range(0, len(p) - 5, 6):
    ident = int.from_bytes(p[i:i + 2], "big")
    settings[ident] = int.from_bytes(p[i + 2:i + 6], "big")
assert settings.get(6) == 8192, \
    f"SETTINGS_MAX_HEADER_LIST_SIZE not advertised as 8192: {settings}"

base = (hdr(b":method", b"GET") + hdr(b":scheme", b"https")
        + hdr(b":authority", b"localhost"))

# 2. an oversized block: 431 on the stream, the connection survives
s.sendall(fr(1, 0x05, 1, base + hdr(b":path", b"/hello.txt")
              + hdr(b"cookie", b"c" * 12000)))
got431 = False
goaway = False
while not got431:
    r = rd()
    assert r is not None, "connection closed on the oversized block"
    t, fl, sid, p = r
    if t == 7:
        goaway = True
        break
    if t == 1 and sid == 1 and b"431" in p:
        got431 = True
assert got431 and not goaway, \
    f"oversized header block: got431={got431} goaway={goaway}"

# 3. the same connection still serves
s.sendall(fr(1, 0x05, 3, base + hdr(b":path", b"/hello.txt")))
served = False
body = False
while not (served and body):
    r = rd()
    assert r is not None, "connection died after the 431"
    t, fl, sid, p = r
    assert t != 7, "GOAWAY after the 431: the connection did not survive"
    if t == 1 and sid == 3 and b"200" in p:
        served = True
    if t == 0 and sid == 3 and b"hello" in p:
        body = True

# 4. a big-but-legal cookie is served, not refused
s.sendall(fr(1, 0x05, 5, base + hdr(b":path", b"/hello.txt")
              + hdr(b"cookie", b"d" * 5000)))
ok5 = False
while not ok5:
    r = rd()
    assert r is not None, "connection closed on the 5 KB cookie"
    t, fl, sid, p = r
    assert t != 7, "GOAWAY on a cookie that fits the advertised limit"
    if t == 1 and sid == 5 and b"200" in p:
        ok5 = True
s.close()
print("ok")
