#!/usr/bin/env python3
# HTTP/2 CONNECT whole-request validation (audit Finding 28). CONNECT is
# unsupported here and answered 405, but RFC 9113 8.5 still requires it to carry
# :authority and to omit :scheme and :path, and any Host must agree with
# :authority. A nonconforming CONNECT is malformed -- a stream error -- not an
# ordinary 405. This sends a well-formed CONNECT (expects 405) and several
# malformed ones (expect RST_STREAM).
#
# Usage: h2_connect.py <ca> <port>.  Prints ok/FAIL lines.
import socket
import ssl
import struct
import sys

ca, port = sys.argv[1], int(sys.argv[2])


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def estr(b):
    return bytes([len(b)]) + b


def hdr(n, v):
    return b"\x00" + estr(n) + estr(v)


def outcome(block):
    """Return ('status', N) for a HEADERS reply or ('RST',) for a stream reset."""
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                        server_hostname="localhost")
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(0x4, 0, 0)
              + fr(0x1, 0x4 | 0x1, 1, block))          # HEADERS, END_HEADERS|END_STREAM
    s.settimeout(3.0)
    buf, res = b"", None
    try:
        while res is None:
            d = s.recv(65536)
            if not d:
                break
            buf += d
            while len(buf) >= 9:
                ln = int.from_bytes(buf[:3], "big")
                if len(buf) < 9 + ln:
                    break
                ftype, payload = buf[3], buf[9:9 + ln]
                buf = buf[9 + ln:]
                if ftype == 0x3:                        # RST_STREAM
                    res = ("RST",)
                    break
                if ftype == 0x1:                        # HEADERS
                    for i in range(len(payload) - 2):
                        if payload[i:i + 3].isdigit():
                            res = ("status", int(payload[i:i + 3]))
                            break
                    if res:
                        break
    except (socket.timeout, OSError):
        pass
    s.close()
    return res


C = hdr(b":method", b"CONNECT")
A = hdr(b":authority", b"example.com:443")
fails = 0


def check(name, got, want):
    global fails
    ok = got == want
    print(("ok   " if ok else "FAIL ") + f"{name} ({got}, want {want})")
    if not ok:
        fails += 1


check("well-formed CONNECT -> 405", outcome(C + A), ("status", 405))
check("CONNECT without :authority -> reset", outcome(C), ("RST",))
check("CONNECT with :scheme -> reset", outcome(C + A + hdr(b":scheme", b"https")), ("RST",))
check("CONNECT with :path -> reset", outcome(C + A + hdr(b":path", b"/")), ("RST",))
check("CONNECT with empty :authority -> reset", outcome(C + hdr(b":authority", b"")), ("RST",))

print("ok" if fails == 0 else f"FAIL ({fails})")
sys.exit(0 if fails == 0 else 1)
