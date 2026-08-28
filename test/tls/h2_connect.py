#!/usr/bin/env python3
# HTTP/2 CONNECT whole-request validation (audit Finding 28, report 124).
# CONNECT is unsupported here and answered 405, but RFC 9113 8.5 still requires
# it to carry :authority and to omit :scheme and :path, and any Host must agree
# with :authority. A nonconforming CONNECT is malformed -- a stream error -- not
# an ordinary 405.
#
# Report 124: :authority also has to BE an authority. That branch skips
# req_check, so it skipped the authority grammar too, and every malformed form
# below reached the 405 path. CONNECT's :authority is the authority form of the
# request target -- host and port, no userinfo, no path -- and the port is not
# optional, because there is no scheme to default one from (RFC 9110 9.3.6).
#
# This sends well-formed CONNECTs (expect 405) and malformed ones (expect
# RST_STREAM(PROTOCOL_ERROR)). The 405s are the control: an implementation that
# reset every CONNECT would pass the rejection half on its own.
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
    """('status', N) for a HEADERS reply, ('RST', code) for a stream reset."""
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
                    res = ("RST", int.from_bytes(payload, "big"))
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


PROTO = ("RST", 1)                                  # PROTOCOL_ERROR

check("well-formed CONNECT -> 405", outcome(C + A), ("status", 405))
check("CONNECT without :authority -> reset", outcome(C), PROTO)
check("CONNECT with :scheme -> reset", outcome(C + A + hdr(b":scheme", b"https")), PROTO)
check("CONNECT with :path -> reset", outcome(C + A + hdr(b":path", b"/")), PROTO)
check("CONNECT with empty :authority -> reset", outcome(C + hdr(b":authority", b"")), PROTO)

# report 124: the authority form itself. Every rejection is paired with an
# accepted authority that reaches the same 405 -- an IPv6 literal WITH a port
# for the bracketed cases, a reg-name with a port for the rest -- so a build
# that simply reset all of them cannot pass.
def auth(v):
    return outcome(C + hdr(b":authority", v))


check("CONNECT [::1]:443 -> 405", auth(b"[::1]:443"), ("status", 405))
check("CONNECT host:65535 -> 405", auth(b"example.com:65535"), ("status", 405))
check("CONNECT Host agreeing with :authority -> 405",
      outcome(C + A + hdr(b"host", b"example.com:443")), ("status", 405))

check("CONNECT authority with a path -> reset", auth(b"bad/path"), PROTO)
check("CONNECT authority with userinfo -> reset", auth(b"user@host:443"), PROTO)
check("CONNECT authority with a space -> reset", auth(b"exa mple.com:443"), PROTO)
check("CONNECT authority with no port -> reset", auth(b"example.com"), PROTO)
check("CONNECT bracketed authority with no port -> reset", auth(b"[::1]"), PROTO)
check("CONNECT authority with a non-numeric port -> reset", auth(b"example.com:44a"), PROTO)
check("CONNECT authority with an out-of-range port -> reset", auth(b"example.com:99999"), PROTO)
check("CONNECT authority with a bad IPv6 literal -> reset", auth(b"[deadbeef]:443"), PROTO)

print("ok" if fails == 0 else f"FAIL ({fails})")
sys.exit(0 if fails == 0 else 1)
