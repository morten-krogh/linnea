#!/usr/bin/env python3
# Finding 2 (audit-report-2): HTTP/2 shares the one authority grammar. A
# :authority with a non-numeric or extra-colon port, or an unterminated IPv6
# bracket, is malformed -- its stream is refused (RST_STREAM), not served --
# while a valid authority still returns the file. Same rule as HTTP/1.1 and
# HTTP/3, enforced by the shared linnea_hpack_req_check -> authority parser.
# Usage: h2_authority_grammar.py <cafile> <port>
import socket
import ssl
import struct
import sys

ca, port = sys.argv[1], int(sys.argv[2])


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def h(n, v):
    return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v


def recvn(s, n):
    b = b""
    while len(b) < n:
        d = s.recv(n - len(b))
        if not d:
            return None
        b += d
    return b


def served(authority):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5),
                        server_hostname="localhost")
    s.settimeout(4)
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(4, 0, 0))
    s.sendall(fr(1, 0x05, 1, h(b":method", b"GET") + h(b":scheme", b"https")
                  + h(b":authority", authority) + h(b":path", b"/index.html")))
    got_body = False
    try:
        for _ in range(24):
            hd = recvn(s, 9)
            if hd is None:
                break
            ln = int.from_bytes(hd[:3], "big")
            typ, flags = hd[3], hd[4]
            sid = int.from_bytes(hd[5:9], "big")
            p = recvn(s, ln) if ln else b""
            if p is None:
                break
            if typ == 0 and sid == 1:            # DATA on our stream -> served
                if p:
                    got_body = True
                if flags & 1:                    # END_STREAM
                    break
            elif typ == 3 and sid == 1:          # RST_STREAM -> refused
                break
            elif typ == 7:                       # GOAWAY -> connection error
                break
    except OSError:
        pass
    s.close()
    return got_body


assert served(b"localhost"), "valid :authority was not served over h2"
# a valid IPv6 literal we do not host is served by the connection's own vhost
assert served(b"[::1]"), "valid IPv6-literal :authority was not served over h2"
# report 126: IPvFuture is the IP-literal grammar's other alternative and was
# refused. It is one shared parser, so h2 has to move with h1 -- an authority
# spelling legal on one protocol and not the other is exactly the divergence
# this file exists to catch.
assert served(b"[v1.fe80]"), "valid IPvFuture :authority was not served over h2"
assert served(b"[V9.x]:443"), "upper-case IPvFuture flag was not served over h2"
# structural AND semantic malformed authorities are refused (audit-report-3 F2:
# out-of-range port, non-reg-name char, bracket contents that are not IPv6;
# report 126: contents that open with "v" but are not an IPvFuture either)
for bad in (b"localhost:garbage", b"localhost:80:bad", b"[::1", b"[::1]x",
            b"localhost:", b"localhost:65536", b"localhost:99999",
            b"localhost/foo", b"[deadbeef]", b"[gggg::1]",
            b"[v.fe80]", b"[v1.]", b"[v1]", b"[vg.x]", b"[v1.a/b]"):
    if served(bad):
        print(f"FAIL: malformed :authority {bad!r} was served over h2")
        sys.exit(1)
print("ok")
