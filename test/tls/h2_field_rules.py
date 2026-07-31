#!/usr/bin/env python3
"""Request-field rules the shared HPACK/QPACK decoder enforces (RFC 9113 8.2-8.3).

Three findings, one decoder, and because HTTP/3 shares it the same fixes land
there too (h3_field_rules_test.py is the other half).

  :scheme      MUST be present (8.3.1). It was decoded into the request struct
               and then read nowhere in the entire tree, so its absence was
               never noticed — a request without one was served a normal 200.
               Its VALUE is deliberately unrestricted: 8.3.1 says outright that
               :scheme "is not restricted to http and https schemed URIs", so
               a non-HTTP scheme must still be accepted.

  :path        MUST NOT be empty for an http/https request (8.3.1). An empty
               one was served as though the client had asked for "/".

  connection-  "Any message containing connection-specific header fields MUST
  specific     be treated as malformed" (8.2.2). These names were matched only
               inside the proxy rebuild, and only to skip them from the head
               sent upstream, so a static request carrying one was served. TE is
               the single exception, and only for the value "trailers".

  field syntax A name MUST NOT contain 0x00-0x20 INCLUSIVE (8.2.1); the scan
               used `jb 0x20`, so a space passed and "x foo" reached the proxy
               rebuild to be written into an HTTP/1.1 head. A value MUST NOT
               begin or end with SP or HTAB; only CR, LF and NUL were refused.

usage: h2_field_rules.py <cafile> <port>
"""
import socket
import ssl
import struct
import sys

ca, port = sys.argv[1], int(sys.argv[2])
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def lit(n, v):
    return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v


def base(method=b"GET", scheme=b"https", auth=b"localhost", path=b"/hello.txt"):
    b = b""
    if method is not None:
        b += lit(b":method", method)
    if scheme is not None:
        b += lit(b":scheme", scheme)
    if auth is not None:
        b += lit(b":authority", auth)
    if path is not None:
        b += lit(b":path", path)
    return b


def ask(block):
    """Send one request; return 'served', 'rejected' or 'closed'."""
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                        server_hostname="localhost")
    s.settimeout(3)
    s.sendall(PREFACE + fr(4, 0, 0) + fr(1, 0x05, 1, block))
    verdict, buf = None, b""
    try:
        while verdict is None:
            d = s.recv(65535)
            if not d:
                verdict = "closed"
                break
            buf += d
            while len(buf) >= 9:
                ln = int.from_bytes(buf[:3], "big")
                if len(buf) < 9 + ln:
                    break
                t, payload = buf[3], buf[9:9 + ln]
                if t == 1:
                    verdict = "served"
                elif t == 3:
                    verdict = "rejected"
                elif t == 7:
                    verdict = "closed"
                buf = buf[9 + ln:]
                if verdict:
                    break
    except (socket.timeout, ConnectionResetError, ssl.SSLError, OSError):
        verdict = verdict or "closed"
    s.close()
    return verdict


fails = 0


def case(label, block, want):
    global fails
    got = ask(block)
    if got == want:
        print(f"ok   {label}: {got}")
    else:
        print(f"FAIL {label}: {got}, expected {want}")
        fails += 1


# a plain request must still work, or nothing below means anything
case("an ordinary request", base(), "served")

# --- pseudo-headers --------------------------------------------------------
case("no :scheme", base(scheme=None), "rejected")
case("empty :path", base(path=b""), "rejected")
case(":scheme: ftp is NOT restricted (8.3.1)", base(scheme=b"ftp"), "served")

# --- connection-specific fields --------------------------------------------
for name in (b"connection", b"keep-alive", b"transfer-encoding", b"upgrade",
             b"proxy-connection"):
    case(f"{name.decode()} is malformed", base() + lit(name, b"x"), "rejected")

case("te: gzip is malformed", base() + lit(b"te", b"gzip"), "rejected")
case("te: trailers is the one exception", base() + lit(b"te", b"trailers"), "served")
case("te: Trailers, matched case-insensitively",
     base() + lit(b"te", b"Trailers"), "served")

# --- field syntax ----------------------------------------------------------
case("space inside a field name", base() + lit(b"x foo", b"v"), "rejected")
case("value with a leading space", base() + lit(b"x-a", b" v"), "rejected")
case("value with a trailing space", base() + lit(b"x-a", b"v "), "rejected")
case("value with a leading tab", base() + lit(b"x-a", b"\tv"), "rejected")
case("value with a trailing tab", base() + lit(b"x-a", b"v\t"), "rejected")
case("an inner space is fine", base() + lit(b"x-a", b"one two"), "served")
case("an empty value is fine", base() + lit(b"x-a", b""), "served")

sys.exit(1 if fails else 0)
