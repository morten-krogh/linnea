#!/usr/bin/env python3
"""Two malformed-message rules the HTTP/2 request side missed.

Finding 24: HEADERS carrying END_STREAM ends the message, so a nonzero
content-length on it is malformed (RFC 9113 8.1.1) -- a body announced with no
DATA. A proxied one used to be forwarded bodiless, so the backend heard a
request the client never sent. It must be a stream error (400) with no upstream.

Finding 4: a trailer HEADERS section MUST carry END_STREAM (RFC 9113 8.1). One
that omits it does not end the body, so the collecting slot stayed open, a later
DATA frame still appended to it, and the stream hung to its 408. It must fail the
stream (400), and a fresh stream must keep working (a stream error, not a
connection one).

usage: h2_malformed.py <cafile> <port>.  Prints ok/FAIL lines; exits nonzero on any FAIL.
"""
import socket
import ssl
import struct
import sys

ca, port = sys.argv[1], int(sys.argv[2])
FT_DATA, FT_HEADERS, FT_SETTINGS = 0x0, 0x1, 0x4
END_STREAM, END_HEADERS = 0x1, 0x4


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def estr(b):
    return bytes([len(b)]) + b


def hdr(n, v):
    return b"\x00" + estr(n) + estr(v)


def connect():
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                        server_hostname="localhost")
    assert s.selected_alpn_protocol() == "h2", "no h2"
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(FT_SETTINGS, 0, 0))
    return s


def status_of(s, sid, budget=8.0):
    """Read frames until a HEADERS on `sid` yields a :status; else None."""
    s.settimeout(budget)
    buf = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
            while len(buf) >= 9:
                ln = int.from_bytes(buf[:3], "big")
                if len(buf) < 9 + ln:
                    break
                ft = buf[3]
                fsid = int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
                payload = buf[9:9 + ln]
                buf = buf[9 + ln:]
                if ft == FT_HEADERS and fsid == sid:
                    for i in range(len(payload) - 2):
                        if payload[i:i + 3].isdigit():
                            return int(payload[i:i + 3])
    except (socket.timeout, OSError):
        pass
    return None


REQ = (hdr(b":method", b"POST") + hdr(b":scheme", b"https")
       + hdr(b":authority", b"localhost") + hdr(b":path", b"/api/echo"))
GET = (hdr(b":method", b"GET") + hdr(b":scheme", b"https")
       + hdr(b":authority", b"localhost") + hdr(b":path", b"/api/echo"))

fails = 0

# Finding 24: terminal HEADERS with a nonzero content-length, no DATA.
s = connect()
block = REQ + hdr(b"content-length", b"5")
s.sendall(fr(FT_HEADERS, END_HEADERS | END_STREAM, 1, block))
st = status_of(s, 1)
s.close()
if st == 400:
    print(f"ok   terminal HEADERS with content-length is rejected ({st})")
else:
    print(f"FAIL terminal HEADERS content-length:5 gave {st}, want 400 (forwarded bodiless?)")
    fails += 1

# a matching content-length: 0 on a terminal HEADERS is a normal bodiless request
s = connect()
s.sendall(fr(FT_HEADERS, END_HEADERS | END_STREAM, 1, REQ + hdr(b"content-length", b"0")))
st = status_of(s, 1)
s.close()
if st == 200:
    print(f"ok   terminal HEADERS with content-length:0 is served ({st})")
else:
    print(f"FAIL content-length:0 terminal HEADERS gave {st}, want 200")
    fails += 1

# Finding 4: a trailer HEADERS without END_STREAM, then a fresh stream must work.
s = connect()
s.sendall(fr(FT_HEADERS, END_HEADERS, 1, REQ))          # request head, no END_STREAM
s.sendall(fr(FT_DATA, 0, 1, b"abc"))                    # some body, no END_STREAM
s.sendall(fr(FT_HEADERS, END_HEADERS, 1, hdr(b"x-trailer", b"1")))  # trailer, NO END_STREAM
st = status_of(s, 1)
if st == 400:
    print(f"ok   a trailer without END_STREAM fails the stream ({st})")
else:
    print(f"FAIL trailer without END_STREAM gave {st}, want 400 (slot left collecting?)")
    fails += 1
# the connection survives: a fresh GET on stream 3 is served
s.sendall(fr(FT_HEADERS, END_HEADERS | END_STREAM, 3, GET))
st3 = status_of(s, 3)
s.close()
if st3 == 200:
    print(f"ok   a fresh stream still works after the malformed trailer ({st3})")
else:
    print(f"FAIL fresh stream after malformed trailer gave {st3}, want 200")
    fails += 1

sys.exit(1 if fails else 0)
