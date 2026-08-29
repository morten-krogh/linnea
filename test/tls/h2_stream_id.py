#!/usr/bin/env python3
"""HTTP/2 stream-id rules (RFC 9113 5.1.1).

A client's stream id is odd, and numerically above every stream it has already
opened. An id breaking either says the peer's stream numbering is broken, which
is a CONNECTION error: no per-stream answer repairs it and the next id cannot be
trusted either.

Both were checked, but AFTER the malformed-request checks — so a malformed
request on an even id was answered with a stream reset instead, and stamped the
strictly-increasing floor with an even number on its way out. The id is now
validated first, once the block is whole.

The last case is the one that keeps the fix honest: a malformed request on a
VALID id must still fail only its stream, with the connection serving after.

usage: h2_stream_id.py <cafile> <port>
"""
import socket
import ssl
import struct
import sys

ca, port = sys.argv[1], int(sys.argv[2])


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def h(n, v):
    return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v


def rd(s):
    hd = b""
    while len(hd) < 9:
        d = s.recv(9 - len(hd))
        if not d:
            return None
        hd += d
    ln = int.from_bytes(hd[:3], "big")
    p = b""
    while len(p) < ln:
        d = s.recv(ln - len(p))
        if not d:
            break
        p += d
    return hd[3], hd[4], int.from_bytes(hd[5:9], "big") & 0x7fffffff, p


M = h(b":method", b"GET")
S = h(b":scheme", b"https")
A = h(b":authority", b"localhost")
P = h(b":path", b"/hello.txt")
GOOD = M + S + A + P
NO_PATH = M + S + A                       # malformed: no :path
DUP_AUTH = M + S + A + h(b":authority", b"evil.test") + P


def connect():
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=6),
                        server_hostname="localhost")
    s.settimeout(5)
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(4, 0, 0))
    return s


def verdict(s, sid):
    for _ in range(12):
        r = rd(s)
        if r is None:
            return "connection closed"
        t, fl, rsid, p = r
        if t == 7:
            return "GOAWAY"
        if t == 3 and rsid == sid:
            return "RST"
        if t == 1 and rsid == sid:
            return "served"
    return "no reply"


fails = 0


def check(label, got, want, extra=""):
    global fails
    ok = got == want
    print(f"{'ok  ' if ok else 'FAIL'} {label}: {got}, want {want}{extra}")
    fails += not ok


# one request per connection, so each case starts from a clean floor
for label, sid, block, want in (
        ("odd id, well formed", 1, GOOD, "served"),
        ("EVEN id, well formed", 2, GOOD, "GOAWAY"),
        ("EVEN id, malformed (no :path)", 2, NO_PATH, "GOAWAY"),
        ("EVEN id, malformed (duplicate :authority)", 2, DUP_AUTH, "GOAWAY"),
        ("EVEN id, well past the floor", 100, GOOD, "GOAWAY")):
    s = connect()
    s.sendall(fr(1, 0x05, sid, block))
    check(label, verdict(s, sid), want)
    s.close()

# an id that goes backwards, on one connection
s = connect()
s.sendall(fr(1, 0x05, 5, GOOD))
verdict(s, 5)
s.sendall(fr(1, 0x05, 3, GOOD))
check("odd but below the floor", verdict(s, 3), "GOAWAY")
s.close()

# A stream id that was USED and completed, then reused (report 146). This is
# NOT the "odd but below the floor" case above: stream 1 was opened, served and
# closed by END_STREAM. RFC 9113 5.1.1 covers it all the same -- "the identifier
# of a newly established stream MUST be numerically greater than all streams
# that the initiating endpoint has opened", and an unexpected identifier is a
# connection error of type PROTOCOL_ERROR. 5.1's "closed" state agrees for a
# stream closed by END_STREAM, which it makes a CONNECTION error of type
# STREAM_CLOSED; only the post-RST_STREAM case there is scoped to the stream.
# nginx 1.30.4, asked the same question, also answers GOAWAY(PROTOCOL_ERROR)
# and drops the following stream 3. Report 146 recommended RST_STREAM + carry
# on; that was declined, and this case is what would catch it being applied.
s = connect()
s.sendall(fr(1, 0x05, 1, GOOD))
first = verdict(s, 1)
s.sendall(fr(1, 0x05, 1, GOOD))
check("a completed stream id, reused", verdict(s, 1), "GOAWAY",
      f" (its first request: {first})")
fails += first != "served"
s.close()

# ...and its control, which a blanket "GOAWAY on the second HEADERS" build
# cannot pass: same connection, same completed stream 1, but a FRESH id next.
# That one is served. The connection error above is caused by the reuse, not by
# there being a second request on the connection at all.
s = connect()
s.sendall(fr(1, 0x05, 1, GOOD))
verdict(s, 1)
s.sendall(fr(1, 0x05, 3, GOOD))
check("a fresh id after a completed one still serves", verdict(s, 3), "served")
s.close()

# and the guard: a malformed request on a VALID id is still only a stream error,
# and the connection keeps serving afterwards
s = connect()
s.sendall(fr(1, 0x05, 1, NO_PATH))
v = verdict(s, 1)
alive = "no"
if v == "RST":
    s.sendall(fr(1, 0x05, 3, GOOD))
    alive = "yes" if verdict(s, 3) == "served" else "no"
check("malformed on a valid id stays a stream error", v, "RST",
      f" (connection still serving: {alive})")
fails += alive != "yes"
s.close()

if fails:
    sys.exit(1)
print("ok")
