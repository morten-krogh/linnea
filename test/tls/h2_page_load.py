#!/usr/bin/env python3
# A whole page over ONE HTTP/2 connection, the way a browser fetches it, with
# every byte checked.
#
# The existing h2 tests each look at one thing — multiplexing, priority,
# trailers, flow-control errors. What none of them does is the ordinary case:
# a dozen files of different sizes asked for at once and reassembled, which is
# the only thing a real page ever does. That mattered less while a browser was
# exercising it daily; once Firefox moved to HTTP/3 nothing was.
#
# What this would catch that a single-stream test cannot: a scheduler that
# interleaves DATA into the wrong stream, a window accounted against the wrong
# one, a slot reused before its body finished, a large response truncated at a
# frame or window boundary. All of those produce the right total byte count
# somewhere and the wrong bytes on a particular stream, so every body is
# compared to the file on disk rather than merely counted.
#
# Usage: h2_page_load.py <cafile> <port> <docroot>
import hashlib
import os
import socket
import ssl
import struct
import sys

ca, port, docroot = sys.argv[1], int(sys.argv[2]), sys.argv[3]


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def estr(b):
    return bytes([len(b)]) + b          # literal, no Huffman, len < 127


def hdr(n, v):
    return b"\x00" + estr(n.encode()) + estr(v.encode())


def request(path, extra=()):
    h = (hdr(":method", "GET") + hdr(":scheme", "https")
         + hdr(":authority", "localhost") + hdr(":path", path))
    for n, v in extra:
        h += hdr(n, v)
    return h


def connect():
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=20),
                        server_hostname="localhost")
    assert s.selected_alpn_protocol() == "h2", s.selected_alpn_protocol()
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(4, 0, 0))
    # a connection window big enough that only per-stream flow control is in
    # play; this test is about correctness, not about pacing
    s.sendall(fr(8, 0, 0, struct.pack(">I", 1 << 28)))
    return s


# Every regular file in the docroot, largest first so the big ones are still
# streaming while the small ones finish — that is when interleaving bugs show.
names = sorted((f for f in os.listdir(docroot)
                if os.path.isfile(os.path.join(docroot, f)) and " " not in f),
               key=lambda f: -os.path.getsize(os.path.join(docroot, f)))[:20]
if not names:
    print("no files in %s" % docroot)
    sys.exit(1)

want = {}
s = connect()
sid = 1
for n in names:
    p = os.path.join(docroot, n)
    # ask for identity: a .br/.gz sibling would otherwise be served instead and
    # the comparison would be against the wrong file
    s.sendall(fr(1, 0x05, sid, request("/" + n, [("accept-encoding", "identity")])))
    want[sid] = (n, open(p, "rb").read())
    sid += 2

# ...and one Range request, since that is what the video does when it seeks
big = max(names, key=lambda f: os.path.getsize(os.path.join(docroot, f)))
blob = open(os.path.join(docroot, big), "rb").read()
lo, hi = 1000, min(50000, len(blob) - 1)
range_sid = sid
s.sendall(fr(1, 0x05, range_sid,
             request("/" + big, [("range", "bytes=%d-%d" % (lo, hi)),
                                 ("accept-encoding", "identity")])))
want[range_sid] = ("%s [%d-%d]" % (big, lo, hi), blob[lo:hi + 1])

got = {k: b"" for k in want}
done = set()
s.settimeout(20)
buf = b""
try:
    while len(done) < len(want):
        d = s.recv(262144)
        if not d:
            break
        buf += d
        while len(buf) >= 9:
            ln = int.from_bytes(buf[:3], "big")
            if len(buf) < 9 + ln:
                break
            typ, flags = buf[3], buf[4]
            sid_ = int.from_bytes(buf[5:9], "big") & 0x7fffffff
            payload = buf[9:9 + ln]
            buf = buf[9 + ln:]
            if typ == 0x00 and sid_ in got:                 # DATA
                body = payload
                if flags & 0x08:                            # PADDED
                    body = body[1:len(body) - payload[0]]
                got[sid_] += body
                # keep the stream window open; the point here is completeness
                s.sendall(fr(8, 0, sid_, struct.pack(">I", max(1, len(body)))))
                s.sendall(fr(8, 0, 0, struct.pack(">I", max(1, len(body)))))
            if flags & 0x01 and typ in (0x00, 0x01) and sid_ in got:
                done.add(sid_)
            if typ == 0x07:                                 # GOAWAY
                raise SystemExit("server sent GOAWAY: %r" % payload[:32])
except socket.timeout:
    pass
s.close()

bad = []
for k, (name, expect) in sorted(want.items()):
    body = got[k]
    if k not in done:
        bad.append("%s: never ended (%d of %d bytes)" % (name, len(body), len(expect)))
    elif len(body) != len(expect):
        bad.append("%s: %d bytes, expected %d" % (name, len(body), len(expect)))
    elif hashlib.sha256(body).digest() != hashlib.sha256(expect).digest():
        bad.append("%s: %d bytes but the content differs" % (name, len(body)))

total = sum(len(v) for v in got.values())
if bad:
    print("; ".join(bad[:4]))
    sys.exit(1)
print("ok (%d streams, %d bytes, all byte-exact)" % (len(want), total))
