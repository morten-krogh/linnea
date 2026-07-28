#!/usr/bin/env python3
# Q119: the request-body slowloris. head_timeout used to stop at the request
# head — a client that opened a proxied upload and then trickled (or sat
# silent, feeding just enough to dodge the idle timeout) held its upstream
# slot forever; enough of them wedge proxying for everyone (max_upstream).
# Now the head deadline keeps running through the body, paid forward by
# progress (LINNEA_BODY_NS_PER_BYTE per received byte), so a trickler is cut
# about head_timeout after its last honest burst while a real uploader —
# who outruns the 500 B/s floor thousands of times over — never notices.
#
# Three phases against a server with head_timeout=3, idle timeout=2:
#   h1 trickle: streamed POST fed a byte per 0.4 s (dodges the idle timeout)
#               must be closed in a few seconds, not held forever
#   h1 legit:   the same POST sent at full speed still round-trips
#   h2 silent:  a claimed upload that goes quiet is failed with :status 408
#               on its stream, and the connection AND upstream slot survive —
#               a follow-up proxied request on the same connection works
# Usage: slow_body.py <cafile> <port>
import socket
import ssl
import struct
import sys
import time

ca, port = sys.argv[1], int(sys.argv[2])


def tls(alpn):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols([alpn])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=15),
                        server_hostname="localhost")
    assert s.selected_alpn_protocol() == alpn
    return s


# --- h1 trickle: must be cut, and promptly -------------------------------
s = tls("http/1.1")
s.sendall(b"POST /api/echo HTTP/1.1\r\nHost: localhost\r\n"
          b"Content-Length: 100000\r\n\r\n" + b"x" * 1000)
start = time.time()
closed = False
try:
    while time.time() - start < 15:
        time.sleep(0.4)               # under the 2 s idle timeout
        s.sendall(b"y")               # one byte of "progress"
        # a close surfaces on the next read, not always on the write
        s.settimeout(0.05)
        try:
            if s.recv(256) == b"":
                closed = True
                break
        except socket.timeout:
            pass
except (ssl.SSLError, OSError):
    closed = True
elapsed = time.time() - start
s.close()
assert closed, "trickled body held its connection (and upstream slot) past 15s"
assert elapsed < 10, f"trickled body cut only after {elapsed:.1f}s"
assert elapsed > 1.5, f"cut suspiciously early ({elapsed:.1f}s) — idle, not body, clock?"

# --- h1 legit: a full-speed upload is untouched --------------------------
s = tls("http/1.1")
body = b"z" * 100000
s.sendall(b"POST /api/echo HTTP/1.1\r\nHost: localhost\r\n"
          b"Content-Length: %d\r\n\r\n" % len(body) + body)
s.settimeout(10)
resp = b""
while b"\r\n\r\n" not in resp:
    d = s.recv(65536)
    assert d, "closed before the response head"
    resp += d
assert b" 200 " in resp.split(b"\r\n", 1)[0], resp[:80]
head, _, rest = resp.partition(b"\r\n\r\n")
while len(rest) < len(body):
    d = s.recv(65536)
    if not d:
        break
    rest += d
assert rest == body, f"echo returned {len(rest)}/{len(body)} bytes"
s.close()

# --- h2 silent upload: 408 on the stream, connection + slot live on ------
s = tls("h2")


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def estr(b):
    return bytes([len(b)]) + b


def hdr(n, v):
    return b"\x00" + estr(n) + estr(v)


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
s.sendall(fr(1, 0x04, 1, hdr(b":method", b"POST") + hdr(b":scheme", b"https")
              + hdr(b":authority", b"localhost") + hdr(b":path", b"/api/echo")
              + hdr(b"content-length", b"60000")))
s.sendall(fr(0, 0, 1, b"q" * 1000))   # one honest chunk, then silence
start = time.time()
s.settimeout(15)
got408 = False
try:
    while time.time() - start < 15 and not got408:
        r = rd()
        if r is None:
            break
        t, fl, sid, p = r
        if t == 1 and sid == 1 and b"408" in p:
            got408 = True
except (socket.timeout, OSError):
    pass
elapsed = time.time() - start
assert got408, "silent h2 upload was never failed with a 408"
assert elapsed < 12, f"408 only after {elapsed:.1f}s"

# the connection survived, and so did the upstream pool: a proxied request
# on a fresh stream must round-trip
s.sendall(fr(1, 0x05, 3, hdr(b":method", b"GET") + hdr(b":scheme", b"https")
              + hdr(b":authority", b"localhost") + hdr(b":path", b"/api/simple")))
ok = False
body3 = False
try:
    while not (ok and body3):
        r = rd()
        if r is None:
            break
        t, fl, sid, p = r
        if t == 1 and sid == 3 and b"200" in p:
            ok = True
        if t == 0 and sid == 3 and b"backend body" in p:
            body3 = True
except (socket.timeout, OSError):
    pass
s.close()
assert ok and body3, f"connection unusable after the 408 (headers={ok} body={body3})"
print("ok")
