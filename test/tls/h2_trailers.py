#!/usr/bin/env python3
"""A trailer section must not tear down the connection (RFC 9113 8.1).

h2_build_request treated every HEADERS frame as a new request, and enforced that
a stream id be strictly greater than any seen before. A trailer section arrives
on a stream already open, so its id fails that test, and the failure was a
CONNECTION error: GOAWAY(PROTOCOL_ERROR), taking every concurrent stream on the
connection down with it. Trailers are explicitly allowed by 8.1, and any client
that sends them met this — gRPC-web, or an upload declaring a checksum after the
body. HTTP/3 has handled trailers since Q134; HTTP/2 did not.

The subtle half is HPACK. The trailer's fields are decoded even though nothing
in them is used, because the dynamic table is connection-wide state: a block
left unwalked desynchronises it and every later request decodes to nonsense.
The last case here is the one that checks that — it sends a trailer carrying an
indexed insertion, then makes a further request on the same connection whose
correctness depends on the table still being in step.

usage: h2_trailers.py <cafile> <port>
"""
import socket
import ssl
import struct
import sys

ca, port = sys.argv[1], int(sys.argv[2])
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def lit(n, v):                       # literal, never indexed
    return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v


def lit_idx(n, v):                   # literal WITH incremental indexing: inserts
    return b"\x40" + bytes([len(n)]) + n + bytes([len(v)]) + v


def idx(i):
    return bytes([0x80 | i])


def post(path=b"/api/echo"):
    return (lit(b":method", b"POST") + lit(b":scheme", b"https")
            + lit(b":authority", b"localhost") + lit(b":path", path))


def get(path=b"/hello.txt", extra=b""):
    return (lit(b":method", b"GET") + lit(b":scheme", b"https")
            + lit(b":authority", b"localhost") + lit(b":path", path) + extra)


class Conn:
    def __init__(self):
        ctx = ssl.create_default_context(cafile=ca)
        ctx.check_hostname = False
        ctx.set_alpn_protocols(["h2"])
        self.s = ctx.wrap_socket(
            socket.create_connection(("127.0.0.1", port), timeout=10),
            server_hostname="localhost")
        self.s.settimeout(3)
        self.s.sendall(PREFACE + fr(4, 0, 0))
        self.buf = b""

    def send(self, data):
        self.s.sendall(data)

    def frames(self, until_stream=None, budget=3.0):
        """Read frames until a HEADERS for `until_stream`, a GOAWAY, or quiet."""
        out = []
        try:
            while True:
                d = self.s.recv(65535)
                if not d:
                    break
                self.buf += d
                while len(self.buf) >= 9:
                    ln = int.from_bytes(self.buf[:3], "big")
                    if len(self.buf) < 9 + ln:
                        break
                    t = self.buf[3]
                    sid = int.from_bytes(self.buf[5:9], "big") & 0x7fffffff
                    payload = self.buf[9:9 + ln]
                    out.append((t, sid, payload))
                    self.buf = self.buf[9 + ln:]
                    if t == 7:
                        return out
                    if until_stream is not None and t == 1 and sid == until_stream:
                        return out
        except (socket.timeout, ConnectionResetError, ssl.SSLError, OSError):
            pass
        return out

    def close(self):
        self.s.close()


def goaway(frames):
    return next((p for t, _s, p in frames if t == 7), None)


def status(frames, sid):
    for t, s_, p in frames:
        if t == 1 and s_ == sid:
            for c in (b"200", b"400", b"404", b"502"):
                if c in p:
                    return c.decode()
            return "?"
    return None


fails = 0

# --- 1: a POST with a trailer section is served, connection intact ----------
c = Conn()
c.send(fr(1, 0x04, 1, post()))            # END_HEADERS, body to follow
c.send(fr(0, 0x00, 1, b"hello"))
c.send(fr(1, 0x05, 1, lit(b"x-checksum", b"abc")))   # trailers, END_STREAM
f = c.frames(until_stream=1)
c.close()
if goaway(f) is not None:
    print("FAIL a trailer section drew a GOAWAY — the whole connection died for "
          "something RFC 9113 8.1 allows")
    fails += 1
elif status(f, 1) == "200":
    print("ok   POST with trailers served, connection intact")
else:
    print(f"FAIL POST with trailers: status {status(f, 1)}")
    fails += 1

# --- 2: other streams on the same connection survive it --------------------
c = Conn()
c.send(fr(1, 0x04, 1, post()))
c.send(fr(0, 0x00, 1, b"hello"))
c.send(fr(1, 0x05, 3, get()))             # a concurrent, ordinary request
c.send(fr(1, 0x05, 1, lit(b"x-checksum", b"abc")))
f = c.frames(until_stream=1)
c.close()
if goaway(f) is not None:
    print("FAIL the trailer took a concurrent stream down with it")
    fails += 1
elif status(f, 3) == "200" and status(f, 1) == "200":
    print("ok   a concurrent stream is unaffected")
else:
    print(f"FAIL concurrent: stream 3 -> {status(f, 3)}, stream 1 -> {status(f, 1)}")
    fails += 1

# --- 3: a pseudo-header in a trailer is malformed, but only the stream ------
c = Conn()
c.send(fr(1, 0x04, 1, post()))
c.send(fr(0, 0x00, 1, b"hello"))
c.send(fr(1, 0x05, 1, lit(b":method", b"GET")))      # 8.1 forbids this
f = c.frames(budget=2.0)
rst = any(t == 3 and s_ == 1 for t, s_, _p in f)
c.close()
if goaway(f) is not None:
    print("FAIL a pseudo-header in a trailer took the connection down; 8.1 "
          "makes it malformed, which is a STREAM error")
    fails += 1
elif rst:
    print("ok   a pseudo-header in a trailer resets only its stream")
else:
    print("FAIL a pseudo-header in a trailer was accepted")
    fails += 1

# --- 4: the HPACK dynamic table survives the trailer ------------------------
# The trailer inserts an entry. If the block were skipped rather than decoded,
# the server's table would be one entry behind the client's, and the indexed
# reference in the next request would resolve to the wrong field — or fail.
c = Conn()
c.send(fr(1, 0x04, 1, post()))
c.send(fr(0, 0x00, 1, b"hello"))
c.send(fr(1, 0x05, 1, lit_idx(b"x-trailer-mark", b"one")))   # inserts
f = c.frames(until_stream=1)
if goaway(f) is not None:
    print("FAIL trailer with an indexed insertion drew a GOAWAY")
    fails += 1
else:
    # index 62 is the newest dynamic entry: the field the trailer just inserted
    c.send(fr(1, 0x05, 3, get() + idx(62)))
    f2 = c.frames(until_stream=3)
    if goaway(f2) is not None:
        print("FAIL the HPACK table desynchronised after a trailer: the next "
              "request's indexed field could not be resolved")
        fails += 1
    elif status(f2, 3) == "200":
        print("ok   the HPACK dynamic table stays in step across a trailer")
    else:
        print(f"FAIL after-trailer request: status {status(f2, 3)}")
        fails += 1
c.close()

sys.exit(1 if fails else 0)
