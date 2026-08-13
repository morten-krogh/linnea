#!/usr/bin/env python3
# A canned HTTP/3 error must describe ITSELF, not the last thing this worker
# served.
#
# The QPACK encoder takes content-encoding, the validators, content-range,
# location and cache-control from globals in .bss -- per WORKER, so shared by
# every connection it holds -- and only linnea_h3_serve clears them. Responses
# built anywhere else inherited whatever was left there:
#
#   * the reader's 413/421/431/500, answered before a request has routed at
#     all, so nothing has cleared anything for it; and
#   * the proxy's 502/503/504, built on an io_uring completion long after the
#     serve that parked the request returned -- so any request answered in the
#     meantime, on any connection, is what the error ends up describing.
#
# One static hit was enough. A 413 went out carrying that file's
# content-encoding over a plain-text body, which a client honouring the
# encoding cannot decode at all, plus its etag, its last-modified and its
# location's Cache-Control -- the last making a transient failure storable for
# as long as the static content was.
#
# Needs workers:1 (or which worker answers is luck) and a location with a
# cache_control, which tls-h3-canned.json has.
#
# Usage: h3_canned_fields_test.py <port>
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)

# Everything a canned error must not have picked up from somebody else. Only
# content-type, content-length, date and server belong on one.
LEAKY = ("content-encoding", "etag", "last-modified", "content-range",
         "location", "cache-control", "vary", "accept-ranges")


class Conn:
    """One QUIC connection, driven a step at a time so two can be interleaved."""

    def __init__(self):
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
        cfg.verify_mode = ssl.CERT_NONE
        cfg.server_name = "localhost"
        self.q = QuicConnection(configuration=cfg)
        self.t = [0.0]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(0.05)
        self.q.connect(ADDR, now=self.clk())
        self.pump()
        dl = time.time() + 10
        while not self.q._handshake_confirmed and time.time() < dl:
            self.step()
        if not self.q._handshake_confirmed:
            raise RuntimeError("handshake failed")
        self.h3 = H3Connection(self.q)
        self.status, self.head, self.body, self.done = None, {}, b"", False

    def clk(self):
        self.t[0] += 0.001
        return self.t[0]

    def pump(self):
        for d, _ in self.q.datagrams_to_send(now=self.clk()):
            self.sock.sendto(d, ADDR)

    def step(self):
        """One receive-and-send turn. Never blocks for long."""
        try:
            self.q.receive_datagram(self.sock.recvfrom(4096)[0], ADDR,
                                    now=self.clk())
        except socket.timeout:
            pass
        while True:
            ev = self.q.next_event()
            if ev is None:
                break
            for e in self.h3.handle_event(ev) if hasattr(self, "h3") else ():
                if isinstance(e, HeadersReceived):
                    self.head = {k.decode(): v.decode() for k, v in e.headers}
                    self.status = self.head.get(":status")
                    self.done = self.done or e.stream_ended
                elif isinstance(e, DataReceived):
                    self.body += e.data
                    self.done = self.done or e.stream_ended
        self.pump()

    def send(self, path, method=b"GET", body=None, extra=()):
        sid = self.q.get_next_available_stream_id()
        hdrs = [(b":method", method), (b":scheme", b"https"),
                (b":authority", b"localhost"), (b":path", path.encode())]
        hdrs += list(extra)
        if body is not None:
            hdrs.append((b"content-length", str(len(body)).encode()))
        self.h3.send_headers(sid, hdrs, end_stream=body is None)
        if body is not None:
            self.h3.send_data(sid, body, end_stream=True)
        self.pump()
        return sid

    def wait(self, seconds):
        """Turn until the response ends or the budget runs out. A ping every
        turn keeps the connection off the server's idle timeout, which is
        shorter than the upstream stall this test waits through."""
        end = time.time() + seconds
        n = 0
        while time.time() < end and not self.done:
            n += 1
            self.q.send_ping(n)
            self.step()
        return self.status, self.head, self.body

    def request(self, path, seconds=20, **kw):
        self.status, self.head, self.body, self.done = None, {}, b"", False
        self.send(path, **kw)
        return self.wait(seconds)

    def close(self):
        self.sock.close()


bad = []


def want(label, cond, detail=""):
    if not cond:
        bad.append(f"{label}: {detail}")


def want_clean(label, status, head, expect):
    want(f"{label} status", status == expect, f"{status} {head}")
    leaked = [f for f in LEAKY if f in head]
    want(f"{label} carries no other response's fields", not leaked,
         ", ".join(f"{f}={head[f]}" for f in leaked))


BIG = b"x" * 8192          # over the fixture's max_body, so the reader answers
GZ = [(b"accept-encoding", b"gzip")]

# (1) The 413 as the very first thing this worker answers. Nothing has run
#     before it, so it is clean even unfixed -- which is the point: it shows
#     the check can tell the two apart rather than passing on a request that
#     never happened.
c = Conn()
st, hd, body = c.request("/", method=b"POST", body=BIG)
want_clean("413 first request", st, hd, "413")
want("413 body", body.startswith(b"413 "), repr(body[:40]))
c.close()

# (2) Arm every global: a pre-compressed variant, from a location with a
#     cache_control, so the encoder now holds a coding, validators and a
#     Cache-Control. Asserted, not assumed -- if this response were bare there
#     would be nothing for the checks below to catch.
c = Conn()
st, hd, _ = c.request("/canned.txt", extra=GZ)
want("armed status", st == "200", f"{st} {hd}")
want("armed content-encoding", hd.get("content-encoding") == "gzip", str(hd))
want("armed etag", "etag" in hd, str(hd))
want("armed cache-control", hd.get("cache-control") == "public, max-age=600",
     str(hd))
c.close()

# (3) The same 413 as (1), on a new connection, with only that static hit in
#     between. Before the fix it came back with gzip, the etag, last-modified
#     and the Cache-Control of a file it has nothing to do with.
c = Conn()
st, hd, body = c.request("/", method=b"POST", body=BIG)
want_clean("413 after a static hit", st, hd, "413")
want("413 body after a static hit", body.startswith(b"413 "), repr(body[:40]))
c.close()

# (4) The proxy's canned error, which is the harder half: it is built on a
#     completion, so the request that dirties the globals runs AFTER the one
#     being answered has already been parked. /api/slow outlives the fixture's
#     upstream timeout, which is what holds the leg open long enough to get a
#     second request in edgeways.
parked = Conn()
parked.status, parked.head, parked.body, parked.done = None, {}, b"", False
parked.send("/api/slow")
mid = time.time() + 0.7
while time.time() < mid and not parked.done:
    parked.step()
other = Conn()                       # a different connection, same worker
st, hd, _ = other.request("/canned.txt", extra=GZ)
want("gap request served", st == "200", f"{st} {hd}")
other.close()
st, hd, body = parked.wait(20)
want_clean("proxy error while another request ran", st, hd, "504")
want("proxy error body", body.startswith(b"504 "), repr(body[:40]))
parked.close()

print("OK" if not bad else "; ".join(bad))
sys.exit(0 if not bad else 1)
