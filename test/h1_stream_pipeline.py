#!/usr/bin/env python3
"""A request pipelined behind a STREAMED request body must still be served.

A body too large to buffer with the head is captured to the spill file as it
arrives (counted) or decoded to it (chunked); the upstream is only contacted
once it is whole. The bug this guards: when the client pipelines its next
request in the SAME recv as the body's final bytes, that suffix was dropped --
the pipelined request went unanswered and the client hung until its timeout.
It was invisible to the existing tests because they read the first response
before sending the second request, so the two never shared a recv.

Each case pipelines a second request behind a large first one on ONE kept-alive
connection and checks that BOTH are answered and BOTH bodies survive byte-exact.
The split matrix forces the seam between the requests to fall at the places that
matter: mid-body, exactly at the body's end, one byte into the next request, and
(for chunked) inside the terminal "0\r\n\r\n". "together" -- one write of the
whole thing -- is the original bug's trigger: the second request lands in the
recv that completes the body.

Usage: h1_stream_pipeline.py <port>.  Prints "OK" or the first failure.
"""
import hashlib
import random
import socket
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 61080
HOST = "one.test"


def body_of(n, seed):
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(n))


def counted_req(path, body):
    return (b"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n"
            b"Connection: keep-alive\r\n\r\n"
            % (path.encode(), HOST.encode(), len(body))) + body


def chunked_req(path, body, chunk=4096):
    out = b"POST %s HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n" \
          b"Connection: keep-alive\r\n\r\n" % (path.encode(), HOST.encode())
    i = 0
    while i < len(body):
        n = min(chunk, len(body) - i)
        out += b"%x\r\n" % n + body[i:i + n] + b"\r\n"
        i += n
    out += b"0\r\n\r\n"          # terminal chunk, no trailers
    return out


class Conn:
    """A socket plus the bytes read past one response, so the next read of the
    same kept-alive connection continues where the last one stopped."""
    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=15)
        self.s.settimeout(15)
        self.buf = b""

    def send_split(self, wire, cuts):
        """Write `wire`, breaking it into separate sends at the absolute offsets
        in `cuts` (each a distinct recv on the other end, since loopback delivers
        a lone small write as its own segment). An empty `cuts` is one write."""
        pts = [0] + sorted(c for c in cuts if 0 < c < len(wire)) + [len(wire)]
        for a, b in zip(pts, pts[1:]):
            self.s.sendall(wire[a:b])

    def read_one(self):
        """Read exactly one response (skipping 1xx); leftover bytes carry over."""
        while True:
            while b"\r\n\r\n" not in self.buf:
                d = self.s.recv(65536)
                if not d:
                    return None, b""
                self.buf += d
            head, rest = self.buf.split(b"\r\n\r\n", 1)
            if head.split(b" ")[1:2] and head.split(b" ")[1].startswith(b"1"):
                self.buf = rest             # interim (100-continue); keep reading
                continue
            break
        clen = 0
        for h in head.split(b"\r\n")[1:]:
            if h.lower().startswith(b"content-length:"):
                clen = int(h.split(b":")[1])
        while len(rest) < clen:
            d = self.s.recv(65536)
            if not d:
                break
            rest += d
        self.buf = rest[clen:]
        return head, rest[:clen]

    def close(self):
        self.s.close()


def run_case(framing, split, first_n=250000):
    body1 = body_of(first_n, seed=first_n + (1 if framing == "chunked" else 0))
    marker = b"SECOND-REQ-" + framing.encode() + b"-" + str(split).encode()
    if framing == "counted":
        req1 = counted_req("/api/echo", body1)
    else:
        req1 = chunked_req("/api/echo", body1)
    req2 = counted_req("/api/echo", marker)   # a body, so we can prove it intact
    wire = req1 + req2
    seam = len(req1)                           # where the pipelined request starts

    cuts = {
        "together":   [],                      # one write: the bug's trigger
        "at-seam":    [seam],                  # body ends exactly at a recv edge
        "into-next":  [seam + 1],              # 1 byte of req2 shares the last recv
        "mid-body":   [seam // 2, seam + 3],   # a split inside the body too
    }[split]
    if framing == "chunked":
        # also break the terminal "0\r\n\r\n" so the body completes mid-recv
        if split == "at-seam":
            cuts = [seam - 2]                   # between the terminal CRLFs
        elif split == "into-next":
            cuts = [seam - 3]                   # right after the "0"

    c = Conn(PORT)
    try:
        c.send_split(wire, cuts)
        h1, b1 = c.read_one()
        if h1 is None or b"200" not in h1.split(b"\r\n")[0]:
            return f"{framing}/{split}: first not 200: {h1!r}"
        if hashlib.md5(b1).hexdigest() != hashlib.md5(body1).hexdigest():
            return f"{framing}/{split}: first body differs ({len(b1)}/{len(body1)})"
        h2, b2 = c.read_one()
        if h2 is None:
            return f"{framing}/{split}: PIPELINED REQUEST DROPPED (no 2nd response)"
        if b"200" not in h2.split(b"\r\n")[0]:
            return f"{framing}/{split}: second not 200: {h2!r}"
        if b2 != marker:
            return f"{framing}/{split}: second body corrupt: {b2!r}"
        return None
    finally:
        c.close()


def main():
    for framing in ("counted", "chunked"):
        for split in ("together", "at-seam", "into-next", "mid-body"):
            err = run_case(framing, split)
            if err:
                print(err)
                return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
