#!/usr/bin/env python3
"""Chunked uploads too large to buffer, which are captured and decoded as they
arrive and forwarded as an ordinary counted request.

Each mode prints OK or a reason. Modes:
  big     a 300000-byte body echoed back byte-exact, with chunk sizes from one
          byte to 60000 and the socket writes deliberately misaligned to them,
          so chunk headers, data and even CRLFs split across recvs
  head    the head the backend receives: a Content-Length we counted, and NO
          Transfer-Encoding -- the client's framing never goes upstream, which
          is what stops a proxy from relaying a smuggled request
  bad     a chunk size that is not hex, mid-body: 400, and nothing forwarded
  abort   the client vanishes mid-chunk: the backend never hears of it at all
  cap     a body past max_body: 413, delivered rather than RST
  flood   trailers forever, so the DECODED length never grows: still 413
  twice   two captures, different bodies, on ONE kept-alive connection: the
          capture file is per REQUEST, not per connection, or the second
          upload appends to the first and is described by the wrong length
"""
import hashlib
import random
import socket
import sys
import time

PORT = 61080
BACKEND_SEEN = "/tmp/linnea_backend_seen.log"


def body_of(n, seed):
    random.seed(seed)
    return bytes(random.getrandbits(8) for _ in range(n))


def frame(body, rng):
    """Chunk it at wildly varying sizes."""
    out, i = b"", 0
    while i < len(body):
        n = min(len(body) - i, rng.choice([1, 2, 7, 1000, 4096, 17000, 60000]))
        out += b"%x\r\n" % n + body[i:i + n] + b"\r\n"
        i += n
    return out


def send_ragged(s, data, rng):
    """Write it in pieces that do not line up with the framing."""
    i = 0
    while i < len(data):
        n = rng.choice([1, 3, 64, 8192, 40000])
        s.sendall(data[i:i + n])
        i += n


def read_response(s):
    s.settimeout(20)
    resp = b""
    while True:
        while b"\r\n\r\n" not in resp:
            d = s.recv(65536)
            if not d:
                return None, b""
            resp += d
        head, rest = resp.split(b"\r\n\r\n", 1)
        # An interim response is not the answer (RFC 9110 15.2): mode_head
        # sends Expect: 100-continue, and whether the 100 arrives in the same
        # recv as the final status is a matter of timing. Reading it as the
        # response failed the run about one time in three.
        if head.split(b" ")[1:2] and head.split(b" ")[1].startswith(b"1"):
            resp = rest
            continue
        break
    clen = 0
    for h in head.split(b"\r\n")[1:]:
        if h.lower().startswith(b"content-length:"):
            clen = int(h.split(b":")[1])
    while len(rest) < clen:
        d = s.recv(65536)
        if not d:
            break
        rest += d
    return head, rest


def post(path, encoded, rng, extra=b""):
    s = socket.create_connection(("127.0.0.1", PORT), timeout=20)
    s.sendall(b"POST %s HTTP/1.1\r\nHost: one.test\r\n"
              b"Transfer-Encoding: chunked\r\n%s\r\n" % (path.encode(), extra))
    send_ragged(s, encoded, rng)
    return s


def mode_big():
    rng = random.Random(11)
    body = body_of(300000, 11)
    s = post("/api/echo", frame(body, rng) + b"0\r\nX-Trailer: dropped\r\n\r\n", rng)
    head, rest = read_response(s)
    s.close()
    if head is None or b"200 OK" not in head:
        return f"not 200: {head!r}"
    if hashlib.md5(rest).hexdigest() != hashlib.md5(body).hexdigest():
        return f"echo differs: got {len(rest)} of {len(body)} bytes"
    return "OK"


def mode_head():
    rng = random.Random(5)
    body = body_of(60000, 5)
    s = post("/api/headers", frame(body, rng) + b"0\r\n\r\n", rng,
             extra=b"Expect: 100-continue\r\nX-Keep: yes\r\n")
    head, rest = read_response(s)
    s.close()
    if head is None or b"200 OK" not in head:
        return f"not 200: {head!r}"
    seen = rest.lower()
    if b"transfer-encoding" in seen:
        return "the backend was told Transfer-Encoding"
    if b"content-length: 60000" not in seen:
        return f"no counted length upstream: {rest!r}"
    if b"expect:" in seen:
        return "Expect was forwarded"
    if b"x-keep: yes" not in seen:
        return "an ordinary client header was dropped"
    return "OK"


def mode_bad():
    rng = random.Random(3)
    body = body_of(300000, 3)
    enc = frame(body, rng)
    enc = enc[:50000] + b"ZZZZ\r\n" + enc[50000:] + b"0\r\n\r\n"
    s = post("/api/badframe", enc, rng)
    head, _ = read_response(s)
    s.close()
    if head is None or b"400 Bad Request" not in head:
        return f"not 400: {head!r}"
    return "OK"


def mode_abort():
    rng = random.Random(9)
    body = body_of(300000, 9)
    s = post("/api/chunkabort", frame(body, rng)[:120000], rng)
    time.sleep(0.4)
    s.close()
    time.sleep(0.6)
    try:
        with open(BACKEND_SEEN) as f:
            if "/api/chunkabort" in f.read():
                return "the backend was handed the abandoned upload"
    except FileNotFoundError:
        pass
    return "OK"


def over_cap(path, payload):
    rng = random.Random(1)
    s = socket.create_connection(("127.0.0.1", PORT), timeout=20)
    s.sendall(b"POST %s HTTP/1.1\r\nHost: one.test\r\n"
              b"Transfer-Encoding: chunked\r\n\r\n" % path.encode())
    try:
        payload(s)
    except (BrokenPipeError, ConnectionResetError):
        pass                      # refused before we finished: fine, read on
    head, _ = read_response(s)
    s.close()
    if head is None or b"413" not in head:
        return f"not 413: {head!r}"
    return "OK"


def mode_cap():
    def send(s):
        for _ in range(300):                     # 300 x 5000 = 1.5 MB
            s.sendall(b"1388\r\n" + b"Q" * 5000 + b"\r\n")
        s.sendall(b"0\r\n\r\n")
    return over_cap("/api/capped", send)


def mode_flood():
    def send(s):
        s.sendall(b"4\r\nabcd\r\n0\r\n")          # body done at 4 bytes...
        for _ in range(3000):                    # ...then trailers forever
            s.sendall(b"X-Pad: " + b"z" * 500 + b"\r\n")
    return over_cap("/api/flood", send)


def mode_twice():
    s = socket.create_connection(("127.0.0.1", PORT), timeout=20)
    for seed, n in ((21, 200000), (99, 250000)):
        rng = random.Random(seed)
        body = body_of(n, seed)
        s.sendall(b"POST /api/echo HTTP/1.1\r\nHost: one.test\r\n"
                  b"Transfer-Encoding: chunked\r\n\r\n")
        send_ragged(s, frame(body, rng) + b"0\r\n\r\n", rng)
        head, rest = read_response(s)
        if head is None or b"200 OK" not in head:
            return f"body of {n}: not 200: {head!r}"
        if hashlib.md5(rest).hexdigest() != hashlib.md5(body).hexdigest():
            return f"body of {n}: echo differs, got {len(rest)} bytes"
    s.close()
    return "OK"


MODES = {"big": mode_big, "twice": mode_twice, "head": mode_head, "bad": mode_bad,
         "abort": mode_abort, "cap": mode_cap, "flood": mode_flood}

try:
    print(MODES[sys.argv[1]]())
except Exception as exc:                          # a crash is a failure, not a traceback
    print(f"{type(exc).__name__}: {exc}")
