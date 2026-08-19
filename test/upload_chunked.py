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
  sizeline the chunk-size line grammar, chunk-size [ ";" chunk-ext ] CRLF, sent
          BOTH small enough to buffer and large enough to capture -- linnea has
          two request decoders and they must give the same verdict
  smuggle a chunk size that overflows 64 bits must not wrap to zero: that reads
          as the last chunk, ends the body early, and turns the bytes behind it
          into a second request
"""
import os
import hashlib
import random
import socket
import sys
import time

_PB = int(__import__("os").environ.get("LINNEA_TEST_PORT_BASE", 61000))
_p = lambda n: _PB + n - 61000   # the suite's port rule, one base per run

PORT = _p(61080)
BACKEND_SEEN = os.path.join(os.environ.get("LINNEA_TEST_RUNDIR", "/tmp"),
                "linnea_backend_seen.log")


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


def read_framed(s, buf):
    """Read exactly one response and return (head, body, leftover). Unlike
    read_response above, the bytes past this response are carried out in
    `leftover` and fed back on the next call -- REQUIRED when two responses are
    pipelined, because the recv that finishes the first body routinely also
    carries the head of the second, and dropping it desyncs the reader (it made
    the first body read 79 bytes long -- the second response's own head)."""
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d:
            return None, b"", buf
        buf += d
    head, rest = buf.split(b"\r\n\r\n", 1)
    clen = 0
    for h in head.split(b"\r\n")[1:]:
        if h.lower().startswith(b"content-length:"):
            clen = int(h.split(b":")[1])
    while len(rest) < clen:
        d = s.recv(65536)
        if not d:
            break
        rest += d
    return head, rest[:clen], rest[clen:]


def mode_pipeline():
    # A GET pipelined behind a large chunked upload, both written in ONE send so
    # the GET rides the same recv as the terminal chunk. Unlike mode_twice, the
    # second request is NOT held back until the first response arrives -- which
    # is exactly the case that used to drop it. Run with and without trailers,
    # since the trailer bytes sit between the body's end and the pipelined GET.
    for trailers in (b"", b"X-A: 1\r\nX-B: 2\r\nX-C: 3\r\n"):
        rng = random.Random(7)
        body = body_of(220000, 7)
        wire = (b"POST /api/echo HTTP/1.1\r\nHost: one.test\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                + frame(body, rng) + b"0\r\n" + trailers + b"\r\n"
                + b"GET /api/echo HTTP/1.1\r\nHost: one.test\r\n"
                  b"Connection: keep-alive\r\n\r\n")
        s = socket.create_connection(("127.0.0.1", PORT), timeout=20)
        s.settimeout(20)
        s.sendall(wire)                               # one write: shared recv
        buf = b""
        head, b1, buf = read_framed(s, buf)
        if head is None or b"200 OK" not in head:
            return f"trailers={len(trailers)}: upload not 200: {head!r}"
        if hashlib.md5(b1).hexdigest() != hashlib.md5(body).hexdigest():
            return f"trailers={len(trailers)}: echo differs, got {len(b1)} bytes"
        head2, _, buf = read_framed(s, buf)           # leftover carried over
        s.close()
        if head2 is None:
            return f"trailers={len(trailers)}: pipelined GET dropped"
        if b"200 OK" not in head2:
            return f"trailers={len(trailers)}: pipelined GET not 200: {head2!r}"
    return "OK"


# chunk = chunk-size [ chunk-ext ] CRLF (RFC 9112 7.1), and chunk-ext is
# token / quoted-string with BWS -- so after the digits only ';' or CR may
# come, and inside an extension HTAB is the only control byte that belongs.
# Both of linnea's request decoders are asserted against the same table
# because they used to disagree: chunked_decode buffers a body that fits in
# in_buf while linnea_spill_chunked takes over above it, and the permissive
# one accepted "4 ", "4g" and "4\0" as a size of four. The same bytes on the
# same listener were 200 under the buffer bound and 400 over it
# (audit-report-22). The valid rows are the control: a rule this strict is
# easy to over-apply, and a decoder that refuses every extension would pass
# the malformed rows alone.
SIZE_LINES = [
    ("plain",          b"4",          b"200"),
    ("extension",      b"4;note=ok",  b"200"),
    ("extension HTAB", b"4;a=\tb",    b"200"),
    ("trailing space", b"4 ",         b"400"),
    ("second letter",  b"4g",         b"400"),
    ("NUL",            b"4\x00",      b"400"),
    ("DEL",            b"4\x7f",      b"400"),
    ("NUL in ext",     b"4;a\x00b",   b"400"),
    ("DEL in ext",     b"4;a\x7fb",   b"400"),
    ("CTL in ext",     b"4;a\x1fb",   b"400"),
    # ...and the accumulator's bound, which is the same rule one level down.
    # 17 digits shift the value one nybble past 64 bits: it wrapped to ZERO,
    # which the decoder reads as the last chunk, so the body ended early and
    # the octets behind it became a pipelined request (see mode_smuggle).
    ("17 hex digits",  b"10000000000000000", b"400"),
    ("16 huge digits", b"1fffffffffffffff",  b"400"),
    # ...and the extension's own grammar, RFC 9112 7.1.1:
    #   chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
    # The rows above ask which BYTES may appear after the digits; these ask what
    # SHAPE they must make (audit-report-23). "4 ;a=b" being valid while "4 " is
    # not is the pair that keeps the rule honest -- BWS is BWS only when a ';'
    # follows it -- and the unterminated quote is the one with teeth: a parser
    # that tracks quotes reads on past the CRLF for the closing one.
    ("quoted value",   b'4;a="q"',           b"200"),
    ("quoted escape",  b'4;a="a\\"b"',       b"200"),
    ("quoted semi",    b'4;a="x;y"',         b"200"),
    ("two extensions", b"4;a;b=c",           b"200"),
    ("BWS before ;",   b"4 ;a=b",            b"200"),
    ("BWS around =",   b"4;a = b",           b"200"),
    ("no extension",   b"4;",                b"400"),
    ("no ext name",    b"4;=bad",            b"400"),
    ("no ext value",   b"4;a=",              b"400"),
    ("unterminated",   b'4;a="unterminated', b"400"),
    ("quote in token", b'4;a=b"c',           b"400"),
    ("byte past quote",b'4;a="q"x',          b"400"),
    ("space in name",  b"4;a b",             b"400"),
    ("non-token byte", b"4;a,b",             b"400"),
    ("dangling escape",b'4;a="x\\',          b"400"),
]


def size_line_case(pad, size):
    """One chunked upload whose LAST size line is `size`, preceded by `pad`
    bytes of valid chunk. Written in a single sendall: a malformed size line
    is refused the moment it is read, and a ragged write still trickling
    behind that refusal draws an RST that discards the response we came to
    read -- which cost five failures in twelve hundred connections before the
    writes were made whole. The junk goes LAST for the same reason, so the
    server cannot answer until every byte we sent is in its hands."""
    lead = b"%x\r\n" % pad + b"P" * pad + b"\r\n" if pad else b""
    s = socket.create_connection(("127.0.0.1", PORT), timeout=20)
    try:
        s.sendall(b"POST /api/echo HTTP/1.1\r\nHost: one.test\r\n"
                  b"Transfer-Encoding: chunked\r\n\r\n"
                  + lead + size + b"\r\nbody\r\n0\r\n\r\n")
        head, _ = read_response(s)
    except (BrokenPipeError, ConnectionResetError, socket.timeout):
        head = None
    finally:
        s.close()
    return head


def mode_sizeline():
    for name, size, want in SIZE_LINES:
        # nothing extra stays inside in_buf (17408 bytes); 40000 is past it,
        # so the same line is read by the capture decoder instead
        for pad, which in ((0, "buffered"), (40000, "captured")):
            head = size_line_case(pad, size)
            if head is None:
                return f"{name} ({which}): no reply, wanted {want.decode()}"
            if head.split(b" ")[1:2] != [want]:
                status = head.split(b"\r\n")[0]
                return f"{name} ({which}): {status!r}, wanted {want.decode()}"
    return "OK"


def mode_smuggle():
    """The wrap above, stated as what it costs: a chunk size that overflows to
    zero ends the body early, and everything after it is parsed as the next
    request on the connection. One request line in, two responses out -- past
    any device in front of us that read the same bytes as one message."""
    body = (b"10000000000000000\r\n\r\n"
            b"GET /index.html HTTP/1.1\r\nHost: one.test\r\n"
            b"X-Smuggled: yes\r\n\r\n")
    buf = b""
    s = socket.create_connection(("127.0.0.1", PORT), timeout=20)
    try:
        s.sendall(b"POST /api/echo HTTP/1.1\r\nHost: one.test\r\n"
                  b"Transfer-Encoding: chunked\r\n\r\n" + body)
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
    except (BrokenPipeError, ConnectionResetError, socket.timeout):
        pass
    finally:
        s.close()
    n = sum(1 for l in buf.split(b"\r\n") if l.startswith(b"HTTP/1.1 "))
    if n != 1:
        return f"{n} responses to one request line: {buf[:120]!r}"
    if not buf.startswith(b"HTTP/1.1 400"):
        status = buf.split(b"\r\n")[0]
        return f"not 400: {status!r}"
    return "OK"


MODES = {"big": mode_big, "twice": mode_twice, "head": mode_head, "bad": mode_bad,
         "abort": mode_abort, "cap": mode_cap, "flood": mode_flood,
         "pipeline": mode_pipeline, "sizeline": mode_sizeline,
         "smuggle": mode_smuggle}

try:
    print(MODES[sys.argv[1]]())
except Exception as exc:                          # a crash is a failure, not a traceback
    print(f"{type(exc).__name__}: {exc}")
