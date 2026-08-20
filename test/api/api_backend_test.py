#!/usr/bin/env python3
"""The /api backend, spoken to directly on loopback.

linnea-api had no tests at all until this — it is the one production component
that shipped without any, which is how the faults below survived a read of it:
a Content-Length that is not a number taken as zero, a filename escaped but not
bounded, an unchecked getrandom, and a peer that says nothing stopping the whole
server for ever, since it served one connection at a time and blocked with no
deadline.

It forks per connection since 2026-08-15, so the last of those is bounded by
concurrency rather than only by the deadline — which is why the deadline now
has a check of its own. A fix that makes an older check pass for a NEW reason
leaves that check testing nothing; see the bottom of this file.

Usage: api_backend_test.py <port>
"""
import hashlib
import json
import socket
import sys
import time

PORT = int(sys.argv[1])
IO_TIMEOUT_SEC = 10        # must match linnea_api.asm
bad = []


def want(label, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + label + (("  " + detail) if detail else ""))
    if not ok:
        bad.append(label)


def read_one(s):
    """One complete response: the head, then exactly Content-Length bytes.

    Reading to EOF instead is what a one-shot client does, and it worked while
    this server closed after every response. It keeps connections for GET now,
    so reading to EOF waits out the ten-second read deadline on EVERY request --
    which did not fail loudly, it just made the suite twenty times slower and
    broke the two checks that measure how long something takes. A test that
    reads until the peer goes away is measuring the peer's timeout, not the
    response."""
    d = b""
    try:
        while b"\r\n\r\n" not in d:
            c = s.recv(4096)
            if not c:
                return b"", b""
            d += c
        head, _, body = d.partition(b"\r\n\r\n")
        n = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                n = int(line.split(b":", 1)[1])
        while len(body) < n:
            c = s.recv(4096)
            if not c:
                break
            body += c
        return head, body[:n]
    except socket.timeout:
        return b"", b""


def req(raw, timeout=20):
    s = socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
    s.sendall(raw)
    head, body = read_one(s)
    s.close()
    if not head:
        return b"", b""
    return head.split(b"\r\n")[0], body


def post(cl, body=b"hello", extra=b""):
    return req(b"POST /api/upload HTTP/1.1\r\nHost: x\r\nContent-Length: " + cl
               + b"\r\n" + extra + b"\r\n" + body)


# --- still does its job ------------------------------------------------
st, body = post(b"5", b"hello")
want("an ordinary upload is answered", st == b"HTTP/1.1 200 OK", st.decode())
want("...with the right checksum",
     json.loads(body).get("checksum") == hashlib.sha256(b"hello").hexdigest(),
     body[:80].decode(errors="replace"))
st, body = req(b"GET /api/random HTTP/1.1\r\nHost: x\r\n\r\n")
want("random still answers", st == b"HTTP/1.1 200 OK"
     and 1 <= json.loads(body).get("value", 0) <= 1000, body[:40].decode())

# --- a malformed Content-Length is refused, not read as zero -----------
for cl in (b"abc", b"-5", b"0x10", b"5x"):
    st, body = post(cl)
    want(f"Content-Length {cl.decode()!r} is a 400", st == b"HTTP/1.1 400 Bad Request",
         st.decode())
st, body = post(b"")
want("an empty Content-Length is a 400", st == b"HTTP/1.1 400 Bad Request", st.decode())
# ...while the ones that ARE numbers keep their old answers
st, _ = post(b"0", b"")
want("a genuine zero-length upload still succeeds", st == b"HTTP/1.1 200 OK", st.decode())
st, _ = post(b"99999999999999999999999999")
want("an unrepresentable length is still 413",
     st == b"HTTP/1.1 413 Content Too Large", st.decode())
st, _ = req(b"POST /api/upload HTTP/1.1\r\nHost: x\r\n\r\n")
want("an absent Content-Length is still 411",
     st == b"HTTP/1.1 411 Length Required", st.decode())

# --- the name is still escaped, and now bounded ------------------------
st, body = post(b"2", b"hi", extra=b'X-Filename: a%22b%5Cc\r\n')
want("a quote in the filename is escaped", json.loads(body).get("name") == 'a"b\\c',
     body[:60].decode(errors="replace"))
st, body = post(b"2", b"hi", extra=b"X-Filename: " + b"%22" * 300 + b"\r\n")
ok = st == b"HTTP/1.1 200 OK"
try:
    json.loads(body)
except Exception as e:
    ok = False
    print("   json: %s" % e)
want("a filename of 300 quotes does not corrupt the answer", ok,
     "%s %d bytes" % (st.decode(), len(body)))

# --- one silent peer costs only its own child --------------------------
# The server forks per connection now, so a silent peer holds one child and
# nothing else. Everything behind it is answered at once rather than after
# IO_TIMEOUT_SEC.
stuck = socket.create_connection(("127.0.0.1", PORT), timeout=60)
t0 = time.time()
try:
    st, _ = req(b"GET /api/random HTTP/1.1\r\nHost: x\r\n\r\n", timeout=25)
    dt = time.time() - t0
    want("a silent peer does not delay anyone behind it",
         st == b"HTTP/1.1 200 OK" and dt < 2, "%s after %.1fs" % (st.decode(), dt))
except socket.timeout:
    want("a silent peer does not delay anyone behind it", False,
         "still wedged after %.0fs" % (time.time() - t0))

# ...and the DEADLINE still has to arm, which the check above can no longer
# tell you. It passes in 0.0s whether or not IO_TIMEOUT_SEC exists, because
# concurrency alone answers the second request — the check stopped testing the
# thing it was written for the moment the server stopped being serial. What the
# deadline bounds now is how long a silent peer's own child lives, and without
# it those children accumulate against MAX_CHILDREN until the ceiling becomes
# the outage the deadline was there to prevent. So assert it where it is still
# observable: on the silent connection itself.
stuck.settimeout(IO_TIMEOUT_SEC * 3)
t0 = time.time()
got = b""
try:
    while True:
        c = stuck.recv(4096)
        if not c:
            break
        got += c
    ended = True
except socket.timeout:
    ended = False
except OSError:
    ended = True
dt = time.time() - t0
want("a silent peer's own connection ends at the deadline",
     ended and dt >= IO_TIMEOUT_SEC * 0.5,
     "ended=%s after %.1fs (deadline %ds)" % (ended, dt, IO_TIMEOUT_SEC))

# And it must be given NOTHING. read_head signalled failure with `mov eax, -1`,
# which is positive in rax, so the caller's `js` never fired and a head that
# never arrived was parsed anyway — out of a headbuf still holding the PREVIOUS
# request's head. A bare TCP connection that sent not one byte was answered
# `HTTP/1.1 200 OK {"value":829}`: the last caller's route, re-run on its
# behalf. Forking hides this (a child's .bss is a fresh zero page, so the
# fall-through reaches 400 instead of a stale route), which is exactly why the
# assertion is that NOTHING comes back rather than that a 400 does.
want("a silent peer is served nothing at all", got == b"",
     "got %r" % got[:60] if got else "no response, connection closed")
stuck.close()

# --- keep-alive ---------------------------------------------------------
# The proxy in front of this asks for a connection it can reuse, and answering
# "close" to everything is how enabling proxy_keepalive on /api came to change
# nothing at all. Reuse is invisible in any single response, so the check is
# that SEVERAL requests are answered over ONE socket.
ka = socket.create_connection(("127.0.0.1", PORT), timeout=20)
answered = 0
said_keep = 0
for _ in range(5):
    ka.sendall(b"GET /api/random HTTP/1.1\r\nHost: x\r\n\r\n")
    head, body = read_one(ka)
    if not head:
        break
    answered += 1
    if b"keep-alive" in head.lower():
        said_keep += 1
    if not body.startswith(b'{"value":'):
        break
ka.close()
want("five GETs are answered over one connection",
     answered == 5 and said_keep == 5,
     "%d answered, %d said keep-alive" % (answered, said_keep))

# ...and a client that says close gets a closed connection, not a promise
c = socket.create_connection(("127.0.0.1", PORT), timeout=20)
c.sendall(b"GET /api/random HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
head, _ = read_one(c)
tail = c.recv(64)
c.close()
want("Connection: close is honoured, and said back",
     b"close" in head.lower().split(b"connection:")[1].split(b"\r\n")[0] and tail == b"",
     "head says close and the peer closed" if tail == b"" else "peer did not close")

# Pipelining follows from keeping the connection: the bytes after one head are
# the next request, and read_head used to discard them.
pl = socket.create_connection(("127.0.0.1", PORT), timeout=20)
one = b"GET /api/random HTTP/1.1\r\nHost: x\r\n\r\n"
pl.sendall(one + one)
h1, b1 = read_one(pl)
h2, b2 = read_one(pl)
pl.close()
want("two pipelined GETs are both answered",
     b1.startswith(b'{"value":') and b2.startswith(b'{"value":'),
     "both answered" if b2 else "the second was lost")

# An upload ends the connection whatever it asks for: the body it consumes is
# its own business, so the loop does not try to find where the next request
# starts.
up = socket.create_connection(("127.0.0.1", PORT), timeout=20)
up.sendall(b"POST /api/upload HTTP/1.1\r\nHost: x\r\nX-Filename: t.txt\r\n"
           b"Content-Length: 5\r\n\r\nhello")
head, _ = read_one(up)
tail = up.recv(64)
up.close()
want("an upload closes the connection", head.startswith(b"HTTP/1.1 200") and tail == b"",
     "closed after 200" if tail == b"" else "still open")

print()
print("all ok" if not bad else "%d FAILED: %s" % (len(bad), ", ".join(bad)))
sys.exit(0 if not bad else 1)
