#!/usr/bin/env python3
"""The /api backend, spoken to directly on loopback.

linnea-api had no tests at all until this — it is the one production component
that shipped without any, which is how the faults below survived a read of it:
a Content-Length that is not a number taken as zero, a filename escaped but not
bounded, an unchecked getrandom, and a peer that says nothing stopping the whole
server for ever, since it serves one connection at a time and blocked with no
deadline.

Usage: api_backend_test.py <port>
"""
import hashlib
import json
import socket
import sys
import time

PORT = int(sys.argv[1])
bad = []


def want(label, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + label + (("  " + detail) if detail else ""))
    if not ok:
        bad.append(label)


def req(raw, timeout=20):
    s = socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
    s.sendall(raw)
    d = b""
    try:
        while True:
            c = s.recv(4096)
            if not c:
                break
            d += c
    except socket.timeout:
        pass
    s.close()
    if not d:
        return b"", b""
    head, _, body = d.partition(b"\r\n\r\n")
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

# --- one silent peer no longer wedges the server for ever --------------
# It still costs everyone behind it IO_TIMEOUT_SEC, which is the point of the
# deadline rather than a shortcoming of it: the server is deliberately serial,
# so the fix bounds the damage instead of removing it. What must not happen is
# what happened before, which is that the wait never ended.
stuck = socket.create_connection(("127.0.0.1", PORT), timeout=30)
t0 = time.time()
try:
    st, _ = req(b"GET /api/random HTTP/1.1\r\nHost: x\r\n\r\n", timeout=25)
    dt = time.time() - t0
    want("a silent peer no longer wedges the server for ever",
         st == b"HTTP/1.1 200 OK" and dt < 20, "%s after %.0fs" % (st.decode(), dt))
except socket.timeout:
    want("a silent peer no longer wedges the server for ever", False,
         "still wedged after %.0fs" % (time.time() - t0))
stuck.close()

print()
print("all ok" if not bad else "%d FAILED: %s" % (len(bad), ", ".join(bad)))
sys.exit(0 if not bad else 1)
