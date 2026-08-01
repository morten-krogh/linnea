#!/usr/bin/env python3
"""If-Match and If-Unmodified-Since must be evaluated (RFC 9110 13.1.1, 13.1.4).

Neither field was read at all. A request carrying one was answered as though it
carried no condition, which is exactly the lost update the fields exist to
prevent: a client says "only if this is still the copy I have", the server
ignores the qualifier and acts anyway.

13.2.2 fixes the order. If-Match is evaluated first and, when it fails, the
answer is 412 and nothing further is considered — in particular a request
carrying BOTH a failing If-Match and a matching If-None-Match is a 412, not a
304, and that case is the one that tells the two implementations apart.

A 412 must also carry the current validators (15.5.13), so a client that guessed
wrong can see what the representation actually is without another round trip.

usage: preconditions.py <port>
"""
import socket
import sys

port = int(sys.argv[1])
HOST = b"one.test"
PATH = b"/hello.txt"


def request(extra=b""):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(3)
    s.sendall(b"GET " + PATH + b" HTTP/1.1\r\nHost: " + HOST + b"\r\n"
              + extra + b"Connection: close\r\n\r\n")
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    s.close()
    head, _, body = out.partition(b"\r\n\r\n")
    head = head.decode("latin1", "replace")
    fields = {}
    for line in head.split("\r\n")[1:]:
        name, _, value = line.partition(":")
        fields[name.strip().lower()] = value.strip()
    return int(head.split()[1]), fields, body


status, fields, _ = request()
etag = fields.get("etag")
last_mod = fields.get("last-modified")
if status != 200 or not etag or not last_mod:
    print(f"FAIL baseline: {status}, etag={etag!r}, last-modified={last_mod!r}")
    sys.exit(1)

OTHER = '"0000000000000000"'
PAST = "Wed, 01 Jan 2020 00:00:00 GMT"
FUTURE = "Fri, 01 Jan 2100 00:00:00 GMT"

fails = 0


def case(label, extra, want):
    global fails
    status, fields, body = request(extra.encode())
    if status != want:
        print(f"FAIL {label}: {status}, want {want}")
        fails += 1
        return None
    if want == 412 and body:
        print(f"FAIL {label}: a 412 carried a {len(body)}-byte body")
        fails += 1
        return None
    print(f"ok   {label} -> {status}")
    return fields


# --- If-Match -------------------------------------------------------------
case("If-Match with our etag", f"If-Match: {etag}\r\n", 200)
case("If-Match with *", "If-Match: *\r\n", 200)
fields = case("If-Match with a different etag", f"If-Match: {OTHER}\r\n", 412)
if fields is not None and fields.get("etag") != etag:
    print(f"FAIL the 412 did not carry the current etag ({fields.get('etag')!r}) "
          f"— 15.5.13 wants the client to see what it actually is")
    fails += 1
case("If-Match listing ours among others",
     f"If-Match: {OTHER}, {etag}\r\n", 200)
# a weak tag can never satisfy If-Match: the comparison is strong (13.1.1)
case("If-Match with a weak form of our etag", f"If-Match: W/{etag}\r\n", 412)

# --- If-Unmodified-Since --------------------------------------------------
case("If-Unmodified-Since at the mtime", f"If-Unmodified-Since: {last_mod}\r\n", 200)
case("If-Unmodified-Since in the future", f"If-Unmodified-Since: {FUTURE}\r\n", 200)
case("If-Unmodified-Since before the mtime", f"If-Unmodified-Since: {PAST}\r\n", 412)
case("an unparsable If-Unmodified-Since is ignored",
     "If-Unmodified-Since: not a date\r\n", 200)

# --- precedence (13.2.2) --------------------------------------------------
# If-Match is evaluated first, so a failing one wins over a matching
# If-None-Match that would otherwise have produced a 304.
case("a failing If-Match beats a matching If-None-Match",
     f"If-Match: {OTHER}\r\nIf-None-Match: {etag}\r\n", 412)
# ...and If-Unmodified-Since is not consulted at all when If-Match succeeded
case("a passing If-Match skips If-Unmodified-Since",
     f"If-Match: {etag}\r\nIf-Unmodified-Since: {PAST}\r\n", 200)
# with no If-Match, the date decides
case("If-Unmodified-Since still applies without If-Match",
     f"If-Unmodified-Since: {PAST}\r\nIf-None-Match: {etag}\r\n", 412)

sys.exit(1 if fails else 0)
