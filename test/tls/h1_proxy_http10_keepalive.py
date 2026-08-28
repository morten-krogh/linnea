#!/usr/bin/env python3
"""HTTP/1.0 "keep-alive" is a client-to-ORIGIN mechanism, not one a proxy honors.

RFC 9112 9.3 determines persistence from the received message, and the HTTP/1.0
branch of that determination carries a condition the other branches do not: the
connection persists only if "the 'keep-alive' connection option is present,
EITHER THE RECIPIENT IS NOT A PROXY or the message is a response". A request
arriving at a proxy location falls through to "the connection will close after
the current response".

audit-report-129: the Connection token loop turned the 1.0 default (close) back
on for any request carrying the token, and the proxy setup copied that state
downstream unchanged -- so a 1.0 client got "Connection: keep-alive" from a
location where linnea is an intermediary, and the socket was genuinely reused.

The controls are the point, and there are two, because two different blanket
implementations would otherwise pass:

  * static /hello.txt, same request -- there linnea IS the origin server, the
    RFC branch permits the persistence, and it must still be honored. A build
    that simply stopped honoring "keep-alive" for HTTP/1.0 fails here.
  * HTTP/1.1 through the same proxy location -- 1.1 defaults to persistent and
    nothing about being a proxy changes that. A build that stopped keeping
    proxy connections alive at all fails here.

The last case checks what did NOT change: the upstream hop still asks its
backend to close, and the relayed body still arrives whole. The decision this
test moves is the client-facing one only.

usage: h1_proxy_http10_keepalive.py <front port>
"""
import socket
import sys

port = int(sys.argv[1])
AUTH = b"one.test"
PROXY = b"/api/simple"             # relayed, Content-Length: 12 "backend body"
STATIC = b"/hello.txt"             # served by us: 18 bytes


def read_response(s):
    """One complete response, framed by its own Content-Length. Returns
    (head, body) or (None, None) if the peer closed first."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d:
            return None, None
        buf += d
    head, _, body = buf.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    while len(body) < length:
        d = s.recv(65536)
        if not d:
            break
        body += d
    return head.decode("latin1", "replace"), body


def request(path, version, token=None):
    return (b"GET %s HTTP/%s\r\nHost: %s\r\n%s\r\n"
            % (path, version, AUTH,
               b"Connection: " + token + b"\r\n" if token else b""))


def probe(path, version, token=None):
    """Send one request, read its response, then ask the same socket for a
    second one. Persistence is what the socket DOES, not only what it says."""
    s = socket.create_connection(("127.0.0.1", port), timeout=8)
    s.settimeout(4)
    s.sendall(request(path, version, token))
    head, _ = read_response(s)
    if head is None:
        s.close()
        return None, None
    conn = [v.strip().lower() for line in head.split("\r\n")
            for n, _, v in [line.partition(":")] if n.strip().lower()
            == "connection"]
    reused = False
    try:
        s.sendall(request(path, version, b"close"))
        second, _ = read_response(s)
        reused = second is not None and second.startswith("HTTP/1.1 200")
    except OSError:
        reused = False          # the close raced us; the connection was gone
    s.close()
    return (conn or ["(absent)"])[0], reused


# (label, path, version, token, expected Connection value, expected reuse)
cases = [
    ("1.0 keep-alive, proxy", PROXY, b"1.0", b"keep-alive", "close", False),
    ("1.0 keep-alive, static (control)",
     STATIC, b"1.0", b"keep-alive", "keep-alive", True),
    ("1.1, proxy (control)", PROXY, b"1.1", None, "keep-alive", True),
    ("1.0 plain, proxy", PROXY, b"1.0", None, "close", False),
    ("1.0 plain, static", STATIC, b"1.0", None, "close", False),
    ("1.1 close, proxy", PROXY, b"1.1", b"close", "close", False),
    ("1.0 close+keep-alive, proxy",
     PROXY, b"1.0", b"close, keep-alive", "close", False),
]

fails = 0
for label, path, version, token, want_conn, want_reuse in cases:
    conn, reused = probe(path, version, token)
    if conn is None:
        print("FAIL %-34s no response at all" % label)
        fails += 1
    elif conn != want_conn or reused != want_reuse:
        print("FAIL %-34s Connection: %s, reused %s (want %s, %s)"
              % (label, conn, reused, want_conn, want_reuse))
        fails += 1
    else:
        print("ok   %-34s Connection: %-10s reused %s"
              % (label, conn, reused))

# What must NOT have changed: the hop we build for the backend, and the body.
# The downstream decision is the only one this rule touches -- the upstream
# request has always asked for close, and still does.
s = socket.create_connection(("127.0.0.1", port), timeout=8)
s.settimeout(4)
s.sendall(request(b"/api/headers", b"1.0", b"keep-alive"))
head, body = read_response(s)
s.close()
seen = body.decode("latin1", "replace") if body else ""
up = [v.strip().lower() for line in seen.split("\r\n")
      for n, _, v in [line.partition(":")] if n.strip().lower() == "connection"]
if up != ["close"]:
    print("FAIL %-34s backend saw Connection %s (want close)"
          % ("upstream hop unchanged", up or "absent"))
    fails += 1
else:
    print("ok   %-34s backend saw Connection: close" % "upstream hop unchanged")

s = socket.create_connection(("127.0.0.1", port), timeout=8)
s.settimeout(4)
s.sendall(request(PROXY, b"1.0", b"keep-alive"))
head, body = read_response(s)
s.close()
if not head or not head.startswith("HTTP/1.1 200") or body != b"backend body":
    print("FAIL %-34s relayed %r" % ("relayed body intact", body))
    fails += 1
else:
    print("ok   %-34s %r" % ("relayed body intact", body))

sys.exit(1 if fails else 0)
