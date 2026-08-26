#!/usr/bin/env python3
"""An absolute-form request is routed AND forwarded by its target's authority.

RFC 9112 3.2.2: "When a proxy receives a request with an absolute-form of
request-target, the proxy MUST ignore the received Host header field (if any)
and instead replace it with the host information of the request-target."

The parser already routed on the target's authority -- that half was right --
but the proxy rewrite copied the client's Host line verbatim, so a request that
selected the front-end vhost and location as one authority reached the backend
claiming another (audit-report-75). A backend serving more than one authority
would answer the wrong one.

On the proxy_h2 leg the same field becomes the sole :authority pseudo-header,
which RFC 9113 8.3.1 requires to be built from the request's control data -- for
absolute-form that is the target, never the Host field.

The origin-form row is the control: there the effective authority IS the Host
value, so the replacement is byte-identical and nothing changes. The query and
no-path rows keep target normalisation coupled to the authority replacement.

usage: h1_absolute_form.py <front port>
"""
import socket
import sys

port = int(sys.argv[1])
AUTH = b"one.test"        # the h1 shard's vhost, as proxy_via.py uses


def exchange(request_line, host):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(3)
    s.sendall(request_line + b" HTTP/1.1\r\nHost: " + host
              + b"\r\nConnection: close\r\n\r\n")
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
    return head.decode("latin1", "replace"), body.decode("latin1", "replace")


def field(text, name):
    for line in text.split("\r\n"):
        n, _, v = line.partition(":")
        if n.strip().lower() == name:
            return v.strip()
    return None


def first_line(text):
    return text.split("\r\n")[0]


fails = 0
cases = [
    (b"GET http://" + AUTH + b"/api/headers", b"other.test",
     "/api/headers", "absolute-form, conflicting Host"),
    (b"GET http://" + AUTH + b"/api/headers?q=1", b"other.test",
     "/api/headers?q=1", "absolute-form with a query"),
    (b"GET http://" + AUTH + b"/api/headers", AUTH,
     "/api/headers", "absolute-form, matching Host"),
    (b"GET /api/headers", AUTH,
     "/api/headers", "origin-form (control)"),
]
for line, host, want_target, label in cases:
    resp, seen = exchange(line, host)
    if not resp.startswith("HTTP/1.1 200"):
        print("FAIL %-34s front said %r" % (label, first_line(resp)))
        fails += 1
        continue
    got_host = field(seen, "host")
    got_line = first_line(seen)
    want_host = AUTH.decode()
    if got_host != want_host or want_target not in got_line:
        print("FAIL %-34s backend saw %r / Host: %s (want %s / %s)"
              % (label, got_line, got_host, want_target, want_host))
        fails += 1
    else:
        print("ok   %-34s %s | Host: %s" % (label, got_line, got_host))

if fails:
    print("%d absolute-form case(s) wrong" % fails)
sys.exit(1 if fails else 0)
