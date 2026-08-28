#!/usr/bin/env python3
"""The proxy rewrite synthesizes a Content-Length only when it owes one.

RFC 9112 6 makes Content-Length the framing of a message. An intermediary that
copied a valid one and then appended a second has manufactured a duplicate
framing field: identical or not, it is ambiguity this hop invented, and a
strict backend answers the pair with 400.

audit-report-128: the "the proxy owes this request a length" state shared a bit
with "the client spoke HTTP/1.0". The version branch sets that bit for every 1.0
request, so EVERY proxied 1.0 request was rewritten as though its chunked body
had just been decoded -- a counted POST reached the backend with its own
Content-Length AND a second copy appended, and a request with no body at all was
given an unsolicited "Content-Length: 0".

The controls are the point, and they are what a blanket fix cannot pass: an
implementation that simply never appends the field satisfies "1.0 sends exactly
one" and then delivers a de-chunked body with NO length, which is a worse bug
than the one being fixed. So both chunked rows demand the synthesized field --
with the right value, and with the Transfer-Encoding gone.

Both chunked paths run, because they set the state in two different places: a
small body is decoded in place in in_buf, a body larger than in_buf (17408) is
captured to a spill file and takes its length from spill_len instead. A fixture
that stays under the buffer size is not coverage of a path that branches on it.

usage: h1_proxy_content_length.py <front port>
"""
import socket
import sys

port = int(sys.argv[1])
AUTH = b"one.test"                 # the h1 shard's vhost, as proxy_via.py uses
BIG = b"z" * 60000                 # > LINNEA_CONN_IN_BUF: the capture path


def chunked(payload):
    out = b"".join(b"%x\r\n%s\r\n" % (len(payload[i:i + 4096]),
                                      payload[i:i + 4096])
                   for i in range(0, len(payload), 4096))
    return out + b"0\r\n\r\n"


def exchange(raw):
    s = socket.create_connection(("127.0.0.1", port), timeout=8)
    s.settimeout(4)
    s.sendall(raw)
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
    # /api/headers echoes the head the BACKEND received as its response body
    return head.decode("latin1", "replace"), body.decode("latin1", "replace")


def values(seen, name):
    return [v.strip() for line in seen.split("\r\n")
            for n, _, v in [line.partition(":")] if n.strip().lower() == name]


# (label, request, expected Content-Length values at the backend)
cases = [
    ("1.0 counted POST",
     b"POST /api/headers HTTP/1.0\r\nHost: " + AUTH + b"\r\n"
     b"Content-Length: 3\r\n\r\nabc", ["3"]),
    ("1.0 GET, no body",
     b"GET /api/headers HTTP/1.0\r\nHost: " + AUTH + b"\r\n\r\n", []),
    ("1.1 counted POST (control)",
     b"POST /api/headers HTTP/1.1\r\nHost: " + AUTH + b"\r\n"
     b"Connection: close\r\nContent-Length: 3\r\n\r\nabc", ["3"]),
    ("1.1 GET, no body (control)",
     b"GET /api/headers HTTP/1.1\r\nHost: " + AUTH + b"\r\n"
     b"Connection: close\r\n\r\n", []),
    # the two that must still GAIN the field -- the pairing this test exists for
    ("1.1 chunked POST, buffered (control)",
     b"POST /api/headers HTTP/1.1\r\nHost: " + AUTH + b"\r\n"
     b"Connection: close\r\nTransfer-Encoding: chunked\r\n\r\n"
     + chunked(b"abc"), ["3"]),
    ("1.1 chunked POST, captured (control)",
     b"POST /api/headers HTTP/1.1\r\nHost: " + AUTH + b"\r\n"
     b"Connection: close\r\nTransfer-Encoding: chunked\r\n\r\n"
     + chunked(BIG), [str(len(BIG))]),
    # 1.0 plus chunked is the crossing case: the two states are now independent,
    # and it is the chunked one that decides the rewrite
    ("1.0 chunked POST",
     b"POST /api/headers HTTP/1.0\r\nHost: " + AUTH + b"\r\n"
     b"Transfer-Encoding: chunked\r\n\r\n" + chunked(b"abc"), ["3"]),
]

fails = 0
for label, raw, want in cases:
    resp, seen = exchange(raw)
    if not resp.startswith("HTTP/1.1 200"):
        print("FAIL %-38s front said %r" % (label, resp.split("\r\n")[0]))
        fails += 1
        continue
    got = values(seen, "content-length")
    te = values(seen, "transfer-encoding")
    if got != want or te:
        print("FAIL %-38s backend saw Content-Length %s, TE %s (want %s, none)"
              % (label, got or "absent", te or "none", want or "absent"))
        fails += 1
    else:
        print("ok   %-38s Content-Length %s" % (label, got or "absent"))

# The length is only half of it: a de-chunked body must still ARRIVE, and arrive
# whole, through both paths. A wrong synthesized length truncates it silently.
for label, payload in (("buffered", b"abc"), ("captured", BIG)):
    resp, body = exchange(b"POST /api/echo HTTP/1.1\r\nHost: " + AUTH + b"\r\n"
                          b"Connection: close\r\nTransfer-Encoding: chunked"
                          b"\r\n\r\n" + chunked(payload))
    if not resp.startswith("HTTP/1.1 200") or body.encode("latin1") != payload:
        print("FAIL %-38s echoed %d of %d bytes (%r)"
              % ("de-chunked body relayed, " + label, len(body), len(payload),
                 resp.split("\r\n")[0]))
        fails += 1
    else:
        print("ok   %-38s %d bytes intact"
              % ("de-chunked body relayed, " + label, len(body)))

if fails:
    print("%d proxy Content-Length case(s) wrong" % fails)
sys.exit(1 if fails else 0)
