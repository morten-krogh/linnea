#!/usr/bin/env python3
"""Canned responses must carry Date, and must say so when they close.

RFC 9110 6.6.1: an origin server with a clock MUST send Date on everything
outside 1xx and 5xx. The canned blobs are assembled ahead of time, so they
shipped without one — 400, 404, 405, 413, 414, 431 and the OPTIONS * 200 — while
every dynamically built response (200/206/301/304/416) had it right. A response
with no Date cannot have its freshness calculated, so a shared cache has to
guess or refuse to store it.

RFC 9112 9.6: a server that will close MUST send the close connection option.
The OPTIONS * blob carried no Connection field while .resp_static closed the
connection regardless — its comment claimed it kept the connection, and the code
disagreed.

usage: canned_response_headers.py <port>
"""
import socket
import sys
import time

port = int(sys.argv[1])
HOST = b"one.test"

WDAY = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def send(raw, budget=2.5):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(budget)
    s.sendall(raw)
    start = time.time()
    out = b""
    closed = None
    try:
        while True:
            d = s.recv(65536)
            if not d:
                closed = time.time() - start
                break
            out += d
    except socket.timeout:
        pass
    s.close()
    head = out.split(b"\r\n\r\n")[0].decode("latin1", "replace")
    if not head:
        return None, {}, closed
    status = int(head.split()[1])
    fields = {}
    for line in head.split("\r\n")[1:]:
        name, _, value = line.partition(":")
        fields[name.strip().lower()] = value.strip()
    return status, fields, closed


CASES = [
    ("404", b"GET /nope-does-not-exist HTTP/1.1\r\nHost: one.test\r\n\r\n", 404),
    ("405", b"DELETE /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n", 405),
    ("400 (no Host)", b"GET /hello.txt HTTP/1.1\r\n\r\n", 400),
    # RFC 9112 3.2 names 414 for this, not 400: 400 tells the client its
    # request was malformed, so it gives up instead of shortening the URL.
    ("414 (over-long target)",
     b"GET /" + b"a" * 4000 + b" HTTP/1.1\r\nHost: one.test\r\n\r\n", 414),
    ("OPTIONS *", b"OPTIONS * HTTP/1.1\r\nHost: one.test\r\n\r\n", 200),
]

fails = 0
for label, raw, want in CASES:
    status, fields, closed = send(raw)
    if status is None:
        print(f"FAIL {label}: no response at all")
        fails += 1
        continue
    if want is not None and status != want:
        print(f"FAIL {label}: status {status}, want {want}")
        fails += 1
        continue

    date = fields.get("date")
    ok_date = bool(date) and date[:3] in WDAY and date.endswith("GMT")
    if not ok_date:
        print(f"FAIL {label} ({status}): Date is {date!r} — 6.6.1 requires one")
        fails += 1
        continue

    # ...and if the response closes, it has to say so
    if closed is not None and fields.get("connection", "").lower() != "close":
        print(f"FAIL {label} ({status}): closed the socket but answered "
              f"Connection: {fields.get('connection')!r}")
        fails += 1
        continue

    print(f"ok   {label} ({status}): Date present"
          + (", and says close" if closed is not None else ", connection kept"))

# a 5xx is exempt from Date (6.6.1), so its absence there is not a failure —
# but the blob path is shared, so check it does not regress into no-response
status, fields, _ = send(b"GET /api/dead HTTP/1.1\r\nHost: one.test\r\n\r\n")
if status in (502, 504, 404):
    print(f"ok   an upstream failure still answers ({status})")
else:
    print(f"FAIL upstream failure gave {status}")
    fails += 1


# --- a field name is a token (RFC 9110 5.1, 5.6.2) -------------------------
# The name loop admitted every printable byte but ':', so the delimiters all
# passed — and such a name is forwarded verbatim when proxying, which is two
# hops disagreeing about where a field name ends.
for bad in ('X(bad)name', 'X"quoted"', 'X,comma', 'X/slash', 'X[bracket]',
            'X@at', 'X\\backslash', 'X=equals', 'X{brace}'):
    status, _, _ = send(f"GET /hello.txt HTTP/1.1\r\nHost: one.test\r\n"
                        f"{bad}: v\r\n\r\n".encode())
    if status == 400:
        print(f"ok   a field name containing {bad[1:]!r} is refused")
    else:
        print(f"FAIL {bad!r} gave {status}, want 400 — it would be forwarded "
              f"verbatim to the backend")
        fails += 1

# ...and every character that IS a token character must still be accepted
ok_name = "X-Weird!#$%&'*+-.^_`|~9"
status, _, _ = send(f"GET /hello.txt HTTP/1.1\r\nHost: one.test\r\n"
                    f"{ok_name}: v\r\n\r\n".encode())
if status == 200:
    print("ok   a name using every token character is accepted")
else:
    print(f"FAIL a legal token name gave {status}, want 200 — the check is too "
          f"strict and would refuse conforming clients")
    fails += 1


# --- 405 for a method we know, 501 for one we do not (RFC 9110 15.6.2) -----
# Both used to be 405 with an Allow header, which tells a client that FROB is a
# real method simply not permitted here.
for method, want in (("POST", 405), ("PUT", 405), ("DELETE", 405),
                     ("OPTIONS", 405), ("TRACE", 405), ("PATCH", 405),
                     ("CONNECT", 405),
                     ("FROB", 501), ("get", 501), ("XYZZY", 501)):
    status, f6, _ = send(f"{method} /hello.txt HTTP/1.1\r\nHost: one.test\r\n"
                         f"\r\n".encode())
    if status != want:
        print(f"FAIL {method} gave {status}, want {want}")
        fails += 1
    elif want == 405 and not f6.get("allow"):
        print(f"FAIL {method} gave 405 without an Allow header (15.5.6)")
        fails += 1
    else:
        print(f"ok   {method} -> {status}")

sys.exit(1 if fails else 0)
