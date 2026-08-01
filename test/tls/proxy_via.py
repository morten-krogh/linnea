#!/usr/bin/env python3
"""A proxied message must carry a Via entry for this hop (RFC 9110 7.6.3).

    "A proxy MUST send an appropriate Via header field, as described below, in
     each message that it forwards."

Without it a request that crossed this proxy is indistinguishable from one that
reached the backend directly, which is what the field exists to prevent: loop
detection, and knowing which hop to blame for a transformation.

The received-protocol has to name the version the message arrived on, so a
request that reached us over HTTP/1.1 is forwarded with `Via: 1.1 linnea` and one
that reached us over HTTP/2 with `Via: 2 linnea`, while a response — always
HTTP/1.1 from the backend — comes back as `Via: 1.1 linnea` whichever protocol
the client is using.

Via is list-valued, so a client's own Via must survive alongside ours rather
than be replaced (5.3 makes a second field line and a comma-separated append the
same thing).

usage: proxy_via.py <port>
"""
import socket
import sys

port = int(sys.argv[1])
HOST = b"one.test"


def exchange(path, extra=b""):
    """-> (response head as text, backend-visible request head as text)"""
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(3)
    s.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: " + HOST + b"\r\n"
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
    return head.decode("latin1", "replace"), body.decode("latin1", "replace")


def via_entries(text):
    """Every Via value in a head, in order."""
    out = []
    for line in text.split("\r\n")[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "via":
            out.extend(v.strip() for v in value.split(","))
    return out


fails = 0

# --- the request we forward upstream --------------------------------------
resp_head, seen_by_backend = exchange(b"/api/headers")
got = via_entries(seen_by_backend)
if got == ["1.1 linnea"]:
    print("ok   the forwarded request carries Via: 1.1 linnea")
else:
    print(f"FAIL the backend saw Via {got!r}, want ['1.1 linnea'] — a proxied "
          f"request is indistinguishable from a direct one without it")
    fails += 1

# --- ...and the response we hand back -------------------------------------
got = via_entries(resp_head)
if got == ["1.1 linnea"]:
    print("ok   the proxied response carries Via: 1.1 linnea")
else:
    print(f"FAIL the client saw Via {got!r} in the response, want ['1.1 linnea']")
    fails += 1

# --- a client's own Via must survive alongside ours ------------------------
_, seen_by_backend = exchange(b"/api/headers", b"Via: 1.0 edge\r\n")
got = via_entries(seen_by_backend)
if got == ["1.0 edge", "1.1 linnea"]:
    print("ok   a client's own Via is kept and ours appended after it")
elif "1.0 edge" not in got:
    print(f"FAIL the client's own Via was dropped: {got!r} — the chain is the "
          f"whole point of the field")
    fails += 1
else:
    print(f"FAIL Via chain is {got!r}, want ['1.0 edge', '1.1 linnea']")
    fails += 1

# --- a static (non-proxied) response must NOT claim a hop ------------------
resp_head, _ = exchange(b"/hello.txt")
got = via_entries(resp_head)
if not got:
    print("ok   a response we served ourselves carries no Via")
else:
    print(f"FAIL a directly served response claims Via {got!r} — nothing "
          f"forwarded it")
    fails += 1

sys.exit(1 if fails else 0)
