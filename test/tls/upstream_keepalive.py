#!/usr/bin/env python3
"""Upstream keep-alive on h1, h2 and h3: reuse, and the vetoes.

Reuse is INVISIBLE from the client -- same status, same body, same headers
whether the proxy opened a connection or reused one. So every check here reads
the BACKEND's accept counter, which is the only direct evidence. A suite
watching status codes would pass with the feature switched off.

Asking the counter costs a connection: the probe goes straight to the backend
and is counted like any other, so every delta came out one too high until the
probes were subtracted back. The instrument was in the reading.

The vetoes matter more than the reuse. "Connection: close" upstream is what
makes a close-delimited response terminate, and it also hid a response length we
got wrong -- the close ended the message whatever we believed. A pooled
connection hides nothing: the next request would read the remainder of this one
as its own head.

usage: upstream_keepalive.py <port> <cafile> <backend-port> <rude-port> [curl-h3]
"""
import socket
import subprocess
import sys

port, ca, bport, rport = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
curl_h3 = sys.argv[5] if len(sys.argv) > 5 else None
RESOLVE = f"localhost:{port}:127.0.0.1"
protos = ["http1.1", "http2"] + (["h3"] if curl_h3 else [])
fails = 0
_probes = 0


def get(proto, path, method="GET"):
    cmd = ([curl_h3, "--http3-only"] if proto == "h3" else ["curl", f"--{proto}"])
    cmd += ["-s", "--max-time", "12", "--cacert", ca, "--resolve", RESOLVE]
    if method == "HEAD":
        cmd += ["-I"]
    elif method != "GET":
        cmd += ["-X", method, "-d", "x"]
    cmd.append(f"https://localhost:{port}{path}")
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def conns():
    """Accepted connections at the backend, minus the ones these probes made.
    Asked over plain HTTP straight to the backend so the question does not
    travel through the proxy and perturb what it is measuring."""
    global _probes
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(("127.0.0.1", bport))
    s.sendall(b"GET /__stats HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    d = b""
    while True:
        c = s.recv(65536)
        if not c:
            break
        d += c
    s.close()
    _probes += 1
    body = d.partition(b"\r\n\r\n")[2]
    return int(body.split(b" ")[0].split(b"=")[1]) - _probes


def check(label, ok):
    global fails
    print(f"{'ok  ' if ok else 'FAIL'} {label}")
    if not ok:
        fails += 1


for p in protos:
    get(p, "/ka/warm")                       # the first one must connect
    before = conns()
    bodies = [get(p, "/ka/x") for _ in range(10)]
    opened = conns() - before
    check(f"{p}: 10 GETs over a keep-alive location open no connection ({opened})",
          opened == 0)
    check(f"{p}: ...and every one is answered correctly",
          bodies == ["A"] * 10)

    before = conns()
    [get(p, "/noka/x") for _ in range(5)]
    check(f"{p}: a location without proxy_keepalive opens one per request",
          conns() - before == 5)

    # A pooled socket can lose a race with the backend's idle timeout, and the
    # only sound answer is to send the request again -- which a POST may not be.
    before = conns()
    get(p, "/ka/x", "POST")
    check(f"{p}: a POST is not sent over a pooled connection",
          conns() - before == 1)

    # HEAD has no body; the next request must not read one that is not there
    ok = True
    for _ in range(5):
        ok = ok and get(p, "/ka/x", "HEAD").startswith("HTTP/")
        ok = ok and get(p, "/ka/x") == "A"
    check(f"{p}: HEAD then GET on the same pooled connection stay in step", ok)

    # The stamp on a parked connection says when WE parked it, never what the
    # peer did afterwards: a liveness peek is what stands between a dead socket
    # and a request sent into it.
    good = sum(1 for _ in range(10) if get(p, "/r/x") == "R")
    check(f"{p}: a backend that closes a kept connection silently is survived "
          f"({good}/10)", good == 10)

print("OK" if not fails else f"{fails} failed")
sys.exit(1 if fails else 0)
