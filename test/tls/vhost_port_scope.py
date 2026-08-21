#!/usr/bin/env python3
"""Two TLS servers sharing a hostname on different ports must not be confused.

A vhost is (listener, hostname), never hostname alone. HTTP/1 has always scoped
its scan to the servers sharing the connection's listening socket; HTTP/2
matched the hostname across EVERY server, so it returned the first one and a
request to the second port was served from the first server's locations, root
and certificate:

    port A, h1 -> SERVER-A      port B, h1 -> SERVER-B
    port A, h2 -> SERVER-A      port B, h2 -> SERVER-A   <-- wrong

Not an exotic shape: 443 and 8443 under one name is ordinary, and the two blocks
would silently share one document root over h2 while behaving correctly over h1.

HTTP/3 cannot reach this case and is not driven here: it serves ONE port -- the
first eligible TLS server's -- and its vhost table is built per port, so a
second port has no h3 vhost to confuse. The server says so once at startup.

usage: vhost_port_scope.py <port-a> <port-b> <cafile>
"""
import subprocess
import sys

pa, pb, ca = sys.argv[1], sys.argv[2], sys.argv[3]
fails = 0


def who(proto, port):
    cmd = ["curl", f"--{proto}", "-s", "--max-time", "10", "--cacert", ca,
           "--resolve", f"localhost:{port}:127.0.0.1",
           f"https://localhost:{port}/who.txt"]
    return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()


def check(label, got, want):
    global fails
    ok = got == want
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok else f"  want {want!r} got {got!r}"))
    if not ok:
        fails += 1


for proto in ("http1.1", "http2"):
    check(f"{proto}: the first port is served by its own server",
          who(proto, pa), "SERVER-A")
    check(f"{proto}: the second port is served by ITS own server",
          who(proto, pb), "SERVER-B")

print("OK" if not fails else f"{fails} failed")
sys.exit(1 if fails else 0)
