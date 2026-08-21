#!/usr/bin/env python3
"""max_upstream must not refuse the idle pool's own inventory.

A parked keep-alive connection is a live backend connection and is correctly
counted against max_upstream. Borrowing it opens no descriptor, so it cannot
exceed the ceiling -- which means the ceiling has to be consulted where a socket
is actually opened, not before the pool is consulted.

HTTP/1 had that ordering from the start. HTTP/2 and HTTP/3 tested the ceiling
first, so at a full count they answered 503 with a reusable descriptor sitting
in the pool (audit-report-39). Worse than a wasted reuse: `take` is the only
thing that reaps an expired pool entry, so an early refusal never reclaimed the
descriptor either. Measured before the fix, max_upstream=1, four GETs to a
keep-alive location on a fresh server:

    h1   200 200 200 200      and 200 after the idle expiry
    h2   200 503 503 503      and STILL 503 after it
    h3   200 503 503 503      and STILL 503 after it

Not a five-second window: on an h2/h3-only site nothing else calls take, so the
location never recovers.

The second half matters as much as the first. A ceiling that stops refusing is
not a fix, so the saturation row asserts a request that CANNOT borrow -- a
different location, no keep-alive, its one slot held by a slow backend -- is
still 503.

usage: upstream_ceiling.py <port> <cafile> <marker-port> [curl-h3]
"""
import socket
import subprocess
import sys
import threading
import time

port, ca, bport = sys.argv[1], sys.argv[2], int(sys.argv[3])
curl_h3 = sys.argv[4] if len(sys.argv) > 4 else None
RESOLVE = f"localhost:{port}:127.0.0.1"
protos = ["http1.1", "http2"] + (["h3"] if curl_h3 else [])
fails = 0
_probes = 0


def code(proto, path):
    cmd = ([curl_h3, "--http3-only"] if proto == "h3" else ["curl", f"--{proto}"])
    cmd += ["-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "20",
            "--cacert", ca, "--resolve", RESOLVE, f"https://localhost:{port}{path}"]
    return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()


def conns():
    """Accepted connections at the marker backend, minus this probe's own."""
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
    return int(d.partition(b"\r\n\r\n")[2].split(b" ")[0].split(b"=")[1]) - _probes


def check(label, ok, got=""):
    global fails
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + (f"  {got}" if not ok else ""))
    if not ok:
        fails += 1


for p in protos:
    # --- the ceiling still refuses when the pool cannot help --------------
    # /slow has no proxy_keepalive, so nothing is poolable; its one slot is
    # held by a backend that sleeps. Run this FIRST: with max_upstream at 1, a
    # connection parked by the rows below would occupy the only slot.
    held = []
    t = threading.Thread(target=lambda: held.append(code(p, "/slow/x")), daemon=True)
    t.start()
    time.sleep(0.6)
    got = code(p, "/slow/x")
    check(f"{p}: a request that cannot borrow is still 503 at the ceiling",
          got == "503", f"got {got}")
    t.join(timeout=25)

    # --- and a request that CAN borrow is served -------------------------
    check(f"{p}: the first keep-alive GET is served", code(p, "/ka/x") == "200")
    before = conns()
    got = [code(p, "/ka/x") for _ in range(3)]
    opened = conns() - before
    check(f"{p}: three more are served at a full ceiling by reusing it",
          got == ["200"] * 3, f"got {got}")
    check(f"{p}: ...opening no further backend connection ({opened})",
          opened == 0)

    # The pool entry expires after 5s. Only `take` reaps it, so an early
    # refusal would never reclaim the descriptor and this would stay 503.
    time.sleep(6)
    got = code(p, "/ka/x")
    check(f"{p}: and the location recovers after the idle expiry", got == "200",
          f"got {got}")

print("OK" if not fails else f"{fails} failed")
sys.exit(1 if fails else 0)
