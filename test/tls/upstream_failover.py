#!/usr/bin/env python3
"""A proxy location with several backends: round-robin, failover, health.

Three questions, and the third is the one that is easy to answer wrongly:

  1. Are requests spread over the backends that are up?
  2. When one is down, is the client served anyway?
  3. Does the server STOP contacting a backend that is down?

(2) hides (3). Failover means the client is served either way, so a suite that
only checks status codes passes whether or not the health state exists at all.
The oracle for (3) is the server's own error log, which names every upstream
connect failure -- so "it stopped trying" is a COUNT that stops growing, not an
absence of complaints from the client.

Two marker backends say which one answered; a third address has nothing behind
it. Failover is attempted only at connect time, so a refused connection is the
whole trigger.

EACH PROTOCOL GETS ITS OWN dead-first location. Health state is per worker and
per location, not per protocol, so a single shared location would be failed out
by whichever protocol ran first and the other two would inherit the answer --
their own failover code would never run, and all three would still print ok.
That is not a hypothetical: driving one shared location is how this was first
written, and h2 and h3 passed without executing a line of the paths they were
meant to cover.

usage: upstream_failover.py <port> <cafile> <logfile> [curl-h3]
"""
import subprocess
import sys
import time

port, ca, logpath = sys.argv[1], sys.argv[2], sys.argv[3]
curl_h3 = sys.argv[4] if len(sys.argv) > 4 else None
RESOLVE = f"localhost:{port}:127.0.0.1"
protos = ["http1.1", "http2"] + (["h3"] if curl_h3 else [])
fails = 0


def get(proto, path):
    cmd = ([curl_h3, "--http3-only"] if proto == "h3" else ["curl", f"--{proto}"])
    cmd += ["-s", "--max-time", "10", "--cacert", ca, "--resolve", RESOLVE,
            f"https://localhost:{port}{path}"]
    return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()


def code(proto, path):
    cmd = ([curl_h3, "--http3-only"] if proto == "h3" else ["curl", f"--{proto}"])
    cmd += ["-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10",
            "--cacert", ca, "--resolve", RESOLVE, f"https://localhost:{port}{path}"]
    return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()


def upstream_failures():
    """How many upstream connect failures the server has logged so far."""
    try:
        with open(logpath, "rb") as f:
            return f.read().count(b"connect failed")
    except FileNotFoundError:
        return 0


def check(label, ok):
    global fails
    if ok:
        print(f"ok   {label}")
    else:
        print(f"FAIL {label}")
        fails += 1


DEADFIRST = {"http1.1": "/dead-h1", "http2": "/dead-h2", "h3": "/dead-h3"}
DEADONLY = {"http1.1": "/only-h1", "http2": "/only-h2", "h3": "/only-h3"}

for p in protos:
    dead, only = DEADFIRST[p], DEADONLY[p]
    # 1. both up: the requests are spread, not all sent to the first
    seen = [get(p, "/both") for _ in range(6)]
    check(f"{p}: requests are spread over both live backends ({''.join(seen)})",
          set(seen) == {"A", "B"})

    # 2. first one dead: the client never learns -- and the dead backend WAS
    # contacted, three times, which is what makes this a test of failover
    # rather than of the location happening to name a live backend first.
    before = upstream_failures()
    served = [get(p, dead) for _ in range(3)]
    tried = upstream_failures() - before
    check(f"{p}: a dead first backend is stepped over ({''.join(served)})",
          served == ["A", "A", "A"])
    check(f"{p}: ...having actually been contacted ({tried} connect failures)",
          tried == 3)

    # 3. ...and it stops being contacted. The three requests above were the
    # three failures that fail it out, so the count must now be frozen: any
    # further attempt would mean the health state is not being consulted.
    before = upstream_failures()
    more = [get(p, dead) for _ in range(4)]
    after = upstream_failures()
    check(f"{p}: a failed-out backend is not contacted again "
          f"(failures {before} -> {after})",
          after == before and more == ["A"] * 4)

    # a location whose only backend is down has nothing to fail over TO
    check(f"{p}: a location with one dead backend is 502",
          code(p, only) == "502")

print("OK" if not fails else f"{fails} failed")
sys.exit(1 if fails else 0)
