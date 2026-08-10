#!/usr/bin/env python3
"""A hot upgrade must retire the old generation even when it cannot finish.

A reload (SIGUSR2) re-execs and retires the previous generation with SIGQUIT,
the drain: those workers stop accepting and finish what they hold, which is
the whole point — the new generation already has everything arriving, so the
old one's last requests complete instead of being dropped.

A WebSocket tunnel never finishes. It is not idle, so no timeout reaps it,
and it ends only when a peer closes it, which a reload does not. Without a
deadline on the drain, one open tab pinned an old worker indefinitely and
every reload left another behind. This checks the deadline releases it.

The fixture sets drain_timeout to 3s so the test waits that out rather than
the 30s default — which also checks the config key reaches the timespec, since
a value that were ignored would leave the worker there for the full default
and fail. Prints OK, or what went wrong.
"""
import base64
import os
import signal
import socket
import subprocess
import sys
import threading
import time

PORT = 61473
CONFIG = "test/configs/reload-deadline.json"
DEADLINE = 3.0               # "drain_timeout" in the fixture below
SLACK = 12.0                 # generous: a loaded box, plus the re-exec itself


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def wait_port_free():
    for _ in range(200):
        try:
            socket.create_connection(("127.0.0.1", PORT), timeout=0.2).close()
            time.sleep(0.1)
        except OSError:
            return
    raise SystemExit("port %d never freed" % PORT)


def start():
    # These ports are above the ephemeral range, but a stale fixture can still
    # hold one; retry rather than report that as a result.
    for _ in range(8):
        wait_port_free()
        p = subprocess.Popen(["./bin/linnea", "--config", CONFIG],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        for _ in range(60):
            try:
                socket.create_connection(("127.0.0.1", PORT), timeout=0.3).close()
                return p
            except OSError:
                time.sleep(0.1)
        p.kill()
        p.wait()
        time.sleep(1.0)
    raise SystemExit("server never came up")


def workers(master):
    r = subprocess.run(["pgrep", "-P", str(master)], capture_output=True,
                       text=True)
    return set(int(x) for x in r.stdout.split())


p = start()
old = workers(p.pid)
if not old:
    raise SystemExit("no workers to retire")

s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
k = base64.b64encode(os.urandom(16))
s.sendall(b"GET /ws HTTP/1.1\r\nHost: one.test\r\nUpgrade: websocket\r\n"
          b"Connection: Upgrade\r\nSec-WebSocket-Key: " + k +
          b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
buf = b""
while b"\r\n\r\n" not in buf:
    chunk = s.recv(4096)
    if not chunk:
        raise SystemExit("backend closed during the handshake")
    buf += chunk
if not buf.startswith(b"HTTP/1.1 101"):
    raise SystemExit("no 101: %r" % buf[:60])

stop = threading.Event()


def chat():
    """Keep the tunnel from ever going idle."""
    while not stop.is_set():
        try:
            m = os.urandom(4)
            pay = b"get"
            s.sendall(bytes([0x81, 0x80 | len(pay)]) + m
                      + bytes(c ^ m[i % 4] for i, c in enumerate(pay)))
        except OSError:
            return
        stop.wait(0.25)


threading.Thread(target=chat, daemon=True).start()
time.sleep(0.5)

t0 = time.time()
p.send_signal(signal.SIGUSR2)
retired = None
while time.time() - t0 < DEADLINE + SLACK:
    if not any(alive(x) for x in old):
        retired = time.time() - t0
        break
    time.sleep(0.2)

fresh = workers(p.pid) - old
problems = []
if retired is None:
    problems.append("old workers still alive %.0fs after the reload"
                    % (time.time() - t0))
elif retired < DEADLINE - 1.0:
    # Going early would mean the tunnel was dropped rather than drained, which
    # is the stop's job, not the upgrade's.
    problems.append("old workers went after only %.1fs, before the %.0fs drain "
                    "deadline" % (retired, DEADLINE))
elif retired > DEADLINE + SLACK / 2:
    # Late by a lot means the configured value did not reach the timespec and
    # the built-in default was used instead.
    problems.append("old workers went after %.1fs, far past the configured "
                    "%.0fs — is drain_timeout reaching the timer?"
                    % (retired, DEADLINE))
if not fresh:
    problems.append("no new generation after the reload")

stop.set()
try:
    s.close()
except OSError:
    pass
p.send_signal(signal.SIGTERM)
try:
    p.wait(timeout=10)
except subprocess.TimeoutExpired:
    p.kill()
for x in old | workers(p.pid):
    if alive(x):
        try:
            os.kill(x, 9)
        except OSError:
            pass

print("OK (%.1fs)" % retired if not problems else "; ".join(problems))
sys.exit(1 if problems else 0)
