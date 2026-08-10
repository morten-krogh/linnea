#!/usr/bin/env python3
"""A stop must not wait for a WebSocket tunnel.

This test owns its own server, because it stops it — the shared fixture on
47080 is serving the rest of the suite.

A tunnel has no request left to finish, so the fast drain closes it. The case
that matters is the BUSY one: a client sending frames pushes last_activity
forward on every one, so the idle reaper never fires and, before this was
fixed, the worker survived until systemd's TimeoutStopSec and was SIGKILLed.
The quiet case is measured too, to show the drain is what closes it and not
the 2-second idle timeout this fixture configures.

Prints OK, or a description of what took too long.
"""
import base64
import os
import signal
import socket
import subprocess
import sys
import threading
import time

PORT = 47471                 # test/configs/ws-drain.json
CONFIG = "test/configs/ws-drain.json"
LIMIT = 1.5                  # must beat the fixture's 2s idle timeout, so a
                             # pass cannot be the reaper doing the work


def wait_port_free():
    for _ in range(200):
        try:
            socket.create_connection(("127.0.0.1", PORT), timeout=0.2).close()
            time.sleep(0.1)
        except OSError:
            return
    raise SystemExit("port %d never freed" % PORT)


def start():
    wait_port_free()
    p = subprocess.Popen(["./bin/linnea", "--config", CONFIG],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", PORT), timeout=0.3).close()
            return p
        except OSError:
            time.sleep(0.1)
    raise SystemExit("server never came up")


def open_tunnel():
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
    return s


def keep_busy(s, stop):
    """Frames every 250ms — each one resets the tunnel's idle timer."""
    while not stop.is_set():
        try:
            k = os.urandom(4)
            pay = b"get"
            s.sendall(bytes([0x81, 0x80 | len(pay)]) + k
                      + bytes(b ^ k[i % 4] for i, b in enumerate(pay)))
        except OSError:
            return
        stop.wait(0.25)


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def stop_time(p):
    """systemd's default KillMode=control-group waits for every process in the
    cgroup, so the master exiting is not the stop — the workers are."""
    kids = [int(x) for x in subprocess.run(
        ["pgrep", "-P", str(p.pid)], capture_output=True,
        text=True).stdout.split()]
    t0 = time.time()
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        pass
    while time.time() - t0 < 20 and any(alive(k) for k in kids):
        time.sleep(0.02)
    el = time.time() - t0
    for k in kids:
        if alive(k):
            os.kill(k, 9)
    return el, [k for k in kids if alive(k)]


bad = []
for label, busy in (("quiet", False), ("busy", True)):
    p = start()
    s = open_tunnel()
    stop = threading.Event()
    if busy:
        threading.Thread(target=keep_busy, args=(s, stop), daemon=True).start()
    time.sleep(0.4)
    el, left = stop_time(p)
    stop.set()
    s.close()
    if left:
        bad.append("%s tunnel: workers survived SIGTERM" % label)
    elif el > LIMIT:
        bad.append("%s tunnel delayed the stop by %.2fs" % (label, el))
    wait_port_free()

print("OK" if not bad else "; ".join(bad))
sys.exit(1 if bad else 0)
