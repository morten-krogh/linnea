#!/usr/bin/env python3
"""A stop is immediate, whatever is open.

This test owns its own server, because it stops it — the shared fixture on
61080 is serving the rest of the suite.

SIGTERM means the unit is going down, and nothing open outlives that however
politely we treat it, so a worker exits at once rather than draining. What
made the old behaviour worth changing was the WebSocket tunnel: it is never
idle and never finishes on its own, so a busy one was never reaped and the
worker survived to systemd's TimeoutStopSec and was SIGKILLed. Every restart
with a page open took the full ten seconds.

The three cases below are the three things that used to hold a stop up: a
quiet tunnel (held for the idle timeout), a busy tunnel (held for ever), and
a response still streaming (finished first, by design, until it did not need
to be). All three must now be immediate.

Prints OK, or what took too long.
"""
import base64
import os
import signal
import socket
import subprocess
import sys
import threading
import time

PORT = 61471                 # test/configs/ws-drain.json
CONFIG = "test/configs/ws-drain.json"
# NOT ws_*: the fixture routes the /ws prefix to the WebSocket
# backend, and "/ws_big.bin" would match it
BIG = "test/www/drain_big.bin"
BIG_SIZE = 6 << 20
LIMIT = 1.5                  # under the fixture's own 2s idle timeout, so a
                             # pass cannot be the idle reaper doing the work


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
    return s, None


def open_busy_tunnel():
    """Frames every 250ms — each one resets the tunnel's idle timer, which is
    what made this case survive a stop entirely."""
    s, _ = open_tunnel()
    stop = threading.Event()

    def chat():
        while not stop.is_set():
            try:
                k = os.urandom(4)
                pay = b"get"
                s.sendall(bytes([0x81, 0x80 | len(pay)]) + k
                          + bytes(b ^ k[i % 4] for i, b in enumerate(pay)))
            except OSError:
                return
            stop.wait(0.25)

    threading.Thread(target=chat, daemon=True).start()
    return s, stop


def open_download():
    """A response still streaming when the stop lands."""
    s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    s.sendall(b"GET /%s HTTP/1.1\r\nHost: one.test\r\n\r\n"
              % os.path.basename(BIG).encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = s.recv(4096)
        if not chunk:
            raise SystemExit("server closed before the response head")
        head += chunk
    if not head.startswith(b"HTTP/1.1 200"):
        raise SystemExit("no 200 for the download: %r" % head[:60])
    return s, None


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


with open(BIG, "wb") as fh:
    fh.write(os.urandom(BIG_SIZE))

bad = []
try:
    for label, opener in (("quiet tunnel", open_tunnel),
                          ("busy tunnel", open_busy_tunnel),
                          ("streaming response", open_download)):
        p = start()
        try:
            s, chatter = opener()
            time.sleep(0.4)
            el, left = stop_time(p)
        finally:
            # anything thrown above leaves a server holding the port, and the
            # next run would blame a leftover rather than the real failure
            if p.poll() is None:
                p.kill()
                p.wait()
                for k in subprocess.run(["pgrep", "-P", str(p.pid)],
                                        capture_output=True,
                                        text=True).stdout.split():
                    if alive(int(k)):
                        os.kill(int(k), 9)
        if chatter:
            chatter.set()
        s.close()
        if left:
            bad.append("%s: workers survived SIGTERM" % label)
        elif el > LIMIT:
            bad.append("%s delayed the stop by %.2fs" % (label, el))
        wait_port_free()
finally:
    if os.path.exists(BIG):
        os.unlink(BIG)

print("OK" if not bad else "; ".join(bad))
sys.exit(1 if bad else 0)
