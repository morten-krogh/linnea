#!/usr/bin/env python3
# Two limits that stop one host from holding the server open.
#
# 1. A request head must finish within head_timeout, however slowly it is fed.
#    The idle timeout cannot do this on its own: it is armed per operation and
#    every byte rearms it, so a client that sends one byte per timeout period
#    keeps its slot indefinitely for almost no traffic — the classic slowloris.
#
# 2. One source address may hold at most max_per_ip connections at once. Without
#    it a single host takes the whole pool with well-formed traffic, no trickery
#    needed, and everyone else is refused.
#
# Run against test/configs/limits.json (head_timeout 3, max_per_ip 8, idle
# timeout 30 — deliberately long, so what closes a trickling connection can only
# be the head deadline).
# Usage: limits_test.py <port>
import socket
import sys
import time

port = int(sys.argv[1])
HOST = "127.0.0.1"
HEAD_TIMEOUT = 3
MAX_PER_IP = 8


def get(sock, path="/hello.txt"):
    sock.sendall(b"GET %s HTTP/1.1\r\nHost: limits.test\r\n\r\n" % path.encode())
    return sock.recv(200)


# --- a normal request still works ---
s = socket.create_connection((HOST, port), timeout=5)
s.settimeout(5)
assert b"200" in get(s), "a plain request should be served"
s.close()

# --- slowloris: a head fed one line at a time is cut off at the deadline ---
s = socket.create_connection((HOST, port), timeout=5)
s.settimeout(HEAD_TIMEOUT * 6)
s.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: limits.test\r\n")
t0 = time.time()
held = None
try:
    for i in range(20):
        time.sleep(HEAD_TIMEOUT / 3)
        s.sendall(b"X-Pad-%d: y\r\n" % i)      # never completes the head
except (BrokenPipeError, ConnectionResetError, socket.timeout):
    held = time.time() - t0
else:
    held = time.time() - t0
    raise AssertionError(
        f"a trickling request head held its slot for {held:.1f}s (deadline is "
        f"{HEAD_TIMEOUT}s): the idle timeout rearms on every byte, so only a "
        f"deadline on the head itself can bound this")
s.close()
# closed after the deadline, and not so early that a slow but real client suffers
assert held >= HEAD_TIMEOUT * 0.5, f"closed after only {held:.1f}s"
assert held < HEAD_TIMEOUT * 5, f"took {held:.1f}s to close"

# --- per-address cap: the same host is held to max_per_ip live connections ---
kept = []
served = 0
for _ in range(MAX_PER_IP + 4):
    try:
        c = socket.create_connection((HOST, port), timeout=3)
        c.settimeout(3)
        if b"200" in get(c):
            served += 1
        kept.append(c)
    except (ConnectionResetError, ConnectionRefusedError, socket.timeout):
        pass
assert served == MAX_PER_IP, (
    f"{served} connections served from one address, cap is {MAX_PER_IP}")

# --- and a different source address is unaffected by that host's cap ---
other = socket.socket()
other.bind(("127.0.0.2", 0))        # 127.0.0.0/8 is all local: a distinct source
other.settimeout(5)
other.connect((HOST, port))
assert b"200" in get(other), (
    "a different source address was refused: the cap must be per address, not "
    "a global limit")
other.close()
for c in kept:
    c.close()

print(f"ok (slow head cut at {held:.1f}s; {MAX_PER_IP} per address, others unaffected)")
