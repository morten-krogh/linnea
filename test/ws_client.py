#!/usr/bin/env python3
"""Upgrade-tunnel client for the websocket proxy tests.

Speaks a faithful RFC 6455 client handshake (so the backend can verify
and answer it) but sends arbitrary bytes through the tunnel afterwards:
linnea relays blindly and never parses frames, so real frames would only
obscure what is being tested.

Usage: ws_client.py <mode>; prints "OK" and exits 0 on success, else
prints a diagnostic and exits 1.
"""
import base64
import hashlib
import os
import socket
import sys
import time

HOST, PORT = "127.0.0.1", 47080
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def fail(why):
    print(why)
    sys.exit(1)


def connect():
    sock = socket.create_connection((HOST, PORT), timeout=10)
    sock.settimeout(10)
    return sock


def handshake(sock, path, extra=b""):
    """Send the upgrade request (plus optional early tunnel bytes) and
    read the response head. Returns (head, leftover, expected_accept)."""
    key = base64.b64encode(os.urandom(16))
    sock.sendall(b"GET " + path + b" HTTP/1.1\r\n"
                 b"Host: 127.0.0.1:47080\r\n"
                 b"Connection: keep-alive, Upgrade\r\n"
                 b"Upgrade: websocket\r\n"
                 b"Sec-WebSocket-Key: " + key + b"\r\n"
                 b"Sec-WebSocket-Version: 13\r\n\r\n" + extra)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            fail("connection closed while reading the response head")
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    accept = base64.b64encode(hashlib.sha1(key + WS_GUID).digest())
    return head, rest, accept


def expect_101(head, accept):
    if not head.startswith(b"HTTP/1.1 101"):
        fail("expected a 101, got: %r" % head.split(b"\r\n")[0])
    lower = head.lower() + b"\r\n"     # the terminator was stripped
    if b"\r\nconnection: upgrade\r\n" not in lower:
        fail("101 head lacks Connection: upgrade: %r" % head)
    if b"sec-websocket-accept: " + accept.lower() not in lower:
        fail("101 head lacks the right Sec-WebSocket-Accept: %r" % head)


def recv_until(sock, buf, want):
    """Accumulate into buf until want is present."""
    while want not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            fail("connection closed waiting for %r (had %r)" % (want, buf))
        buf += chunk
    return buf


def recv_to_eof(sock, buf):
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            return buf
        buf += chunk


def mode_echo():
    sock = connect()
    head, rest, accept = handshake(sock, b"/api/ws-echo")
    expect_101(head, accept)
    buf = rest
    for n in (1, 2, 3):        # several round trips: both chains re-arm
        msg = b"ping-%d" % n
        sock.sendall(msg)
        buf = recv_until(sock, buf, msg)
    print("OK")


def mode_pipelined():
    # tunnel bytes sent in the same write as the handshake, before the
    # 101 exists: they are buffered behind the head and must not be lost
    sock = connect()
    head, rest, accept = handshake(sock, b"/api/ws-echo", extra=b"early-bird")
    expect_101(head, accept)
    recv_until(sock, rest, b"early-bird")
    print("OK")


def mode_push():
    # server-initiated bytes, the first riding in the same segment as
    # the 101 head; the backend then hangs up, which must reach us as EOF
    sock = connect()
    head, rest, accept = handshake(sock, b"/api/ws-push")
    expect_101(head, accept)
    buf = recv_to_eof(sock, rest)
    if buf != b"push-onepush-two":
        fail("pushed bytes wrong: %r" % buf)
    print("OK")


def mode_tick():
    # one-way traffic at 1s intervals with a 2s idle timeout: activity on
    # the upstream side must keep the silent client side alive
    sock = connect()
    start = time.monotonic()
    head, rest, accept = handshake(sock, b"/api/ws-tick")
    expect_101(head, accept)
    buf = recv_to_eof(sock, rest)
    elapsed = time.monotonic() - start
    for n in (1, 2, 3, 4):
        if b"tick-%d" % n not in buf:
            fail("missing tick-%d after %.1fs: %r" % (n, elapsed, buf))
    if elapsed < 3.0:
        fail("ticks ended after only %.1fs" % elapsed)
    print("OK")


def mode_silent():
    # nothing in either direction: linnea should close the tunnel once
    # the idle timeout (2s in the test config) has passed, not before
    sock = connect()
    head, rest, accept = handshake(sock, b"/api/ws-silent")
    expect_101(head, accept)
    if rest:
        fail("unexpected tunnel bytes: %r" % rest)
    start = time.monotonic()
    chunk = sock.recv(65536)
    elapsed = time.monotonic() - start
    if chunk:
        fail("expected EOF, got %r" % chunk)
    if not 1.0 <= elapsed <= 5.0:
        fail("tunnel closed after %.1fs, expected ~2s" % elapsed)
    print("OK")


def mode_reject():
    # the backend answers the upgrade with an ordinary 403: it must come
    # through as a normal proxied response
    sock = connect()
    head, rest, accept = handshake(sock, b"/api/ws-reject")
    if not head.startswith(b"HTTP/1.1 403"):
        fail("expected a 403, got: %r" % head.split(b"\r\n")[0])
    while len(rest) < 10:
        chunk = sock.recv(65536)
        if not chunk:
            break
        rest += chunk
    if rest != b"no upgrade":
        fail("403 body wrong: %r" % rest)
    print("OK")


MODES = {"echo": mode_echo, "pipelined": mode_pipelined, "push": mode_push,
         "tick": mode_tick, "silent": mode_silent, "reject": mode_reject}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in MODES:
        fail("usage: ws_client.py <%s>" % "|".join(sorted(MODES)))
    try:
        MODES[sys.argv[1]]()
    except socket.timeout:
        fail("socket timeout")
