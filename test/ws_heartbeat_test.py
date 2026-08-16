#!/usr/bin/env python3
"""linnea-ws pings its clients, and drops the ones that stop answering.

An idle socket and a vanished one look identical on the wire, so silence
cannot tell them apart -- which is why reaping a tunnel on silence drops
healthy connections and why RFC 6455 5.5.2 provides Ping/Pong instead.

Both halves matter and each is the other's control:

  * a client that ANSWERS survives past the point a silence-based timer would
    have closed it -- if only this half passed, a server that never reaped
    anything would look correct;
  * a client that IGNORES the ping is dropped soon after the grace period --
    if only this half passed, a server that dropped everyone would look
    correct.

usage: ws_heartbeat_test.py <port>
"""
import base64
import os
import socket
import sys
import time

PORT = int(sys.argv[1])
# The backend's intervals, because there is more than one backend now:
# bin/linnea-ws ships 30/15 and bin/linnea-ws-fast is the same source built at
# 3/1.5 so the fast suite can prove the mechanism without waiting 45 s for it.
PING_EVERY = float(sys.argv[2]) if len(sys.argv) > 2 else 30.0
PONG_WITHIN = float(sys.argv[3]) if len(sys.argv) > 3 else 15.0
# The slack has to scale with them or it becomes the whole cost: 12 s of margin
# on top of 4.5 s of intervals is a check that is 3/4 waiting for nothing. The
# ratios below are the original 12 and 20 against the shipped 45, so the
# default run behaves exactly as it did.
SLACK = max(4.0, (PING_EVERY + PONG_WITHIN) * 12.0 / 45.0)
SOCK_SLACK = max(8.0, (PING_EVERY + PONG_WITHIN) * 20.0 / 45.0)
# The window a silent client must be dropped INSIDE is an assertion, not slack,
# so it is scaled separately and lands on the original 8 s at the shipped
# intervals rather than inheriting SLACK's 12 and quietly widening.
DROP_SLACK = max(2.0, (PING_EVERY + PONG_WITHIN) * 8.0 / 45.0)
bad = []


def connect():
    s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    s.settimeout(PING_EVERY + PONG_WITHIN + SOCK_SLACK)
    k = base64.b64encode(os.urandom(16)).decode()
    s.sendall(("GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
               "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
               "Sec-WebSocket-Version: 13\r\n\r\n" % k).encode())
    h = b""
    while b"\r\n\r\n" not in h:
        d = s.recv(1)
        if not d:
            raise RuntimeError("handshake closed")
        h += d
    return s


def run(answer):
    """Hold a socket until it is closed or the window ends. Returns the
    seconds until close (None if it stayed up) and the pings seen."""
    s = connect()
    t0 = time.time()
    pings = 0
    deadline = t0 + PING_EVERY + PONG_WITHIN + SLACK
    try:
        while time.time() < deadline:
            b = s.recv(512)
            if not b:
                return time.time() - t0, pings
            if b[0] & 0x0f == 0x9:
                pings += 1
                if answer:
                    s.sendall(b"\x8a\x80\x00\x00\x00\x00")   # masked empty Pong
    except socket.timeout:
        pass
    finally:
        s.close()
    return None, pings


closed, pings = run(answer=True)
if pings < 1:
    bad.append("a client that answers saw no ping in %.1fs" % (PING_EVERY + SLACK))
if closed is not None:
    bad.append("a client that answers was dropped after %.0fs" % closed)

closed, pings = run(answer=False)
if pings < 1:
    bad.append("a silent client saw no ping at all")
if closed is None:
    bad.append("a silent client was never dropped")
elif not (PING_EVERY <= closed <= PING_EVERY + PONG_WITHIN + DROP_SLACK):
    bad.append("a silent client was dropped at %.1fs, outside %.1f-%.1fs"
               % (closed, PING_EVERY, PING_EVERY + PONG_WITHIN + DROP_SLACK))

print("OK" if not bad else "; ".join(bad))
sys.exit(0 if not bad else 1)
