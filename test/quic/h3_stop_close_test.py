#!/usr/bin/env python3
# A stop must tell h3 peers, not just vanish.
#
# SIGTERM exits the worker at once — nothing open survives a stop, so there is
# nothing to drain. But a QUIC connection that simply stops answering leaves
# its client waiting out an idle timeout with no idea why, and repeated
# unexplained losses are how a browser decides an origin's HTTP/3 is
# unreliable and quietly stops offering it. So the stop sends
# CONNECTION_CLOSE(H3_NO_ERROR) to every connected peer first: one datagram
# each, and the client knows immediately.
#
# The connection here is idle at the moment of the stop, which is the case
# that matters — a browser holding an open tab. Prints OK, or what went wrong.
# Usage: h3_stop_close_test.py <port> <master_pid>
import os
import signal
import socket
import ssl
import sys
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated

port = int(sys.argv[1])
master = int(sys.argv[2])

cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
vt = [0.0]


def clk():
    vt[0] += 0.001
    return vt[0]


conn.connect(("127.0.0.1", port), now=clk())
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setblocking(False)

state = {"closed": None, "reason": None}


def handle(ev):
    if isinstance(ev, ConnectionTerminated):
        state["closed"] = ev.error_code
        state["reason"] = ev.reason_phrase


def pump(dur):
    end = time.time() + dur
    while time.time() < end:
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ("127.0.0.1", port))
        try:
            while True:
                r, _ = s.recvfrom(4096)
                conn.receive_datagram(r, ("127.0.0.1", port), now=clk())
        except (BlockingIOError, socket.error):
            pass
        try:
            conn.handle_timer(now=clk())
        except TypeError:
            pass
        ev = conn.next_event()
        while ev:
            handle(ev)
            ev = conn.next_event()
        time.sleep(0.002)


pump(0.05)
deadline = time.time() + 5
while not conn._handshake_confirmed and time.time() < deadline:
    pump(0.05)
if not conn._handshake_confirmed:
    print("handshake not confirmed")
    sys.exit(1)

# Idle, connected, and the server goes down.
t0 = time.time()
os.kill(master, signal.SIGTERM)
while state["closed"] is None and time.time() - t0 < 8:
    pump(0.05)
elapsed = time.time() - t0

if state["closed"] is None:
    print("no CONNECTION_CLOSE: the peer was left to time out after %.1fs"
          % elapsed)
    sys.exit(1)
# H3_NO_ERROR (RFC 9114), the application-space code — the same orderly
# goodbye the drain sends, not QUIC transport NO_ERROR (0x0).
H3_NO_ERROR = 0x0100
if state["closed"] != H3_NO_ERROR:
    print("closed with 0x%x (%s), expected H3_NO_ERROR 0x100"
          % (state["closed"], state["reason"]))
    sys.exit(1)
print("OK (CONNECTION_CLOSE H3_NO_ERROR in %.2fs)" % elapsed)
