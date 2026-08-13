#!/usr/bin/env python3
# Q117: a worker draining with an in-flight h3 response must finish it, close
# the connection with CONNECTION_CLOSE(H3_NO_ERROR), and only then exit. The
# drain-exit test used to count only TCP connections — a worker whose work was
# all QUIC exited the moment the drain began (and stopped re-arming the
# datagram recv besides), so the peer hung mid-download with nothing on the
# wire to tell it anything had happened.
# Usage: h3_drain_inflight_test.py <port> <master_pid>
import os
import signal
import socket
import subprocess
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived

WWW = os.path.join(os.environ.get("LINNEA_TEST_RUNDIR", "test"), "www")
# the run's own document root: a copy, so a run may generate into it and
# delete from it without colliding with a suite running beside it


def drain_workers(master):
    """Start a drain on the workers of `master`.

    SIGTERM is an immediate stop now — it drops whatever is open — so a test
    about the drain has to send what a hot upgrade sends: SIGQUIT, and to the
    workers, since that is what kill_old_workers signals. The master is then
    SIGTERMed so it cannot respawn them; a worker already draining ignores the
    SIGTERM its PR_SET_PDEATHSIG delivers when the master goes.
    """
    kids = subprocess.run(["pgrep", "-P", str(master)],
                          capture_output=True, text=True).stdout.split()
    for k in kids:
        os.kill(int(k), signal.SIGQUIT)
    os.kill(master, signal.SIGTERM)


port = int(sys.argv[1])
master = int(sys.argv[2])
big_path = os.path.join(WWW, "h3big.bin")
if not os.path.exists(big_path):
    with open(big_path, "wb") as f:
        f.write(bytes((i * 131) & 0xFF for i in range(600000)))
BIG_SIZE = os.path.getsize(big_path)

cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
# A small connection window: the response cannot be fully in flight when the
# drain lands, so finishing it needs the credit and ACKs the client sends
# AFTER the drain began — exactly what a deaf drain never read.
cfg.max_data = 131072
conn = QuicConnection(configuration=cfg)
vt = [0.0]


def clk():
    # a virtual clock: aioquic only needs time to advance monotonically
    vt[0] += 0.001
    return vt[0]


conn.connect(("127.0.0.1", port), now=clk())
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setblocking(False)

state = {"got": 0, "fin": False, "closed": None}


def handle(ev):
    if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
        state["got"] += len(ev.data)
        if ev.end_stream:
            state["fin"] = True
    if isinstance(ev, ConnectionTerminated):
        state["closed"] = ev.error_code


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


def vlq(n):
    return bytes([n]) if n < 64 else (0x4000 | n).to_bytes(2, "big")


pump(0.05)
deadline = time.time() + 20
while not conn._handshake_confirmed and time.time() < deadline:
    pump(0.05)
assert conn._handshake_confirmed, "handshake not confirmed"

enc = pylsqpack.Encoder()
enc.apply_settings(max_table_capacity=0, blocked_streams=0)
_, fields = enc.encode(0, [(b":method", b"GET"), (b":path", b"/h3big.bin"),
                           (b":scheme", b"https"), (b":authority", b"localhost")])
conn.send_stream_data(0, vlq(1) + vlq(len(fields)) + fields, end_stream=True)

deadline = time.time() + 20
while state["got"] == 0 and time.time() < deadline:
    pump(0.01)
assert state["got"] > 0, "no response data before the drain"

drain_workers(master)                # the drain lands mid-download

deadline = time.time() + 80
while not state["fin"] and state["closed"] is None and time.time() < deadline:
    pump(0.05)
assert state["fin"], (
    f"drain stranded the in-flight response at {state['got']} bytes "
    f"(closed={state['closed']})")
# the stream carries HTTP/3 framing too, so only a lower bound is checked
assert state["got"] >= BIG_SIZE, f"short body: {state['got']} < {BIG_SIZE}"

# and the goodbye must arrive: the drain closes the connection the moment
# nothing is left in flight
deadline = time.time() + 20
while state["closed"] is None and time.time() < deadline:
    pump(0.05)
assert state["closed"] == 0x100, \
    f"no clean close after the drain (error_code={state['closed']})"
print("ok")
