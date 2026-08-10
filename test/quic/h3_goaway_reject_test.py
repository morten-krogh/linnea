#!/usr/bin/env python3
# h3-7: GOAWAY must stop processing what it disowns (RFC 9114 5.2). The drain's
# GOAWAY names the lowest stream id the server will not process — but the server
# then served such a stream anyway, so a client that retried the request on a
# fresh connection (as the GOAWAY tells it to) could see it run twice.
#
# The window only exists on a connection that SURVIVES the drain sweep: an idle
# connection is closed the moment the drain begins, so the test keeps a big
# response in flight — and stalled — by freezing the client's flow-control
# grants. Then, after the GOAWAY arrives, a request on the disowned stream id
# must draw RESET_STREAM(H3_REQUEST_REJECTED 0x10b), not a response. Finally the
# grants are unfrozen and the in-flight response must still complete with a
# clean close — the half the GOAWAY promised TO finish.
# Usage: h3_goaway_reject_test.py <port> <master_pid>
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
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, StreamReset


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
big_path = os.path.join(os.path.dirname(__file__), "..", "www", "h3big.bin")
if not os.path.exists(big_path):
    with open(big_path, "wb") as f:
        f.write(bytes((i * 131) & 0xFF for i in range(600000)))
BIG_SIZE = os.path.getsize(big_path)

cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
# Small initial windows, and (below) no growth: the response stalls at ~64KB of
# 600KB with its tx stream active, which is what keeps the connection alive
# across the drain sweep.
cfg.max_data = 131072
cfg.max_stream_data = 65536
conn = QuicConnection(configuration=cfg)
# Freeze flow control: these two write MAX_DATA / MAX_STREAM_DATA; shadowing
# them on the instance stops every grant beyond the initial windows.
conn._write_connection_limits = lambda builder, space: None
conn._write_stream_limits = lambda builder, space, stream: None
vt = [0.0]


def clk():
    # a virtual clock: aioquic only needs time to advance monotonically
    vt[0] += 0.001
    return vt[0]


conn.connect(("127.0.0.1", port), now=clk())
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setblocking(False)

state = {"got": 0, "fin": False, "closed": None, "ctrl": b"",
         "reset": None, "served4": 0}


def handle(ev):
    if isinstance(ev, StreamDataReceived):
        if ev.stream_id == 0:
            state["got"] += len(ev.data)
            if ev.end_stream:
                state["fin"] = True
        elif ev.stream_id == 3:
            state["ctrl"] += ev.data
        elif ev.stream_id == 4:
            state["served4"] += len(ev.data)
    if isinstance(ev, StreamReset) and ev.stream_id == 4:
        state["reset"] = ev.error_code
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


def rvlq(b, i):
    n = 1 << (b[i] >> 6)
    v = b[i] & 0x3F
    for k in range(1, n):
        v = (v << 8) | b[i + k]
    return v, i + n


def find_goaway(buf):
    # control stream = type byte (0x00) then frames; return the GOAWAY payload's
    # stream id, or None if not (yet) present.
    i = 1
    while i < len(buf):
        try:
            ft, j = rvlq(buf, i)
            fl, k = rvlq(buf, j)
        except IndexError:
            break
        if k + fl > len(buf):
            break
        if ft == 0x07:
            return rvlq(buf, k)[0]
        i = k + fl
    return None


pump(0.05)
deadline = time.time() + 5
while not conn._handshake_confirmed and time.time() < deadline:
    pump(0.05)
assert conn._handshake_confirmed, "handshake not confirmed"

enc = pylsqpack.Encoder()
enc.apply_settings(max_table_capacity=0, blocked_streams=0)


def req(path):
    _, fields = enc.encode(0, [(b":method", b"GET"), (b":path", path),
                               (b":scheme", b"https"), (b":authority", b"localhost")])
    return vlq(1) + vlq(len(fields)) + fields


conn.send_stream_data(0, req(b"/h3big.bin"), end_stream=True)

deadline = time.time() + 5
while state["got"] == 0 and time.time() < deadline:
    pump(0.01)
assert state["got"] > 0, "no response data before the drain"

drain_workers(master)                # the drain lands mid-download, stalled

# the GOAWAY proves this worker is draining; only from then on is a request
# at/above its id one the server has promised not to process
deadline = time.time() + 10
while find_goaway(state["ctrl"]) is None and time.time() < deadline:
    pump(0.05)
goaway_id = find_goaway(state["ctrl"])
assert goaway_id is not None, "no GOAWAY on the control stream after drain"
assert goaway_id == 4, f"GOAWAY stream id={goaway_id} (want 4: stream 0 in flight)"
assert state["closed"] is None, \
    f"connection closed under the stalled response (error_code={state['closed']})"

# the disowned request: stream 4 is exactly the announced boundary
conn.send_stream_data(4, req(b"/hello.txt"), end_stream=True)
deadline = time.time() + 10
while state["reset"] is None and state["served4"] == 0 and time.time() < deadline:
    pump(0.05)
assert state["served4"] == 0, \
    f"disowned stream 4 was served ({state['served4']} bytes) instead of rejected"
assert state["reset"] == 0x10b, \
    f"stream 4 reset code {state['reset']!r} (want H3_REQUEST_REJECTED 0x10b)"

# unfreeze the grants: the in-flight response the GOAWAY promised to finish
# must now complete, and the drain must then say a clean goodbye
del conn._write_connection_limits
del conn._write_stream_limits
deadline = time.time() + 20
while not state["fin"] and state["closed"] is None and time.time() < deadline:
    pump(0.05)
assert state["fin"], (
    f"drain stranded the in-flight response at {state['got']} bytes "
    f"(closed={state['closed']})")
assert state["got"] >= BIG_SIZE, f"short body: {state['got']} < {BIG_SIZE}"
deadline = time.time() + 5
while state["closed"] is None and time.time() < deadline:
    pump(0.05)
assert state["closed"] == 0x100, \
    f"no clean close after the drain (error_code={state['closed']})"
print("ok")
