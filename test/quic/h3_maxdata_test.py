#!/usr/bin/env python3
# Connection-level flow control credit (MAX_DATA) must be absorbed from every
# packet, including packets that arrive while no response stream is open.
#
# A peer sends each new MAX_DATA value once: the packet carrying it is
# acknowledged, so a value the server fails to read is never repeated. The server
# then believes its send window is smaller than the peer granted, and once it
# reaches that stale limit the connection stalls forever with nothing in flight —
# no timeout fires, no error is reported, the page simply never loads.
#
# The window where this is easy to get wrong is the one a browser reload creates:
# every download is cancelled, so no response stream is open, and the packets that
# follow carry the credit for everything the peer just consumed. This test drives
# exactly that: a small connection window (so credit must be raised repeatedly),
# a large response cancelled as soon as it starts, then a quiet stretch in which the
# peer's ACKs for the tail still in flight — and the MAX_DATA raise riding with them —
# arrive with no response stream open. After several such cycles the same connection
# must still be able to deliver a whole response.
# Usage: h3_maxdata_test.py <port> [cycles]
import os
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

WWW = os.path.join(os.environ.get("LINNEA_TEST_RUNDIR", "test"), "www")
# the run's own document root: a copy, so a run may generate into it and
# delete from it without colliding with a suite running beside it

port = int(sys.argv[1])
CYCLES = int(sys.argv[2]) if len(sys.argv) > 2 else 8
BIG = b"/h3big.bin"
big_path = os.path.join(WWW, "h3big.bin")
if not os.path.exists(big_path):
    with open(big_path, "wb") as f:
        f.write(bytes((i * 131) & 0xFF for i in range(600000)))
BIG_SIZE = os.path.getsize(big_path)

cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
# A small connection window: the client must raise it repeatedly, so a raise the
# server drops is quickly fatal instead of hiding behind a generous initial limit.
cfg.max_data = 262144
conn = QuicConnection(configuration=cfg)
vt = [0.0]


def clk():
    # A virtual clock: the transfer is loopback-fast, and aioquic only needs time
    # to advance monotonically. Keep the step small so the peer's idle timer does
    # not fire during the deliberately quiet stretches below.
    vt[0] += 0.001
    return vt[0]


conn.connect(("127.0.0.1", port), now=clk())
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setblocking(False)


def flush():
    for d, _ in conn.datagrams_to_send(now=clk()):
        s.sendto(d, ("127.0.0.1", port))


def pump(dur, cb=None):
    end = time.time() + dur
    while time.time() < end:
        flush()
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
            if cb:
                cb(ev)
            ev = conn.next_event()
        time.sleep(0.002)


def vlq(n):
    return bytes([n]) if n < 64 else (0x4000 | n).to_bytes(2, "big")


nxt = [0]


def req():
    sid = nxt[0]
    nxt[0] += 4
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, f = enc.encode(0, [(b":method", b"GET"), (b":path", BIG),
                          (b":scheme", b"https"), (b":authority", b"localhost")])
    conn.send_stream_data(sid, vlq(1) + vlq(len(f)) + f, end_stream=True)
    return sid


flush()
while not conn._handshake_confirmed:
    pump(0.05)

state = {"sid": -1, "seen": False, "fin": False}


def note(ev):
    if isinstance(ev, StreamDataReceived) and ev.stream_id == state["sid"]:
        state["seen"] = True
        if ev.end_stream:
            state["fin"] = True


for cycle in range(CYCLES):
    state.update(sid=req(), seen=False, fin=False)
    end = time.time() + 10
    while not state["seen"] and time.time() < end:
        pump(0.005, note)
    assert state["seen"], (
        f"cycle {cycle}: no response data on stream {state['sid']} — the reused "
        f"connection stalled, which is what losing a MAX_DATA raise looks like")
    if not state["fin"]:
        conn.stop_stream(state["sid"], 0x10c)   # reload: cancel it mid-transfer
    # Quiet stretch: the cancelled stream's slot is gone, so the ACKs the peer keeps
    # sending for the tail still in flight — and the MAX_DATA raise riding with them
    # — arrive with no response stream open on the server.
    pump(0.25, note)

# the same connection must still deliver a whole response
final = req()
got = [0]
done = [False]


def collect(ev):
    if isinstance(ev, StreamDataReceived) and ev.stream_id == final:
        got[0] += len(ev.data)
        if ev.end_stream:
            done[0] = True


deadline = time.time() + 20
while not done[0] and time.time() < deadline:
    pump(0.1, collect)

assert done[0], (
    f"after {CYCLES} cancel cycles the reused connection delivered only "
    f"{got[0]} bytes of the next response and then stalled — connection-level "
    f"credit (MAX_DATA) that arrived while no stream was open was lost")
# the body is the file plus its HTTP/3 framing, so only a lower bound is checked
assert got[0] >= BIG_SIZE, f"short response: {got[0]} < {BIG_SIZE}"
print(f"ok (MAX_DATA absorbed with no stream open: {CYCLES} cancel cycles, "
      f"then {got[0]} bytes delivered on the same connection)")
