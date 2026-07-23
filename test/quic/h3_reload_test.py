#!/usr/bin/env python3
# Browser reloads on ONE reused h3 connection. On reload a browser cancels the
# previous page's in-flight downloads (STOP_SENDING). If the server ignores that,
# the abandoned response chunks are never acknowledged: they pin the congestion
# window (and repeated probe timeouts collapse it to the floor), so after enough
# reloads the connection can send nothing new — the page hangs and Firefox falls
# back to h2. This drives many reload-cancel cycles, then loads a final page on the
# SAME connection and requires it to complete: proof the server tears a cancelled
# stream down (frees its slot, unmaps it, drops its in-flight chunks).
# Usage: h3_reload_test.py <port> [reloads]
import os
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

port = int(sys.argv[1])
RELOADS = int(sys.argv[2]) if len(sys.argv) > 2 else 20
BIG = b"/h3big.bin"
big_path = os.path.join(os.path.dirname(__file__), "..", "www", "h3big.bin")
if not os.path.exists(big_path):
    with open(big_path, "wb") as f:
        f.write(bytes((i * 131) & 0xFF for i in range(600000)))

cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
vt = [0.0]


def clk():
    vt[0] += 0.01
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


def nextsid():
    v = nxt[0]
    nxt[0] += 4
    return v


def req(sid):
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, f = enc.encode(0, [(b":method", b"GET"), (b":path", BIG),
                          (b":scheme", b"https"), (b":authority", b"localhost")])
    conn.send_stream_data(sid, vlq(1) + vlq(len(f)) + f, end_stream=True)


flush()
while not conn._handshake_confirmed:
    pump(0.05)

# reload cycles: request a page of large images, let them barely start, cancel them
for _ in range(RELOADS):
    sids = [nextsid() for _ in range(6)]
    for sid in sids:
        req(sid)
    pump(0.05)                       # downloads in flight but nowhere near done
    for sid in sids:
        try:
            conn.stop_stream(sid, 0x10c)   # H3_REQUEST_CANCELLED (reload cancel)
        except Exception:
            pass
    pump(0.05)

# final page on the SAME reused connection — must complete despite all the cancels
final = [nextsid() for _ in range(6)]
done = set()
for sid in final:
    req(sid)


def collect(ev):
    if isinstance(ev, StreamDataReceived) and ev.stream_id in final and ev.end_stream:
        done.add(ev.stream_id)


deadline = time.time() + 30
while len(done) < len(final) and time.time() < deadline:
    pump(0.1, collect)

assert len(done) == len(final), (
    f"final page after {RELOADS} reloads: only {len(done)}/{len(final)} completed — "
    f"cancelled streams (STOP_SENDING) were not torn down and pinned the window")
print(f"ok (final page complete on one connection after {RELOADS} reload-cancels)")
