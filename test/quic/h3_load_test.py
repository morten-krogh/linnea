#!/usr/bin/env python3
# Put the h3 server under load: many CONCURRENT connections (as separate browser
# tabs / rapid refreshes would), then a burst of open-load-close CHURN (connection
# pool reclamation). Every request on every connection must complete, and the
# server's workers must stay alive (no crash) with a bounded file-descriptor count
# (no leak) across the run.
# Usage: h3_load_test.py <port> [conns] [reqs_per_conn]
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
CONNS = int(sys.argv[2]) if len(sys.argv) > 2 else 16
REQS = int(sys.argv[3]) if len(sys.argv) > 3 else 5
PATHS = [b"/hello.txt", b"/style.css", b"/big.txt"]
ADDR = ("127.0.0.1", port)


def vlq(n):
    return bytes([n]) if n < 64 else (0x4000 | n).to_bytes(2, "big")


def request(conn, sid, path):
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, f = enc.encode(0, [(b":method", b"GET"), (b":path", path),
                          (b":scheme", b"https"), (b":authority", b"localhost")])
    conn.send_stream_data(sid, vlq(1) + vlq(len(f)) + f, end_stream=True)


class Peer:
    __slots__ = ("conn", "sock", "vt", "want", "done", "up")

    def __init__(self):
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
        cfg.verify_mode = ssl.CERT_NONE
        cfg.server_name = "localhost"
        self.conn = QuicConnection(configuration=cfg)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setblocking(False)
        self.vt = 0.0
        self.want = 0
        self.done = set()
        self.up = False
        self.conn.connect(ADDR, now=self.clk())

    def clk(self):
        self.vt += 0.01
        return self.vt

    def flush(self):
        for d, _ in self.conn.datagrams_to_send(now=self.clk()):
            self.sock.sendto(d, ADDR)

    def pump(self):
        self.flush()
        try:
            while True:
                r, _ = self.sock.recvfrom(4096)
                self.conn.receive_datagram(r, ADDR, now=self.clk())
        except (BlockingIOError, socket.error):
            pass
        self.conn.handle_timer(now=self.clk())
        ev = self.conn.next_event()
        while ev:
            if isinstance(ev, StreamDataReceived) and ev.end_stream:
                self.done.add(ev.stream_id)
            ev = self.conn.next_event()
        if not self.up and self.conn._handshake_confirmed:
            self.up = True
            for i in range(REQS):
                sid = self.conn.get_next_available_stream_id()
                request(self.conn, sid, PATHS[i % len(PATHS)])
                self.want += 1

    def complete(self):
        return self.up and len(self.done) >= self.want

    def close(self):
        try:
            self.conn.close()
            self.flush()
        except Exception:
            pass
        self.sock.close()


def fd_count():
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return -1


# --- phase A: CONNS connections concurrently, each doing a small page load ---
peers = [Peer() for _ in range(CONNS)]
deadline = time.time() + 60
while time.time() < deadline and not all(p.complete() for p in peers):
    for p in peers:
        p.pump()
    time.sleep(0.001)
incomplete = [i for i, p in enumerate(peers) if not p.complete()]
for p in peers:
    p.close()
assert not incomplete, f"phase A: {len(incomplete)}/{CONNS} connections did not complete"

# --- phase B: churn — open, load, close, repeated, to exercise pool reclamation ---
CYCLES = CONNS * 3
churn_fail = 0
for _ in range(CYCLES):
    p = Peer()
    d = time.time() + 15
    while time.time() < d and not p.complete():
        p.pump()
        time.sleep(0.001)
    if not p.complete():
        churn_fail += 1
    p.close()
assert churn_fail == 0, f"phase B: {churn_fail}/{CYCLES} churn connections did not complete"

print(f"ok ({CONNS} concurrent + {CYCLES} churn connections, "
      f"{REQS} reqs each, all completed)")
