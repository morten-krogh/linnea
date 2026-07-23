#!/usr/bin/env python3
# Adversarial multi-stream h3 stress test. A real browser loading a page of large
# images "works sometimes, fails sometimes" — the signature of a loss/reordering
# race, which the earlier tests (one-way drop, lockstep clock) can't surface. This
# drives many concurrent large responses through an emulated network that DROPS,
# REORDERS and DELAYS datagrams in BOTH directions, across many seeds, and fails
# if any stream on any seed does not arrive complete and byte-exact.
#
# The emulator lives in the client's own pump loop: server->client datagrams are
# parked in a min-heap keyed by a randomized release time (→ reordering + jitter)
# and some are dropped; client->server datagrams are dropped with some probability.
# A virtual clock drives aioquic's timers deterministically per seed; the server's
# own PTO runs on the wall clock, which the socket timeouts advance.
#
# Usage: h3_stress_test.py <port> [seeds] [nstreams] [loss_pct]
import heapq
import itertools
import os
import random
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

port = int(sys.argv[1])
SEEDS = int(sys.argv[2]) if len(sys.argv) > 2 else 6
NSTREAMS = int(sys.argv[3]) if len(sys.argv) > 3 else 6
LOSS = (float(sys.argv[4]) if len(sys.argv) > 4 else 3.0) / 100.0
here = os.path.dirname(os.path.abspath(__file__))
DOCROOT = os.path.join(here, "..", "www")

# distinct large fixtures so a reordered/swapped/duplicated chunk breaks equality.
# Sized so many chunks stream per response (exercising loss recovery and the tail)
# while a full multi-seed run stays quick — the transfer rate is bounded by this
# Python pump loop, not the server.
FILES = []
for i in range(NSTREAMS):
    n = 70000 + i * 12000
    a, b, c = 131 + i * 7, 17 + i, 3 + i * 5
    body = bytes((j * a + (j >> 8) * b + c) & 0xFF for j in range(n))
    name = f"h3s{i}.bin"
    with open(os.path.join(DOCROOT, name), "wb") as f:
        f.write(body)
    FILES.append((name.encode(), body))


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def rvlq(b, i):
    k = 1 << (b[i] >> 6)
    v = b[i] & 0x3F
    for j in range(1, k):
        v = (v << 8) | b[i + j]
    return v, i + k


def parse_h3(stream):
    frames = []
    i = 0
    while i < len(stream):
        ty, i = rvlq(stream, i)
        ln, i = rvlq(stream, i)
        frames.append((ty, stream[i:i + ln]))
        i += ln
    hdr = next((p for ty, p in frames if ty == 1), None)
    data = b"".join(p for ty, p in frames if ty == 0)
    st = None
    if hdr is not None:
        dec = pylsqpack.Decoder(0, 0)
        _, headers = dec.feed_header(0, hdr)
        st = dict(headers).get(b":status")
    return st, data


def get(conn, sid, path):
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, f = enc.encode(0, [(b":method", b"GET"), (b":path", b"/" + path),
                          (b":scheme", b"https"), (b":authority", b"localhost")])
    conn.send_stream_data(sid, vlq(1) + vlq(len(f)) + f, end_stream=True)


def run_trial(seed):
    rng = random.Random(seed)
    # browser-like generous windows: this isolates loss/reordering, not flow control
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
                            max_data=8 << 20, max_stream_data=2 << 20)
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    vt = [0.0]

    def clk():
        vt[0] += 0.004
        return vt[0]

    conn.connect(("127.0.0.1", port), now=clk())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    addr = ("127.0.0.1", port)
    heap = []                       # (release_vt, seq, datagram) — reordering buffer
    seq = itertools.count()
    lossy = [False]                 # loss/reorder only after the handshake is up
                                    # (a real browser completes the handshake first;
                                    # dropping Initials here is a harness artifact)

    def tick():                     # aioquic idle-closes when a transfer stalls; then
        try:                        # handle_timer trips on a None _close_at. Treat that
            conn.handle_timer(now=clk())   # as "connection dead" so the trial reports the
            return True                    # partial (stalled) streams rather than crashing.
        except TypeError:
            return False

    def send_out():                 # client -> server, with loss (data phase only)
        for d, _ in conn.datagrams_to_send(now=clk()):
            if not lossy[0] or rng.random() >= LOSS:
                s.sendto(d, addr)

    def pump_in(now):               # drain socket -> reorder heap -> deliver due
        while True:
            try:
                r, _ = s.recvfrom(4096)
            except (BlockingIOError, socket.error):
                break
            if lossy[0] and rng.random() < LOSS:
                continue            # drop server->client
            # release after a randomized delay → out-of-order + jitter
            delay = rng.uniform(0.0, 0.05) if lossy[0] else 0.0
            heapq.heappush(heap, (now + delay, next(seq), r))
        while heap and heap[0][0] <= now:
            _, _, dg = heapq.heappop(heap)
            conn.receive_datagram(dg, addr, now=now)

    # bring up the handshake through the same lossy path
    send_out()
    t_hs = time.time() + 10
    while not conn._handshake_confirmed and time.time() < t_hs:
        now = clk()
        pump_in(now)
        if not heap:
            try:
                r, _ = s.recvfrom(4096)
                if rng.random() >= LOSS:
                    conn.receive_datagram(r, addr, now=now)
            except (BlockingIOError, socket.error):
                pass
        tick()
        send_out()
        time.sleep(0.002)
    if not conn._handshake_confirmed:
        return {"handshake": False}
    while conn.next_event():
        pass
    lossy[0] = True                 # now stress the data path: drop + reorder

    streams = {}
    for name, body in FILES:
        sid = conn.get_next_available_stream_id()
        get(conn, sid, name)
        streams[sid] = [name, body, b"", False]

    deadline = time.time() + 40
    got_total = 0
    last_progress = time.time()
    while time.time() < deadline and not all(v[3] for v in streams.values()):
        send_out()
        now = clk()
        pump_in(now)
        if not tick():
            break                   # connection went idle/dead: report what stalled
        ev = conn.next_event()
        while ev:
            if isinstance(ev, StreamDataReceived) and ev.stream_id in streams:
                streams[ev.stream_id][2] += ev.data
                streams[ev.stream_id][3] = streams[ev.stream_id][3] or ev.end_stream
            ev = conn.next_event()
        now_total = sum(len(v[2]) for v in streams.values())
        if now_total != got_total:
            got_total = now_total
            last_progress = time.time()
        elif time.time() - last_progress > 10.0:
            break                   # no bytes for 10 s: a real stall, report it
        time.sleep(0.0002)

    results = {}
    for sid, (name, body, raw, fin) in streams.items():
        st, data = parse_h3(raw)
        ok = fin and st == b"200" and data == body
        results[name.decode()] = {
            "ok": ok, "fin": fin, "status": st,
            "got": len(data), "want": len(body),
        }
    s.close()
    return results


bad = 0
for seed in range(SEEDS):
    res = run_trial(seed)
    if res.get("handshake") is False:
        print(f"seed {seed:2d}: HANDSHAKE FAILED")
        bad += 1
        continue
    failed = {n: r for n, r in res.items() if not r["ok"]}
    if failed:
        bad += 1
        detail = ", ".join(f"{n}:{r['got']}/{r['want']} fin={r['fin']} st={r['status']}"
                           for n, r in failed.items())
        print(f"seed {seed:2d}: FAIL {len(failed)}/{len(res)} -> {detail}")
    else:
        print(f"seed {seed:2d}: ok ({len(res)} streams)")

print(f"--- {SEEDS - bad}/{SEEDS} seeds fully complete "
      f"({NSTREAMS} streams, {LOSS*100:.0f}% loss + reorder both ways)")
sys.exit(1 if bad else 0)
