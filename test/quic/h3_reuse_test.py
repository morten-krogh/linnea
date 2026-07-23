#!/usr/bin/env python3
# Connection reuse across many requests (RFC 9000 MAX_STREAMS). A browser reuses
# one h3 connection across page loads and refreshes; each request opens a new bidi
# stream. We advertise initial_max_streams_bidi=100, so without raising it the peer
# can open only ~100 bidi streams for the connection's whole life, then new requests
# can't be sent — images stop loading and the browser falls back to h2 after ~30s.
# This drives many more than 100 requests on ONE connection: every one must
# complete, proving MAX_STREAMS keeps the peer's limit ahead of it.
# Usage: h3_reuse_test.py <port> [n]
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

port = int(sys.argv[1])
N = int(sys.argv[2]) if len(sys.argv) > 2 else 250


def vlq(n):
    return bytes([n]) if n < 64 else (0x4000 | n).to_bytes(2, "big")


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
s.settimeout(0.2)


def flush():
    for d, _ in conn.datagrams_to_send(now=clk()):
        s.sendto(d, ("127.0.0.1", port))


flush()
while not conn._handshake_confirmed:
    try:
        r, _ = s.recvfrom(4096)
        conn.receive_datagram(r, ("127.0.0.1", port), now=clk())
    except socket.timeout:
        conn.handle_timer(now=clk())
    flush()
while conn.next_event():
    pass


def req(sid):
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, f = enc.encode(0, [(b":method", b"GET"), (b":path", b"/hello.txt"),
                          (b":scheme", b"https"), (b":authority", b"localhost")])
    conn.send_stream_data(sid, vlq(1) + vlq(len(f)) + f, end_stream=True)


# Issue the requests in small batches over the connection's life (as page loads /
# refreshes do), draining each before the next. This opens far more than the
# advertised 100 bidi streams on ONE connection, so it fails unless the server
# raises the limit with MAX_STREAMS. (Small batches also keep each request within a
# single packet, isolating this from the separate multi-packet-request reassembly
# path.)
done = set()
opened = 0
deadline = time.time() + 60
while opened < N and time.time() < deadline:
    batch = []
    for _ in range(min(8, N - opened)):
        sid = conn.get_next_available_stream_id()
        req(sid)
        batch.append(sid)
        opened += 1
    target = done | set(batch)
    while not target <= done and time.time() < deadline:
        flush()
        try:
            r, _ = s.recvfrom(4096)
        except socket.timeout:
            conn.handle_timer(now=clk())
            continue
        conn.receive_datagram(r, ("127.0.0.1", port), now=clk())
        ev = conn.next_event()
        while ev:
            if isinstance(ev, StreamDataReceived) and ev.end_stream:
                done.add(ev.stream_id)
            ev = conn.next_event()

assert len(done) >= N, (
    f"only {len(done)}/{N} requests completed on one connection — the peer's bidi "
    f"stream limit was not raised (MAX_STREAMS); a reused connection stalls past ~100")
print(f"ok ({N} requests on one reused connection, all completed)")
