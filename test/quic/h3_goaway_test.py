#!/usr/bin/env python3
# HTTP/3 GOAWAY on drain. When a worker receives SIGTERM it must let connected h3
# peers know it is going away, so a client opens no new requests before the
# worker exits. linnea sends a GOAWAY frame on its control stream, carrying the
# lowest request stream it will not process. We complete a handshake, serve one
# request (on stream 0), signal the master to drain, and read the GOAWAY off the
# server's control stream (id 3) — it must reject streams from 4 up.
# Usage: h3_goaway_test.py <port> <master_pid>
import os
import signal
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived


def vlq(n):
    if n < 64:
        return bytes([n])
    return (0x4000 | n).to_bytes(2, "big")


def rvlq(b, i):
    n = 1 << (b[i] >> 6)
    v = b[i] & 0x3F
    for k in range(1, n):
        v = (v << 8) | b[i + k]
    return v, i + n


port = int(sys.argv[1])
master = int(sys.argv[2])
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
conn.connect(("127.0.0.1", port), now=0.0)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)


def flush(t):
    for d, _ in conn.datagrams_to_send(now=t):
        s.sendto(d, ("127.0.0.1", port))


flush(0.0)
r, _ = s.recvfrom(4096)
conn.receive_datagram(r, ("127.0.0.1", port), now=0.1)
flush(0.2)
r, _ = s.recvfrom(4096)
conn.receive_datagram(r, ("127.0.0.1", port), now=0.3)
assert conn._handshake_confirmed, "handshake not confirmed"

# collect the server's control stream (id 3): its SETTINGS arrive with
# HANDSHAKE_DONE, and a GOAWAY frame will follow on the same stream after drain.
ctrl = b""
ev = conn.next_event()
while ev is not None:
    if isinstance(ev, StreamDataReceived) and ev.stream_id == 3:
        ctrl += ev.data
    ev = conn.next_event()

# serve one request on stream 0, so the GOAWAY id reflects it
enc = pylsqpack.Encoder()
enc.apply_settings(max_table_capacity=0, blocked_streams=0)
_, fields = enc.encode(0, [(b":method", b"GET"), (b":path", b"/hello.txt"),
                           (b":scheme", b"https"), (b":authority", b"h3.test")])
bidi = conn.get_next_available_stream_id()
conn.send_stream_data(bidi, vlq(1) + vlq(len(fields)) + fields, end_stream=True)
flush(0.4)
r, _ = s.recvfrom(4096)
conn.receive_datagram(r, ("127.0.0.1", port), now=0.5)
while conn.next_event() is not None:
    pass

# drain the server, then read the GOAWAY off its control stream
os.kill(master, signal.SIGTERM)


def find_goaway(buf):
    # control stream = type byte (0x00) then a sequence of frames; return the
    # GOAWAY (type 0x07) payload's stream id, or None if not present yet.
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


goaway_id = find_goaway(ctrl)
deadline = time.time() + 3
while goaway_id is None and time.time() < deadline:
    try:
        r, _ = s.recvfrom(4096)
    except socket.timeout:
        break
    conn.receive_datagram(r, ("127.0.0.1", port), now=0.6)
    ev = conn.next_event()
    while ev is not None:
        if isinstance(ev, StreamDataReceived) and ev.stream_id == 3:
            ctrl += ev.data
        ev = conn.next_event()
    goaway_id = find_goaway(ctrl)
s.close()

assert goaway_id is not None, "no GOAWAY on the control stream after drain"
assert goaway_id == 4, f"GOAWAY stream id={goaway_id} (want 4: stream 0 served)"
print("ok")
