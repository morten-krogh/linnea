#!/usr/bin/env python3
# eBPF connection-ID steering: a connection survives client migration. With
# SO_REUSEPORT alone the kernel steers by the UDP 4-tuple, so a client that moves
# to a new source address re-hashes to a different worker that has never seen the
# connection and drops its packets. The BPF program routes by the connection id
# encoded in the packet instead, so every worker's packets reach the worker that
# owns the connection. We complete a handshake, then send several requests each
# from a fresh source port, and require every one to be served. Without steering
# a migration lands on the owning worker only ~1/workers of the time, so six in a
# row essentially never all succeed.
# Usage: h3_migrate_test.py <port>
import socket
import ssl
import sys

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def rvlq(b, i):
    n = 1 << (b[i] >> 6)
    v = b[i] & 0x3F
    for k in range(1, n):
        v = (v << 8) | b[i + k]
    return v, i + n


port = int(sys.argv[1])
addr = ("127.0.0.1", port)
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
conn.connect(addr, now=0.0)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)


def flush_via(sock, t):
    for d, _ in conn.datagrams_to_send(now=t):
        sock.sendto(d, addr)


flush_via(s, 0.0)
r, _ = s.recvfrom(4096)
conn.receive_datagram(r, addr, now=0.1)
flush_via(s, 0.2)
r, _ = s.recvfrom(4096)
conn.receive_datagram(r, addr, now=0.3)
assert conn._handshake_confirmed, "handshake not confirmed"
while conn.next_event() is not None:
    pass


def request(sock, t):
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"GET"), (b":path", b"/hello.txt"),
                               (b":scheme", b"https"), (b":authority", b"h3.test")])
    sid = conn.get_next_available_stream_id()
    conn.send_stream_data(sid, vlq(1) + vlq(len(fields)) + fields, end_stream=True)
    flush_via(sock, t)
    resp = b""
    try:
        r, _ = sock.recvfrom(4096)
    except socket.timeout:
        return None
    conn.receive_datagram(r, addr, now=t + 0.1)
    ev = conn.next_event()
    while ev is not None:
        if isinstance(ev, StreamDataReceived) and ev.stream_id == sid:
            resp += ev.data
        ev = conn.next_event()
    frames = []
    i = 0
    while i < len(resp):
        ty, i = rvlq(resp, i)
        ln, i = rvlq(resp, i)
        frames.append((ty, resp[i:i + ln]))
        i += ln
    hdr = next((p for ty, p in frames if ty == 1), None)
    if hdr is None:
        return None
    dec = pylsqpack.Decoder(0, 0)
    _, headers = dec.feed_header(0, hdr)
    return dict(headers).get(b":status")


t = 0.4
for m in range(6):
    s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s2.settimeout(3)
    s2.bind(("127.0.0.1", 0))          # a fresh source port: a migration
    status = request(s2, t)
    s2.close()
    t += 0.2
    assert status == b"200", f"migration {m} (fresh source port) got {status}"
print("ok")
