#!/usr/bin/env python3
# A malformed request stream that has already ended must be ANSWERED, not
# dropped (the client would otherwise wait forever). RFC 9114 distinguishes:
#   - DATA before any HEADERS is an invalid frame sequence (4.1), a CONNECTION
#     error H3_FRAME_UNEXPECTED (0x105).
#   - a truncated HEADERS frame is a malformed request, a STREAM reset
#     (H3_MESSAGE_ERROR 0x10e).
# Both used to be silently dropped.
# Usage: h3_malformed_test.py <port>
import socket
import ssl
import sys
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import (ConnectionTerminated, StreamDataReceived,
                                 StreamReset)

port = int(sys.argv[1])
ADDR = ("127.0.0.1", port)


def vlq(n):
    return bytes([n]) if n < 64 else (0x4000 | n).to_bytes(2, "big")


def ask(payload):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    t = [0.0]

    def clk():
        t[0] += 0.001
        return t[0]

    conn.connect(ADDR, now=clk())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    got = [None]

    def pump(dur):
        end = time.time() + dur
        while time.time() < end:
            for d, _ in conn.datagrams_to_send(now=clk()):
                s.sendto(d, ADDR)
            try:
                while True:
                    r, _ = s.recvfrom(4096)
                    conn.receive_datagram(r, ADDR, now=clk())
            except (BlockingIOError, OSError):
                pass
            try:
                conn.handle_timer(now=clk())
            except TypeError:
                pass
            ev = conn.next_event()
            while ev is not None:
                if isinstance(ev, StreamReset):
                    got[0] = ("reset", ev.error_code)
                elif isinstance(ev, ConnectionTerminated):
                    got[0] = ("killed", ev.error_code)
                elif (isinstance(ev, StreamDataReceived) and ev.stream_id == 0
                        and ev.data):
                    got[0] = ("response", len(ev.data))
                ev = conn.next_event()
            time.sleep(0.003)

    pump(0.05)
    deadline = time.time() + 5
    while not conn._handshake_confirmed and time.time() < deadline:
        pump(0.05)
    assert conn._handshake_confirmed, "handshake not confirmed"

    conn.send_stream_data(0, payload, end_stream=True)
    deadline = time.time() + 4
    while got[0] is None and time.time() < deadline:
        pump(0.1)
    s.close()
    return got[0]


for payload, what, expect in (
        (vlq(0) + vlq(4) + b"body", "DATA with no HEADERS", ("killed", 0x105)),
        (vlq(1) + vlq(50) + b"\x00\x00", "truncated HEADERS frame", ("reset", None))):
    got = ask(payload)
    assert got is not None, f"{what}: no answer at all — the client would hang"
    assert got[0] == expect[0], f"{what}: expected {expect[0]}, got {got}"
    if expect[1] is not None:
        assert got[1] == expect[1], \
            f"{what}: expected code 0x{expect[1]:x}, got 0x{got[1]:x}"

print("ok (malformed complete requests are answered, not silently dropped)")
