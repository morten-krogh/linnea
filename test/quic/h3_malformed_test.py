#!/usr/bin/env python3
# A malformed request stream that has already ended must be answered, not
# dropped. Both ways into the h3 serve path require the FIN, so when the frame
# layer rejects the stream nothing more is coming — yet the request was simply
# abandoned, leaving the client waiting on a response that could never arrive.
# RESET_STREAM ends it and settles the flow-control credit the stream's bytes
# are holding.
# Usage: h3_malformed_test.py <port>
import socket
import ssl
import sys

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import (ConnectionTerminated, StreamDataReceived,
                                 StreamReset)

port = int(sys.argv[1])
ADDR = ("127.0.0.1", port)
H3_MESSAGE_ERROR = 0x10E


def vlq(n):
    return bytes([n]) if n < 64 else (0x4000 | n).to_bytes(2, "big")


def ask(payload):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    conn.connect(ADDR, now=0.0)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)

    def flush(t):
        for d, _ in conn.datagrams_to_send(now=t):
            s.sendto(d, ADDR)

    flush(0.0)
    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ADDR, now=0.1)
    flush(0.2)
    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ADDR, now=0.3)
    assert conn._handshake_confirmed, "handshake not confirmed"
    while conn.next_event() is not None:
        pass

    conn.send_stream_data(0, payload, end_stream=True)
    t, got = 0.4, None
    try:
        for _ in range(12):
            flush(t)
            t += 0.1
            r, _ = s.recvfrom(4096)
            conn.receive_datagram(r, ADDR, now=t)
            t += 0.1
            ev = conn.next_event()
            while ev is not None:
                if isinstance(ev, StreamReset):
                    got = ("reset", ev.error_code)
                elif isinstance(ev, ConnectionTerminated):
                    got = ("killed", ev.error_code)
                elif isinstance(ev, StreamDataReceived) and ev.stream_id == 0 and ev.data:
                    got = ("response", len(ev.data))
                ev = conn.next_event()
            if got:
                break
    except socket.timeout:
        pass
    s.close()
    return got


for payload, what in ((vlq(0) + vlq(4) + b"body", "DATA with no HEADERS"),
                      (vlq(1) + vlq(50) + b"\x00\x00", "truncated HEADERS frame")):
    got = ask(payload)
    assert got is not None, f"{what}: no answer at all — the client would hang"
    assert got[0] == "reset", f"{what}: expected a stream reset, got {got}"
    assert got[1] == H3_MESSAGE_ERROR, \
        f"{what}: expected H3_MESSAGE_ERROR, got {hex(got[1])}"
print("ok (malformed complete requests are reset, not silently dropped)")
