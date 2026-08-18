#!/usr/bin/env python3
# 0-RTT early data over QUIC (RFC 9001 4.6). A first connection obtains a ticket.
# A second connection resumes and sends its HTTP/3 GET as 0-RTT — in a packet
# coalesced with the ClientHello, before the handshake completes. The server
# derives the early keys, decrypts the 0-RTT packet, accepts (the EE carries an
# empty early_data extension), and serves the buffered request once the 1-RTT
# keys are up. We assert aioquic reports early data as accepted and the response
# (200 with the file body) arrives.
#
# The version matters here and is a parameter (quic-6b). RFC 9369 shifts every
# long-header packet type up by one for QUIC v2, so a 0-RTT packet is type 0x10
# in v1 and 0x20 in v2 -- and the walk that hunts for the coalesced 0-RTT packet
# has to know that, or it looks for a type the client never sent and the early
# data is silently ignored. Same code, same assertions, one byte different on
# the wire.
# Usage: h3_0rtt_test.py <port> [1|2]     (QUIC version, default 1)
import socket
import ssl
import sys

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived
from aioquic.quic.packet import QuicProtocolVersion

port = int(sys.argv[1])
VERSION = (QuicProtocolVersion.VERSION_2 if len(sys.argv) > 2 and sys.argv[2] == "2"
           else QuicProtocolVersion.VERSION_1)
ADDR = ("127.0.0.1", port)


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


def h3_get(path):
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"GET"),
                               (b":path", path.encode()),
                               (b":scheme", b"https"),
                               (b":authority", b"h3.test")])
    return vlq(1) + vlq(len(fields)) + fields


def full_handshake():
    """Complete a full handshake and return the ticket the server issues."""
    tickets = []
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
                            supported_versions=[VERSION])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg, session_ticket_handler=tickets.append)
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
    while conn.next_event() is not None:
        pass
    s.close()
    assert tickets, "no ticket from the first handshake"
    return tickets[0]


ticket = full_handshake()

# Second connection: resume and send the GET as 0-RTT (before the handshake).
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
                        supported_versions=[VERSION])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
cfg.session_ticket = ticket
conn = QuicConnection(configuration=cfg)
conn.connect(ADDR, now=0.0)
# queue the request now: with a ticket that allows early data, aioquic sends it
# in a 0-RTT packet coalesced with the ClientHello.
conn.send_stream_data(0, h3_get("/hello.txt"), end_stream=True)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)


def flush(t):
    for d, _ in conn.datagrams_to_send(now=t):
        s.sendto(d, ADDR)


flush(0.0)                                   # Initial(ClientHello) + 0-RTT(GET)
r, _ = s.recvfrom(4096)
conn.receive_datagram(r, ADDR, now=0.1)
flush(0.2)                                   # client Finished
resp = b""
s.settimeout(1.5)
try:
    while True:
        r, _ = s.recvfrom(4096)
        conn.receive_datagram(r, ADDR, now=0.3)
        ev = conn.next_event()
        while ev is not None:
            if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
                resp += ev.data
            ev = conn.next_event()
        if resp:
            break
except socket.timeout:
    pass
s.close()

assert conn._handshake_confirmed, "handshake not confirmed"
assert conn.tls.early_data_accepted, "server did not accept 0-RTT early data"
assert resp, "no response to the 0-RTT request"

# parse the h3 response: HEADERS(0x01) then DATA(0x00); confirm 200 + body.
i = 0
status = None
body = b""
dec = pylsqpack.Decoder(0, 0)
while i < len(resp):
    t, i = rvlq(resp, i)
    length, i = rvlq(resp, i)
    payload = resp[i:i + length]
    i += length
    if t == 0x01:
        for name, value in dec.feed_header(0, payload)[1]:
            if name == b":status":
                status = value
    elif t == 0x00:
        body += payload
assert status == b"200", f"status {status!r}, want 200"
assert body, "empty body"

# A NON-idempotent early request is refused with 425 Too Early (RFC 8470): 0-RTT
# is replayable (RFC 9001 9.2), so only safe methods may be served from it. Same
# 0-RTT flow, POST instead of GET -- the gate sits before routing, so even a
# static path answers 425 rather than the 405 a 1-RTT POST would get.
def h3_post(path):
    e = pylsqpack.Encoder()
    e.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, f = e.encode(0, [(b":method", b"POST"), (b":path", path.encode()),
                        (b":scheme", b"https"), (b":authority", b"h3.test")])
    return vlq(1) + vlq(len(f)) + f

ticket2 = full_handshake()
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"], supported_versions=[VERSION])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
cfg.session_ticket = ticket2
conn = QuicConnection(configuration=cfg)
conn.connect(ADDR, now=0.0)
conn.send_stream_data(0, h3_post("/hello.txt"), end_stream=True)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)


def pflush(t):
    for d, _ in conn.datagrams_to_send(now=t):
        s.sendto(d, ADDR)


pflush(0.0)
r, _ = s.recvfrom(4096)
conn.receive_datagram(r, ADDR, now=0.1)
pflush(0.2)
presp = b""
try:
    while True:
        r, _ = s.recvfrom(4096)
        conn.receive_datagram(r, ADDR, now=0.3)
        ev = conn.next_event()
        while ev is not None:
            if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
                presp += ev.data
            ev = conn.next_event()
        if presp:
            break
except socket.timeout:
    pass
s.close()
assert conn.tls.early_data_accepted, "server did not accept 0-RTT for the POST case"
pstatus = None
j = 0
pdec = pylsqpack.Decoder(0, 0)
while j < len(presp):
    t, j = rvlq(presp, j)
    length, j = rvlq(presp, j)
    payload = presp[j:j + length]
    j += length
    if t == 0x01:
        for name, value in pdec.feed_header(0, payload)[1]:
            if name == b":status":
                pstatus = value
assert pstatus == b"425", f"early POST status {pstatus!r}, want 425 Too Early (RFC 8470)"

print(f"ok (0-RTT accepted over QUIC v{2 if VERSION == QuicProtocolVersion.VERSION_2 else 1}, {len(body)}B body; early POST -> 425)")
