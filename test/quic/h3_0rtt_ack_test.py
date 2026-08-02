#!/usr/bin/env python3
# quic-6 (part a): a 0-RTT packet shares the Application packet number space with
# 1-RTT and MUST be acknowledged (RFC 9000 13.2.1). The server used to discard
# the 0-RTT packet number, so it never acknowledged the client's early request.
# This checks the server's behaviour directly, via the qlog: the packet number
# the client sent its 0-RTT on must appear in an ACK the server sends back.
#   post-fix: the 0-RTT packet number is acknowledged
#   pre-fix:  it is not (discarded, never recorded into the ack state)
# Checking the ACK rather than a client retransmission is deliberate — aioquic
# does not retransmit the request once the response has arrived, so "did the
# client re-send" does not discriminate; "did the server ack" does.
# Usage: h3_0rtt_ack_test.py <port>
import socket
import ssl
import sys

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.logger import QuicLogger
from aioquic.quic.events import StreamDataReceived

port = int(sys.argv[1])
ADDR = ("127.0.0.1", port)


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def h3_get(path):
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"GET"), (b":path", path.encode()),
                               (b":scheme", b"https"), (b":authority", b"h3.test")])
    return vlq(1) + vlq(len(fields)) + fields


def full_handshake():
    tickets = []
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
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

logger = QuicLogger()
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
cfg.session_ticket = ticket
cfg.quic_logger = logger
conn = QuicConnection(configuration=cfg)
conn.connect(ADDR, now=0.0)
conn.send_stream_data(0, h3_get("/hello.txt"), end_stream=True)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.3)

t = [0.0]


def flush():
    for d, _ in conn.datagrams_to_send(now=t[0]):
        s.sendto(d, ADDR)


def drain():
    try:
        while True:
            r, _ = s.recvfrom(4096)
            conn.receive_datagram(r, ADDR, now=t[0])
    except socket.timeout:
        pass
    while conn.next_event() is not None:
        pass


flush()
t[0] = 0.1
drain()
flush()
t[0] = 0.3
drain()
assert conn._handshake_confirmed, "handshake not confirmed"
assert conn.tls.early_data_accepted, "server did not accept 0-RTT early data"

# a couple more exchanges so the server's HANDSHAKE_DONE (which carries the ACK)
# is delivered and any of its ACKs are logged
for _ in range(6):
    t[0] += 0.2
    try:
        conn.handle_timer(now=t[0])
    except Exception:
        pass
    flush()
    drain()
s.close()


def ev_name(ev):
    return ev.get("name") if isinstance(ev, dict) else (ev[1] if len(ev) > 1 else "")


def ev_data(ev):
    return (ev.get("data") if isinstance(ev, dict) else (ev[3] if len(ev) > 3 else {})) or {}


events = []
for tr in logger.to_dict().get("traces", []):
    events += tr.get("events", [])

# the packet number the client sent its 0-RTT (early-data) packet on
zerortt_pns = []
for ev in events:
    if ev_name(ev) != "transport:packet_sent":
        continue
    d = ev_data(ev)
    hdr = d.get("header", {})
    ptype = hdr.get("packet_type", "")
    if ptype in ("0RTT", "zerortt", "0rtt"):
        # confirm it carries the stream-0 request
        if any(fr.get("frame_type") == "stream" and int(fr.get("stream_id", -1)) == 0
               for fr in d.get("frames", [])):
            zerortt_pns.append(int(hdr.get("packet_number", -1)))
assert zerortt_pns, "no 0-RTT packet carrying the stream-0 request was logged"

# every packet-number range the server acknowledged, from ACK frames we received
acked = set()
for ev in events:
    if ev_name(ev) != "transport:packet_received":
        continue
    for fr in ev_data(ev).get("frames", []):
        if fr.get("frame_type") != "ack":
            continue
        for rng in fr.get("acked_ranges", []):
            lo, hi = (rng if isinstance(rng, (list, tuple)) else (rng, rng))
            for pn in range(int(lo), int(hi) + 1):
                acked.add(pn)

covered = [pn for pn in zerortt_pns if pn in acked]
print(f"0-RTT pn(s) {zerortt_pns}; server-acked pns include them: {bool(covered)}")
assert covered, (
    f"the server never acknowledged the 0-RTT packet number(s) {zerortt_pns} "
    f"(acked: {sorted(acked)}) — RFC 9000 13.2.1")
print("ok")
