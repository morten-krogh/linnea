#!/usr/bin/env python3
# A COMPLETED request must not be dispatched twice (audit Finding 11). An inline
# response is forgotten the instant it is sent and a slotted one's slot is reaped
# once acked, so -- unlike the active-large-response case -- a completed stream
# leaves no trace, and a fresh-packet-number retransmission of the request
# re-routed it (a proxied POST would reach the backend twice).
#
# aioquic will not retransmit a small completed request's STREAM frame (its PTO
# probe is a PING), so this reproduces the retransmission directly: serve the
# request once, then RE-INJECT the exact same STREAM frame in a hand-built 1-RTT
# packet under a fresh packet number, using aioquic's own send keys. The caller
# then greps the access log -- the request must appear exactly once.
# Usage: h3_dup_served.py <port> <unique-token>.  Prints ok/FAIL.
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived as H3Headers
from aioquic.tls import Epoch

PORT = int(sys.argv[1])
TOKEN = sys.argv[2]


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
vt = [0.0]


def clk():
    vt[0] += 0.001
    return vt[0]


conn.connect(("127.0.0.1", PORT), now=clk())
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.2)


def flush():
    for d, _ in conn.datagrams_to_send(now=clk()):
        s.sendto(d, ("127.0.0.1", PORT))


flush()
dl = time.time() + 8
while not conn._handshake_confirmed and time.time() < dl:
    try:
        r, _ = s.recvfrom(4096)
        conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
    except socket.timeout:
        conn.handle_timer(now=clk())
    flush()
assert conn._handshake_confirmed, "handshake failed"

# Build the request as raw HTTP/3 bytes so the exact same bytes can be re-injected.
enc = pylsqpack.Encoder()
enc.apply_settings(max_table_capacity=0, blocked_streams=0)
_, fields = enc.encode(0, [(b":method", b"GET"), (b":scheme", b"https"),
                           (b":authority", b"localhost"),
                           (b":path", f"/hello.txt?{TOKEN}".encode())])
h3bytes = vlq(1) + vlq(len(fields)) + fields          # one HEADERS frame
sid = conn.get_next_available_stream_id()
conn.send_stream_data(sid, h3bytes, end_stream=True)   # one offset-0 STREAM frame, FIN
flush()

# receive the first response
status = None
dl = time.time() + 8
h3 = H3Connection(conn)
while status is None and time.time() < dl:
    try:
        r, _ = s.recvfrom(65535)
        conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        for qe in iter(conn.next_event, None):
            for ev in h3.handle_event(qe):
                if isinstance(ev, H3Headers) and ev.stream_id == sid:
                    for k, v in ev.headers:
                        if k == b":status":
                            status = v.decode()
    except socket.timeout:
        conn.handle_timer(now=clk())
    flush()
if status is None:
    print("FAIL first request got no response")
    sys.exit(1)

# --- re-inject the SAME STREAM frame under a fresh packet number ---
# STREAM frame type 0x0b = STREAM | LEN | FIN, offset 0 (no OFF bit).
stream_frame = b"\x0b" + vlq(sid) + vlq(len(h3bytes)) + h3bytes
dcid = conn._peer_cid.cid
send = conn._cryptos[Epoch.ONE_RTT].send
for k in range(3):                                     # a few, like repeated PTOs
    pn = conn._packet_number + 5000 + k                # well above anything in flight
    header = bytes([0x43]) + dcid + pn.to_bytes(4, "big")   # short header, 4-byte pn, phase 0
    packet = send.encrypt_packet(header, stream_frame, pn)
    s.sendto(packet, ("127.0.0.1", PORT))
    time.sleep(0.05)

# drain any server reply to the injection (an ack, or -- pre-fix -- a second response)
time.sleep(0.4)
try:
    while True:
        s.recvfrom(65535)
except socket.timeout:
    pass

print(f"ok (request answered {status}, then re-injected under a fresh PN; caller checks the log)")
