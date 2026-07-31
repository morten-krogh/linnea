#!/usr/bin/env python3
# Regression for the server's handshake flight never being retransmitted
# (RFC 9000 13.3, RFC 9002 6.2).
#
# There was no loss recovery for the Initial or Handshake packet number spaces at
# all. .send_flight ran once when the flight was built, and once more when the
# anti-amplification budget released the tail it had held back; the periodic sweep
# walked only the 1-RTT rings, which are empty for a connection still handshaking.
# So if the datagram carrying ServerHello and Certificate was lost, the handshake
# was simply over: the client retransmitted its ClientHello forever, got nothing,
# and eventually abandoned HTTP/3 and fell back to TCP. That datagram is ~1150
# bytes, the largest and most drop-prone of the connection, so this fired at
# roughly the path's loss rate on every h3 connection attempt.
#
# The server could not even rebuild it. The Handshake half recomposes from
# per-connection state, but the ServerHello lived only in per-datagram scratch, so
# the Initial carrying it was unreconstructible. It is now kept on the connection.
#
# Here: complete the handshake normally but DROP every server datagram until the
# first probe timeout has passed, simulating the loss of the whole first flight.
# A fixed server re-sends it unprompted and the handshake completes; an unfixed one
# never speaks again and this times out.
#
# Usage: h3_hs_rtx_test.py <port>
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived

PORT = int(sys.argv[1])
PATH = "/hello.txt"
DROP_FOR = 0.60           # longer than the 250 ms base PTO, shorter than the cap

cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
vt = [0.0]
def clk():
    vt[0] += 0.002
    return vt[0]

conn.connect(("127.0.0.1", PORT), now=clk())
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.05)

def flush():
    for d, _ in conn.datagrams_to_send(now=clk()):
        s.sendto(d, ("127.0.0.1", PORT))

flush()

# Phase 1: swallow everything the server sends. The client stays silent too — it
# has nothing to say until it sees a ServerHello — so nothing here can prompt the
# server. Only its own probe timer can.
dropped = 0
t_end = time.time() + DROP_FOR
while time.time() < t_end:
    try:
        d, _ = s.recvfrom(65535)
        dropped += len(d)
    except socket.timeout:
        pass

if dropped == 0:
    print("FAIL: the server sent no first flight at all — test cannot conclude")
    sys.exit(1)

# Phase 2: start listening properly. Anything that arrives now is a retransmission
# the server decided to send on its own.
dl = time.time() + 12
while not conn._handshake_confirmed and time.time() < dl:
    try:
        r, _ = s.recvfrom(65535)
        conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
    except socket.timeout:
        conn.handle_timer(now=clk())
    flush()

if not conn._handshake_confirmed:
    print(f"FAIL: dropped {dropped} bytes of the first flight and the handshake "
          f"never completed — the server did not retransmit it")
    sys.exit(1)

# and the connection must be genuinely usable, not merely "handshaked"
h3 = H3Connection(conn)
sid = conn.get_next_available_stream_id()
h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                      (b":authority", b"localhost"), (b":path", PATH.encode())],
                end_stream=True)
flush()

body = b""
dl = time.time() + 10
while b"hello" not in body and time.time() < dl:
    try:
        r, _ = s.recvfrom(65535)
        conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        for qe in iter(conn.next_event, None):
            for ev in h3.handle_event(qe):
                if isinstance(ev, DataReceived):
                    body += ev.data
    except socket.timeout:
        conn.handle_timer(now=clk())
    flush()

if b"hello" not in body:
    print(f"FAIL: handshake recovered but the request was not served ({body!r})")
    sys.exit(1)
print(f"ok (dropped {dropped} bytes of the first flight; the server retransmitted "
      f"it unprompted and served the request)")
