#!/usr/bin/env python3
# A client may start its packet numbers above 0 — Chrome begins its Initials at
# packet number 1 to resist ossification. The server's ServerHello ACK must then
# cover the real [smallest, largest] range it received, not assume [0, largest]:
# acknowledging a packet number the client never sent is an invalid ACK, and a
# strict client (Chrome: QUIC_INVALID_ACK_DATA) aborts the handshake to h2.
#
# aioquic starts at 0 and is lenient about acks for unsent packets, so we (a) skip
# packet number 0 like Chrome and (b) wrap its ack handler to reject an ack for a
# packet it never sent — mirroring Chrome. The handshake must then complete.
# Usage: h3_pn_offset_test.py <port>
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived

PORT = int(sys.argv[1])
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
vt = [0.0]
def clk():
    vt[0] += 0.002
    return vt[0]
conn.connect(("127.0.0.1", PORT), now=clk())
# skip packet number 0: the first packet we send goes out as packet number 1
conn._packet_number = 1

# make aioquic strict like Chrome: an ack covering a packet we never sent is fatal
_orig_on_ack = conn._loss.on_ack_received
def _strict_on_ack(*, ack_rangeset, ack_delay, now, space):
    sent = set(space.sent_packets.keys())
    for rng in ack_rangeset:
        for pn in rng:
            if pn not in sent:
                raise AssertionError(
                    f"server acked packet {pn}, which we never sent (sent={sorted(sent)})")
    return _orig_on_ack(ack_rangeset=ack_rangeset, ack_delay=ack_delay, now=now, space=space)
conn._loss.on_ack_received = _strict_on_ack

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.1)
def flush():
    for d, _ in conn.datagrams_to_send(now=clk()):
        s.sendto(d, ("127.0.0.1", PORT))
flush()
dl = time.time() + 8
bad_ack = None
while not conn._handshake_confirmed and time.time() < dl and bad_ack is None:
    try:
        r, _ = s.recvfrom(4096); conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
    except socket.timeout:
        conn.handle_timer(now=clk())
    except AssertionError as e:
        bad_ack = str(e)
        break
    flush()

if bad_ack is not None:
    print(f"FAIL: {bad_ack}")
    sys.exit(1)
assert conn._handshake_confirmed, \
    "handshake did not complete with Initials starting at packet number 1"

h3 = H3Connection(conn)
sid = conn.get_next_available_stream_id()
h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                      (b":authority", b"localhost"), (b":path", b"/index.html")],
                end_stream=True)
flush()
got = 0
deadline = time.time() + 8
while got == 0 and time.time() < deadline:
    try:
        r, _ = s.recvfrom(65535)
        conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        for qe in iter(conn.next_event, None):
            for ev in h3.handle_event(qe):
                if isinstance(ev, DataReceived):
                    got += len(ev.data)
    except socket.timeout:
        conn.handle_timer(now=clk())
    flush()
if got == 0:
    print("FAIL: no response after a handshake starting at packet number 1")
    sys.exit(1)
print("ok (handshake + request completed; ACK covered only packets we actually sent)")
