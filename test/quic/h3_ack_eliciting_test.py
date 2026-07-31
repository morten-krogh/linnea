#!/usr/bin/env python3
# An ack-eliciting packet must be acknowledged (RFC 9000 13.2.1).
#
# An ACK was only ever built when the server independently had something to send
# — a response, a flight, a chunk. So a packet carrying only a PING, or only
# MAX_DATA, or only a stream reset, drew nothing back at all. The peer's loss
# detection then declared that packet lost and resent it, with the probe timeout
# doubling each time, for as long as the connection lived. A browser meets this
# on every keepalive and on every reload-cancel storm, where the cancels arrive
# with no request for the server to answer.
#
# What makes it invisible in ordinary testing is that nothing breaks: the
# transfer still completes, the client just keeps re-sending packets the server
# received perfectly well the first time.
#
# Here: complete the handshake, let it go quiet, then send packets the server has
# no reason to reply to and require an acknowledgement anyway. aioquic's own loss
# recovery is the judge — a packet it considers acknowledged leaves its in-flight
# set, and one it does not stays there and is eventually declared lost.
#
# Usage: h3_ack_eliciting_test.py <port>
import socket
import ssl
import sys
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.tls import Epoch

PORT = int(sys.argv[1])


def connect():
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
    s.settimeout(0.1)

    def flush():
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ("127.0.0.1", PORT))

    flush()
    dl = time.time() + 10
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
    assert conn._handshake_confirmed, "handshake failed"
    return conn, s, clk, flush


def inflight_pns(conn):
    """Packet numbers the client is still waiting to hear about.

    The set, not the count: an acknowledgement may clear leftovers from the
    handshake too, and a count cannot tell that apart from clearing OUR probe.
    """
    space = conn._spaces[Epoch.ONE_RTT]
    return {pn for pn, pkt in space.sent_packets.items() if pkt.is_ack_eliciting}


def probe(label, send_it):
    conn, s, clk, flush = connect()

    # settle: drain anything still owed from the handshake
    dl = time.time() + 1.0
    while time.time() < dl:
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
            for _ in iter(conn.next_event, None):
                pass
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()

    before = inflight_pns(conn)
    send_it(conn)
    flush()
    mine = inflight_pns(conn) - before
    if not mine:
        print(f"SKIP {label}: nothing went out to acknowledge")
        s.close()
        return None

    # Give the server two seconds of our silence. Only an acknowledgement it
    # chose to send on its own can clear these.
    dl = time.time() + 2.0
    while time.time() < dl and (inflight_pns(conn) & mine):
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
            for _ in iter(conn.next_event, None):
                pass
        except socket.timeout:
            pass                     # deliberately no handle_timer: no resending
    left = inflight_pns(conn) & mine
    s.close()
    return left, mine


fails = 0

# case 1: a bare PING — exactly what a browser keepalive is
res = probe("PING alone (a browser keepalive)", lambda c: c.send_ping(0x5150))
if res is None:
    print("FAIL PING probe never left the client")
    fails += 1
else:
    left, mine = res
    if not left:
        print(f"ok   PING alone is acknowledged (packet {sorted(mine)} cleared)")
    else:
        print(f"FAIL PING alone drew no acknowledgement: packet(s) {sorted(left)} "
              f"of {sorted(mine)} still unacked after 2s — the peer will resend "
              f"them with a doubling timeout for the life of the connection")
        fails += 1

# case 2: a stream the server will not answer, then its cancellation. This is the
# reload-cancel shape: the client withdraws the request, so there is no response
# for the acknowledgement to ride along with.
conn, s, clk, flush = connect()
dl = time.time() + 1.0
while time.time() < dl:
    try:
        r, _ = s.recvfrom(65535)
        conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        for _ in iter(conn.next_event, None):
            pass
    except socket.timeout:
        conn.handle_timer(now=clk())
    flush()

before = inflight_pns(conn)
sid = conn.get_next_available_stream_id()
conn.reset_stream(sid, 0x10C)        # H3_REQUEST_CANCELLED on a stream never sent
flush()
mine = inflight_pns(conn) - before
if not mine:
    print("SKIP stream-reset probe: nothing went out")
else:
    dl = time.time() + 2.0
    while time.time() < dl and (inflight_pns(conn) & mine):
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
            for _ in iter(conn.next_event, None):
                pass
        except socket.timeout:
            pass
    left = inflight_pns(conn) & mine
    if not left:
        print(f"ok   a lone stream reset is acknowledged (packet {sorted(mine)} cleared)")
    else:
        print(f"FAIL a lone stream reset drew no acknowledgement: packet(s) "
              f"{sorted(left)} of {sorted(mine)} still unacked after 2s")
        fails += 1
s.close()

sys.exit(1 if fails else 0)
