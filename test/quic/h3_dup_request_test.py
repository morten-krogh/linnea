#!/usr/bin/env python3
# Regression for the duplicate-response wedge found with a real browser (Safari):
# when the server's ACK of a request is lost during a loss burst, the client
# retransmits the request packet; the server used to serve the SAME stream twice,
# opening a second response slot whose duplicate body pinned the shared congestion
# window and permanently stalled the connection.
#
# Reproduce the trigger deterministically: after each request, DROP every
# server->client datagram for a window (losing the ack of the request) while
# driving the client's timer so it PTO-retransmits the request. Then deliver
# normally. All responses must still arrive byte-exact and the connection must not
# wedge. One connection carries several chunked responses (the wedge needed the
# shared window). Usage: h3_dup_request_test.py <port>
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

PORT = int(sys.argv[1])
# Several chunked responses over ONE connection (the wedge needed the shared
# window). Repeat the small set so many streams contend — like a browser's image
# gallery reloaded.
BASE = [("/h3big.bin", 600000), ("/h3big2.bin", 400000),
        ("/h3big3.bin", 500000), ("/h3big4.bin", 300000)]
WANT = BASE * 3   # 12 concurrent chunked streams on one connection

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
s.settimeout(0.1)
def flush():
    for d, _ in conn.datagrams_to_send(now=clk()):
        s.sendto(d, ("127.0.0.1", PORT))
flush()
dl = time.time() + 8
while not conn._handshake_confirmed and time.time() < dl:
    try:
        r, _ = s.recvfrom(4096); conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
    except socket.timeout:
        conn.handle_timer(now=clk())
    flush()
assert conn._handshake_confirmed, "handshake failed"

h3 = H3Connection(conn)
got = {}         # stream id -> bytes received
want_by_sid = {} # stream id -> expected size
for path, size in WANT:
    sid = conn.get_next_available_stream_id()
    h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                          (b":authority", b"localhost"), (b":path", path.encode())],
                    end_stream=True)
    got[sid] = 0
    want_by_sid[sid] = size
flush()

# Loss window: drop every server->client datagram for ~0.8s while driving the
# timer, so the requests' acks are lost and the client retransmits the requests
# repeatedly (each retransmission re-triggered a duplicate dispatch pre-fix).
drop_until = time.time() + 0.8
while time.time() < drop_until:
    try:
        s.recvfrom(65535)      # received but DROPPED (not fed to aioquic)
    except socket.timeout:
        pass
    conn.handle_timer(now=clk())
    flush()                    # retransmits the request packets

# Now deliver normally until all responses complete or we time out.
done = False
deadline = time.time() + 20
while not done and time.time() < deadline:
    try:
        r, _ = s.recvfrom(65535)
        conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        for qe in iter(conn.next_event, None):
            for ev in h3.handle_event(qe):
                if isinstance(ev, DataReceived):
                    got[ev.stream_id] = got.get(ev.stream_id, 0) + len(ev.data)
    except socket.timeout:
        conn.handle_timer(now=clk())
    flush()
    done = all(got.get(sid, 0) >= want_by_sid[sid] for sid in want_by_sid)

bad = [(sid, got.get(sid, 0), want_by_sid[sid]) for sid in want_by_sid
       if got.get(sid, 0) != want_by_sid[sid]]
if bad:
    for sid, g, w in bad:
        print(f"stream {sid}: got {g} of {w}")
    sys.exit(1)
print(f"ok ({len(WANT)} chunked responses complete byte-exact despite request retransmission)")
