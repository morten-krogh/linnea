#!/usr/bin/env python3
# How long does a client wait when the LAST packet of an exchange is lost?
#
# Linnea recovers a lost response two ways. The fast one is ACK-based:
# tx_detect_loss resends a chunk once LINNEA_QUIC_LOSS_THRESH (3) later packets
# have been acknowledged, so recovery costs about one round trip. The slow one is
# the probe timeout, derived from the measured RTT and doubling per attempt.
#
# The final packet of a request can only ever use the slow one. Three packets
# cannot arrive after the last packet, so the threshold can never be met, and
# there is nothing else in flight to reveal the gap. That is the shape behind a
# browser sitting on "waiting for the server's digest" for most of a second on a
# lossy path while every loopback test says the server answers in milliseconds.
#
# This makes it deterministic instead of waiting for the network to do it: the
# client accepts everything up to the response, DROPS the datagram carrying the
# response (identified by size -- a reply carrying HEADERS and DATA is far larger
# than a bare ACK), and then measures how long the server takes to produce it
# again. Nothing is faked on the server side; the packet really is never
# acknowledged, exactly as if the path had eaten it.
#
# Run it twice, once with --drop 0, and the difference between the two is the
# cost of tail loss.
#
# --warmup N issues N small GETs first. That matters more than it sounds:
# linnea takes an RTT sample in ONE place, the 1-RTT ACK path, and only when the
# largest acknowledged packet is in the small-reply rtx ring. ACK-only packets
# are emitted untracked and response-stream chunks live in a different table, so
# a connection can run a whole upload without ever producing a sample -- leaving
# the probe timeout at the kInitialRtt cold-start guess (333 + 4*166 + 25 =
# 1024 ms) however fast the path really is. A warmup gives it samples to use.
#
# Usage: h3_tail_loss.py <host> <port> <path> [--drop N] [--min-bytes B] [--warmup N]
import hashlib, socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

host, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
argv = sys.argv[4:]
DROP = int(argv[argv.index("--drop") + 1]) if "--drop" in argv else 1
MINB = int(argv[argv.index("--min-bytes") + 1]) if "--min-bytes" in argv else 100
WARM = int(argv[argv.index("--warmup") + 1]) if "--warmup" in argv else 0
warmpath = argv[argv.index("--warmpath") + 1] if "--warmpath" in argv else "/hello.txt"
MAXMS = int(argv[argv.index("--max-ms") + 1]) if "--max-ms" in argv else 0
ADDR = ("127.0.0.1", port)
BODY = bytes((i * 37 + 11) & 0xFF for i in range(4096))

cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.server_name = host
cfg.verify_mode = ssl.CERT_NONE
conn = QuicConnection(configuration=cfg)
conn.connect(ADDR, now=time.time())
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.02)


def flush():
    for d, _ in conn.datagrams_to_send(now=time.time()):
        s.sendto(d, ADDR)


flush()
dl = time.time() + 15
while not conn._handshake_confirmed and time.time() < dl:
    try:
        conn.receive_datagram(s.recvfrom(4096)[0], ADDR, now=time.time())
    except socket.timeout:
        pass
    flush()
if not conn._handshake_confirmed:
    print("handshake failed")
    sys.exit(2)

h3 = H3Connection(conn)

for _ in range(WARM):
    w = conn.get_next_available_stream_id()
    h3.send_headers(w, [(b":method", b"GET"), (b":scheme", b"https"),
                        (b":authority", host.encode()), (b":path", warmpath.encode())],
                    end_stream=True)
    flush()
    wend, wdone = time.time() + 5, False
    while time.time() < wend and not wdone:
        try:
            conn.receive_datagram(s.recvfrom(4096)[0], ADDR, now=time.time())
        except socket.timeout:
            pass
        while True:
            ev = conn.next_event()
            if ev is None:
                break
            for e in h3.handle_event(ev):
                if getattr(e, "stream_id", None) == w and getattr(e, "stream_ended", False):
                    wdone = True
        flush()

sid = conn.get_next_available_stream_id()
h3.send_headers(sid, [(b":method", b"POST"), (b":scheme", b"https"),
                      (b":authority", host.encode()), (b":path", path.encode()),
                      (b"content-length", str(len(BODY)).encode())],
                end_stream=False)
h3.send_data(sid, BODY, end_stream=True)
flush()
t_sent = time.time()

status, done = None, False
dropped, dropped_sizes = 0, []
end = time.time() + 30
while time.time() < end and not done:
    try:
        pkt = s.recvfrom(4096)[0]
    except socket.timeout:
        flush()
        continue
    # The response is the first datagram big enough to be carrying one. A bare
    # ACK is tens of bytes; HEADERS + DATA + the QUIC header is well past MINB.
    # Dropping by SIZE rather than by ordinal is what keeps this aimed at the
    # response instead of at the ACK for our own upload -- losing that would
    # measure a different thing entirely.
    if dropped < DROP and len(pkt) >= MINB:
        dropped += 1
        dropped_sizes.append(len(pkt))
        continue                       # never reaches the connection: unACKed
    conn.receive_datagram(pkt, ADDR, now=time.time())
    while True:
        ev = conn.next_event()
        if ev is None:
            break
        for e in h3.handle_event(ev):
            if isinstance(e, HeadersReceived):
                status = dict(e.headers).get(b":status", b"?").decode()
                done = done or e.stream_ended
            elif isinstance(e, DataReceived):
                done = done or e.stream_ended
    flush()

dt = time.time() - t_sent
s.close()
if status is None:
    print("no response after %.2fs (dropped %d: %s)" % (dt, dropped, dropped_sizes))
    sys.exit(1)
ms = dt * 1000
if MAXMS and ms > MAXMS:
    print("recovered in %.0f ms, over the %d ms bound (dropped %d %s)"
          % (ms, MAXMS, dropped, dropped_sizes))
    sys.exit(1)
print("status %s, recovered in %.0f ms (dropped %d datagram(s) %s)"
      % (status, ms, dropped, dropped_sizes))
