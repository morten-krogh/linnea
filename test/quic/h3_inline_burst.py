#!/usr/bin/env python3
# A burst of small h3 requests on one connection (audit Finding 16). Inline
# responses share the congestion window and the loss-recovery ring with
# everything else in flight; once the ring or the window is full, further
# responses are handed to the congestion-controlled pump rather than emitted
# untracked (before the fix the ninth outstanding small response was sent
# without a recovery record, so a lost copy was never resent and the stream
# hung). The observable property is that every request in a burst larger than
# the ring is still answered: none is dropped on the way out.
#
# Usage: h3_inline_burst.py <port> [count].  Prints ok/FAIL, exits non-zero on
# any missing response.
import socket
import ssl
import sys
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived

PORT = int(sys.argv[1])
N = int(sys.argv[2]) if len(sys.argv) > 2 else 40

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

h3 = H3Connection(conn)
sids = []
for i in range(N):
    sid = conn.get_next_available_stream_id()
    h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                          (b":authority", b"localhost"),
                          (b":path", f"/hello.txt?b{i}".encode())], end_stream=True)
    sids.append(sid)
flush()

status = {}
dl = time.time() + 20
while sum(1 for sid in sids if status.get(sid)) < N and time.time() < dl:
    try:
        r, _ = s.recvfrom(65535)
        conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        for qe in iter(conn.next_event, None):
            for ev in h3.handle_event(qe):
                if isinstance(ev, HeadersReceived):
                    for k, v in ev.headers:
                        if k == b":status":
                            status[ev.stream_id] = v.decode()
    except socket.timeout:
        conn.handle_timer(now=clk())
    flush()

ok = sum(1 for sid in sids if status.get(sid) == "200")
print(f"ok ({ok}/{N} answered 200)" if ok == N else f"FAIL {ok}/{N} answered 200")
sys.exit(0 if ok == N else 1)
