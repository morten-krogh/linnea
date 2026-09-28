#!/usr/bin/env python3
# The HTTP/3 twin of test/h2_many_streams.py: N proxied event streams at once
# on ONE QUIC connection, each held open until it has delivered an event.
#
# HTTP/3 already allowed 100 (initial_max_streams_bidi) where HTTP/2 relayed 8;
# this is here so the two are held to the same number by the same kind of
# check, and because each h3 relay borrows a connection-pool slot for its
# upstream half -- the pool whose layout changed.
#
# Usage: h3_many_streams.py <port> <streams> [path]
# Prints "ok ..." or "not ok ..."; exit status says which. Needs aioquic.
import os
import socket
import ssl
import sys
import time

try:
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
except ImportError:
    print("skipped: aioquic unavailable")
    sys.exit(2)

PORT = int(sys.argv[1])
N = int(sys.argv[2])
PATH = (sys.argv[3] if len(sys.argv) > 3 else "/sse/forever?gap=0.3").encode()
addr = ("127.0.0.1", PORT)
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
conn.connect(addr, now=time.time())
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(0.05)


def pump():
    for d, _ in conn.datagrams_to_send(now=time.time()):
        u.sendto(d, addr)


status, events, ended = {}, {}, set()
h3 = None


def step():
    try:
        conn.receive_datagram(u.recvfrom(65536)[0], addr, now=time.time())
    except socket.timeout:
        pass
    timer = conn.get_timer()
    if timer is not None and timer <= time.time():
        conn.handle_timer(now=time.time())
    while True:
        ev = conn.next_event()
        if ev is None:
            break
        if h3 is None:
            continue
        for h in h3.handle_event(ev):
            if isinstance(h, HeadersReceived):
                for k, v in h.headers:
                    if k == b":status":
                        status[h.stream_id] = v.decode()
                if h.stream_ended:
                    ended.add(h.stream_id)
            elif isinstance(h, DataReceived):
                if b"data: event" in h.data:
                    events[h.stream_id] = events.get(h.stream_id, 0) + 1
                if h.stream_ended:
                    ended.add(h.stream_id)
    pump()


pump()
end = time.time() + 5
while not conn._handshake_confirmed and time.time() < end:
    step()
if not conn._handshake_confirmed:
    print("not ok: no QUIC handshake")
    sys.exit(1)
h3 = H3Connection(conn)
sids = []
for _ in range(N):
    sid = conn.get_next_available_stream_id()
    h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                          (b":authority", b"localhost"), (b":path", PATH)],
                    end_stream=True)
    sids.append(sid)
pump()
end = time.time() + 30
while time.time() < end and not all(x in events or x in ended for x in sids):
    step()
ok = [x for x in sids if status.get(x) == "200" and x in events and x not in ended]
conn.close(error_code=0x100)
pump()
u.close()
if len(ok) != N:
    bad = [x for x in sids if x not in ok]
    print("not ok: %d of %d h3 streams served concurrently (first failing: %s)" % (
        len(ok), N, ", ".join("%d:%s" % (x, status.get(x)) for x in bad[:5])))
    sys.exit(1)
print("ok: %d of %d concurrent event streams on one h3 connection" % (len(ok), N))
