"""Inject a STREAM_DATA_BLOCKED mid-upload, wait a known time, then resume.

The point is a POSITIVE CONTROL with a value known in advance: the server
should report stalled_ms close to the wait below. aioquic never sends this
frame on its own -- which is why nothing measured it for the life of the
server -- so it is injected the way h3_data_blocked_test.py injects the
connection-level one: while a packet is OPEN.
"""
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection

STREAM_DATA_BLOCKED = 0x15
PAUSE = float(sys.argv[2]) if len(sys.argv) > 2 else 0.40
port = int(sys.argv[1])
addr = ("127.0.0.1", port)
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.server_name = "localhost"; cfg.verify_mode = ssl.CERT_NONE
conn = QuicConnection(configuration=cfg)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.02)
conn.connect(addr, now=time.time())

def pump(sec=0.0):
    end = time.time() + sec
    while True:
        for d, _ in conn.datagrams_to_send(now=time.time()):
            s.sendto(d, addr)
        try:
            while True:
                conn.receive_datagram(s.recvfrom(2048)[0], addr, now=time.time())
        except (socket.timeout, BlockingIOError):
            pass
        while conn.next_event() is not None:
            pass
        if time.time() >= end:
            return

dl = time.time() + 15
while not conn._handshake_confirmed and time.time() < dl:
    pump()
h3 = H3Connection(conn)
sid = conn.get_next_available_stream_id()
body = bytes(200000)
first = bytes(1200)                 # small enough to drain before we go quiet
h3.send_headers(sid, [(b":method", b"POST"), (b":scheme", b"https"),
                      (b":authority", b"localhost"), (b":path", b"/api/echo"),
                      (b"content-length", str(len(body) * 2).encode())],
               end_stream=False)
h3.send_data(sid, first, end_stream=False)
# Drain completely: the peer must have NOTHING queued, or aioquic keeps
# sending the backlog through the "pause" and the server sees no gap at all.
# That is what the first version of this measured -- stalled_ms=0 for a 900 ms
# wait, because the wait was only in the application.
pump(1.0)

sent = [False]
_write = conn._write_application

class OpenPacketProxy:
    def __init__(self, b): object.__setattr__(self, "_b", b)
    def __getattr__(self, n): return getattr(object.__getattribute__(self, "_b"), n)
    def __setattr__(self, n, v): setattr(object.__getattribute__(self, "_b"), n, v)
    def start_packet(self, *a, **k):
        b = object.__getattribute__(self, "_b")
        r = b.start_packet(*a, **k)
        if not sent[0]:
            try:
                buf = b.start_frame(STREAM_DATA_BLOCKED)
                buf.push_uint_var(sid)
                buf.push_uint_var(conn._streams[sid].max_stream_data_remote)
                sent[0] = True
            except Exception:
                pass
        return r

conn._write_application = lambda b, p, n: _write(OpenPacketProxy(b), p, n)
conn.send_ping(1)
pump(0.2)
print("injected STREAM_DATA_BLOCKED: %s" % sent[0])
conn._write_application = _write
# ...the wait the server should measure
pump(PAUSE)
h3.send_data(sid, body, end_stream=True)
end = time.time() + 10
while time.time() < end:
    pump(0.05)
print("paused %.2fs before resuming" % PAUSE)
