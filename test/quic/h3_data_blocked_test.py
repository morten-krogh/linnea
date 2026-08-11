#!/usr/bin/env python3
# A peer that says it is blocked on the connection window must be told the
# window again.
#
# MAX_DATA rides whatever 1-RTT packet is going out, and for a peer that is
# uploading that is usually a bare ACK — which this server emits UNTRACKED, so
# a lost one is never retransmitted. The next grant only fires when more data
# arrives, and a blocked peer is precisely one that cannot send any. The peer's
# own remedy under RFC 9000 4.1 is to send DATA_BLOCKED; the server parsed that
# frame only to step over it, so there was no repair at all and the connection
# stalled for good.
#
# aioquic never sends DATA_BLOCKED itself, so this injects one through the
# packet builder. The observable is direct: MAX_DATA frames arriving back,
# counted by wrapping aioquic's own handler. The connection is left idle first,
# so a grant arriving after the injection can only be a reply to it.
#
# Usage: h3_data_blocked_test.py <port>
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)
DATA_BLOCKED = 0x14

cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
conn.connect(ADDR, now=time.time())
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(0.05)

# Count MAX_DATA frames arriving back. It has to go into aioquic's dispatch
# TABLE, which is built in __init__ from bound methods: assigning
# conn._handle_max_data_frame afterwards changes nothing the dispatcher reads,
# so the counter stays at zero however many grants arrive -- a probe that
# cannot observe its own subject, which is indistinguishable from a server that
# never answers. It read as a failure against a server that was replying.
grants = []
_table = conn._QuicConnection__frame_handlers
_orig, _epochs = _table[0x10]


def counting(context, frame_type, buf):
    grants.append(True)
    return _orig(context, frame_type, buf)


_table[0x10] = (counting, _epochs)


def flush():
    for d, _ in conn.datagrams_to_send(now=time.time()):
        sock.sendto(d, ADDR)


def pump(seconds):
    dl = time.time() + seconds
    while time.time() < dl:
        try:
            conn.receive_datagram(sock.recvfrom(2048)[0], ADDR, now=time.time())
        except socket.timeout:
            pass
        flush()


flush()
dl = time.time() + 15
while not conn._handshake_confirmed and time.time() < dl:
    try:
        conn.receive_datagram(sock.recvfrom(2048)[0], ADDR, now=time.time())
    except socket.timeout:
        pass
    flush()
if not conn._handshake_confirmed:
    print("handshake failed")
    sys.exit(1)

pump(0.5)                       # let the handshake's own traffic settle
before = len(grants)

# Inject one DATA_BLOCKED, claiming we are stuck at the limit we believe in.
#
# It has to go in while a packet is OPEN. aioquic's _write_application starts
# and ends the packet itself, so a frame appended after it returns lands in a
# packet nobody finalises and is silently dropped -- which reads exactly like
# the server ignoring it, and did.
sent = [False]
_write = conn._write_application


class OpenPacketProxy:
    """Forwards to the real builder, and slips one frame in just after a
    packet starts, which is the only moment start_frame is legal."""

    def __init__(self, b):
        object.__setattr__(self, "_b", b)

    def __getattr__(self, n):
        return getattr(object.__getattribute__(self, "_b"), n)

    def __setattr__(self, n, v):
        setattr(object.__getattribute__(self, "_b"), n, v)

    def start_packet(self, *a, **k):
        b = object.__getattribute__(self, "_b")
        r = b.start_packet(*a, **k)
        if not sent[0]:
            try:
                buf = b.start_frame(DATA_BLOCKED)
                buf.push_uint_var(conn._remote_max_data)
                sent[0] = True
            except Exception:
                pass
        return r


def write_with_blocked(builder, network_path, now):
    return _write(OpenPacketProxy(builder), network_path, now)


conn._write_application = write_with_blocked
conn.send_ping(1)               # force a packet to be built right now
flush()
for _ in range(5):
    if sent[0]:
        break
    pump(0.2)
    conn.send_ping(2)
    flush()
if not sent[0]:
    print("setup: could not inject a DATA_BLOCKED frame")
    sys.exit(1)

pump(1.5)
sock.close()
got = len(grants) - before
if got == 0:
    print("no MAX_DATA came back after DATA_BLOCKED: a grant lost on an "
          "untracked ACK would never be repaired")
    sys.exit(1)
print("ok (DATA_BLOCKED drew %d MAX_DATA back)" % got)
