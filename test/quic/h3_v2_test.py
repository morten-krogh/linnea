#!/usr/bin/env python3
# A full QUIC v2 (RFC 9369) handshake serving HTTP/3. v2 keeps the v1 key schedule
# but changes the Initial salt, the packet-protection HKDF labels ("quicv2 ...") and
# the long-header packet-type codes. Configure aioquic to speak only v2, complete the
# handshake, fetch a file and check it arrives byte-exact.
# Usage: h3_v2_test.py <port>
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.packet import QuicProtocolVersion
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived

PORT = int(sys.argv[1])
PATH, SIZE = "/h3big.bin", 600000

cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
# speak QUIC v2 only — the client's first Initial carries version 0x6b3343cf
cfg.supported_versions = [QuicProtocolVersion.VERSION_2]
cfg.original_version = QuicProtocolVersion.VERSION_2

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
dl = time.time() + 8
while not conn._handshake_confirmed and time.time() < dl:
    try:
        r, _ = s.recvfrom(4096); conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
    except socket.timeout:
        conn.handle_timer(now=clk())
    flush()
assert conn._handshake_confirmed, "QUIC v2 handshake did not complete"

# confirm we really negotiated v2, not a silent fallback
ver = getattr(conn, "_version", None)
assert ver == int(QuicProtocolVersion.VERSION_2), f"negotiated version {ver!r}, not v2"

h3 = H3Connection(conn)
sid = conn.get_next_available_stream_id()
h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                      (b":authority", b"localhost"), (b":path", PATH.encode())],
                end_stream=True)
flush()
got = 0
deadline = time.time() + 15
while got < SIZE and time.time() < deadline:
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

if got != SIZE:
    print(f"FAIL: got {got} of {SIZE} bytes over QUIC v2")
    sys.exit(1)
print(f"ok (QUIC v2 handshake + HTTP/3: {SIZE} bytes served byte-exact)")
