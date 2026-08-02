#!/usr/bin/env python3
# quic-11 (part): once the handshake is confirmed the server discards its
# Initial and Handshake keys (RFC 9001 4.9, 4.9.1) and MUST NOT process a
# packet in those spaces. There is no client-observable difference between
# "dropped before decrypt" and the old "decrypt then drop" — a re-sent
# Finished already hit the CONNECTED guard — so this is a robustness check:
# a burst of long-header (Initial/Handshake-typed) datagrams on an established
# connection must not disturb it. The server must stay up (checked by the
# caller for respawns) and keep serving 1-RTT requests on the same connection.
# Usage: h3_post_handshake_long.py <port>
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

port = int(sys.argv[1])
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
vt = [0.0]


def clk():
    vt[0] += 0.002
    return vt[0]


conn.connect(("127.0.0.1", port), now=clk())
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.3)
addr = ("127.0.0.1", port)


def pump():
    for d, _ in conn.datagrams_to_send(now=clk()):
        s.sendto(d, addr)
    try:
        r, _ = s.recvfrom(65535)
        conn.receive_datagram(r, addr, now=clk())
    except socket.timeout:
        conn.handle_timer(now=clk())


dl = time.time() + 8
while not conn._handshake_confirmed and time.time() < dl:
    pump()
assert conn._handshake_confirmed, "handshake failed"

# the server-issued connection id we address (its SCID = our DCID)
dcid = conn._peer_cid.cid

# A burst of long-header datagrams into the confirmed connection. Byte 0 has
# the long-header + fixed bits set; the type bits cycle through Initial (0x00)
# and Handshake (0x20). Version v1, our DCID, empty SCID, then random-ish body.
# None can authenticate; the server must drop them and stay healthy.
for i in range(200):
    tbits = 0x00 if (i & 1) else 0x20
    pkt = bytes([0xC0 | tbits]) + b"\x00\x00\x00\x01"      # long hdr + version 1
    pkt += bytes([len(dcid)]) + dcid + b"\x00"             # DCID, empty SCID
    pkt += bytes([(i * 37) & 0xFF]) * 64                   # length/pn/payload junk
    s.sendto(pkt, addr)
time.sleep(0.2)

# drain anything the server sent back (it should have sent nothing to those)
try:
    while True:
        r, _ = s.recvfrom(65535)
        conn.receive_datagram(r, addr, now=clk())
except socket.timeout:
    pass

# the connection must still serve a normal 1-RTT request
enc = pylsqpack.Encoder()
enc.apply_settings(max_table_capacity=0, blocked_streams=0)
_, f = enc.encode(0, [(b":method", b"GET"), (b":path", b"/hello.txt"),
                      (b":scheme", b"https"), (b":authority", b"localhost")])
conn.send_stream_data(0, b"\x01" + bytes([len(f)]) + f, end_stream=True)
got = 0
dl = time.time() + 5
while got == 0 and conn._close_event is None and time.time() < dl:
    pump()
    ev = conn.next_event()
    while ev is not None:
        if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
            got += len(ev.data)
        ev = conn.next_event()
s.close()
assert conn._close_event is None, \
    f"connection was closed after the long-header burst ({conn._close_event})"
assert got > 0, "connection stopped serving 1-RTT after the long-header burst"
print("ok")
