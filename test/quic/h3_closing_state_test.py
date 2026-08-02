#!/usr/bin/env python3
# quic-8: after sending a CONNECTION_CLOSE the server must keep the connection
# in the closing state for a while (RFC 9000 10.2), re-sending the close in
# response to the peer's packets — so the peer learns the actual error even if
# the first close is lost, instead of drawing a stateless reset from a freed
# connection id.
#
# The test provokes a close (reset the control stream -> H3_CLOSED_CRITICAL_
# STREAM 0x104), then DISCARDS the server's first close datagram — as though it
# were lost — WITHOUT telling aioquic. It then sends a fresh request on the same
# connection. Only a server that kept the closing state answers that with the
# close again; a server that freed the slot answers with a stateless reset the
# client cannot decrypt, so it never learns the error.
#   post-fix: aioquic reports ConnectionTerminated(error 0x104)
#   pre-fix:  no close is ever delivered — the slot was freed and the re-request
#             drew a stateless reset
# Usage: h3_closing_state_test.py <port>
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)
H3_CLOSED_CRITICAL = 0x104

cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
vt = [0.0]


def clk():
    vt[0] += 0.002
    return vt[0]


conn.connect(ADDR, now=clk())
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.3)


def send():
    for d, _ in conn.datagrams_to_send(now=clk()):
        s.sendto(d, ADDR)


def feed():
    # deliver replies to aioquic, draining events
    try:
        while True:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ADDR, now=clk())
    except socket.timeout:
        pass
    while conn.next_event() is not None:
        pass


def discard():
    # read replies off the socket but do NOT tell aioquic (simulate loss)
    got = 0
    try:
        while True:
            r, _ = s.recvfrom(65535)
            got += 1
    except socket.timeout:
        pass
    return got


send()
dl = time.time() + 8
while not conn._handshake_confirmed and time.time() < dl:
    feed()
    send()
assert conn._handshake_confirmed, "handshake not confirmed"

# open a control uni stream (type 0x00 + empty SETTINGS), then reset it — a
# critical stream closed by any means is H3_CLOSED_CRITICAL_STREAM (RFC 9114 6.2)
uni = conn.get_next_available_stream_id(is_unidirectional=True)
conn.send_stream_data(uni, b"\x00\x04\x00")
send()
time.sleep(0.1)
discard()                                  # drain the SETTINGS-ack etc.
conn.reset_stream(uni, error_code=0x10c)
send()
time.sleep(0.15)

# the server has now sent its CONNECTION_CLOSE. Throw it away, unseen by aioquic.
lost = discard()
assert conn._close_event is None, "close arrived before we could drop it — rerun"

# a fresh request on the same connection. A server holding the closing state
# answers it with the close again; a freed slot answers with a stateless reset.
enc = pylsqpack.Encoder()
enc.apply_settings(max_table_capacity=0, blocked_streams=0)
_, f = enc.encode(0, [(b":method", b"GET"), (b":path", b"/hello.txt"),
                      (b":scheme", b"https"), (b":authority", b"localhost")])
conn.send_stream_data(0, b"\x01" + bytes([len(f)]) + f, end_stream=True)
send()

dl = time.time() + 4
while conn._close_event is None and time.time() < dl:
    feed()
    send()
s.close()

assert conn._close_event is not None, (
    "no close was re-delivered after the first was dropped — the slot was freed "
    "(the re-request drew a stateless reset the client cannot read)")
assert conn._close_event.error_code == H3_CLOSED_CRITICAL, \
    f"re-delivered close had code {conn._close_event.error_code:#x}, want 0x104"
print("ok")
