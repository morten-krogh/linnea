#!/usr/bin/env python3
# A retransmitted STREAM frame with a fresh packet number must not consume
# connection-level receive credit twice (audit Finding 6). Packet-number
# duplicate suppression cannot help here: QUIC retransmissions deliberately use
# new packet numbers, while the stream offsets and bytes are unchanged.
#
# The server grants another MAX_DATA window after 256 KiB of received
# high-water growth. Reinjecting one completed request enough times to cross
# that threshold therefore exposes the old raw-frame accounting directly.
# Usage: h3_fc_dedup_test.py <port>
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.tls import Epoch


PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
clock = [0.0]


def now():
    clock[0] += 0.001
    return clock[0]


conn.connect(ADDR, now=now())
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(0.1)


def flush():
    for datagram, _ in conn.datagrams_to_send(now=now()):
        sock.sendto(datagram, ADDR)


flush()
deadline = time.time() + 8
while not conn._handshake_confirmed and time.time() < deadline:
    try:
        datagram, _ = sock.recvfrom(65535)
        conn.receive_datagram(datagram, ADDR, now=now())
    except socket.timeout:
        try:
            conn.handle_timer(now=now())
        except TypeError:
            pass
    flush()
assert conn._handshake_confirmed, "handshake failed"

h3 = H3Connection(conn)
encoder = pylsqpack.Encoder()
encoder.apply_settings(max_table_capacity=0, blocked_streams=0)
_, fields = encoder.encode(
    0,
    [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"localhost"),
        (b":path", b"/hello.txt"),
        (b"x-padding", b"x" * 900),
    ],
)
h3bytes = vlq(1) + vlq(len(fields)) + fields
sid = conn.get_next_available_stream_id()
# Let aioquic know that the response stream is a locally opened client-bidi
# stream; the actual request bytes below are hand-built and injected.
conn.send_stream_data(sid, b"", end_stream=False)
list(conn.datagrams_to_send(now=now()))
send = conn._cryptos[Epoch.ONE_RTT].send
dcid = conn._peer_cid.cid
base_pn = conn._packet_number + 5000


def inject(payload, pn):
    header = bytes([0x43]) + dcid + pn.to_bytes(4, "big")
    sock.sendto(send.encrypt_packet(header, payload, pn), ADDR)


# Leave the request open so the server keeps its reassembly context alive while
# the duplicate burst arrives. An empty, offset-bearing FIN completes it after
# the burst.
first = b"\x0a" + vlq(sid) + vlq(len(h3bytes)) + h3bytes  # STREAM | LEN
last = b"\x0f" + vlq(sid) + vlq(len(h3bytes)) + b"\x00"  # STREAM | OFF | LEN | FIN
inject(first, base_pn)

# Receive the legitimate first ACK / MAX_DATA grant, establishing the baseline
# after the initial request bytes have been accounted for.
deadline = time.time() + 5
while time.time() < deadline:
    try:
        datagram, _ = sock.recvfrom(65535)
        conn.receive_datagram(datagram, ADDR, now=now())
        for event in iter(conn.next_event, None):
            for h3event in h3.handle_event(event):
                pass
        break
    except socket.timeout:
        try:
            conn.handle_timer(now=now())
        except TypeError:
            pass
    flush()
baseline_credit = conn._remote_max_data

# Reinject the exact same stream bytes under fresh packet numbers. Keep the
# frame below the server's datagram buffer size; the repetition, not the frame,
# is what crosses the grant threshold.
duplicates = (300000 // len(h3bytes)) + 2
for index in range(duplicates):
    pn = base_pn + index
    inject(first, pn)
inject(last, base_pn + duplicates + 1)

# Feed the replies so a MAX_DATA frame, if the server emitted one, reaches the
# client's transport state. Also ACK those replies; this keeps the test from
# being dominated by loss recovery while the injected packets are drained.
status = None
deadline = time.time() + 5
while status is None and time.time() < deadline:
    try:
        datagram, _ = sock.recvfrom(65535)
        conn.receive_datagram(datagram, ADDR, now=now())
        for event in iter(conn.next_event, None):
            for h3event in h3.handle_event(event):
                if isinstance(h3event, HeadersReceived) and h3event.stream_id == sid:
                    status = dict(h3event.headers).get(b":status")
    except socket.timeout:
        try:
            conn.handle_timer(now=now())
        except TypeError:
            pass
    flush()

sock.close()
assert status == b"200", f"reassembled request failed: {status!r}"
assert conn._remote_max_data == baseline_credit, (
    f"duplicate stream bytes raised MAX_DATA from {baseline_credit} "
    f"to {conn._remote_max_data}"
)
print(f"ok (fresh-PN retransmissions did not raise MAX_DATA: {baseline_credit})")
