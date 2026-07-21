#!/usr/bin/env python3
# Acknowledgements. A server that never acknowledges leaves the client holding
# every request packet as unacknowledged, so the client keeps retransmitting
# work already done. After the exchange, the client's 1-RTT space must show our
# acknowledgement: the request packet recorded as acked and nothing left in
# flight.
# Usage: h3_ack_test.py <port>
import socket
import ssl
import sys

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.tls import Epoch


def vlq(n):
    if n < 64:
        return bytes([n])
    return (0x4000 | n).to_bytes(2, "big")


port = int(sys.argv[1])
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
conn.connect(("127.0.0.1", port), now=0.0)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)


def flush(t):
    for d, _ in conn.datagrams_to_send(now=t):
        s.sendto(d, ("127.0.0.1", port))


flush(0.0)
r, _ = s.recvfrom(4096)
conn.receive_datagram(r, ("127.0.0.1", port), now=0.1)
flush(0.2)
r, _ = s.recvfrom(4096)
conn.receive_datagram(r, ("127.0.0.1", port), now=0.3)
assert conn._handshake_confirmed, "handshake not confirmed"
while conn.next_event() is not None:
    pass

space = conn._spaces[Epoch.ONE_RTT]
enc = pylsqpack.Encoder()
enc.apply_settings(max_table_capacity=0, blocked_streams=0)
_, fields = enc.encode(0, [(b":method", b"GET"), (b":path", b"/hello.txt"),
                           (b":scheme", b"https"), (b":authority", b"h3.test")])
conn.send_stream_data(0, vlq(1) + vlq(len(fields)) + fields, end_stream=True)
flush(0.4)
in_flight_before = len(space.sent_packets)
assert in_flight_before > 0, "client sent nothing to acknowledge"

r, _ = s.recvfrom(4096)
conn.receive_datagram(r, ("127.0.0.1", port), now=0.5)
s.close()

assert space.largest_acked_packet > 0, \
    f"our reply acknowledged nothing (largest_acked={space.largest_acked_packet})"
assert len(space.sent_packets) == 0, \
    f"{len(space.sent_packets)} packets still unacknowledged after our reply"
print("ok")
