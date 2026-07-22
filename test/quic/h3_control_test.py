#!/usr/bin/env python3
# HTTP/3 control stream. RFC 9114 6.2.1 requires each side to open a control
# stream and send SETTINGS as its first frame; RFC 9204 4.2 adds the QPACK
# encoder/decoder streams. Once the handshake completes, linnea must open its
# server-initiated unidirectional streams. We complete the handshake and, from
# the same packet that carries HANDSHAKE_DONE, read the three uni streams the
# server opens and check each is exactly what it should be — control (id 3) with
# a SETTINGS frame advertising a zero QPACK table, and the encoder (id 7) and
# decoder (id 11) streams with just their type byte.
# Usage: h3_control_test.py <port>
import socket
import ssl
import sys

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

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
flush(0.2)                                       # client Finished
r, _ = s.recvfrom(4096)
conn.receive_datagram(r, ("127.0.0.1", port), now=0.3)   # HANDSHAKE_DONE + streams
assert conn._handshake_confirmed, "handshake not confirmed"

# The server opens its uni streams in the HANDSHAKE_DONE packet, so their data
# is available as soon as that datagram is processed.
streams = {}
ev = conn.next_event()
while ev is not None:
    if isinstance(ev, StreamDataReceived):
        streams[ev.stream_id] = streams.get(ev.stream_id, b"") + ev.data
    ev = conn.next_event()
s.close()

# stream 3 (control): type byte 0x00, then SETTINGS (0x04) length 4 with
# QPACK_MAX_TABLE_CAPACITY (0x01) = 0 and QPACK_BLOCKED_STREAMS (0x07) = 0.
assert streams.get(3) == b"\x00\x04\x04\x01\x00\x07\x00", \
    f"control stream: {streams.get(3)!r}"
# stream 7 (QPACK encoder) and 11 (QPACK decoder): just the stream-type byte.
assert streams.get(7) == b"\x02", f"qpack encoder stream: {streams.get(7)!r}"
assert streams.get(11) == b"\x03", f"qpack decoder stream: {streams.get(11)!r}"
print("ok")
