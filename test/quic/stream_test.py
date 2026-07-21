#!/usr/bin/env python3
# After confirming the handshake, send application data on a QUIC stream in a
# 1-RTT (short-header) packet. linnea unprotects it with the client 1-RTT keys,
# parses the STREAM frame, and echoes the payload to stdout (the caller greps
# for the known marker). Exercises the QUIC data-receive path end to end.
# Usage: stream_test.py <port>
import socket
import ssl
import sys
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

port = int(sys.argv[1])
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"

conn = QuicConnection(configuration=cfg)
conn.connect(("127.0.0.1", port), now=0.0)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)


def flush(t):
    for data, _ in conn.datagrams_to_send(now=t):
        s.sendto(data, ("127.0.0.1", port))


flush(0.0)
resp, _ = s.recvfrom(4096)
conn.receive_datagram(resp, ("127.0.0.1", port), now=0.1)
flush(0.2)                              # client Finished
done, _ = s.recvfrom(4096)
conn.receive_datagram(done, ("127.0.0.1", port), now=0.3)   # HANDSHAKE_DONE
assert conn._handshake_confirmed, "handshake not confirmed"

# application data on a client-initiated bidirectional stream (stream 0)
conn.send_stream_data(0, b"linnea-quic-stream-42", end_stream=True)
flush(0.4)
s.close()
time.sleep(0.3)
print("ok")
