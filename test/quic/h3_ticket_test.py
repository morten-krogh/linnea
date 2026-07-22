#!/usr/bin/env python3
# NewSessionTicket over QUIC (RFC 9001 4.6.1). After the handshake, the server
# sends a NewSessionTicket as a post-handshake CRYPTO frame (RFC 9001 4.1.3),
# coalesced into the HANDSHAKE_DONE packet, so the client can resume later. For
# QUIC the ticket MUST carry an early_data extension with max_early_data_size ==
# 0xffffffff; any other value makes it invalid for 0-RTT. We complete the
# handshake and assert the client's session_ticket_handler fired with a ticket
# that advertises exactly that.
# Usage: h3_ticket_test.py <port>
import socket
import ssl
import sys

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

port = int(sys.argv[1])

tickets = []
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg, session_ticket_handler=tickets.append)
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
conn.receive_datagram(r, ("127.0.0.1", port), now=0.3)   # HANDSHAKE_DONE + NST
# drain any post-handshake events so the ticket handler runs
while conn.next_event() is not None:
    pass
s.close()

assert conn._handshake_confirmed, "handshake not confirmed"
assert len(tickets) == 1, f"expected one ticket, got {len(tickets)}"
t = tickets[0]
assert t.max_early_data_size == 0xFFFFFFFF, \
    f"max_early_data_size = {t.max_early_data_size:#x}, want 0xffffffff"
# the ticket blob is our sealed stateless ticket: 76 bytes (nonce 12 + 48
# plaintext + 16 tag).
assert len(t.ticket) == 76, f"ticket length {len(t.ticket)}, want 76"
print("ok")
