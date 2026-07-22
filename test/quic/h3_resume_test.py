#!/usr/bin/env python3
# Session resumption over QUIC (RFC 8446 4.6.1, RFC 9001). A first connection
# completes a full handshake and receives a NewSessionTicket. A second connection
# offers that ticket as a pre_shared_key; the server opens it, verifies the
# binder, and resumes — sending a ServerHello with the pre_shared_key extension
# and a flight with NO certificate. We assert the second handshake completes and
# aioquic reports it as resumed, and that its handshake flight is materially
# smaller than the first (the certificate chain is gone).
# Usage: h3_resume_test.py <port>
import socket
import ssl
import sys

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

port = int(sys.argv[1])
ADDR = ("127.0.0.1", port)


def handshake(session_ticket=None):
    """Run one handshake; return (ticket_received, server_bytes, session_resumed)."""
    tickets = []
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    if session_ticket is not None:
        cfg.session_ticket = session_ticket
    conn = QuicConnection(configuration=cfg, session_ticket_handler=tickets.append)
    conn.connect(ADDR, now=0.0)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)

    def flush(t):
        for d, _ in conn.datagrams_to_send(now=t):
            s.sendto(d, ADDR)

    server_bytes = 0
    flush(0.0)
    r, _ = s.recvfrom(4096)              # server Initial + Handshake flight
    server_bytes += len(r)
    conn.receive_datagram(r, ADDR, now=0.1)
    # the full-handshake flight can span several datagrams (cert segmentation);
    # drain whatever else is immediately available before replying
    s.settimeout(0.3)
    try:
        while True:
            r, _ = s.recvfrom(4096)
            server_bytes += len(r)
            conn.receive_datagram(r, ADDR, now=0.15)
    except socket.timeout:
        pass
    s.settimeout(3)
    flush(0.2)                           # client Finished
    r, _ = s.recvfrom(4096)              # HANDSHAKE_DONE + NST
    server_bytes += len(r)
    conn.receive_datagram(r, ADDR, now=0.3)
    while conn.next_event() is not None:
        pass
    resumed = conn.tls.session_resumed
    confirmed = conn._handshake_confirmed
    s.close()
    assert confirmed, "handshake not confirmed"
    return (tickets[0] if tickets else None), server_bytes, resumed


# First connection: full handshake, obtain a ticket.
ticket, full_bytes, resumed1 = handshake()
assert ticket is not None, "no ticket from the first handshake"
assert not resumed1, "first handshake should not be a resumption"

# Second connection: resume with that ticket.
ticket2, resume_bytes, resumed2 = handshake(session_ticket=ticket)
assert resumed2, "second handshake was not resumed"
# the resumed flight carries no certificate, so the server sent far fewer bytes
assert resume_bytes < full_bytes, \
    f"resumed handshake not smaller: {resume_bytes} vs {full_bytes}"
# resumption also issues a fresh ticket (rotation)
assert ticket2 is not None, "no ticket issued on the resumed handshake"
print(f"ok (full={full_bytes}B resumed={resume_bytes}B)")
