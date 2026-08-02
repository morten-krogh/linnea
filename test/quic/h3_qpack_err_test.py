#!/usr/bin/env python3
# A field section linnea's QPACK decoder cannot decode must end the
# CONNECTION with QPACK_DECOMPRESSION_FAILED (0x200, RFC 9204 2.2.1) — not
# leave the request stream silently dropped, which would hang the client
# until its own timeout. We advertise QPACK_MAX_TABLE_CAPACITY=0 and QPACK's
# capacity starts at zero, so a compliant client never sends these; a broken
# one gets a diagnosable error.
# Usage: h3_qpack_err_test.py <port>
import socket
import ssl
import sys

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def send_block(port, block):
    """Handshake, send `block` as a HEADERS frame on stream 0, return the
    connection's close event (or None if it stayed up)."""
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

    conn.send_stream_data(0, vlq(1) + vlq(len(block)) + block, end_stream=True)
    flush(0.4)
    try:
        r, _ = s.recvfrom(4096)
        conn.receive_datagram(r, ("127.0.0.1", port), now=0.5)
    except socket.timeout:
        pass
    s.close()
    # a received CONNECTION_CLOSE surfaces on _close_event, not next_event()
    return conn._close_event


port = int(sys.argv[1])

# An Indexed Field Line naming the DYNAMIC table (pattern 1T......, T=0):
# 0x80 | 0 = index 0 of a table we do not have. Prefix: Required Insert
# Count 0, Delta Base 0.
ev = send_block(port, bytes([0x00, 0x00, 0x80]))
assert ev is not None, "connection stayed up on an undecodable field section"
assert ev.error_code == 0x200, hex(ev.error_code)

# A non-zero Required Insert Count also means the encoder used the dynamic
# table (it says how many entries the section depends on).
ev = send_block(port, bytes([0x05, 0x00, 0xC0]))
assert ev is not None, "connection stayed up on a nonzero Required Insert Count"
assert ev.error_code == 0x200, hex(ev.error_code)

# A literal whose NAME is a dynamic reference (0101 N=0 T=0 index): same rule.
ev = send_block(port, bytes([0x00, 0x00, 0x40, 0x01, 0x41]))
assert ev is not None, "connection stayed up on a dynamic name reference"
assert ev.error_code == 0x200, hex(ev.error_code)

# A NEGATIVE Base (h3-14): Delta Base with the sign bit set. With Required
# Insert Count 0, S=1 means Base = 0 - 0 - 1 = -1, which RFC 9204 4.5.1.2
# forbids — but the sign bit used to be discarded, so 0x80 here decoded
# exactly like 0x00 and the section was served. The field line is a valid
# static reference (:method GET, index 17), so ONLY the sign is at fault.
ev = send_block(port, bytes([0x00, 0x80, 0xC0 | 17]))
assert ev is not None, "connection stayed up on a negative Base (sign bit discarded)"
assert ev.error_code == 0x200, hex(ev.error_code)

print("ok")
