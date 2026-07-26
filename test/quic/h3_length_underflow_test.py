#!/usr/bin/env python3
# A QUIC Initial whose long-header Length field is rewritten to 0 must not
# crash the server. ctlen = Length - pn_len would otherwise underflow to ~2^64
# and drive an unbounded OOB read/write in the AEAD open (a pre-auth,
# single-datagram worker crash). The Length varint is in the cleartext part of
# the long header, so rewriting it to a same-width encoding of 0 leaves header
# protection and the packet-number offset intact.
#
# This script only puts the datagram on the wire; the suite decides pass/fail
# by watching the worker PIDs (a crash is masked by the master respawning).
# Usage: h3_length_underflow_test.py <port>
import socket
import ssl
import sys

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

port = int(sys.argv[1])


def build_initial():
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    conn.connect(("127.0.0.1", port), now=0.0)
    for data, _ in conn.datagrams_to_send(now=0.0):
        return bytearray(data)
    raise SystemExit("no datagram to send")


def vlen(b):
    return 1 << (b[0] >> 6)


def corrupt(pkt):
    assert pkt[0] & 0x80, "not a long header"
    off = 5
    off += 1 + pkt[off]                       # DCID
    off += 1 + pkt[off]                       # SCID
    tl = vlen(pkt[off:])                       # token length varint
    tok = pkt[off] & 0x3f
    for i in range(1, tl):
        tok = (tok << 8) | pkt[off + i]
    off += tl + tok
    ln = vlen(pkt[off:])                       # Length varint
    pkt[off] = {1: 0x00, 2: 0x40, 4: 0x80, 8: 0xc0}[ln]
    for i in range(1, ln):
        pkt[off + i] = 0x00                    # value 0, same width
    return pkt


pkt = corrupt(build_initial())
# a couple of them, and from two source ports, to hit more than one worker
for _ in range(4):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(bytes(pkt), ("127.0.0.1", port))
    s.close()
print("sent malformed Length=0 Initials")
