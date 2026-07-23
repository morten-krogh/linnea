#!/usr/bin/env python3
# Out-of-order, multi-frame ClientHello reassembly (the shape ngtcp2/curl sends).
# aioquic packs one CRYPTO frame per Initial in offset order, so it never
# exercised this; a real browser stack (ngtcp2) splits the ClientHello into many
# small CRYPTO frames sent out of offset order, sometimes several per packet.
# linnea must place each fragment at its offset and advance a contiguous prefix,
# not assume order.
#
# This crafts the pathological case directly: take a valid ClientHello, chop it
# into small chunks, shuffle them, spread them over two Initial packets (several
# CRYPTO frames each, deliberately out of order), encrypt with the Initial keys,
# and send. The server must reassemble it and reply with its Initial flight
# (ServerHello) — which it could only do after the whole ClientHello arrived.
# Usage: h3_frag_test.py <port>
import socket
import ssl
import sys

from aioquic.quic import packet as P
from aioquic.quic.crypto import CryptoPair
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)
V1 = 0x00000001


_ENCRYPT = CryptoPair.encrypt_packet


def client_initial_and_hello():
    """Return (dcid, scid, ClientHello bytes) from a real aioquic Initial,
    capturing the *plaintext* the client would encrypt (no decrypt needed)."""
    grab = []

    def hook(self, plain_header, plain_payload, packet_number):
        grab.append((bytes(plain_header), bytes(plain_payload)))
        return _ENCRYPT(self, plain_header, plain_payload, packet_number)

    CryptoPair.encrypt_packet = hook
    try:
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
        cfg.verify_mode = ssl.CERT_NONE
        cfg.server_name = "localhost"
        conn = QuicConnection(configuration=cfg)
        conn.connect(ADDR, now=0.0)
        conn.datagrams_to_send(now=0.0)
    finally:
        CryptoPair.encrypt_packet = _ENCRYPT

    plain_header, payload = grab[0]                    # the first Initial
    # header = first(1) version(4) dcidlen(1) dcid scidlen(1) scid ...
    dcidlen = plain_header[5]
    dcid = plain_header[6:6 + dcidlen]
    scidlen = plain_header[6 + dcidlen]
    scid = plain_header[7 + dcidlen:7 + dcidlen + scidlen]
    chunks = {}
    i = 0
    while i < len(payload):
        ftype = payload[i]; i += 1
        if ftype in (0x00, 0x01):                      # PADDING / PING
            continue
        if ftype == 0x06:                              # CRYPTO
            off, i = pull_vint(payload, i)
            ln, i = pull_vint(payload, i)
            chunks[off] = payload[i:i + ln]; i += ln
            continue
        raise SystemExit(f"unexpected frame {ftype:#x} in client Initial")
    hello = b"".join(chunks[o] for o in sorted(chunks))
    return dcid, scid, hello


def pull_vint(b, i):
    n = 1 << (b[i] >> 6)
    v = b[i] & 0x3F
    for k in range(1, n):
        v = (v << 8) | b[i + k]
    return v, i + n


def vint(v):
    if v < 64:
        return bytes([v])
    if v < 16384:
        return (0x4000 | v).to_bytes(2, "big")
    return (0x80000000 | v).to_bytes(4, "big")


def crypto_frame(off, data):
    return b"\x06" + vint(off) + vint(len(data)) + data


def build_initial(dcid, scid, pn, frames):
    """Encrypt one client Initial carrying `frames`, padded to 1200 bytes."""
    payload = frames
    # pad the whole datagram to the 1200-byte minimum (RFC 9000 14.1)
    pad = 1200 - (7 + len(dcid) + len(scid) + 2 + 1 + len(payload) + 16)
    if pad > 0:
        payload += b"\x00" * pad
    pn_bytes = pn.to_bytes(1, "big")
    length = len(pn_bytes) + len(payload) + 16      # pn + payload + AEAD tag
    first = P.encode_long_header_first_byte(V1, P.QuicPacketType.INITIAL, 0)
    header = (bytes([first]) + V1.to_bytes(4, "big")
              + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
              + vint(0)                              # token length 0
              + vint(length) + pn_bytes)
    pair = CryptoPair()
    pair.setup_initial(dcid, is_client=True, version=V1)
    return bytes(_ENCRYPT(pair, header, payload, pn))    # header includes the pn byte


dcid, scid, hello = client_initial_and_hello()
assert hello[0] == 0x01, "not a ClientHello"
print(f"ClientHello {len(hello)} bytes, dcid {dcid.hex()}")

# chop the ClientHello into ~120-byte chunks and shuffle them badly
STEP = 120
pieces = [(o, hello[o:o + STEP]) for o in range(0, len(hello), STEP)]
order = list(range(len(pieces)))
# a deterministic non-identity shuffle: reverse, then swap halves
order = order[::-1]
order = order[len(order) // 2:] + order[:len(order) // 2]
shuffled = [pieces[k] for k in order]
# split across two Initial packets, several out-of-order CRYPTO frames each
half = len(shuffled) // 2
pkt0 = b"".join(crypto_frame(o, d) for o, d in shuffled[:half])
pkt1 = b"".join(crypto_frame(o, d) for o, d in shuffled[half:])

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)
s.sendto(build_initial(dcid, scid, 0, pkt0), ADDR)
s.sendto(build_initial(dcid, scid, 1, pkt1), ADDR)

# The server can only answer once the whole ClientHello is reassembled — and its
# reply is addressed to the source connection id we chose, so a datagram back is
# proof the out-of-order fragments were placed and completed. (Before the fix the
# server dropped every out-of-order fragment and stayed silent.) The reply's
# first packet is a long-header Initial (its high bit set).
reply = None
try:
    reply, _ = s.recvfrom(4096)
except socket.timeout:
    pass

assert reply, "server did not answer the out-of-order ClientHello"
assert reply[0] & 0x80, f"reply is not a long-header packet: {reply[0]:#x}"
# the reply's DCID must be the SCID we chose (the server echoes it)
assert reply[6:6 + len(scid)] == scid, "reply not addressed to our connection id"
print("ok (out-of-order multi-frame ClientHello reassembled; server replied)")
