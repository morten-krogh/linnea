#!/usr/bin/env python3
# 0-RTT frame and stream-limit validation (audit Finding 15, RFC 9000 12.5 / 4.6).
# Accepted early data used to jump straight into the STREAM scanner, so a frame a
# 0-RTT packet may not carry (ACK, CRYPTO, NEW_TOKEN, PATH_RESPONSE, HANDSHAKE_DONE)
# was silently stepped over instead of a PROTOCOL_VIOLATION, and an early STREAM
# above the granted limit was served instead of a STREAM_LIMIT_ERROR. Early data
# now runs the same validate+scan pipeline a 1-RTT packet does.
#
# aioquic will not build a 0-RTT packet carrying a forbidden frame or an
# over-limit stream, so the early packet is crafted by hand and encrypted with
# aioquic's own 0-RTT keys, then coalesced behind aioquic's Initial exactly as a
# real early flight is. The server must close the connection with the transport
# error the equivalent 1-RTT packet would draw.
#
# Usage: h3_0rtt_validation.py <port>.  Prints ok/FAIL lines.
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.packet import pull_quic_header
from aioquic.quic.events import ConnectionTerminated
from aioquic.tls import Epoch

PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)
PROTOCOL_VIOLATION = 0x0A
STREAM_LIMIT_ERROR = 0x04


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def h3_get(path=b"/hello.txt"):
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"GET"), (b":path", path),
                               (b":scheme", b"https"), (b":authority", b"h3.test")])
    return vlq(1) + vlq(len(fields)) + fields


def stream_frame(sid, data, fin=True):
    # STREAM | OFF | LEN | FIN
    t = 0x08 | 0x04 | 0x02 | (0x01 if fin else 0)
    return bytes([t]) + vlq(sid) + vlq(0) + vlq(len(data)) + data


def full_handshake():
    tickets = []
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg, session_ticket_handler=tickets.append)
    conn.connect(ADDR, now=0.0)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)

    def flush(t):
        for d, _ in conn.datagrams_to_send(now=t):
            s.sendto(d, ADDR)

    flush(0.0)
    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ADDR, now=0.1)
    flush(0.2)
    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ADDR, now=0.3)
    while conn.next_event() is not None:
        pass
    s.close()
    assert tickets, "no ticket from the first handshake"
    return tickets[0]


def first_long_packet(datagram):
    """Parse the leading long-header (Initial) packet and return
    (header, whole_packet_bytes)."""
    buf = Buffer(data=datagram)
    hdr = pull_quic_header(buf, host_cid_length=8)
    return hdr, datagram[:hdr.packet_length]


def early_close(ticket, early_payload):
    """Resume, send Initial + a hand-built 0-RTT packet carrying early_payload,
    finish the handshake, and return the transport error the server closed with."""
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    cfg.session_ticket = ticket
    conn = QuicConnection(configuration=cfg)
    conn.connect(ADDR, now=0.0)
    # queue a stream so aioquic derives the 0-RTT keys and emits an Initial+0RTT
    conn.send_stream_data(0, h3_get(), end_stream=True)
    outgoing = conn.datagrams_to_send(now=0.0)
    datagram = outgoing[0][0]
    hdr, initial = first_long_packet(datagram)
    assert hdr.packet_type.name == "INITIAL", f"expected Initial, got {hdr.packet_type}"

    # Build our own 0-RTT packet with aioquic's 0-RTT send keys. Long header:
    # first byte (0-RTT v1 = 0xD0 with a 1-byte packet number), version, DCID, SCID,
    # length (pn + payload + 16-byte tag), then the packet number.
    zerortt = conn._cryptos[Epoch.ZERO_RTT].send
    dcid = hdr.destination_cid
    scid = hdr.source_cid
    version = hdr.version
    pn = 0
    length = 1 + len(early_payload) + 16
    plain_header = (bytes([0xD0]) + version.to_bytes(4, "big")
                    + bytes([len(dcid)]) + dcid
                    + bytes([len(scid)]) + scid
                    + vlq(length) + bytes([pn]))
    early_packet = zerortt.encrypt_packet(plain_header, early_payload, pn)

    coalesced = initial + early_packet
    if len(coalesced) < 1200:
        coalesced += b"\x00" * (1200 - len(coalesced))

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.2)
    s.sendto(coalesced, ADDR)
    close = None
    dl = time.time() + 3
    now = 0.1
    while close is None and time.time() < dl:
        try:
            r, _ = s.recvfrom(4096)
            conn.receive_datagram(r, ADDR, now=now)
            for ev in iter(conn.next_event, None):
                if isinstance(ev, ConnectionTerminated):
                    close = ev.error_code
        except socket.timeout:
            try:
                conn.handle_timer(now=now)
            except Exception:
                pass
        for d, _ in conn.datagrams_to_send(now=now):
            s.sendto(d, ADDR)
        ce = getattr(conn, "_close_event", None)
        if isinstance(ce, ConnectionTerminated):
            close = ce.error_code
        now += 0.1
    s.close()
    return close


ticket = full_handshake()
fails = 0


def check(name, got, want):
    global fails
    ok = got == want
    g = "none" if got is None else f"0x{got:02x}"
    print(("ok   " if ok else "FAIL ") + f"{name} (close={g}, want 0x{want:02x})")
    if not ok:
        fails += 1


# an ACK in 0-RTT is forbidden (RFC 9000 12.5): a valid GET follows it, and the
# whole flight must be rejected PROTOCOL_VIOLATION rather than served.
ack_frame = bytes([0x02]) + vlq(0) + vlq(0) + vlq(0) + vlq(0)   # ACK largest=0, 1 range
check("ACK before a valid 0-RTT GET",
      early_close(ticket, ack_frame + stream_frame(0, h3_get())),
      PROTOCOL_VIOLATION)

# a CRYPTO frame is likewise forbidden in 0-RTT
crypto_frame = bytes([0x06]) + vlq(0) + vlq(3) + b"abc"        # CRYPTO off=0 len=3
check("CRYPTO in 0-RTT",
      early_close(ticket, crypto_frame + stream_frame(0, h3_get())),
      PROTOCOL_VIOLATION)

# a 0-RTT STREAM above the granted bidi limit (100 streams -> ids 0..396) is a
# STREAM_LIMIT_ERROR; 4*100 = 400 is the first over-limit client bidi id
check("over-limit early stream",
      early_close(ticket, stream_frame(400, h3_get())),
      STREAM_LIMIT_ERROR)

print("ok" if fails == 0 else f"FAIL ({fails})")
sys.exit(0 if fails == 0 else 1)
