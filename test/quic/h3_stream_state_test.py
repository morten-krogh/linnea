#!/usr/bin/env python3
# QUIC stream direction/state invariants (audit Finding 14, RFC 9000 3.1/3.2).
# aioquic will not deliberately send frames on the wrong stream half, so each
# case hand-injects a structurally valid 1-RTT frame under a fresh packet number.
# The server must report STREAM_STATE_ERROR (transport error 0x05), rather than
# ACKing the packet and letting a specialized scanner ignore or act on it.
#
# Usage: h3_stream_state_test.py <port>.  Prints one result per invalid frame.
import socket
import ssl
import sys
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated
from aioquic.tls import Epoch

PORT = int(sys.argv[1])
STREAM_STATE_ERROR = 0x05


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def stream(sid):
    # STREAM + LEN, zero bytes: enough payload to name the stream and remain a
    # completely valid frame for the structural frame walk.
    return b"\x0a" + vlq(sid) + b"\x00"


def reset(sid):
    return b"\x04" + vlq(sid) + b"\x00\x00"  # app error, final size


def stop(sid):
    return b"\x05" + vlq(sid) + b"\x00"  # application error


def max_stream_data(sid):
    return b"\x11" + vlq(sid) + b"\x00"


def stream_data_blocked(sid):
    return b"\x15" + vlq(sid) + b"\x00"


def handshake():
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    virtual_time = [0.0]

    def now():
        virtual_time[0] += 0.001
        return virtual_time[0]

    conn.connect(("127.0.0.1", PORT), now=now())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.2)

    def flush():
        for datagram, _ in conn.datagrams_to_send(now=now()):
            sock.sendto(datagram, ("127.0.0.1", PORT))

    flush()
    deadline = time.time() + 8
    while not conn._handshake_confirmed and time.time() < deadline:
        try:
            datagram, _ = sock.recvfrom(65535)
            conn.receive_datagram(datagram, ("127.0.0.1", PORT), now=now())
        except socket.timeout:
            conn.handle_timer(now=now())
        flush()
    assert conn._handshake_confirmed, "handshake failed"
    return conn, sock, now


def inject(conn, sock, frame, packet_number):
    dcid = conn._peer_cid.cid
    send = conn._cryptos[Epoch.ONE_RTT].send
    pn = conn._packet_number + packet_number
    header = bytes([0x43]) + dcid + pn.to_bytes(4, "big")
    sock.sendto(send.encrypt_packet(header, frame, pn), ("127.0.0.1", PORT))


def close_code(conn, sock, now):
    deadline = time.time() + 3
    while time.time() < deadline:
        try:
            datagram, _ = sock.recvfrom(65535)
            conn.receive_datagram(datagram, ("127.0.0.1", PORT), now=now())
            for event in iter(conn.next_event, None):
                if isinstance(event, ConnectionTerminated):
                    return event.error_code
        except socket.timeout:
            conn.handle_timer(now=now())
        for datagram, _ in conn.datagrams_to_send(now=now()):
            sock.sendto(datagram, ("127.0.0.1", PORT))
        close_event = getattr(conn, "_close_event", None)
        if isinstance(close_event, ConnectionTerminated):
            return close_event.error_code
    return None


def run(name, frame):
    conn, sock, now = handshake()
    inject(conn, sock, frame, 5000)
    code = close_code(conn, sock, now)
    sock.close()
    shown = "none" if code is None else f"0x{code:02x}"
    ok = code == STREAM_STATE_ERROR
    print(f"  {name}: close={shown} " + ("OK" if ok else "FAIL"))
    return ok


cases = [
    ("STREAM on server uni 3", stream(3)),
    ("RESET_STREAM on server uni 3", reset(3)),
    ("STREAM_DATA_BLOCKED on server uni 3", stream_data_blocked(3)),
    ("STOP_SENDING on unopened server bidi 1", stop(1)),
    ("STOP_SENDING on client uni 2", stop(2)),
    ("MAX_STREAM_DATA on client uni 2", max_stream_data(2)),
]

all_ok = True
for name, frame in cases:
    all_ok &= run(name, frame)
print("ok" if all_ok else "FAIL")
sys.exit(0 if all_ok else 1)
