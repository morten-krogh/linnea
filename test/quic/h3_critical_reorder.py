#!/usr/bin/env python3
# Reordered closure of an HTTP/3 critical stream (audit Finding 9, RFC 9114 6.2).
# The control stream and both QPACK streams must not be closed by any means. When
# a FIN, RESET_STREAM or STOP_SENDING for one of them arrived BEFORE its offset-0
# type frame, the closure was taken for an ordinary teardown and the late type
# frame then registered the stream as live -- the connection carried on with a
# critical stream it believed was still open. It must instead close the connection
# H3_CLOSED_CRITICAL_STREAM (0x0104), exactly as the same closure delivered after
# typing already does.
#
# aioquic opens its control/QPACK streams type-frame-first, so the reordering is
# hand-built and injected in 1-RTT packets under fresh packet numbers with
# aioquic's own send keys (as h3_final_size.py does). A raw QuicConnection is used
# so the only unidirectional streams on the wire are the crafted ones.
#
# Usage: h3_critical_reorder.py <port>.  Prints ok/FAIL lines.
import socket
import ssl
import sys
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated
from aioquic.tls import Epoch

PORT = int(sys.argv[1])
H3_CLOSED_CRITICAL = 0x0104


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def stream_frame(sid, off, data, fin):
    t = 0x08 | 0x04 | 0x02 | (0x01 if fin else 0)   # STREAM | OFF | LEN | FIN?
    return bytes([t]) + vlq(sid) + vlq(off) + vlq(len(data)) + data


def reset_stream(sid, final_size):
    # RESET_STREAM: type, stream id, application error code, final size
    return bytes([0x04]) + vlq(sid) + vlq(0) + vlq(final_size)


def handshake():
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    vt = [0.0]

    def clk():
        vt[0] += 0.001
        return vt[0]

    conn.connect(("127.0.0.1", PORT), now=clk())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.2)

    def flush():
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ("127.0.0.1", PORT))

    flush()
    dl = time.time() + 8
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            r, _ = s.recvfrom(4096)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
    assert conn._handshake_confirmed, "handshake failed"
    return conn, s, clk


def inject(conn, s, frames, pn_bump):
    dcid = conn._peer_cid.cid
    send = conn._cryptos[Epoch.ONE_RTT].send
    pn = conn._packet_number + pn_bump
    header = bytes([0x43]) + dcid + pn.to_bytes(4, "big")   # short header, 4-byte pn
    s.sendto(send.encrypt_packet(header, frames, pn), ("127.0.0.1", PORT))


def close_code(conn, s, clk):
    dl = time.time() + 3
    while time.time() < dl:
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
            for ev in iter(conn.next_event, None):
                if isinstance(ev, ConnectionTerminated):
                    return ev.error_code
        except socket.timeout:
            conn.handle_timer(now=clk())
        ce = getattr(conn, "_close_event", None)
        if isinstance(ce, ConnectionTerminated):
            return ce.error_code
    return None


fails = 0


def check(name, got, want):
    global fails
    ok = got == want
    g = "none" if got is None else f"0x{got:04x}"
    print(("ok   " if ok else "FAIL ") + f"{name} (close={g}, want 0x{want:04x})")
    if not ok:
        fails += 1


def run(name, pre_close, type_sid, type_byte):
    # pre_close: a frame closing the stream while untyped, injected first; then the
    # offset-0 type frame that would register it as a critical stream.
    conn, s, clk = handshake()
    inject(conn, s, pre_close, 5000)
    time.sleep(0.05)
    inject(conn, s, stream_frame(type_sid, 0, bytes([type_byte]), fin=False), 5001)
    check(name, close_code(conn, s, clk), H3_CLOSED_CRITICAL)
    s.close()


# The peer's critical streams are its client-initiated unidirectional streams
# (id mod 4 == 2), on which the server only receives; STOP_SENDING for one is
# already a STREAM_STATE_ERROR (RFC 9000 19.5), so the closures reordered ahead of
# typing that Finding 9 is about are a FIN and a RESET_STREAM.
# control stream (uni id 2, type byte 0x00):
run("FIN before the control type frame",
    stream_frame(2, 1, b"x", fin=True), 2, 0x00)
run("RESET_STREAM before the control type frame",
    reset_stream(2, 2), 2, 0x00)
# QPACK encoder stream (uni id 6, type byte 0x02) and decoder (id 10, type 0x03):
run("RESET_STREAM before the QPACK encoder type frame",
    reset_stream(6, 0), 6, 0x02)
run("RESET_STREAM before the QPACK decoder type frame",
    reset_stream(10, 0), 10, 0x03)

print("ok" if fails == 0 else f"FAIL ({fails})")
sys.exit(0 if fails == 0 else 1)
