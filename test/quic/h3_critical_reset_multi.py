#!/usr/bin/env python3
# TWO untyped uni streams closed before either types (RFC 9114 6.2, audit-report-78).
#
# Its sibling h3_critical_reorder.py covers one such stream: a closure that
# arrives before the offset-0 type frame is remembered against the stream id, so
# the late type frame still raises H3_CLOSED_CRITICAL_STREAM. That memory was a
# single slot, so a SECOND closure overwrote the first and the earlier stream
# typed as though it had never been closed.
#
# The distinction the rows below draw is the whole finding: the LAST closed
# stream was always caught, so resetting one stream, or typing the later of two,
# passes on the broken build. Only typing the stream whose record was
# overwritten shows it.
#
# Usage: h3_critical_reset_multi.py <port>.  Prints ok/FAIL lines.
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
CONTROL, QPACK_ENC, QPACK_DEC, GREASE = 0x00, 0x02, 0x03, 0x21


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
    header = bytes([0x43]) + dcid + pn.to_bytes(4, "big")
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
    w = "none" if want is None else f"0x{want:04x}"
    print(("ok   " if ok else "FAIL ") + f"{name} (close={g}, want {w})")
    if not ok:
        fails += 1


def run(name, closures, type_sid, type_byte, want=H3_CLOSED_CRITICAL):
    """Inject each closure (own packet), then the offset-0 type frame."""
    conn, s, clk = handshake()
    for i, frame in enumerate(closures):
        inject(conn, s, frame, 5000 + i)
        time.sleep(0.05)
    inject(conn, s, stream_frame(type_sid, 0, bytes([type_byte]), fin=False),
           5000 + len(closures))
    check(name, close_code(conn, s, clk), want)
    s.close()


for label, tb in (("control", CONTROL), ("qpack-enc", QPACK_ENC),
                  ("qpack-dec", QPACK_DEC)):
    # THE FINDING: 2 is reset first, 6 second, and it is 2 that types
    run(f"{label}: two resets, the FIRST types",
        [reset_stream(2, 1), reset_stream(6, 1)], 2, tb)
    # the case that passed all along -- the last closure typed
    run(f"{label}: two resets, the LAST types (control)",
        [reset_stream(2, 1), reset_stream(6, 1)], 6, tb)
    # both closures in ONE packet, which is a different walk of the reset scan
    run(f"{label}: both resets in one packet, FIRST types",
        [reset_stream(2, 1) + reset_stream(6, 1)], 2, tb)
    # ...and a FIN and a reset mixed, since either can be the one overwritten.
    # The FIN carries NO data: a byte here would reach a zero-capacity QPACK
    # encoder and close the connection 0x0201 for an unrelated reason, which on
    # the broken build looks like a pass if the row only asks "did it close?"
    run(f"{label}: FIN then reset, the FINNED types",
        [stream_frame(2, 1, b"", True), reset_stream(6, 1)], 2, tb)

# A GREASE stream may be closed and typed freely: the memory of its closure must
# not become "close the connection on any late type frame".
run("grease: two resets, the first types (control)",
    [reset_stream(2, 1), reset_stream(6, 1)], 2, GREASE, want=None)
# ...and one that was never closed at all still types normally
run("control: no closure at all (control)", [], 2, CONTROL, want=None)

sys.exit(1 if fails else 0)
