#!/usr/bin/env python3
# QUIC final-size invariants (audit Finding 12, RFC 9000 4.5). Once a stream's
# final size is learned from a FIN, it is fixed: a second FIN naming a different
# size, a FIN naming fewer bytes than were already received, and data extending
# past the final size are each FINAL_SIZE_ERROR (transport error 0x06), which
# closes the connection.
#
# aioquic sends stream data sequentially and will not craft the conflicting
# frames these need, so they are hand-built and injected in 1-RTT packets under
# fresh packet numbers using aioquic's own send keys (as h3_dup_served.py does).
# Each case opens a request stream with a GAP at offset 0 so the reassembly
# context stays alive (the walk never runs), then injects the offending frame.
# The server must answer with CONNECTION_CLOSE carrying error 0x06.
#
# Usage: h3_final_size.py <port>.  Prints ok/FAIL and exits non-zero on failure.
import socket
import ssl
import sys
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated
from aioquic.tls import Epoch

PORT = int(sys.argv[1])
FINAL_SIZE_ERROR = 0x06


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def stream_frame(sid, off, data, fin):
    # type: STREAM(0x08) | OFF(0x04) | LEN(0x02) | FIN(0x01 when fin)
    t = 0x08 | 0x04 | 0x02 | (0x01 if fin else 0)
    return bytes([t]) + vlq(sid) + vlq(off) + vlq(len(data)) + data


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
    header = bytes([0x43]) + dcid + pn.to_bytes(4, "big")  # short header, 4-byte pn
    packet = send.encrypt_packet(header, frames, pn)
    s.sendto(packet, ("127.0.0.1", PORT))


def close_code(conn, s, clk):
    # drain briefly and return the transport error the server closed with, if any.
    # aioquic parks a received CONNECTION_CLOSE in conn._close_event rather than
    # always emitting it through next_event(), so check both.
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
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ("127.0.0.1", PORT))
        ce = getattr(conn, "_close_event", None)
        if isinstance(ce, ConnectionTerminated):
            return ce.error_code
    return None


def run(name, frames_list):
    conn, s, clk = handshake()
    # sid 0 = first client-initiated bidi stream. Each frame set is injected in
    # its own packet under a distinct packet number so none is a duplicate.
    for i, frames in enumerate(frames_list):
        inject(conn, s, frames, 5000 + i)
        time.sleep(0.05)
    code = close_code(conn, s, clk)
    s.close()
    ok = code == FINAL_SIZE_ERROR
    print(f"  {name}: close=0x{code:02x}" if code is not None
          else f"  {name}: NO CLOSE",
          "OK" if ok else "FAIL")
    return ok


SID = 0
# gap at 0..10 keeps the context alive; the FIN at offset 10 declares final = 15
fin15 = stream_frame(SID, 10, b"AAAAA", fin=True)          # final size 15

cases = [
    # two FINs, second names a SMALLER size (equality violation)
    ("two-fin decreasing", [fin15, stream_frame(SID, 10, b"BBB", fin=True)]),   # 15 then 13
    # two FINs, second names a LARGER size (also extends data past the first)
    ("two-fin increasing", [fin15, stream_frame(SID, 10, b"CCCCCCCCCC", fin=True)]),  # 15 then 20
    # data past an already-declared final size, no second FIN
    ("data past final", [fin15, stream_frame(SID, 15, b"DDDDD", fin=False)]),   # bytes at 15..20
]

allok = True
for name, frames_list in cases:
    allok &= run(name, frames_list)

print("ok" if allok else "FAIL")
sys.exit(0 if allok else 1)
