#!/usr/bin/env python3
# QUIC max_udp_payload_size enforcement on a large inline response (audit Finding
# 20, RFC 9000 18.2). A redirect's Location is the configured target plus the
# client's RAW request target, so a long request to a redirect location pushes the
# encoded HTTP/3 field section well past the 1200-byte datagram floor every QUIC
# path must carry. The server used to emit that whole field section in ONE 1-RTT
# packet -- a ~2120-byte datagram a peer enforcing its limit drops, and one prone
# to IP fragmentation. It must instead split the response across STREAM frames so
# no datagram exceeds 1200, while still delivering the complete 301 + Location.
#
# This measures every datagram the server sends in response to a redirect request
# with a long client path and asserts (a) the reassembled response is 301 with the
# full Location, and (b) no response datagram exceeds 1200 bytes. A short path is
# the control. Usage: h3_redirect_datagram.py <port>.  Prints ok/FAIL lines.
import socket
import ssl
import sys
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived

PORT = int(sys.argv[1])


def run(pathlen):
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
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
    assert conn._handshake_confirmed, "handshake failed"

    h3 = H3Connection(conn)
    sid = conn.get_next_available_stream_id()
    path = "/r" + ("A" * pathlen)
    h3.send_headers(stream_id=sid, headers=[
        (b":method", b"GET"), (b":scheme", b"https"),
        (b":authority", b"localhost"), (b":path", path.encode())],
        end_stream=True)
    flush()

    status = loc = None
    maxresp = 0
    dl = time.time() + 4
    while status is None and time.time() < dl:
        try:
            r, _ = s.recvfrom(65535)
            maxresp = max(maxresp, len(r))          # a RESPONSE datagram
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
            while True:
                qe = conn.next_event()
                if qe is None:
                    break
                for ev in h3.handle_event(qe):
                    if isinstance(ev, HeadersReceived):
                        for k, v in ev.headers:
                            if k == b":status":
                                status = v.decode()
                            if k == b"location":
                                loc = v.decode()
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
    s.close()
    return status, (len(loc) if loc else 0), maxresp


fails = 0


def check(cond, msg):
    global fails
    print(("ok   " if cond else "FAIL ") + msg)
    if not cond:
        fails += 1


# control: a short path fits one datagram and redirects
status, loclen, mx = run(5)
check(status == "301" and mx <= 1200,
      f"short redirect: status={status} loc_len={loclen} max_datagram={mx}")

# the bug: a long client path makes the field section exceed one datagram. The
# response must still be a complete 301 with the full Location, and every datagram
# must stay within the 1200-byte floor.
status, loclen, mx = run(2000)
check(status == "301", f"long redirect delivered: status={status} loc_len={loclen}")
check(loclen >= 2000, f"long redirect Location is complete: loc_len={loclen}")
check(mx <= 1200, f"long redirect: no datagram over 1200 (max_datagram={mx})")

print("ok" if fails == 0 else f"FAIL ({fails})")
sys.exit(0 if fails == 0 else 1)
