#!/usr/bin/env python3
# Multi-address HTTP/3: the config binds TWO SEPARATE specific-host TLS servers
# on one UDP port -- 127.0.0.1 (a v4 literal, bound as ::ffff:127.0.0.1) listed
# first, ::1 (a native v6 literal) listed second. Each host is its own listener,
# so h3 needs its OWN QUIC socket on each. A full h3 GET must complete against
# BOTH.
#
# Discriminating: the server used to create exactly one QUIC socket -- for the
# FIRST eligible TLS server -- and stop. That socket bound ::ffff:127.0.0.1, so
# a datagram to [::1]:PORT reached no UDP socket at all (its TCP still answered,
# which is why the loss was quiet) and the ::1 handshake below never completes.
# Serving both proves a socket is created per distinct host on the port.
# Usage: h3_multiaddr_test.py <port>
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

PORT = int(sys.argv[1])


def fetch(family, addr):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    vt = [0.0]
    def clk():
        vt[0] += 0.002
        return vt[0]
    dest = (addr, PORT)
    conn.connect(dest, now=clk())
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(0.1)
    def flush():
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, dest)
    flush()
    dl = time.time() + 8
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            r, _ = s.recvfrom(4096)
            conn.receive_datagram(r, dest, now=clk())
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
    if not conn._handshake_confirmed:
        return None, "handshake did not complete"

    h3 = H3Connection(conn)
    sid = conn.get_next_available_stream_id()
    h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                          (b":authority", b"localhost"), (b":path", b"/index.html")],
                    end_stream=True)
    flush()
    status = None
    got = 0
    fin = False
    deadline = time.time() + 8
    while not fin and time.time() < deadline:
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, dest, now=clk())
            for qe in iter(conn.next_event, None):
                for ev in h3.handle_event(qe):
                    if isinstance(ev, HeadersReceived):
                        for k, v in ev.headers:
                            if k == b":status":
                                status = v.decode()
                    elif isinstance(ev, DataReceived):
                        got += len(ev.data)
                        if ev.stream_ended:
                            fin = True
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
    s.close()
    if not fin:
        return None, f"no FIN (status={status}, {got} bytes)"
    if status != "200":
        return None, f"status {status}"
    if got == 0:
        return None, "empty body"
    return got, None


# the first-listed host (v4 literal), which is the one the single-socket server
# already served
n4, err = fetch(socket.AF_INET, "127.0.0.1")
if err:
    print(f"FAIL (127.0.0.1, listener 0): {err}")
    sys.exit(1)
# the second-listed host (native v6 literal), which had no QUIC socket before
n6, err = fetch(socket.AF_INET6, "::1")
if err:
    print(f"FAIL (::1, listener 1 -- no h3 socket?): {err}")
    sys.exit(1)
if n6 != n4:
    print(f"FAIL: 127.0.0.1 got {n4} bytes but ::1 got {n6}")
    sys.exit(1)
print(f"ok (multi-address h3: 127.0.0.1 and ::1 each served {n4} bytes from their own QUIC socket)")
