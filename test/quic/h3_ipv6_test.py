#!/usr/bin/env python3
# Dual-stack HTTP/3: the server binds a single AF_INET6 socket (host "::") with
# IPV6_V6ONLY cleared, so ONE listener serves both families. This drives a full
# h3 GET over native IPv6 (::1) AND over IPv4 (127.0.0.1) against that same
# listener; both must complete the handshake and return the file. A native-IPv6
# peer also exercises the server's 28-byte sockaddr_in6 handling end to end
# (recvmsg name, conn.peer copy, sendto reply to a v6 address).
# Usage: h3_ipv6_test.py <port>
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


# native IPv6 loopback
n6, err = fetch(socket.AF_INET6, "::1")
if err:
    print(f"FAIL (IPv6 ::1): {err}")
    sys.exit(1)
# IPv4 loopback against the same dual-stack listener (arrives as ::ffff:127.0.0.1)
n4, err = fetch(socket.AF_INET, "127.0.0.1")
if err:
    print(f"FAIL (IPv4 mapped 127.0.0.1): {err}")
    sys.exit(1)
if n6 != n4:
    print(f"FAIL: IPv6 got {n6} bytes but IPv4 got {n4}")
    sys.exit(1)
print(f"ok (dual-stack h3: ::1 and 127.0.0.1 both served {n6} bytes from one AF_INET6 listener)")
