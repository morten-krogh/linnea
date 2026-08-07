#!/usr/bin/env python3
# h3 routes to locations (stage 2 of HTTP/3 proxying).
#
# Before this, linnea_h3_serve was handed a document root and nothing else, so
# a vhost with any non-root location was kept off h3 entirely -- and when
# another vhost on the same port owned the listener, the excluded one's h3
# requests were answered from THAT vhost's document root, under its
# certificate. This fixture reproduces exactly that shape: a mixed vhost and a
# pure one sharing a port, with disjoint roots so a fall-through cannot pass.
#
# Usage: h3_locations_test.py <port>
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)

# path -> (expected status, expected body substring)
WANT = [
    # served from the mixed vhost's own "/" root (test/www/sub). The other
    # vhost's root has no page.html, so a fall-through shows up as a 404.
    ("/page.html", "200", "subdirectory page"),
    # the "/sub" location has a DIFFERENT root (test/www), and this file exists
    # only through it -- so a 200 proves longest-prefix routing, not luck
    ("/sub/index.html", "200", ""),
    # a proxy location: h3 cannot reach an upstream yet, and says so rather
    # than resolving the path under a static root
    ("/api/anything", "502", ""),
]


def request(path):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    vt = [0.0]

    def clk():
        vt[0] += 0.001
        return vt[0]

    conn.connect(ADDR, now=clk())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.1)

    def flush():
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ADDR)

    flush()
    dl = time.time() + 10
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            r, _ = s.recvfrom(4096)
            conn.receive_datagram(r, ADDR, now=clk())
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
    if not conn._handshake_confirmed:
        s.close()
        return None, "handshake failed"

    h3 = H3Connection(conn)
    sid = conn.get_next_available_stream_id()
    h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                          (b":authority", b"localhost"), (b":path", path.encode())],
                    end_stream=True)
    flush()
    status, body, done = None, b"", False
    end = time.time() + 15
    while time.time() < end and not done:
        try:
            r, _ = s.recvfrom(4096)
            conn.receive_datagram(r, ADDR, now=clk())
        except socket.timeout:
            conn.handle_timer(now=clk())
        while True:
            ev = conn.next_event()
            if ev is None:
                break
            for e in h3.handle_event(ev):
                if isinstance(e, HeadersReceived):
                    status = dict(e.headers).get(b":status", b"?").decode()
                    done = done or e.stream_ended
                elif isinstance(e, DataReceived):
                    body += e.data
                    done = done or e.stream_ended
        flush()
    s.close()
    return status, body.decode(errors="replace")


bad = []
for path, want_status, want_body in WANT:
    got, body = request(path)
    if got != want_status:
        bad.append(f"{path}: status {got}, wanted {want_status} ({body[:40]!r})")
    elif want_body and want_body not in body:
        bad.append(f"{path}: body {body[:60]!r} lacks {want_body!r}")
print("OK" if not bad else "; ".join(bad))
