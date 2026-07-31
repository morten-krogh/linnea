#!/usr/bin/env python3
# The same request-field rules over HTTP/3 (RFC 9114 4.2, 4.3.1).
#
# h2_field_rules.py is the other half. Both protocols decode into one shared
# checker, so these are the same three fixes seen from the other side — and HTTP/3
# had the weaker position of the two. The connection-specific names were matched
# only inside the proxy rebuild, which is gated on a field HTTP/3 never sets, so
# that block never ran here at all: `connection: keep-alive` or `te: gzip` over
# HTTP/3 was not merely forwarded, it was never even looked at.
#
# A malformed request is a STREAM error (4.1.2), so the connection survives and
# only the offending request is refused — which is what this checks, rather than
# just "did not get a 200".
#
# Usage: h3_field_rules_test.py <port>
import socket
import ssl
import sys
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

PORT = int(sys.argv[1])

OK = [(b":method", b"GET"), (b":scheme", b"https"),
      (b":authority", b"localhost"), (b":path", b"/hello.txt")]


def session():
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    vt = [0.0]

    def clk():
        vt[0] += 0.002
        return vt[0]

    conn.connect(("127.0.0.1", PORT), now=clk())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.1)

    def flush():
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ("127.0.0.1", PORT))

    flush()
    dl = time.time() + 10
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
    assert conn._handshake_confirmed, "handshake failed"
    return conn, s, clk, flush


def ask(headers, budget=5.0):
    """Send one request. Returns 'served', 'refused' or 'closed'."""
    conn, s, clk, flush = session()
    h3 = H3Connection(conn)
    sid = conn.get_next_available_stream_id()
    h3.send_headers(sid, headers, end_stream=True)
    flush()

    verdict = None
    dl = time.time() + budget
    while verdict is None and time.time() < dl:
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
            for qe in iter(conn.next_event, None):
                if type(qe).__name__ == "StreamReset":
                    verdict = "refused"
                for ev in h3.handle_event(qe):
                    if isinstance(ev, (HeadersReceived, DataReceived)):
                        verdict = "served"
        except socket.timeout:
            conn.handle_timer(now=clk())
        except Exception:
            break
        flush()
        if conn._close_event is not None:
            verdict = "closed"
            break
    s.close()
    return verdict or "refused"


fails = 0


def case(label, headers, want):
    global fails
    got = ask(headers)
    if got == want:
        print(f"ok   {label}: {got}")
    else:
        print(f"FAIL {label}: {got}, expected {want}")
        fails += 1


case("an ordinary request", OK, "served")

# pseudo-headers
case("no :scheme", [h for h in OK if h[0] != b":scheme"], "refused")
case("empty :path",
     [(k, b"" if k == b":path" else v) for k, v in OK], "refused")
case(":scheme: ftp is NOT restricted",
     [(k, b"ftp" if k == b":scheme" else v) for k, v in OK], "served")

# connection-specific fields — the block that never ran on this path
for name in (b"connection", b"keep-alive", b"transfer-encoding", b"upgrade",
             b"proxy-connection"):
    case(f"{name.decode()} is malformed", OK + [(name, b"x")], "refused")
case("te: gzip is malformed", OK + [(b"te", b"gzip")], "refused")
case("te: trailers is the one exception", OK + [(b"te", b"trailers")], "served")

# field syntax
case("space inside a field name", OK + [(b"x foo", b"v")], "refused")
case("value with a leading space", OK + [(b"x-a", b" v")], "refused")
case("value with a trailing tab", OK + [(b"x-a", b"v\t")], "refused")
case("an inner space is fine", OK + [(b"x-a", b"one two")], "served")

sys.exit(1 if fails else 0)
