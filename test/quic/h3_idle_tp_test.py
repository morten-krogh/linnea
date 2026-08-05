#!/usr/bin/env python3
# quic-12: the effective idle timeout is the MINIMUM of the two advertised
# max_idle_timeouts (RFC 9000 10.1). The server advertises LINNEA_QUIC_IDLE_SECS
# (30) and used to ignore the client's 0x01 transport parameter entirely, so a
# client that said it would forget us in a second still held a pool slot for 30.
#   post-fix: a client advertising a short one is discarded on ITS window
#   pre-fix:  the server keeps the connection for its own 30s either way
#
# Both cases run here, and the CONTROL is what makes this a test rather than a
# coincidence: the same silent window with a GENEROUS max_idle_timeout must still
# be served. Without it, "no response" only shows that a connection went idle —
# it would pass against a server that ignores the parameter and one that reads it.
#
# Two things the client must not do, or it measures itself instead of the server:
#   - aioquic derives its OWN idle timer from the same configuration value, so it
#     would close first. The virtual clock (0.002s per call, as in
#     h3_key_update_test.py) keeps every client timer from ever firing, leaving
#     the server as the only endpoint that can drop us.
#   - nothing may leave the socket during the silent window: any packet restarts
#     the server's idle timer. So no flush() and no handle_timer() in there.
#
# This is also the answer to "the idle timeout is time-based, so testing it needs
# a 30s+ wait": it needs 4 seconds, because the client picks the window.
# Usage: h3_idle_tp_test.py <port> [host]   (host defaults to 127.0.0.1)
import socket
import ssl
import sys
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.events import ConnectionTerminated

PORT = int(sys.argv[1])
HOST = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
SNI = HOST if HOST != "127.0.0.1" else "localhost"
ADDR = (socket.gethostbyname(HOST), PORT)

SHORT = 1          # advertised max_idle_timeout, seconds: server reclaims past it
QUIET = 4          # silent window: over SHORT, well under the server's own 30
GENEROUS = 60      # the control's advertised value: the server's 30 wins


def run(idle_secs):
    """Handshake, GET, go silent for QUIET seconds, GET again.

    Returns the second GET's :status, or None if the server stopped answering.
    """
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
                            idle_timeout=idle_secs)
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = SNI
    conn = QuicConnection(configuration=cfg)
    vt = [0.0]

    def clk():
        vt[0] += 0.002
        return vt[0]

    conn.connect(ADDR, now=clk())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.1)

    def flush():
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ADDR)

    flush()
    deadline = time.time() + 10
    while not conn._handshake_confirmed and time.time() < deadline:
        try:
            r, _ = s.recvfrom(4096)
            conn.receive_datagram(r, ADDR, now=clk())
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
    if not conn._handshake_confirmed:
        sys.exit("handshake failed (advertised %gs)" % idle_secs)

    h3 = H3Connection(conn)
    gone = [False]

    def get(tag):
        sid = conn.get_next_available_stream_id()
        h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                              (b":authority", SNI.encode()), (b":path", b"/")],
                        end_stream=True)
        flush()
        end = time.time() + 8
        while time.time() < end:
            try:
                r, _ = s.recvfrom(65535)
                conn.receive_datagram(r, ADDR, now=clk())
            except socket.timeout:
                pass
            for qe in iter(conn.next_event, None):
                # a stateless reset means the server holds no state for this
                # connection id, which is the same observation as silence
                if isinstance(qe, ConnectionTerminated):
                    gone[0] = True
                    print("  %s: connection terminated by the peer" % tag)
                    return None
                for ev in h3.handle_event(qe):
                    if isinstance(ev, HeadersReceived):
                        st = dict(ev.headers).get(b":status", b"?").decode()
                        print("  %s: :status %s" % (tag, st))
                        return st
            flush()
        print("  %s: no response" % tag)
        return None

    print("advertised max_idle_timeout = %gs" % idle_secs)
    if get("first GET") != "200":
        sys.exit("first GET failed (advertised %gs) - connection never worked, "
                 "nothing to conclude" % idle_secs)
    time.sleep(QUIET)
    print("  stayed silent %gs" % QUIET)
    st = get("second GET")
    s.close()
    return st


short = run(SHORT)
generous = run(GENEROUS)

if generous != "200":
    sys.exit("CONTROL FAILED: a connection advertising %gs was dropped after only "
             "%gs idle (got %r) - the server is not honouring its own %s window, "
             "so the short case proves nothing"
             % (GENEROUS, QUIET, generous, "30s"))
if short is not None:
    sys.exit("advertising max_idle_timeout=%gs was still served after %gs idle "
             "(:status %s) - the client's parameter is being ignored (RFC 9000 10.1)"
             % (SHORT, QUIET, short))
print("PASS: the short max_idle_timeout was honoured, the generous one was not")
