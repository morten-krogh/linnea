#!/usr/bin/env python3
# Several uploads at once on ONE h3 connection.
#
# A request whose body outgrows the RAM window takes a reassembly context, and
# there are LINNEA_QUIC_RA_CTXS (6) of them per connection. Every upload check
# in the suite runs one request at a time, so nothing has ever asked what
# happens when the contexts run out: a browser posting several files, or an
# XHR-per-file uploader, does exactly that.
#
# SIX fills every context at once and must all be served.
#
# NINE cannot fit, and the three that miss out must be REFUSED rather than
# dropped: RESET_STREAM + STOP_SENDING carrying H3_REQUEST_REJECTED (0x10b),
# which means "not processed, safe to retry". That is what makes a limit of six
# acceptable — the client is told, in a way it can act on, instead of holding a
# request that never returns.
#
# An earlier version of this check asserted only the six and described the
# other three as hanging for ever. They were not hanging: the check simply
# never looked at StreamReset, so a correct refusal was indistinguishable from
# silence. Both terminal outcomes are asserted now, and a stream that ends in
# NEITHER is the actual regression to catch.
#
# Each body is distinct and checked byte for byte: with several reassemblies
# in flight through one connection, bytes landing in the wrong context is the
# failure that matters, and equal-length bodies would hide it.
#
# Usage: h3_concurrent_uploads_test.py <port>
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)
# Past LINNEA_QUIC_RA_BUF (32768) so each one really needs a context and a
# capture file; different lengths so a mixed-up body cannot look right.
H3_REQUEST_REJECTED = 0x10b
SIZES = [40000, 41000, 42000, 43000, 44000, 45000, 46000, 47000, 48000]


def run(count):
    bodies = {}
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    conn.connect(ADDR, now=time.time())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.02)

    def flush():
        for d, _ in conn.datagrams_to_send(now=time.time()):
            sock.sendto(d, ADDR)

    flush()
    dl = time.time() + 15
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            conn.receive_datagram(sock.recvfrom(2048)[0], ADDR, now=time.time())
        except socket.timeout:
            pass
        flush()
    if not conn._handshake_confirmed:
        return "handshake failed"

    h3 = H3Connection(conn)
    got = {}
    status = {}
    # Opened before any is sent, so they really are in flight together rather
    # than one after another.
    for i in range(count):
        n = SIZES[i % len(SIZES)] + i
        body = bytes(((i + 1) * 37 + j * 11) & 0xFF for j in range(n))
        sid = conn.get_next_available_stream_id()
        bodies[sid] = body
        got[sid] = b""
        h3.send_headers(sid, [(b":method", b"POST"), (b":scheme", b"https"),
                              (b":authority", b"localhost"), (b":path", b"/api/echo"),
                              (b"content-length", str(n).encode())], end_stream=False)
    for sid, body in bodies.items():
        h3.send_data(sid, body, end_stream=True)
    flush()

    done = set()
    refused = {}
    dl = time.time() + 120
    while time.time() < dl and len(done) < count:
        try:
            conn.receive_datagram(sock.recvfrom(2048)[0], ADDR, now=time.time())
        except socket.timeout:
            pass
        while True:
            ev = conn.next_event()
            if ev is None:
                break
            evname = type(ev).__name__
            if evname == "ConnectionTerminated":
                sock.close()
                return "the server closed the connection: error 0x%x %r" % (
                    ev.error_code, ev.reason_phrase)
            if evname == "StreamReset" and ev.stream_id in bodies:
                # refused rather than served: a terminal answer, and the only
                # acceptable one when every context is taken
                refused[ev.stream_id] = ev.error_code
                done.add(ev.stream_id)
            for e in h3.handle_event(ev):
                if isinstance(e, HeadersReceived):
                    status[e.stream_id] = dict(e.headers).get(b":status", b"?").decode()
                    if e.stream_ended:
                        done.add(e.stream_id)
                elif isinstance(e, DataReceived):
                    got[e.stream_id] = got.get(e.stream_id, b"") + e.data
                    if e.stream_ended:
                        done.add(e.stream_id)
        flush()
    sock.close()

    if len(done) < count:
        missing = [s for s in bodies if s not in done]
        return ("%d of %d reached a terminal answer; %d got NEITHER a response "
                "nor a reset, which is the silent drop this guards against"
                % (len(done), count, len(missing)))
    wrongcode = {s: c for s, c in refused.items() if c != H3_REQUEST_REJECTED}
    if wrongcode:
        return ("refused with %s, want H3_REQUEST_REJECTED 0x10b (the code that "
                "tells the client it may retry)"
                % sorted({hex(c) for c in wrongcode.values()}))
    served = [s for s in bodies if s not in refused]
    if not served:
        return "every one of the %d was refused; none was served" % count
    bad = [s for s in served if status.get(s) != "200"]
    if bad:
        return "statuses %s (want all 200)" % sorted({status.get(s) for s in bad})
    wrong = [s for s in served if got[s] != bodies[s]]
    if wrong:
        return ("%d of %d bodies came back wrong -- reassemblies crossed"
                % (len(wrong), len(served)))
    return (None, len(served), len(refused))


for count in (6, 9):
    t0 = time.time()
    r = run(count)
    if isinstance(r, str):
        print("%d at once: %s" % (count, r))
        sys.exit(1)
    _, served, refused = r
    if count <= 6 and refused:
        print("%d at once: %d were refused, but all six contexts were free"
              % (count, refused))
        sys.exit(1)
    print("  %d at once: %d served byte-exact, %d refused 0x10b (%.1fs)"
          % (count, served, refused, time.time() - t0))
print("ok (six served at once; past that, refused retryably rather than dropped)")
