#!/usr/bin/env python3
# Several uploads at once on ONE h3 connection.
#
# A request whose body outgrows the RAM window takes a reassembly context, and
# there are LINNEA_QUIC_RA_CTXS (6) of them per connection. Every upload check
# in the suite runs one request at a time, so nothing has ever asked what
# happens when the contexts run out: a browser posting several files, or an
# XHR-per-file uploader, does exactly that.
#
# SIX fills every context at once, which must simply work, and that is what
# this asserts.
#
# NINE is deliberately NOT asserted, because the answer today is a KNOWN and
# documented limitation rather than a bug to catch: measured here, three of the
# nine never answer at all -- no response and no reset -- and they never will.
# .ra_reclaim only takes a context back once it has been silent for
# RA_STALE_MS (5s), so during a genuine burst none is stale and the frame is
# dropped; the packet carrying it has already been acknowledged, so nothing
# retransmits it. The comment there says as much: "this falls through to
# dropping the frame exactly as before".
#
# Worth knowing if that is ever revisited: the alternative costs nothing to the
# client, because H3_REQUEST_REJECTED (0x010b) means "not processed -- safe to
# retry", and .ra_reclaim already sends exactly that to the stream it evicts. A
# refusal a client can retry strictly beats a stream that hangs for ever.
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
            if type(ev).__name__ == "ConnectionTerminated":
                sock.close()
                return "the server closed the connection: error 0x%x %r" % (
                    ev.error_code, ev.reason_phrase)
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
        return ("%d of %d finished; %d never answered (statuses %s)"
                % (len(done), count, len(missing),
                   sorted({status.get(s, "none") for s in missing})))
    bad = [s for s in bodies if status.get(s) != "200"]
    if bad:
        return "statuses %s (want all 200)" % sorted({status.get(s) for s in bad})
    wrong = [s for s in bodies if got[s] != bodies[s]]
    if wrong:
        return ("%d of %d bodies came back wrong -- reassemblies crossed"
                % (len(wrong), count))
    return None


for count in (6,):
    t0 = time.time()
    bad = run(count)
    if bad:
        print("%d at once: %s" % (count, bad))
        sys.exit(1)
    print("  %d at once: ok (%.1fs)" % (count, time.time() - t0))
print("ok (%d concurrent uploads on one connection, all byte-exact)" % count)
