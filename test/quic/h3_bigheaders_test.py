#!/usr/bin/env python3
# A request whose header section is larger than the server will hold must be
# refused on its own stream, and the connection must survive it.
#
# This used to be reported as QPACK_DECOMPRESSION_FAILED — a connection-level
# error — so one ordinary request with too many cookies destroyed every other
# request in flight on the same connection, and a client awaiting only its own
# response saw nothing at all. It is our resource limit, not the peer's encoder
# going wrong: RFC 9114 4.2.2 wants a 431 or a stream reset.
#
# The field section is hand-built with raw (non-Huffman) literals: pylsqpack
# refuses to encode a list this large, and raw literals exercise the header-list
# bound rather than the Huffman output buffer.
# Usage: h3_bigheaders_test.py <port>
import socket
import ssl
import sys

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived, ConnectionTerminated

port = int(sys.argv[1])
ADDR = ("127.0.0.1", port)


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def qint(v, prefix_bits, pattern):
    """QPACK/HPACK prefix integer (RFC 7541 5.1)."""
    mask = (1 << prefix_bits) - 1
    if v < mask:
        return bytes([pattern | v])
    out = bytearray([pattern | mask])
    v -= mask
    while v >= 128:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def lit(name, value):
    """Literal field line with literal name, neither Huffman-coded."""
    return (qint(len(name), 3, 0x20) + name
            + qint(len(value), 7, 0x00) + value)


def field_section(extra):
    fs = b"\x00\x00"                     # Required Insert Count 0, Delta Base 0
    for n, v in ([(b":method", b"GET"), (b":path", b"/hello.txt"),
                  (b":scheme", b"https"), (b":authority", b"h3.test")] + extra):
        fs += lit(n, v)
    return fs


def connect():
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    conn.connect(ADDR, now=0.0)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)

    def flush(t):
        for d, _ in conn.datagrams_to_send(now=t):
            s.sendto(d, ADDR)

    flush(0.0)
    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ADDR, now=0.1)
    flush(0.2)
    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ADDR, now=0.3)
    assert conn._handshake_confirmed, "handshake not confirmed"
    while conn.next_event() is not None:
        pass
    return conn, s, flush


def ask(conn, s, flush, sid, fs, t0):
    """Send one request; return ('status', code) / ('killed', err) / None."""
    conn.send_stream_data(sid, vlq(1) + vlq(len(fs)) + fs, end_stream=True)
    t = t0
    try:
        for _ in range(14):
            flush(t)
            t += 0.1
            r, _ = s.recvfrom(4096)
            conn.receive_datagram(r, ADDR, now=t)
            t += 0.1
            ev = conn.next_event()
            while ev is not None:
                if isinstance(ev, ConnectionTerminated):
                    return ("killed", hex(ev.error_code)), t
                if isinstance(ev, StreamDataReceived) and ev.stream_id == sid and ev.data:
                    b = ev.data
                    assert b[0] == 1, f"first frame is not HEADERS: {b[:4]!r}"
                    n = 1 << (b[1] >> 6)
                    ln = b[1] & 0x3F
                    for k in range(1, n):
                        ln = (ln << 8) | b[1 + k]
                    off = 1 + n
                    _, h = pylsqpack.Decoder(0, 0).feed_header(sid, b[off:off + ln])
                    return ("status", dict(h).get(b":status")), t
                ev = conn.next_event()
    except socket.timeout:
        pass
    return None, t


conn, s, flush = connect()

# ~8.2 KB of header list: over the bound, but a perfectly well-formed request
big = [(b"cookie%d" % i, b"x" * 2000) for i in range(4)]
got, t = ask(conn, s, flush, 0, field_section(big), 0.4)
assert got is not None, "oversized request got no answer at all"
assert got[0] != "killed", f"connection destroyed instead of answering the stream: {got}"
assert got[1] == b"431", f"expected 431, got {got}"

# and the connection is still good: the next request is served normally
got2, _ = ask(conn, s, flush, 4, field_section([]), t)
assert got2 is not None and got2[0] == "status" and got2[1] == b"200", \
    f"connection unusable after the 431: {got2}"
s.close()
print("ok (oversized header list -> 431 on the stream, connection survives)")
