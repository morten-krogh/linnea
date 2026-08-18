#!/usr/bin/env python3
"""A malformed upstream response head is refused the same way on every protocol.

The proxy rewrites an upstream's HTTP/1 response head into whatever the client
negotiated, so a head that cannot legally become that message must be refused
rather than translated (RFC 9110 5.5/5.6.2, RFC 9112 5, RFC 9110 8.6). HTTP/2
had done this since Finding 34. The other two had not, and each failed
differently (audit-report-6 Finding 1):

    route         h1 before   h2 before   h3 before
    badname       200 !       502         200 ! -- QPACK-encoded a field name
                                                   containing a SPACE
    badvalue      200 !       502         200 ! -- and a NUL byte in a value
    nocolon       200 !       502         200 !
    clconflict    502         502         200 ! -- took the FIRST length, kept
                                                   five bytes, and re-issued
                                                   the contradiction as a 200
    cldupe        502 !       200         200   -- h1 refused a repeat that
                                                   AGREED with itself

h1 relayed "Bad Name: x" to the client verbatim; h3 put it on the wire
QPACK-encoded, which a compliant peer may treat as a malformed field section and
answer by killing the QUIC connection -- so the leniency was not merely
cosmetic. The point of running the matrix in ONE file is that the defect was
never "protocol X is wrong": it was the three DISAGREEING, so the assertion that
matters is that they agree.

HTTP/3 is skipped, loudly, when aioquic is unavailable.

usage: proxy_upstream_head.py <cafile> <tls port>
"""
import socket
import ssl
import struct
import sys
import time

ca, port = sys.argv[1], int(sys.argv[2])
HOST = "127.0.0.1"

# route -> (expected status, expected body or None to not care)
CASES = [
    ("badname",    502, None),   # a field name that is not a token
    ("badvalue",   502, None),   # a NUL in a field value
    ("nocolon",    502, None),   # a header line with no colon at all
    ("clconflict", 502, None),   # Content-Length 5 then 7
    ("cldupe",     200, b"hello"),   # Content-Length 5 twice: agrees, so served
    # "Content-Length:   5  " -- OWS on BOTH sides of a field value is legal
    # (RFC 9112 5). h1 trimmed both and served it; the shared validator trimmed
    # only the leading half, so h2 answered 502 to a perfectly good response and
    # nothing noticed, because this fixture was only ever pointed at h1. Its
    # partner below is what stops the trim going too far: internal whitespace is
    # NOT OWS, and "12 34" must still be refused.
    ("clpad",      200, b"valid"),
    ("cljunk",     502, None),       # "Content-Length: 12 34" -- not a number
    # HTAB is OWS too, and the two framing lookups trimmed only SP -- so h2 and
    # h3 answered 502 to these while h1 served them (audit-report-7 Finding 2).
    ("cltab",      200, b"valid"),   # HTAB either side
    ("cltablead",  200, b"valid"),   # leading only
    ("cltabtrail", 200, b"valid"),   # trailing only
    # An upstream 1xx is an INTERIM response: the final one still follows
    # (RFC 9114 4.1, and RFC 9110 15.2 makes forwarding it a MUST). h3 used to
    # classify any status under 200 as a bodiless FINAL response, deliver the
    # 103 and tear the leg down, so the answer never arrived at all
    # (audit-report-7 Finding 1). The status checked here is the FINAL one; the
    # interim sequence itself is checked below.
    ("early",         200, b"final-reply"),   # 103, then 200 in a later write
    ("early-atonce",  200, b"final-reply"),   # both in ONE upstream write
    ("multi-early",   200, b"final-reply"),   # 103, 103, 100, then 200
    ("upgrade101",    502, None),    # a 101 has no meaning here: refuse it
    ("simple",     200, b"backend body"),
]

# The interim responses must arrive as their own HEADERS frames, in order,
# ahead of the final one -- not be silently dropped, which would deliver the
# right body while quietly violating RFC 9110 15.2.
INTERIM_SEQ = {
    "early":        ["103", "200"],
    "early-atonce": ["103", "200"],
    "multi-early":  ["103", "103", "100", "200"],
    "simple":       ["200"],
}

fails = 0


def check(name, ok, detail=""):
    global fails
    print(f"{'ok  ' if ok else 'FAIL'} {name}{detail}")
    if not ok:
        fails += 1


# ---------------------------------------------------------------- HTTP/1.1 --
def h1(route):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["http/1.1"])
    s = ctx.wrap_socket(socket.create_connection((HOST, port), timeout=10),
                        server_hostname="localhost")
    s.sendall(b"GET /api/" + route.encode() + b" HTTP/1.1\r\nHost: localhost\r\n"
              b"Connection: close\r\n\r\n")
    s.settimeout(10)
    buf = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
    except (socket.timeout, OSError):
        pass
    s.close()
    if not buf:
        return None, b"", []
    # Skip interim responses, as any HTTP/1 client must: a 1xx is a complete
    # head followed by the real response (RFC 9110 15.2). Without this the
    # helper reads the 103's head as the answer and calls the rest "the body",
    # which is a bug in the CLIENT -- curl gets these right -- and would have
    # been reported here as a server fault.
    while True:
        head, sep, rest = buf.partition(b"\r\n\r\n")
        if not sep:
            return None, b"", []
        lines = head.split(b"\r\n")
        st = int(lines[0].split(b" ")[1])
        if 100 <= st < 200:
            buf = rest
            continue
        return st, rest, lines[1:]


# ------------------------------------------------------------------ HTTP/2 --
def h2(route):
    def fr(t, fl, sid, p=b""):
        return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p

    def es(b):
        return bytes([len(b)]) + b

    def hd(n, v):
        return b"\x00" + es(n) + es(v)

    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection((HOST, port), timeout=10),
                        server_hostname="localhost")
    blk = (hd(b":method", b"GET") + hd(b":scheme", b"https")
           + hd(b":authority", b"localhost") + hd(b":path", b"/api/" + route.encode()))
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(0x4, 0, 0)
              + fr(0x1, 0x4 | 0x1, 1, blk))
    s.settimeout(10)
    buf, st, body, done = b"", None, b"", False
    try:
        while not done:
            d = s.recv(65536)
            if not d:
                break
            buf += d
            while len(buf) >= 9:
                ln = int.from_bytes(buf[:3], "big")
                if len(buf) < 9 + ln:
                    break
                ft, fl, pl = buf[3], buf[4], buf[9:9 + ln]
                buf = buf[9 + ln:]
                if ft == 0x0:
                    body += pl
                if ft == 0x1:
                    for i in range(len(pl) - 2):
                        c = pl[i:i + 3]
                        if c.isdigit():
                            st = int(c)
                            break
                if ft in (0x0, 0x1) and fl & 0x1:
                    done = True
                if ft == 0x3:
                    done = True
    except (socket.timeout, OSError):
        pass
    s.close()
    return st, body, []


# ------------------------------------------------------------------ HTTP/3 --
def h3_all(routes):
    """-> {route: (status, body, [extra field lines])}, or None if unavailable."""
    try:
        import pylsqpack
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.connection import QuicConnection
        from aioquic.quic.events import StreamDataReceived, StreamReset
    except ImportError:
        return None

    def vlq(n):
        if n < 64:
            return bytes([n])
        if n < 16384:
            return (0x4000 | n).to_bytes(2, "big")
        return (0x80000000 | n).to_bytes(4, "big")

    def rvlq(b, i):
        n = 1 << (b[i] >> 6)
        v = b[i] & 0x3F
        for k in range(1, n):
            v = (v << 8) | b[i + k]
        return v, i + n

    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    addr = (HOST, port)
    conn.connect(addr, now=0.0)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    clock = [0.0]

    def pump():
        for d, _ in conn.datagrams_to_send(now=clock[0]):
            sock.sendto(d, addr)

    pump()
    for _ in range(8):
        try:
            r, _ = sock.recvfrom(4096)
        except socket.timeout:
            break
        clock[0] += 0.1
        conn.receive_datagram(r, addr, now=clock[0])
        pump()
        if conn._handshake_confirmed:
            break
    if not conn._handshake_confirmed:
        return {}
    while conn.next_event() is not None:
        pass
    clock[0] = 0.4

    out = {}
    for route in routes:
        enc = pylsqpack.Encoder()
        enc.apply_settings(max_table_capacity=0, blocked_streams=0)
        _, blk = enc.encode(0, [(b":method", b"GET"),
                                (b":path", b"/api/" + route.encode()),
                                (b":scheme", b"https"), (b":authority", b"localhost")])
        bidi = conn.get_next_available_stream_id()
        conn.send_stream_data(bidi, vlq(1) + vlq(len(blk)) + blk, end_stream=True)
        resp, reset = b"", False
        sock.settimeout(0.3)
        deadline = time.time() + 15
        while not resp and not reset and time.time() < deadline:
            pump()
            clock[0] += 0.2
            try:
                r, _ = sock.recvfrom(65536)
            except socket.timeout:
                continue
            conn.receive_datagram(r, addr, now=clock[0])
            ev = conn.next_event()
            while ev is not None:
                if isinstance(ev, StreamDataReceived) and ev.stream_id == bidi:
                    resp += ev.data
                elif isinstance(ev, StreamReset) and ev.stream_id == bidi:
                    reset = True
                ev = conn.next_event()
        if reset and not resp:
            out[route] = ("RESET", b"", [], [])
            continue
        i, st, body, extra, seq = 0, None, b"", [], []
        dec = pylsqpack.Decoder(0, 0)
        while i < len(resp):
            ty, i = rvlq(resp, i)
            ln, i = rvlq(resp, i)
            if ty == 1:
                _, h = dec.feed_header(0, resp[i:i + ln])
                st = int(dict(h).get(b":status", b"0"))
                seq.append(dict(h).get(b":status", b"?").decode())
                extra = [b"%s: %s" % (n, v) for n, v in h if not n.startswith(b":")]
            elif ty == 0:
                body += resp[i:i + ln]
            i += ln
        out[route] = (st, body, extra, seq)
    return out


h3 = h3_all([r for r, _, _ in CASES])

for route, want_status, want_body in CASES:
    got = {}
    got["h1"] = h1(route)
    got["h2"] = h2(route)
    if h3 is not None:
        got["h3"] = h3.get(route, (None, b"", [], []))

    statuses = {p: v[0] for p, v in got.items()}
    check(f"{route}: every protocol answers {want_status}",
          all(s == want_status for s in statuses.values()),
          f"  {statuses}")

    if want_body is not None:
        bodies = {p: v[1] for p, v in got.items()}
        check(f"{route}: every protocol returns the same body",
              all(b == want_body for b in bodies.values()), f"  {bodies}")

    # ...and for the malformed ones, nothing of the bad head may have travelled.
    if want_status == 502:
        leaked = {p: [l for l in v[2]
                      if b"bad name" in l.lower() or b"\x00" in l or b"nocolon" in l.lower()]
                  for p, v in got.items()}
        check(f"{route}: no part of the bad head reaches the client",
              not any(leaked.values()), f"  {leaked}" if any(leaked.values()) else "")

# --- the interim frames themselves, on HTTP/3 --------------------------------
if h3 is not None:
    for route, want_seq in INTERIM_SEQ.items():
        got_seq = (h3.get(route) or (None, b"", [], []))[3]
        check(f"{route}: h3 relays the interim responses in order",
              got_seq == want_seq, f"  got {got_seq}, want {want_seq}")

if h3 is None:
    print("note: HTTP/3 not checked (aioquic unavailable) -- h1 and h2 only")

sys.exit(1 if fails else 0)
