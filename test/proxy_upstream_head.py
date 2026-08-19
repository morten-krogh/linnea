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

Report 9 added two more of the same shape: a status line ended by a BARE CR was
normalised into a 200 on all three (Finding 1), and Content-Length was relayed on
the two statuses HTTP forbids it on -- where h1 also turned out never to have
relayed an interim head at all, taking the 103 for the final response (Finding
2).

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
    # RFC 9112 2.3: HTTP-version is HTTP-name "/" DIGIT "." DIGIT, so
    # "HTTP/x.y 200 OK" is not a status line. The shared validator skipped the
    # status line outright and only h1 checked it afterwards, so h2 and h3
    # manufactured a downstream 200 from the three digits and never looked at
    # the version (audit-report-8 Finding 1). /api/http10 is its control: a
    # legal HTTP/1.0 upstream must still translate.
    ("badversion",    502, None),
    ("http10",        200, b"old hi"),
    # Six 103 Early Hints whose ENCODED sum overran the one staging buffer the
    # interim frames share, so h3 answered 502 to an exchange h1 and h2 served
    # (audit-report-8 Finding 2).
    ("bigearly",      200, b"valid"),
    # RFC 9112 2.2: a CR ends an HTTP/1 line only when an LF follows it. The
    # shared gate located the status line's first CR and stepped over two bytes
    # without looking at the second, so "HTTP/1.1 200\rX-Fold: accepted" was
    # read as a status line plus a field named "-Fold" -- and normalised into an
    # ordinary 200 on all three protocols, h1 even writing a real CRLF where the
    # bare CR had been (audit-report-9 Finding 1).
    ("badstatuscr",   502, None),
    # RFC 9110 8.6 forbids Content-Length on 1xx and 204. Upstreams send it
    # anyway; the proxy relayed it. These three are judged by NO_CLEN below as
    # well as by status and body (audit-report-9 Finding 2).
    ("204",           204, b""),        # 204 whose upstream sent one
    ("204clean",      204, b""),        # ...and the control that did not
    ("earlycl",       200, b"valid"),   # a 103 carrying one, then the real 200
    # RFC 9110 15.3.6: a 205 implies no content and a server MUST NOT generate
    # any. All three framing paths listed HEAD/204/304 and omitted 205, so a
    # four-byte 205 was relayed as a four-byte response (audit-report-10
    # Finding 1). Unlike 204 a 205 MAY carry Content-Length -- to say zero -- so
    # this is NOT report 9's "Content-Length is forbidden" rule, and the two
    # controls below are what stop the fix becoming "refuse every 205".
    ("205body",       502, None),   # declares four bytes: a contradiction
    ("205chunked",    502, None),   # ...and the other way of framing content
    ("205zero",       205, b""),    # legal: Content-Length: 0
    ("205bare",       205, b""),    # legal: no framing at all
    # RFC 9110 7.6.1: Connection NAMES the connection-specific fields, and an
    # intermediary must drop every name it lists. Linnea dropped the fixed list
    # it knew and relayed whatever the upstream nominated (Finding 2). The
    # request direction has had this rule since http_conn_option_named; the
    # response direction never got it.
    ("hopnamed",      200, b"body"),
    ("hopnamedmulti", 200, b"body"),   # two lines, OWS, mixed case, plus close
    ("earlyhop",      200, b"valid"),  # ...and on an INTERIM head
    ("simple",     200, b"backend body"),
]

# route -> field names that must not survive on ANY protocol, in ANY field
# section: the upstream nominated them in its own Connection header.
NOMINATED = {
    "hopnamed":      [b"x-backend-only"],
    "hopnamedmulti": [b"x-one", b"x-two", b"x-three"],
    "earlyhop":      [b"x-hint-only"],
}
# ...and the control that stops the fix becoming "drop everything unfamiliar".
KEPT = {"hopnamed": b"x-kept", "hopnamedmulti": b"x-kept"}

# Routes the HTTP/3 leg here cannot judge, and why. Listed rather than quietly
# dropped, so a reader sees the gap instead of assuming coverage.
H3_SKIP = {
    "bigearly": "pylsqpack stops decoding once a stream's field sections total "
                "more than a few KiB, which any response big enough to exercise "
                "this bound also exceeds -- curl-h3 handles it, and the shard "
                "checks it with curl-h3 instead",
}

# The interim responses must arrive as their own HEADERS frames, in order,
# ahead of the final one -- not be silently dropped, which would deliver the
# right body while quietly violating RFC 9110 15.2.
INTERIM_SEQ = {
    "early":        ["103", "200"],
    "earlycl":      ["103", "200"],
    "earlyhop":     ["103", "200"],
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
        return None, b"", [], []
    # Step over interim responses, as any HTTP/1 client must: a 1xx is a
    # complete head followed by the real response (RFC 9110 15.2). Without this
    # the helper reads the 103's head as the answer and calls the rest "the
    # body", which is a bug in the CLIENT -- curl gets these right -- and would
    # have been reported here as a server fault. Each head is kept, so what the
    # interim ones carried can be judged too.
    sections = []
    while True:
        head, sep, rest = buf.partition(b"\r\n\r\n")
        if not sep:
            return None, b"", [], sections
        lines = head.split(b"\r\n")
        parts = lines[0].split(b" ")
        st = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        sections.append((str(st), lines[1:]))
        if 100 <= st < 200:
            buf = rest
            continue
        return st, rest, lines[1:], sections


# ------------------------------------------------------------------ HTTP/2 --
# linnea never inserts into the HPACK dynamic table and never Huffman-encodes a
# response: every field goes out as "literal without indexing" with the name
# either a static index or a literal. A stateless decoder is therefore exact.
# Anything outside that shape is surfaced rather than skipped, since it would
# mean the encoder changed under a test that had quietly stopped reading it.
HPACK_STATIC = [b""] + (
    ":authority :method :method :path :path :scheme :scheme :status :status "
    ":status :status :status :status :status accept-charset accept-encoding "
    "accept-language accept-ranges accept access-control-allow-origin age "
    "allow authorization cache-control content-disposition content-encoding "
    "content-language content-length content-location content-range "
    "content-type cookie date etag expect expires from host if-match "
    "if-modified-since if-none-match if-range if-unmodified-since last-modified "
    "link location max-forwards proxy-authenticate proxy-authorization range "
    "referer refresh retry-after server set-cookie strict-transport-security "
    "transfer-encoding user-agent vary via www-authenticate"
).encode().split()


def hpack_int(b, i, prefix):
    mask = (1 << prefix) - 1
    v = b[i] & mask
    i += 1
    if v < mask:
        return v, i
    shift = 0
    while True:
        v += (b[i] & 0x7F) << shift
        shift += 7
        more = b[i] & 0x80
        i += 1
        if not more:
            return v, i


def hpack_str(b, i):
    huffman = b[i] & 0x80
    n, i = hpack_int(b, i, 7)
    return (b"<huffman>" if huffman else b[i:i + n]), i + n


def hpack_decode(blk):
    out, i = [], 0
    while i < len(blk):
        c = blk[i]
        if c & 0x80:                       # indexed field, name and value both
            idx, i = hpack_int(blk, i, 7)
            out.append((HPACK_STATIC[idx] if idx < len(HPACK_STATIC)
                        else b"<dynamic>", b"<indexed>"))
            continue
        if c & 0xE0 == 0x20:               # dynamic table size update
            _, i = hpack_int(blk, i, 5)
            continue
        idx, i = hpack_int(blk, i, 6 if c & 0x40 else 4)
        if idx:
            name = HPACK_STATIC[idx] if idx < len(HPACK_STATIC) else b"<dynamic>"
        else:
            name, i = hpack_str(blk, i)
        val, i = hpack_str(blk, i)
        out.append((name.lower(), val))
    return out


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
    buf, st, body, done, sections = b"", None, b"", False, []
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
                    fields = hpack_decode(pl)
                    d2 = dict(fields)
                    code = d2.get(b":status", b"?").decode()
                    if code.isdigit():
                        st = int(code)
                    sections.append((code, [b"%s: %s" % (n, v) for n, v in fields
                                            if not n.startswith(b":")]))
                if ft in (0x0, 0x1) and fl & 0x1:
                    done = True
                if ft == 0x3:
                    done = True
    except (socket.timeout, OSError):
        pass
    s.close()
    return st, body, sections[-1][1] if sections else [], sections


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
        i, st, body, extra, sections = 0, None, b"", [], []
        dec = pylsqpack.Decoder(0, 0)
        while i < len(resp):
            ty, i = rvlq(resp, i)
            ln, i = rvlq(resp, i)
            if ty == 1:
                _, h = dec.feed_header(0, resp[i:i + ln])
                code = dict(h).get(b":status", b"?").decode()
                if code.isdigit():
                    st = int(code)
                extra = [b"%s: %s" % (n, v) for n, v in h if not n.startswith(b":")]
                sections.append((code, extra))
            elif ty == 0:
                body += resp[i:i + ln]
            i += ln
        out[route] = (st, body, extra, sections)
    return out


h3 = h3_all([r for r, _, _ in CASES if r not in H3_SKIP])

RESULTS = {}

for route, want_status, want_body in CASES:
    got = {}
    got["h1"] = h1(route)
    got["h2"] = h2(route)
    if h3 is not None and route not in H3_SKIP:
        got["h3"] = h3.get(route, (None, b"", [], []))
    RESULTS[route] = got

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

# --- the interim heads themselves, on every protocol -------------------------
# This used to ask HTTP/3 alone, because HTTP/3 was the protocol report 7 had
# just fixed. h2 has relayed interim heads since Finding 30 -- but h1 had never
# relayed one at all: it took the 103 for the final response, believed the
# Content-Length on it, and handed the client the real response's first bytes as
# the interim's body (audit-report-9 Finding 2). Asking all three is what turns
# this from a check on one protocol into a check that they agree.
for route, want_seq in INTERIM_SEQ.items():
    seqs = {p: [st for st, _ in v[3]] for p, v in RESULTS.get(route, {}).items()}
    check(f"{route}: every protocol relays the interim responses in order",
          all(seq == want_seq for seq in seqs.values()), f"  {seqs}")


# --- ...and no 1xx or 204 head carries a Content-Length ----------------------
# RFC 9110 8.6 says MUST NOT, and on an interim head it is not a mere surplus
# field: a client that believes the length reads the following response's bytes
# as this one's body. Every route is examined rather than a chosen few, so a
# fixture that later grows an interim head is covered by having been added.
def forbids_clen(code):
    return code.isdigit() and (100 <= int(code) <= 199 or int(code) == 204)


for route, got in RESULTS.items():
    if not any(forbids_clen(st) for v in got.values() for st, _ in v[3]):
        continue
    leaked = {}
    for proto, v in got.items():
        hits = [(st, f) for st, fields in v[3] if forbids_clen(st)
                for f in fields if f.lower().startswith(b"content-length")]
        if hits:
            leaked[proto] = hits
    check(f"{route}: no Content-Length on a 1xx or 204 (RFC 9110 8.6)",
          not leaked, f"  {leaked}" if leaked else "")

# --- nothing the upstream declared connection-specific may travel ------------
for route, names in NOMINATED.items():
    got = RESULTS.get(route, {})
    leaked = {}
    for proto, v in got.items():
        # h1 sends its OWN Connection header and must: it states this hop's
        # keep-alive wish. Only h2 and h3, where the field is forbidden
        # outright, are checked for it.
        hits = [(st, f) for st, fields in v[3] for f in fields
                if any(f.lower().startswith(n + b":") for n in names)
                or (proto != "h1" and f.lower().startswith(b"connection:"))]
        if hits:
            leaked[proto] = hits
    check(f"{route}: no Connection-nominated field reaches the client "
          f"(RFC 9110 7.6.1)", not leaked, f"  {leaked}" if leaked else "")

for route, keep in KEPT.items():
    got = RESULTS.get(route, {})
    present = {p: any(f.lower().startswith(keep + b":")
                      for _, fields in v[3] for f in fields)
               for p, v in got.items()}
    check(f"{route}: the ordinary field beside them is still relayed",
          all(present.values()), f"  {present}")

for route, why in H3_SKIP.items():
    print(f"note: {route} not checked over HTTP/3 here -- {why}")

if h3 is None:
    print("note: HTTP/3 not checked (aioquic unavailable) -- h1 and h2 only")

sys.exit(1 if fails else 0)
