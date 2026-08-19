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
    # RFC 9110 7.8: a sender of Upgrade names it as a Connection option so
    # intermediaries do not forward it. Report 10's Connection walk exempted
    # `upgrade` unconditionally so the 101 tunnel could complete -- broader than
    # its purpose, and an HTTP/1-only leak on an ordinary 200 response
    # (audit-report-11 Finding 1). h2 and h3 drop it from their fixed tables.
    ("upgrade200",    200, b"body"),
    # RFC 9112 6.1's own example: gzipped THEN chunk-framed. Removing the chunk
    # framing does not undo the gzip (audit-report-11 Finding 2).
    ("tegzip",        502, None),
    ("tegzipbare",    502, None),
    ("tepad",         200, b"plain"),   # sole chunked, with OWS and case: served
    # Content-Encoding is a REPRESENTATION property and end-to-end;
    # Transfer-Encoding is a property of the HTTP/1 message on ONE hop. Refusing
    # a transfer coding we cannot remove must not disturb a content coding we
    # were never meant to touch -- otherwise the fix above would have broken
    # every compressed backend response.
    ("cegzip",        200, None),
    # RFC 9112 6.1: Transfer-Encoding MUST NOT appear on a 1xx or a 204 -- an
    # absolute prohibition, unlike 205 where the field is permitted to state
    # zero. h1 emitted an invalid 204 carrying it while h2/h3 scrubbed it into a
    # clean success, so one bad backend head produced three client-visible
    # answers (audit-report-12 Finding 1).
    ("204te",         502, None),
    ("204tezero",     502, None),   # it is the FIELD, not the bytes behind it
    ("earlyte",       502, None),   # ...and on an interim head
    # RFC 9110 5.1: a proxy MUST forward unrecognized fields. h2 and h3 dropped
    # any field name past 64 bytes -- an encoder scratch-buffer size, not an
    # HTTP limit or a configured policy -- while h1 forwarded it, so an
    # extension field survived or vanished by ALPN (Finding 2).
    ("name64",        200, b"body"),
    ("name65",        200, b"body"),
    ("namebig",       502, None),   # past the documented limit: refused everywhere
    # RFC 9110 15: a status code is a three-digit integer in 100..599. The gate
    # checked that there were three DIGITS and never their range, so h1 relayed
    # 099 as an interim response -- a lifecycle decision, not just a display one
    # -- while h2/h3 refused it, and nothing anywhere checked the upper bound
    # (audit-report-13 Finding 1).
    ("status099",     502, None),
    ("status600",     502, None),
    ("status299",     299, b"body"),   # in range, unregistered: MUST be forwarded
    # Repeated list-valued field lines combine, so two of them state
    # "chunked, chunked": two layers, forbidden, and not what the one layer
    # below is. Each line was checked in isolation (Finding 2).
    ("tedupe",        502, None),
    # Connection names which fields are specific to THIS hop; it does not unsay
    # what they mean ON this hop. h1 filtered them before reading its own
    # framing, so a nominated Transfer-Encoding left the response
    # close-delimited and h1 relayed the chunk syntax as content while h2/h3
    # de-chunked properly (audit-report-14 Finding 1).
    ("connte",        200, b"body"),
    ("conncl",        200, b"body"),
    ("conntecl",      502, None),      # still a framing conflict when nominated
    # HTTP/1 OWS around a value belongs to the field LINE. RFC 9113 8.2.1
    # forbids an h2 value that starts or ends with SP or HTAB; h2 and h3
    # stripped a leading SP and nothing else (Finding 2).
    ("fieldows",      200, b"body"),
    ("fieldsptrail",  200, b"body"),
    ("fieldinner",    200, b"body"),   # internal whitespace: must NOT be touched
    # The vhost's configured hsts/nosniff describe the ORIGIN, so they ride a
    # proxied response on every protocol. h1 added them to static and error
    # heads but not to a successful proxied one (audit-report-15 Finding 1), and
    # an upstream could switch them off on h2/h3 by naming its own copies in
    # Connection: dropped from the response, yet still counted as "the backend
    # set a policy" (Finding 2).
    ("sechop",        200, b"body"),
    ("secown",        200, b"body"),
    # An upstream Connection line is specific to the upstream hop and must not
    # travel. Report 14's framing-first move left h1's check reading registers
    # framing had clobbered, so it forwarded the line -- and beside report 15
    # that is a policy bypass: the upstream names our own field, we replace the
    # discarded backend value with the configured one, and then hand the client
    # the instruction to discard the replacement (audit-report-16).
    ("connsts",       200, b"body"),
    ("connclose",     200, b"body"),
    ("connfirst",     200, b"body"),   # the position that worked by accident
    # Malformed chunk framing. h2's decoder took a leading space that
    # RFC 9112 7.1's 1*HEXDIG does not allow, and shifted its accumulator
    # unbounded so a 17-digit size wrapped to ZERO and read as the terminal
    # chunk -- a truncated response completing successfully (audit-report-17).
    # Found beside it: h3 accepted a chunked capture that simply STOPPED,
    # delivering the bytes that had arrived as a whole 200.
    ("chunkspace",    502, None),
    ("chunkoverflow", 502, None),
    ("chunkbig",      502, None),      # 16 digits: too big, but never wraps
    ("chunktrunc",    502, None),      # the body just stops
    # "0\r\n" opens the TRAILER section; the empty line after it ends the
    # message. h2 collapsed those two boundaries and completed at the first, so
    # an upstream closing after "0\r\n" produced a clean 200 (audit-report-18).
    ("chunknoterm",       502, None),
    ("chunkpartialtrail", 502, None),
    # ...and a COMPLETE message that carries a trailer field. A decoder that
    # stops at the zero-size line passes this by ignoring the bytes that make it
    # valid, so the control has to exist.
    ("chunktrailer",  200, b"body"),
    ("simple",     200, b"backend body"),
]

# route -> field names that must not survive on ANY protocol, in ANY field
# section: the upstream nominated them in its own Connection header.
NOMINATED = {
    "upgrade200":    [b"upgrade"],
    "hopnamed":      [b"x-backend-only"],
    "hopnamedmulti": [b"x-one", b"x-two", b"x-three"],
    "earlyhop":      [b"x-hint-only"],
}
# ...and the control that stops the fix becoming "drop everything unfamiliar".
KEPT = {"hopnamed": b"x-kept", "hopnamedmulti": b"x-kept",
        "cegzip": b"content-encoding"}
# route -> a field name that must survive on ALL THREE, whatever its length.
# The point is not the length but that the three agree about it.
LONGNAME = {"name64": b"x-" + b"a" * 62, "name65": b"x-" + b"a" * 63}
# route -> the exact value every protocol must present for x-note. The bytes
# matter, not just the field's presence: OWS is a field-line delimiter, and
# internal whitespace is value.
FIELDVAL = {"fieldows": b"value", "fieldsptrail": b"value",
            "fieldinner": b"value one"}
# route -> (expected Strict-Transport-Security value, expected nosniff value).
# The vhost configures max-age=31536000; /api/secown sends its own max-age=99,
# which must WIN and must not be duplicated -- that is what stops the fix from
# becoming "always append ours".
CONFIGURED_STS = b"max-age=31536000"
POLICY = {"simple": CONFIGURED_STS, "sechop": CONFIGURED_STS,
          "secown": b"max-age=99"}

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
        # h1 relays chunked framing as framing -- that is the protocol, not a
        # defect -- so de-chunk here or a chunked route's body compares raw
        # "5\r\nplain\r\n0\r\n\r\n" against what h2 and h3 decoded.
        if any(l.lower().startswith(b"transfer-encoding:") and b"chunked" in l.lower()
               for l in lines[1:]):
            out, i = b"", 0
            while i < len(rest):
                j = rest.find(b"\r\n", i)
                if j < 0:
                    break
                try:
                    n = int(rest[i:j].split(b";")[0], 16)
                except ValueError:
                    break
                if n == 0:
                    break
                out += rest[j + 2:j + 2 + n]
                i = j + 2 + n + 2
            rest = out
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
    was_reset = False
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
                    sections.append((code, [b"%s:%s" % (n, v) for n, v in fields
                                            if not n.startswith(b":")]))
                if ft in (0x0, 0x1) and fl & 0x1:
                    done = True
                if ft == 0x3:
                    was_reset = True
                    done = True
    except (socket.timeout, OSError):
        pass
    s.close()
    H2_RESET[route] = was_reset
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
                extra = [b"%s:%s" % (n, v) for n, v in h if not n.startswith(b":")]
                sections.append((code, extra))
            elif ty == 0:
                body += resp[i:i + ln]
            i += ln
        out[route] = (st, body, extra, sections)
    return out


h3 = h3_all([r for r, _, _ in CASES if r not in H3_SKIP])

# These four are judged on h2 and h3 only, and the reason is protocol, not
# laxity: h1 relays a chunked body byte for byte and has already sent its 200
# by the time any chunk line is read, so it can only close and let the client
# detect the error. h2 decodes and can reset the stream after the head; h3
# captures the WHOLE body before sending anything, so it alone can still answer
# 502 -- which is exactly why it must. Written down rather than exempted,
# because an exemption is where a defect lives (audit-report-16).
STREAMED_BODY = {"chunkspace", "chunkoverflow", "chunkbig"}

# chunktrunc is the same family but a step further, and it separates "malformed"
# from "detectable in time". Its head and first chunk line are VALID, so h2 has
# already emitted the 200 before the upstream stops; all it can do then is reset
# the stream, which is what a client must see instead of a clean end. h3 buffers
# the whole body first, so it alone can still answer 502 -- and must, or it
# hands over a truncated response as a complete one, which is what it did.
H2_RESET = {}
# ...so its correct answer differs per protocol BY NECESSITY, and the generic
# "all three agree" check does not apply. It is asserted on its own terms below
# instead of being dropped from the matrix.
PROTOCOL_SPECIFIC = {"chunktrunc", "chunknoterm", "chunkpartialtrail"}

RESULTS = {}

for route, want_status, want_body in CASES:
    got = {}
    got["h1"] = h1(route)
    got["h2"] = h2(route)
    if h3 is not None and route not in H3_SKIP:
        got["h3"] = h3.get(route, (None, b"", [], []))
    RESULTS[route] = got

    statuses = {p: v[0] for p, v in got.items()}
    if route in PROTOCOL_SPECIFIC:
        pass                       # asserted separately: see H2_RESET
    elif route in STREAMED_BODY:
        binary = {p: st for p, st in statuses.items() if p != "h1"}
        check(f"{route}: h2 and h3 refuse the malformed framing "
              f"(h1 relays it: see STREAMED_BODY)",
              all(s == want_status for s in binary.values()), f"  {statuses}")
    else:
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
        # h1 sends its OWN Connection header and must, so this cannot simply
        # forbid the field there -- but exempting it outright is what let an
        # upstream Connection line ride along beside ours unnoticed
        # (audit-report-16). CONNECTION_OK below is the real rule; here only
        # h2/h3, where the field is forbidden outright, are checked for it.
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

# --- a body we cannot predict must still be the SAME body everywhere --------
# gzip bytes are opaque to this test, so the assertion is agreement rather than
# a literal: three protocols, one representation.
for route in ("cegzip",):
    bodies = {p: v[1] for p, v in RESULTS.get(route, {}).items()}
    same = len(set(bodies.values())) == 1 and all(bodies.values())
    check(f"{route}: every protocol delivers the identical representation",
          same, f"  {[(p, len(b)) for p, b in bodies.items()]}")

# --- a long-but-valid field name survives, identically, on all three ---------
for route, name in LONGNAME.items():
    got = RESULTS.get(route, {})
    present = {p: any(f.lower().startswith(name + b":")
                      for _, fields in v[3] for f in fields)
               for p, v in got.items()}
    check(f"{route}: the {len(name)}-byte field name is forwarded by every "
          f"protocol (RFC 9110 5.1)", all(present.values()), f"  {present}")

# --- the value, exactly, on every protocol ----------------------------------
for route, want in FIELDVAL.items():
    got = {}
    for proto, v in RESULTS.get(route, {}).items():
        # the sections are formatted as "name: value" by the helpers above, so
        # split on ": " -- splitting on ":" alone re-adds that separator space
        # and every value looks OWS-padded, including the correct ones
        # h1 sections hold RAW header lines, h2/h3 hold "name:value" with no
        # separator of our own -- so everything after the first colon is the
        # value exactly as that protocol carries it, OWS included.
        vals = [f.partition(b":")[2] for _, fields in v[3] for f in fields
                if f.lower().startswith(b"x-note:")]
        got[proto] = vals[0] if vals else None
    # h1 may relay the upstream line verbatim -- that is legal HTTP/1 and the
    # value is recovered by stripping OWS, which any HTTP/1 client does. h2 and
    # h3 carry no field-line syntax, so for them the bytes must already BE the
    # value.
    ok_h1 = got.get("h1") is not None and got["h1"].strip(b" \t") == want
    ok_bin = all(got.get(p) == want for p in ("h2", "h3") if p in got)
    check(f"{route}: x-note is exactly {want!r} on h2/h3 (h1 may keep its OWS)",
          ok_h1 and ok_bin, f"  {got}")

# --- the configured origin policy, on every protocol, exactly once ----------
def _vals(v, name):
    out = []
    for _, fields in v[3]:
        for f in fields:
            if f.lower().startswith(name + b":"):
                out.append(f.partition(b":")[2].strip(b" \t"))
    return out


for route, want_sts in POLICY.items():
    got = RESULTS.get(route, {})
    sts = {p: _vals(v, b"strict-transport-security") for p, v in got.items()}
    xcto = {p: _vals(v, b"x-content-type-options") for p, v in got.items()}
    ok = (all(v == [want_sts] for v in sts.values())
          and all(v == [b"nosniff"] for v in xcto.values()))
    check(f"{route}: every protocol sends exactly one {want_sts.decode()} "
          f"and one nosniff", ok, f"  sts={sts} xcto={xcto}")

# --- exactly one Connection line on h1, and it is OURS ----------------------
# Checked on EVERY route rather than a chosen few: an upstream Connection value
# reaching the client is a hop-boundary break whatever it names, and the only
# reason it went unseen was a test that waved the field through because linnea
# emits one of its own.
for route in [r for r, _, _ in CASES if r not in H3_SKIP]:
    got = RESULTS.get(route, {})
    bad = {}
    for proto, v in got.items():
        lines = [f for _, fields in v[3] for f in fields
                 if f.lower().startswith(b"connection:")]
        if proto == "h1":
            vals = [l.partition(b":")[2].strip(b" \t").lower() for l in lines]
            # a 502 head is generated, not rewritten, and carries one too
            if len(vals) > 1 or any(x not in (b"close", b"keep-alive")
                                    for x in vals):
                bad[proto] = lines
        elif lines:
            bad[proto] = lines
    check(f"{route}: no upstream Connection line survives (h1 keeps only its "
          f"own)", not bad, f"  {bad}" if bad else "")

# --- a truncated chunked body is never a complete response ------------------
for route in sorted(PROTOCOL_SPECIFIC):
    got = RESULTS.get(route, {})
    h3_refused = got.get("h3", (None,))[0] == 502
    h2_reset = H2_RESET.get(route, False)
    check(f"{route}: h3 refuses it outright and h2 resets the stream rather "
          f"than ending it cleanly",
          h3_refused and h2_reset,
          f"  h3={got.get('h3', (None,))[0]} h2_reset={h2_reset}")

for route, why in H3_SKIP.items():
    print(f"note: {route} not checked over HTTP/3 here -- {why}")

if h3 is None:
    print("note: HTTP/3 not checked (aioquic unavailable) -- h1 and h2 only")

sys.exit(1 if fails else 0)
