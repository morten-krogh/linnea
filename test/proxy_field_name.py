#!/usr/bin/env python3
"""A field name that is not a token stops at the door, on all three protocols.

An HTTP field name is a TOKEN (RFC 9110 5.1, 5.6.2), so the delimiters -- @ ( )
, " / [ ] { } \\ = -- cannot appear in one. HTTP/1 has always been held to that
by linnea_string_is_token; HTTP/2 and HTTP/3 were not (audit-report-123). RFC
9113 8.2.1's MINIMAL validation only excludes 0x00-0x20, uppercase, 0x7f-0xff
and a non-leading colon, and that list is a floor: the same section opens by
saying implementations "SHOULD validate field names and values according to
their definitions in Sections 5.1 and 5.5 of [HTTP] ... and treat messages that
contain prohibited characters as malformed", and RFC 9114 4.2 sends HTTP/3 to
the same 5.1. So "x@test" passed the h2/h3 decoder, and the proxy rebuild wrote
it verbatim into the HTTP/1.1 head sent upstream -- an h1 request our own h1
parser answers 400 to.

    protocol   x@test before   x@test after
    h1         400             400
    h2         200 !           RESET
    h3         200 !           RESET

The negative assertion is the point: the backend echoes the head it received
(/api/headers), so "no x@test in the body" is what proves the invalid h1
request was never sent, rather than merely that we changed our mind about the
status.

Three acceptance controls travel with it, because an implementation that
refused every unusual field name -- or every request -- would pass the check
above:

  * "x-test" is served and echoed, the plainest field there is;
  * "x!#$%&'*+-.^_`|~09test" is served and echoed: that is every tchar
    punctuation mark RFC 9110 5.6.2 allows, so a fix that refused punctuation
    wholesale, or kept only the hyphen, would refuse a legal name and nothing
    else here would notice;
  * a static location still serves an ordinary request.

And every case sends the four pseudo-headers, whose names begin with the one
byte a token may not contain -- so a check applied without the pseudo-header
exception would fail all of them, not just the ones under test.

The static rejections are deliberate and are the difference from report 122's
DEL in a VALUE. DEL is legal over h2/h3 and illegal only in the h1 message we
would forward, so it is refused at the proxy boundary and a static request
keeps it. A non-token NAME is prohibited by the definition 8.2.1 points at, so
it is malformed wherever the request was going: refused in the field decoder,
static location included.

HTTP/3 is skipped, loudly, when aioquic is unavailable.

usage: proxy_field_name.py <cafile> <tls port>
"""
import socket
import ssl
import struct
import sys
import time

ca, port = sys.argv[1], int(sys.argv[2])
HOST = "127.0.0.1"

REFUSED = {"h1": 400, "h2": "RESET", "h3": "RESET"}

# label -> (path, field name, value, expected status, must the backend echo it?)
# h1 answers 400 and h2/h3 reset the stream: a malformed request is a stream
# error over both binary protocols (RFC 9113 8.1.1, RFC 9114 4.1.2), which is
# already how this decoder answers an uppercase name or a space in one.
CASES = [
    ("ordinary",  b"/api/headers", b"x-test",                  b"yes", 200, True),
    ("tchar",     b"/api/headers", b"x!#$%&'*+-.^_`|~09test",   b"yes", 200, True),
    ("at",        b"/api/headers", b"x@test",                   b"yes", REFUSED, False),
    ("slash",     b"/api/headers", b"x/test",                   b"yes", REFUSED, False),
    ("static-ok", b"/hello.txt",   b"x-test",                   b"yes", 200, False),
    ("static-at", b"/hello.txt",   b"x@test",                   b"yes", REFUSED, False),
]


# ------------------------------------------------------------------ HTTP/1 --
def h1(path, name, value):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["http/1.1"])
    s = ctx.wrap_socket(socket.create_connection((HOST, port), timeout=10),
                        server_hostname="localhost")
    s.settimeout(10)
    s.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: localhost\r\n" + name
              + b": " + value + b"\r\nConnection: close\r\n\r\n")
    buf = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
    except OSError:
        pass
    s.close()
    if not buf:
        return "CLOSED", b""
    line = buf.split(b"\r\n", 1)[0].split(b" ")
    st = int(line[1]) if len(line) > 1 and line[1].isdigit() else "?"
    return st, buf.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in buf else b""


# ------------------------------------------------------------------ HTTP/2 --
# The response decoder is the one proxy_upstream_head.py uses, for the same
# reason: linnea never inserts into the HPACK dynamic table and never Huffman-
# encodes a response, so a stateless decoder is exact -- and reading :status by
# hunting for three ASCII digits would find them in a Date instead.
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
HPACK_STATIC_VAL = {8: b"200", 9: b"204", 10: b"206", 11: b"304",
                    12: b"400", 13: b"404", 14: b"500"}


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


def hpack_status(blk):
    """The :status of a response field block, or None."""
    i = 0
    while i < len(blk):
        c = blk[i]
        if c & 0x80:                       # indexed: name and value both
            idx, i = hpack_int(blk, i, 7)
            if idx in HPACK_STATIC_VAL:
                return int(HPACK_STATIC_VAL[idx])
            continue
        if c & 0xE0 == 0x20:               # dynamic table size update
            _, i = hpack_int(blk, i, 5)
            continue
        idx, i = hpack_int(blk, i, 6 if c & 0x40 else 4)
        name = (HPACK_STATIC[idx] if idx and idx < len(HPACK_STATIC)
                else None)
        if idx == 0:
            name, i = hpack_str(blk, i)
        val, i = hpack_str(blk, i)
        if name == b":status" and val.isdigit():
            return int(val)
    return None


# Literal fields, never indexed, no Huffman: the byte on the wire is the byte
# under test, which a real client library would be free to re-encode.
def h2(path, name, value):
    def fr(t, fl, sid, p=b""):
        return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p

    def hd(n, v):
        return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v

    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection((HOST, port), timeout=10),
                        server_hostname="localhost")
    blk = (hd(b":method", b"GET") + hd(b":scheme", b"https")
           + hd(b":authority", b"localhost") + hd(b":path", path)
           + hd(name, value))
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
                elif ft == 0x1:
                    code = hpack_status(pl)
                    if code is not None:
                        st = code
                elif ft == 0x3:
                    st = "RESET"
                    done = True
                    break
                if ft in (0x0, 0x1) and fl & 0x1:
                    done = True
                    break
    except OSError:
        pass
    s.close()
    return st, body


# ------------------------------------------------------------------ HTTP/3 --
def h3(values):
    """-> {label: (status, body)}, or None when aioquic is unavailable."""
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
    for label, path, name, value in values:
        enc = pylsqpack.Encoder()
        enc.apply_settings(max_table_capacity=0, blocked_streams=0)
        _, blk = enc.encode(0, [(b":method", b"GET"), (b":path", path),
                                (b":scheme", b"https"), (b":authority", b"localhost"),
                                (name, value)])
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
            out[label] = ("RESET", b"")
            continue
        i, st, body = 0, None, b""
        dec = pylsqpack.Decoder(0, 0)
        while i < len(resp):
            ty, i = rvlq(resp, i)
            ln, i = rvlq(resp, i)
            if ty == 1:
                _, h = dec.feed_header(0, resp[i:i + ln])
                code = dict(h).get(b":status", b"?").decode()
                if code.isdigit():
                    st = int(code)
            elif ty == 0:
                body += resp[i:i + ln]
            i += ln
        out[label] = (st, body)
    return out


def judge(proto, label, name, value, want_status, want_echo, got):
    st, body = got
    if isinstance(want_status, dict):
        want_status = want_status[proto]
    # The backend echoes the head it was given, so "our value came back on a
    # line with our field name" is the same statement as "the request reached
    # upstream" -- which is the half a status code alone cannot show.
    echoed = value in body and name in body.lower()
    ok = st == want_status and echoed == want_echo
    print("%-3s %-9s status=%-5s backend echo=%-5s %s"
          % (proto, label, st, echoed, "ok" if ok else "FAIL"))
    return ok


def main():
    ok = True
    for label, path, name, value, st, echo in CASES:
        ok &= judge("h1", label, name, value, st, echo, h1(path, name, value))
    for label, path, name, value, st, echo in CASES:
        ok &= judge("h2", label, name, value, st, echo, h2(path, name, value))
    got = h3([(label, path, name, value) for label, path, name, value, _, _ in CASES])
    if got is None:
        print("note: HTTP/3 not checked (aioquic unavailable) -- h1 and h2 only")
    elif not got:
        print("h3  handshake did not complete")
        ok = False
    else:
        for label, path, name, value, st, echo in CASES:
            ok &= judge("h3", label, name, value, st, echo, got[label])
    print("all protocols agree" if ok else "DISAGREEMENT")
    return 0 if ok else 1


sys.exit(main())
