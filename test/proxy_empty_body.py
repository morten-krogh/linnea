#!/usr/bin/env python3
"""A body of no bytes is not the same request as no body, and every protocol
must forward it the same way.

Reported from production: uploading an EMPTY file returned 411 Length Required.
The 411 came from the backend, correctly -- linnea had handed it a POST with no
framing at all. h1 forwarded "Content-Length: 0" and worked; h2 and h3 dropped
the header whenever the measured body was zero, so a backend entitled to require
a length had nothing to go on.

The rule, taken from what h1 already did:

    request                          forwarded upstream
    -------------------------------  ------------------
    GET, no body, no declaration     no Content-Length
    POST, Content-Length: 0          Content-Length: 0
    POST, five bytes                 Content-Length: 5

/api/headers echoes the request head it received, so this asserts what linnea
actually SENT upstream rather than inferring it from a status code -- the 411
would come back identically whether the header was missing or malformed.

HTTP/3 is skipped, loudly, when aioquic is unavailable.

usage: proxy_empty_body.py <cafile> <tls port>
"""
import socket
import ssl
import struct
import sys
import time

ca, port = sys.argv[1], int(sys.argv[2])
HOST = "127.0.0.1"
PATH = b"/api/headers"

# (label, method, body or None for "no body at all", expected Content-Length
#  line in the forwarded head, or None for "no such line")
CASES = [
    ("plain GET",            b"GET",  None,     None),
    ("POST with no bytes",   b"POST", b"",      b"content-length: 0"),
    ("POST with five bytes", b"POST", b"hello", b"content-length: 5"),
]

fails = 0


def check(name, ok, detail=""):
    global fails
    print(f"{'ok  ' if ok else 'FAIL'} {name}{detail}")
    if not ok:
        fails += 1


def clen_of(head):
    """The Content-Length line the backend saw, lowercased, or None."""
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            return b"content-length: " + line.split(b":", 1)[1].strip()
    return None


# ---------------------------------------------------------------- HTTP/1.1 --
def h1(method, body):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["http/1.1"])
    s = ctx.wrap_socket(socket.create_connection((HOST, port), timeout=10),
                        server_hostname="localhost")
    req = method + b" " + PATH + b" HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
    if body is not None:
        req += b"Content-Length: " + str(len(body)).encode() + b"\r\n"
    req += b"\r\n" + (body or b"")
    s.sendall(req)
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
    return buf.partition(b"\r\n\r\n")[2]


# ------------------------------------------------------------------ HTTP/2 --
def h2(method, body):
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
    blk = (hd(b":method", method) + hd(b":scheme", b"https")
           + hd(b":authority", b"localhost") + hd(b":path", PATH))
    if body is not None:
        blk += hd(b"content-length", str(len(body)).encode())
    if body is None or body == b"":
        # END_STREAM on the HEADERS frame: no DATA at all. An empty POST really
        # is framed this way by browsers, which is the shape that broke.
        wire = fr(0x1, 0x4 | 0x1, 1, blk)
    else:
        wire = fr(0x1, 0x4, 1, blk) + fr(0x0, 0x1, 1, body)
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(0x4, 0, 0) + wire)
    s.settimeout(10)
    buf, out, done = b"", b"", False
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
                    out += pl
                if ft in (0x0, 0x1) and fl & 0x1:
                    done = True
                if ft == 0x3:
                    done = True
    except (socket.timeout, OSError):
        pass
    s.close()
    return out


# ------------------------------------------------------------------ HTTP/3 --
def h3_all(cases):
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
    for label, method, body, _ in cases:
        enc = pylsqpack.Encoder()
        enc.apply_settings(max_table_capacity=0, blocked_streams=0)
        fields = [(b":method", method), (b":path", PATH),
                  (b":scheme", b"https"), (b":authority", b"localhost")]
        if body is not None:
            fields.append((b"content-length", str(len(body)).encode()))
        _, blk = enc.encode(0, fields)
        stream = vlq(1) + vlq(len(blk)) + blk
        if body:
            stream += vlq(0) + vlq(len(body)) + body
        bidi = conn.get_next_available_stream_id()
        conn.send_stream_data(bidi, stream, end_stream=True)
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
        got = b""
        i = 0
        while i < len(resp):
            ty, i = rvlq(resp, i)
            ln, i = rvlq(resp, i)
            if ty == 0:
                got += resp[i:i + ln]
            i += ln
        out[label] = got
    return out


h3 = h3_all(CASES)

for label, method, body, want in CASES:
    got = {"h1": clen_of(h1(method, body)), "h2": clen_of(h2(method, body))}
    if h3 is not None:
        got["h3"] = clen_of(h3.get(label, b""))
    check(f"{label}: every protocol forwards "
          + (want.decode() if want else "no Content-Length"),
          all(v == want for v in got.values()),
          f"  {{{', '.join(f'{k}: {v!r}' for k, v in got.items())}}}")

if h3 is None:
    print("note: HTTP/3 not checked (aioquic unavailable) -- h1 and h2 only")

sys.exit(1 if fails else 0)
