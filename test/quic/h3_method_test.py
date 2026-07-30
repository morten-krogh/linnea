#!/usr/bin/env python3
# HTTP/3 request methods. h3 serves static files, and static files answer GET and
# HEAD — the same rule h1 and h2 apply. Nothing enforced it: only POST (which
# echoes its body, the observable that proves DATA frames are captured) and HEAD
# were ever recognised, and every other method fell through to be served AS IF IT
# WERE A GET. So `PROPFIND /hello.txt` came back 200 with the file's contents,
# where h1 and h2 both answer 405.
#
# The method is also matched exactly. RFC 9110 9.1 makes it case-sensitive, so a
# lowercase "get" is not GET and does not serve a file.
#
# And a 405 must name the methods the resource does take (RFC 9110 15.5.6). h1
# always sent that Allow header; h2 and h3 did not until now, so every case here
# asserts its presence on a 405 and its absence everywhere else.
# Usage: h3_method_test.py <port>
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived, StreamReset

PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def rvlq(b, i):
    k = 1 << (b[i] >> 6)
    v = b[i] & 0x3F
    for j in range(1, k):
        v = (v << 8) | b[i + j]
    return v, i + k


def probe(method):
    """Returns (status or 'RESET 0x…', the allow header or None)."""
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    c = QuicConnection(configuration=cfg)
    t = [0.0]

    def clk():
        t[0] += 0.02
        return t[0]

    c.connect(ADDR, now=clk())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.4)

    def flush():
        for d, _ in c.datagrams_to_send(now=clk()):
            s.sendto(d, ADDR)

    flush()
    dl = time.time() + 8
    while not c._handshake_confirmed and time.time() < dl:
        try:
            r, _ = s.recvfrom(4096)
            c.receive_datagram(r, ADDR, now=clk())
        except socket.timeout:
            c.handle_timer(now=clk())
        flush()
    while c.next_event():
        pass
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, f = enc.encode(0, [(b":method", method), (b":path", b"/hello.txt"),
                          (b":scheme", b"https"), (b":authority", b"localhost")])
    sid = c.get_next_available_stream_id()
    c.send_stream_data(sid, vlq(1) + vlq(len(f)) + f, end_stream=True)
    flush()
    verdict, resp = None, b""
    dl = time.time() + 5
    while time.time() < dl:
        try:
            r, _ = s.recvfrom(65535)
        except socket.timeout:
            c.handle_timer(now=clk())
            flush()
            continue
        c.receive_datagram(r, ADDR, now=clk())
        ev, done = c.next_event(), False
        while ev:
            if isinstance(ev, StreamReset) and ev.stream_id == sid:
                verdict = f"RESET 0x{ev.error_code:x}"
                done = True
            elif isinstance(ev, StreamDataReceived) and ev.stream_id == sid:
                resp += ev.data
                if ev.end_stream:
                    done = True
            ev = c.next_event()
        flush()
        if done:
            break
    allow = None
    if verdict is None:
        i = 0
        while i < len(resp):
            ty, i = rvlq(resp, i)
            ln, i = rvlq(resp, i)
            if ty == 1:
                _, hh = pylsqpack.Decoder(0, 0).feed_header(0, resp[i:i + ln])
                h = dict(hh)
                verdict = h.get(b":status", b"?").decode()
                if b"allow" in h:
                    allow = h[b"allow"].decode()
                break
            i += ln
    s.close()
    return verdict or "no reply", allow


# (method, expected status, expected allow header). RFC 9110 15.5.6: a 405 must
# say what the resource does take, and nothing else should claim to.
CASES = [
    (b"GET", "200", None),
    (b"HEAD", "200", None),
    # POST echoes its request body — h3's own observable that DATA frames are
    # captured, and the one method h3 answers that h1 and h2 refuse
    (b"POST", "200", None),
    # every other method is a 405, where each used to be served as a GET
    (b"PUT", "405", "GET, HEAD"),
    (b"DELETE", "405", "GET, HEAD"),
    (b"PROPFIND", "405", "GET, HEAD"),
    (b"OPTIONS", "405", "GET, HEAD"),
    (b"PATCH", "405", "GET, HEAD"),
    # a method is case-sensitive (RFC 9110 9.1), so these are not GET or HEAD
    (b"get", "405", "GET, HEAD"),
    (b"Get", "405", "GET, HEAD"),
    (b"head", "405", "GET, HEAD"),
]

fails = 0
for method, want, want_allow in CASES:
    got, allow = probe(method)
    ok = got == want and allow == want_allow
    print(f"{'ok  ' if ok else 'FAIL'} {method.decode() or '(empty)':10} -> {got} "
          f"allow={allow!r}, want {want} allow={want_allow!r}")
    fails += not ok
if fails:
    sys.exit(1)
print("ok")
