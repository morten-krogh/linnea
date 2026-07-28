#!/usr/bin/env python3
"""Does a TRAILING HEADERS frame influence the response on h3?

Sends a normal request for /hello.txt (18 bytes), then a trailer field
section carrying `range: bytes=0-4`. If the reply is a 206 of 5 bytes, the
trailer was merged into the request's header set — the request means one
thing to the client and another to us.
"""
import socket, ssl, sys, time
import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived, ConnectionTerminated

port = int(sys.argv[1])


def vlq(n):
    return bytes([n]) if n < 64 else (0x4000 | n).to_bytes(2, "big")


def run(name, trailer_fields):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    c = QuicConnection(configuration=cfg)
    t = [0.0]

    def clk():
        t[0] += 0.001
        return t[0]

    c.connect(("127.0.0.1", port), now=clk())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    st = {"data": b"", "term": None}

    def pump(d):
        end = time.time() + d
        while time.time() < end:
            for dg, _ in c.datagrams_to_send(now=clk()):
                s.sendto(dg, ("127.0.0.1", port))
            try:
                while True:
                    r, _ = s.recvfrom(4096)
                    c.receive_datagram(r, ("127.0.0.1", port), now=clk())
            except (BlockingIOError, OSError):
                pass
            try:
                c.handle_timer(now=clk())
            except TypeError:
                pass
            ev = c.next_event()
            while ev:
                if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
                    st["data"] += ev.data
                elif isinstance(ev, ConnectionTerminated):
                    st["term"] = ev.error_code
                ev = c.next_event()
            time.sleep(0.002)

    pump(0.05)
    dl = time.time() + 5
    while not c._handshake_confirmed and time.time() < dl:
        pump(0.05)

    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, head = enc.encode(0, [(b":method", b"GET"), (b":scheme", b"https"),
                             (b":authority", b"localhost"), (b":path", b"/hello.txt")])
    body = b"\x01" + vlq(len(head)) + head
    if trailer_fields is not None:
        enc2 = pylsqpack.Encoder()
        enc2.apply_settings(max_table_capacity=0, blocked_streams=0)
        _, tr = enc2.encode(0, trailer_fields)
        body += b"\x01" + vlq(len(tr)) + tr
    c.send_stream_data(0, body, end_stream=True)
    pump(1.5)
    s.close()

    blob = st["data"]
    status = "?"
    for code in (b"206", b"200", b"400", b"416"):
        if code in blob[:80]:
            status = code.decode()
            break
    if st["term"] is not None:
        return None
    return (len(blob), b"content-range" in blob)


# A trailing HEADERS frame (trailers, RFC 9114 4.1) must not merge into the
# request and change the response. Before the fix, a trailer "range: bytes=0-4"
# turned a whole-file GET into a 206.
base = run("no trailer", None)
rng  = run("trailer range: bytes=0-4", [(b"range", b"bytes=0-4")])
assert base is not None and rng is not None, "no response"
assert not rng[1], "a trailer Range produced a Content-Range: trailers still merge"
assert rng[0] == base[0], f"trailer changed the byte count ({rng[0]} vs {base[0]})"
print("ok")
