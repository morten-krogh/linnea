#!/usr/bin/env python3
# Q136: frames illegal on a request stream must be a connection error
# H3_FRAME_UNEXPECTED (0x105, RFC 9114 7.2), not silently ignored. The
# reserved HTTP/2 types and the control/push frames are rejected; GREASE and
# unknown types are ignored; a legitimate request still serves.
# Usage: h3_frame_reject_test.py <port>
import socket, ssl, sys, time
import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived, ConnectionTerminated

port = int(sys.argv[1])


def vlq(n):
    return bytes([n]) if n < 64 else (0x4000 | n).to_bytes(2, "big")


def probe(prefix):
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
    ctrl = c.get_next_available_stream_id(is_unidirectional=True)
    c.send_stream_data(ctrl, b"\x00\x04\x00")
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, f = enc.encode(0, [(b":method", b"GET"), (b":scheme", b"https"),
                          (b":authority", b"localhost"), (b":path", b"/hello.txt")])
    c.send_stream_data(0, prefix + b"\x01" + vlq(len(f)) + f, end_stream=True)
    pump(1.2)
    s.close()
    return st


# each of these frames is illegal on a request stream -> connection error 0x105
for code in (0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0d):
    st = probe(bytes([code]) + b"\x00")
    assert st["term"] == 0x105, \
        f"frame 0x{code:02x}: expected H3_FRAME_UNEXPECTED 0x105, got {st['term']} / served={bool(st['data'])}"
# DATA before HEADERS -> 0x105
st = probe(b"\x00\x04abcd")
assert st["term"] == 0x105, f"DATA-before-HEADERS: got {st['term']}"

# GREASE and unknown types are ignored, the request still serves
for pfx in (b"\x21\x02\xff\xff", b"\x2f\x02\xaa\xbb"):
    st = probe(pfx)
    assert st["term"] is None and b"hello" in st["data"], \
        f"grease/unknown prefix {pfx!r} should be ignored and served: {st}"
# and a plain request with no odd prefix serves
st = probe(b"")
assert st["term"] is None and b"hello" in st["data"], f"baseline broke: {st}"
print("ok")
