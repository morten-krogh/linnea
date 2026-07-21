#!/usr/bin/env python3
# Two QUIC connections interleaved. Both handshakes are driven step by step in
# lockstep, then a request is made on each, so every stage of connection A is
# separated from A's next stage by a stage of connection B. This only works if
# the keys, transcript, connection IDs and packet numbers live per connection —
# with shared state, B's handshake would clobber A's.
# Usage: h3_conns_test.py <port>
import socket
import ssl
import sys

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived


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


class Client:
    def __init__(self, port):
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
        cfg.verify_mode = ssl.CERT_NONE
        cfg.server_name = "localhost"
        self.port = port
        self.conn = QuicConnection(configuration=cfg)
        self.conn.connect(("127.0.0.1", port), now=0.0)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.settimeout(3)
        self.t = 0.0

    def flush(self):
        self.t += 0.1
        for d, _ in self.conn.datagrams_to_send(now=self.t):
            self.s.sendto(d, ("127.0.0.1", self.port))

    def recv(self):
        self.t += 0.1
        r, _ = self.s.recvfrom(4096)
        self.conn.receive_datagram(r, ("127.0.0.1", self.port), now=self.t)

    def drain(self):
        while self.conn.next_event() is not None:
            pass

    def request(self, path):
        enc = pylsqpack.Encoder()
        enc.apply_settings(max_table_capacity=0, blocked_streams=0)
        _, fields = enc.encode(0, [(b":method", b"GET"),
                                   (b":path", path.encode()),
                                   (b":scheme", b"https"),
                                   (b":authority", b"h3.test")])
        self.conn.send_stream_data(0, vlq(1) + vlq(len(fields)) + fields,
                                   end_stream=True)

    def response(self):
        resp = b""
        ev = self.conn.next_event()
        while ev is not None:
            if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
                resp += ev.data
            ev = self.conn.next_event()
        frames = []
        i = 0
        while i < len(resp):
            t, i = rvlq(resp, i)
            length, i = rvlq(resp, i)
            frames.append((t, resp[i:i + length]))
            i += length
        hdr = next(p for t, p in frames if t == 1)
        body = next((p for t, p in frames if t == 0), b"")
        dec = pylsqpack.Decoder(0, 0)
        _, headers = dec.feed_header(0, hdr)
        return dict(headers), body

    def close(self):
        self.s.close()


port = int(sys.argv[1])
a = Client(port)
b = Client(port)

# interleave every handshake stage between the two connections
a.flush()                 # A: Initial
b.flush()                 # B: Initial
a.recv()                  # A: server flight
b.recv()                  # B: server flight
a.flush()                 # A: client Finished
b.flush()                 # B: client Finished
a.recv()                  # A: HANDSHAKE_DONE
b.recv()                  # B: HANDSHAKE_DONE
assert a.conn._handshake_confirmed, "connection A not confirmed"
assert b.conn._handshake_confirmed, "connection B not confirmed"
a.drain()
b.drain()

# interleave the requests too, asking for different files
a.request("/hello.txt")
b.request("/style.css")
a.flush()
b.flush()
a.recv()
b.recv()

ha, ba = a.response()
hb, bb = b.response()
a.close()
b.close()

assert ha.get(b":status") == b"200", ha
assert ha.get(b"content-type") == b"text/plain", ha
assert ba == open("test/www/hello.txt", "rb").read(), ba
assert hb.get(b":status") == b"200", hb
assert hb.get(b"content-type") == b"text/css", hb
assert bb == open("test/www/style.css", "rb").read(), bb
print("ok")
