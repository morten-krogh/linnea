#!/usr/bin/env python3
# h3-6: control-stream rule enforcement must survive reordering. The frame walk
# consumes only the contiguous prefix; a STREAM frame delivered (and acked)
# ahead of it used to be DROPPED, and since a reordered frame is delivered
# exactly once, the hole was never filled — enforcement quietly ended there for
# the life of the connection. Now the ahead-bytes are held (one bounded segment
# per connection) and walked the moment the in-order bytes catch up.
#
# Three cases, each on a fresh connection:
#   A: control stream established, then a legal frame and an ILLEGAL one (DATA)
#      sent in separate datagrams, delivered in reverse — the illegal frame
#      arrives ahead, is held, and must still draw H3_FRAME_UNEXPECTED (0x105)
#      once the hole fills. Pre-fix: silence.
#   B: the stream's TYPE frame itself is the late one — the illegal frame's
#      bytes arrive on a stream not yet known to be the control stream, and
#      must still be held. Pre-fix: silence.
#   C: the same reordering with only LEGAL frames must close nothing and the
#      connection must still serve a request — the guard against a fix that
#      punishes any hole.
# Usage: h3_ctrl_reorder_test.py <port>
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

PORT = int(sys.argv[1])
H3_FRAME_UNEXPECTED = 0x105

SETTINGS = b"\x04\x00"                 # an empty SETTINGS frame
MAX_PUSH_ID = b"\x0d\x01\x3f"          # legal on the control stream
GOAWAY = b"\x07\x01\x00"               # legal on the control stream
DATA = b"\x00\x01\x41"                 # illegal there (RFC 9114 7.2.1)


class Client:
    def __init__(self):
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
        cfg.verify_mode = ssl.CERT_NONE
        cfg.server_name = "localhost"
        self.conn = QuicConnection(configuration=cfg)
        self.vt = 0.0
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.settimeout(0.3)
        self.served = 0
        self.conn.connect(("127.0.0.1", PORT), now=self.clk())
        self.flush()
        dl = time.time() + 8
        while not self.conn._handshake_confirmed and time.time() < dl:
            self.pump_once()
        assert self.conn._handshake_confirmed, "handshake failed"
        self.drain_events()

    def clk(self):
        self.vt += 0.002
        return self.vt

    def flush(self):
        for d, _ in self.conn.datagrams_to_send(now=self.clk()):
            self.s.sendto(d, ("127.0.0.1", PORT))

    def take(self):
        # the pending datagrams, NOT sent: the caller chooses the order
        return [d for d, _ in self.conn.datagrams_to_send(now=self.clk())]

    def deliver(self, dgrams):
        for d in dgrams:
            self.s.sendto(d, ("127.0.0.1", PORT))

    def pump_once(self):
        try:
            r, _ = self.s.recvfrom(65535)
            self.conn.receive_datagram(r, ("127.0.0.1", PORT), now=self.clk())
        except socket.timeout:
            self.conn.handle_timer(now=self.clk())
        self.flush()

    def drain_events(self):
        ev = self.conn.next_event()
        while ev is not None:
            if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
                self.served += len(ev.data)
            ev = self.conn.next_event()

    def close_code(self, budget):
        dl = time.time() + budget
        while time.time() < dl and self.conn._close_event is None:
            self.pump_once()
            self.drain_events()
        return (self.conn._close_event.error_code
                if self.conn._close_event else None)


def reorder_case(first_chunk, held_first, chunks):
    """Open a control stream; send first_chunk, then each of chunks in its own
    datagram — delivered in REVERSE order. held_first also holds first_chunk
    back until the very end (case B). -> (close code or None, client)."""
    c = Client()
    uni = c.conn.get_next_available_stream_id(is_unidirectional=True)
    c.conn.send_stream_data(uni, first_chunk)
    d0 = c.take()
    if not held_first:
        c.deliver(d0)
        time.sleep(0.1)
    held = []
    for chunk in chunks:
        c.conn.send_stream_data(uni, chunk)
        held.append(c.take())
    for dgrams in reversed(held):
        c.deliver(dgrams)
        time.sleep(0.05)
    if held_first:
        time.sleep(0.1)
        c.deliver(d0)
    return c.close_code(3), c


def request_ok(c):
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"GET"), (b":path", b"/hello.txt"),
                               (b":scheme", b"https"),
                               (b":authority", b"localhost")])
    c.conn.send_stream_data(0, b"\x01" + bytes([len(fields)]) + fields,
                            end_stream=True)
    c.flush()
    dl = time.time() + 5
    while c.served == 0 and c.conn._close_event is None and time.time() < dl:
        c.pump_once()
        c.drain_events()
    return c.served > 0


fails = 0

# A: the illegal frame arrives ahead of a legal one on an established stream
code, _ = reorder_case(b"\x00" + SETTINGS, False, [MAX_PUSH_ID, DATA])
if code == H3_FRAME_UNEXPECTED:
    print(f"ok   reordered illegal frame still rejected (0x{code:x})")
else:
    print(f"FAIL reordered illegal frame drew {code!r}, want 0x105 — "
          f"enforcement ended at the hole")
    fails += 1

# B: the type frame itself is the late one
code, _ = reorder_case(b"\x00" + SETTINGS, True, [DATA])
if code == H3_FRAME_UNEXPECTED:
    print(f"ok   illegal frame ahead of the type frame still rejected (0x{code:x})")
else:
    print(f"FAIL illegal frame ahead of the type frame drew {code!r}, want 0x105")
    fails += 1

# C: legal frames reordered — nothing may close, and requests still serve
code, c = reorder_case(b"\x00" + SETTINGS, False, [MAX_PUSH_ID, GOAWAY])
if code is None and request_ok(c):
    print("ok   legal reordering closes nothing and the connection still serves")
elif code is not None:
    print(f"FAIL legal reordering closed the connection (0x{code:x})")
    fails += 1
else:
    print("FAIL connection went dead after legal reordering")
    fails += 1

sys.exit(1 if fails else 0)
