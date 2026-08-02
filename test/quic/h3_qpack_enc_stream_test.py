#!/usr/bin/env python3
# h3-8: QPACK encoder-stream instructions must be read, not ignored. We
# advertise QPACK_MAX_TABLE_CAPACITY=0, so the only instruction a conforming
# encoder can send is Set Dynamic Table Capacity to 0 (the byte 0x20); any
# other capacity exceeds the maximum we set and any Insert/Duplicate lands in
# a table we refused — QPACK_ENCODER_STREAM_ERROR (0x201, RFC 9204 4.1.3,
# 4.3.1). Pre-fix the stream's bytes were never read at all, so an encoder
# whose table state had silently diverged from ours was told nothing.
#
# Also: a FIN on a LATER frame of a QPACK stream is a critical-stream closure
# (RFC 9114 6.2, "by any means") just like one on the typing frame — only the
# typing frame's FIN used to be noticed.
# Usage: h3_qpack_enc_stream_test.py <port>
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

PORT = int(sys.argv[1])


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

    def clk(self):
        self.vt += 0.002
        return self.vt

    def flush(self):
        for d, _ in self.conn.datagrams_to_send(now=self.clk()):
            self.s.sendto(d, ("127.0.0.1", PORT))

    def pump_once(self):
        try:
            r, _ = self.s.recvfrom(65535)
            self.conn.receive_datagram(r, ("127.0.0.1", PORT), now=self.clk())
        except socket.timeout:
            self.conn.handle_timer(now=self.clk())
        ev = self.conn.next_event()
        while ev is not None:
            if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
                self.served += len(ev.data)
            ev = self.conn.next_event()
        self.flush()

    def close_code(self, budget):
        dl = time.time() + budget
        while time.time() < dl and self.conn._close_event is None:
            self.pump_once()
        return (self.conn._close_event.error_code
                if self.conn._close_event else None)

    def request_ok(self):
        enc = pylsqpack.Encoder()
        enc.apply_settings(max_table_capacity=0, blocked_streams=0)
        _, f = enc.encode(0, [(b":method", b"GET"), (b":path", b"/hello.txt"),
                              (b":scheme", b"https"),
                              (b":authority", b"localhost")])
        self.conn.send_stream_data(0, b"\x01" + bytes([len(f)]) + f,
                                   end_stream=True)
        self.flush()
        dl = time.time() + 5
        while (self.served == 0 and self.conn._close_event is None
               and time.time() < dl):
            self.pump_once()
        return self.served > 0


def uni_case(chunks, fin_last=False):
    """Open a uni stream, send each chunk (last optionally with FIN).
    -> (close code or None, client)."""
    c = Client()
    uni = c.conn.get_next_available_stream_id(is_unidirectional=True)
    for i, chunk in enumerate(chunks):
        fin = fin_last and i == len(chunks) - 1
        c.conn.send_stream_data(uni, chunk, end_stream=fin)
        c.flush()
        time.sleep(0.05)
    return c.close_code(3), c


fails = 0

# a capacity we refused to grant
code, _ = uni_case([b"\x02\x3f\x21"])          # Set Dynamic Table Capacity 64
if code == 0x201:
    print(f"ok   Set Capacity 64 against our 0 -> 0x{code:x}")
else:
    print(f"FAIL Set Capacity 64 against our 0 drew {code!r}, want 0x201")
    fails += 1

# an insertion into the table that capacity 0 means we do not have
code, _ = uni_case([b"\x02", b"\xc0\x03GET"])  # Insert w/ static name ref, later frame
if code == 0x201:
    print(f"ok   Insert With Name Reference -> 0x{code:x}")
else:
    print(f"FAIL Insert With Name Reference drew {code!r}, want 0x201")
    fails += 1

# the one legal instruction must NOT close, and the connection must still serve
code, c = uni_case([b"\x02\x20"])              # Set Dynamic Table Capacity 0
if code is None and c.request_ok():
    print("ok   Set Capacity 0 is honoured and the connection still serves")
elif code is not None:
    print(f"FAIL Set Capacity 0 closed the connection (0x{code:x})")
    fails += 1
else:
    print("FAIL connection went dead after Set Capacity 0")
    fails += 1

# the decoder stream is the client's to write: a Stream Cancellation (which
# real browsers send) must be left alone
code, c = uni_case([b"\x03", b"\x40"])         # Stream Cancellation, stream 0
if code is None and c.request_ok():
    print("ok   a decoder-stream Stream Cancellation is left alone")
elif code is not None:
    print(f"FAIL a Stream Cancellation closed the connection (0x{code:x})")
    fails += 1
else:
    print("FAIL connection went dead after a Stream Cancellation")
    fails += 1

# a FIN on a LATER frame of a critical stream is still a closure
code, _ = uni_case([b"\x02", b"\x20"], fin_last=True)
if code == 0x104:
    print(f"ok   FIN on an encoder-stream continuation -> 0x{code:x}")
else:
    print(f"FAIL FIN on an encoder-stream continuation drew {code!r}, want 0x104")
    fails += 1

sys.exit(1 if fails else 0)
