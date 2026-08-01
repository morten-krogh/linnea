#!/usr/bin/env python3
# HTTP/3 control stream, receive side. RFC 9114 6.2.1 requires the peer's control
# stream to open with a SETTINGS frame; any other first frame is a connection
# error of type H3_MISSING_SETTINGS. linnea now reads the client's control stream
# and enforces this. We check both outcomes: a control stream that opens with
# SETTINGS is accepted and the request is served, and one whose first frame is
# something else ends the connection with H3_MISSING_SETTINGS (0x10a).
# Usage: h3_settings_test.py <port>
import socket
import ssl
import sys

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived


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


def handshake(port):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    conn.connect(("127.0.0.1", port), now=0.0)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    for d, _ in conn.datagrams_to_send(now=0.0):
        s.sendto(d, ("127.0.0.1", port))
    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ("127.0.0.1", port), now=0.1)
    for d, _ in conn.datagrams_to_send(now=0.2):
        s.sendto(d, ("127.0.0.1", port))
    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ("127.0.0.1", port), now=0.3)
    assert conn._handshake_confirmed, "handshake not confirmed"
    while conn.next_event() is not None:
        pass
    return conn, s


def flush(conn, s, port, t):
    for d, _ in conn.datagrams_to_send(now=t):
        s.sendto(d, ("127.0.0.1", port))


port = int(sys.argv[1])

# --- valid: the control stream opens with SETTINGS, so the request is served ---
conn, s = handshake(port)
uni = conn.get_next_available_stream_id(is_unidirectional=True)
conn.send_stream_data(uni, b"\x00\x04\x00")          # control type + empty SETTINGS
enc = pylsqpack.Encoder()
enc.apply_settings(max_table_capacity=0, blocked_streams=0)
_, fields = enc.encode(0, [(b":method", b"GET"), (b":path", b"/hello.txt"),
                           (b":scheme", b"https"), (b":authority", b"h3.test")])
bidi = conn.get_next_available_stream_id()
conn.send_stream_data(bidi, vlq(1) + vlq(len(fields)) + fields, end_stream=True)
flush(conn, s, port, 0.4)
r, _ = s.recvfrom(4096)
conn.receive_datagram(r, ("127.0.0.1", port), now=0.5)
resp = b""
ev = conn.next_event()
while ev is not None:
    if isinstance(ev, StreamDataReceived) and ev.stream_id == bidi:
        resp += ev.data
    ev = conn.next_event()
s.close()
frames = []
i = 0
while i < len(resp):
    ty, i = rvlq(resp, i)
    ln, i = rvlq(resp, i)
    frames.append((ty, resp[i:i + ln]))
    i += ln
hdr = next(p for ty, p in frames if ty == 1)
dec = pylsqpack.Decoder(0, 0)
_, headers = dec.feed_header(0, hdr)
assert dict(headers).get(b":status") == b"200", dict(headers)

# --- invalid: the control stream's first frame is not SETTINGS ---
conn, s = handshake(port)
uni = conn.get_next_available_stream_id(is_unidirectional=True)
conn.send_stream_data(uni, b"\x00\x03\x00")          # control type + CANCEL_PUSH, not SETTINGS
flush(conn, s, port, 0.4)
# aioquic surfaces a received CONNECTION_CLOSE on _close_event (it moves the
# connection to DRAINING rather than queueing a next_event()).
try:
    for _ in range(4):
        r, _ = s.recvfrom(4096)
        conn.receive_datagram(r, ("127.0.0.1", port), now=0.5)
        if conn._close_event is not None:
            break
except socket.timeout:
    pass
s.close()
term = conn._close_event
assert term is not None, "server did not close the connection"
assert isinstance(term, ConnectionTerminated) and term.error_code == 0x10a, \
    f"{term!r} (want H3_MISSING_SETTINGS 0x10a)"

# --- invalid: closing the control stream is H3_CLOSED_CRITICAL_STREAM ---
# The frame is a valid control stream (SETTINGS first) but carries FIN, which
# closes a stream that must stay open.
conn, s = handshake(port)
uni = conn.get_next_available_stream_id(is_unidirectional=True)
conn.send_stream_data(uni, b"\x00\x04\x00", end_stream=True)
flush(conn, s, port, 0.4)
try:
    for _ in range(4):
        r, _ = s.recvfrom(4096)
        conn.receive_datagram(r, ("127.0.0.1", port), now=0.5)
        if conn._close_event is not None:
            break
except socket.timeout:
    pass
s.close()
term = conn._close_event
assert term is not None, "server did not close the connection on control-stream FIN"
assert isinstance(term, ConnectionTerminated) and term.error_code == 0x104, \
    f"{term!r} (want H3_CLOSED_CRITICAL_STREAM 0x104)"


# --- the SETTINGS payload itself (RFC 9114 7.2.4 / 7.2.4.1) ----------------
# The walk checked which FRAMES may appear on the control stream but skipped the
# payload of the one frame that carries configuration, so a peer could send an
# identifier HTTP/3 reserves — or the same one twice — and hear nothing back.
def control_close_code(payload, budget=4):
    """Open a control stream carrying one SETTINGS frame; return the close code."""
    conn, s = handshake(port)
    uni = conn.get_next_available_stream_id(is_unidirectional=True)
    conn.send_stream_data(uni, b"\x00" + vlq(4) + vlq(len(payload)) + payload)
    flush(conn, s, port, 0.4)
    try:
        for _ in range(budget):
            r, _ = s.recvfrom(4096)
            conn.receive_datagram(r, ("127.0.0.1", port), now=0.5)
            if conn._close_event is not None:
                break
    except socket.timeout:
        pass
    s.close()
    ev = conn._close_event
    return getattr(ev, "error_code", None)


SETTINGS_ERROR, FRAME_ERROR = 0x109, 0x106

# Collected rather than asserted one at a time, so a run against a build that
# does not parse the payload reports every case instead of stopping at the first.
payload_cases = [
    # an HTTP/2 identifier HTTP/3 reserves: 0x02 was ENABLE_PUSH. Reserving these
    # is precisely so an HTTP/2-shaped peer is caught rather than misunderstood.
    ("reserved identifier 0x02", vlq(0x02) + vlq(1), SETTINGS_ERROR),
    ("reserved identifier 0x05", vlq(0x05) + vlq(1), SETTINGS_ERROR),
    ("the same identifier twice",
     vlq(0x06) + vlq(100) + vlq(0x06) + vlq(200), SETTINGS_ERROR),
    # the payload ends mid-pair (7.1)
    ("an identifier with no value", vlq(0x06), FRAME_ERROR),
]
problems = []
for label, payload, want in payload_cases:
    got = control_close_code(payload)
    if got != want:
        problems.append(f"{label}: got {got!r}, want 0x{want:x}")
assert not problems, "; ".join(problems)

# ...and the settings a real client sends must still be accepted, GREASE and all
conn, s = handshake(port)
uni = conn.get_next_available_stream_id(is_unidirectional=True)
good = (vlq(0x01) + vlq(0) + vlq(0x06) + vlq(16384)
        + vlq(0x07) + vlq(0) + vlq(0x21) + vlq(0))     # 0x21 is GREASE: ignored
conn.send_stream_data(uni, b"\x00" + vlq(4) + vlq(len(good)) + good)
enc = pylsqpack.Encoder()
enc.apply_settings(max_table_capacity=0, blocked_streams=0)
_, fields = enc.encode(0, [(b":method", b"GET"), (b":path", b"/hello.txt"),
                           (b":scheme", b"https"), (b":authority", b"h3.test")])
bidi = conn.get_next_available_stream_id()
conn.send_stream_data(bidi, vlq(1) + vlq(len(fields)) + fields, end_stream=True)
flush(conn, s, port, 0.4)
r, _ = s.recvfrom(4096)
conn.receive_datagram(r, ("127.0.0.1", port), now=0.5)
resp = b""
ev = conn.next_event()
while ev is not None:
    if isinstance(ev, StreamDataReceived) and ev.stream_id == bidi:
        resp += ev.data
    ev = conn.next_event()
s.close()
assert conn._close_event is None, f"a valid SETTINGS frame was refused: {conn._close_event!r}"
frames = []
i = 0
while i < len(resp):
    ty, i = rvlq(resp, i)
    ln, i = rvlq(resp, i)
    frames.append((ty, resp[i:i + ln]))
    i += ln
hdr = next(p for ty, p in frames if ty == 1)
dec = pylsqpack.Decoder(0, 0)
_, headers = dec.feed_header(0, hdr)
assert dict(headers).get(b":status") == b"200", dict(headers)

print("ok")
