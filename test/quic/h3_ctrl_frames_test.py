#!/usr/bin/env python3
# HTTP/3 control-stream framing (RFC 9114 6.2.1, 7.2). The control stream carries
# a frame sequence like any other stream, but linnea only ever peeked at its
# first two bytes to check the opening SETTINGS and then ignored everything that
# followed — so a DATA or HEADERS frame, a second SETTINGS, or a frame type
# HTTP/3 reserves all sailed through where the RFC calls each one a connection
# error of type H3_FRAME_UNEXPECTED (0x105).
#
# The frames now stream through a walk carried in the connection, so a frame
# header split across two STREAM frames resumes where it stopped, and frames we
# do not read are skipped by their declared length.
#
# Each case sends control-stream bytes in one or more chunks (each chunk becomes
# its own STREAM frame) and then either expects a connection close with a given
# error code, or expects the connection to still serve a request.
# Usage: h3_ctrl_frames_test.py <port>
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived

PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)


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


def handshake():
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    conn.connect(ADDR, now=0.0)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    for d, _ in conn.datagrams_to_send(now=0.0):
        s.sendto(d, ADDR)
    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ADDR, now=0.1)
    for d, _ in conn.datagrams_to_send(now=0.2):
        s.sendto(d, ADDR)
    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ADDR, now=0.3)
    assert conn._handshake_confirmed, "handshake not confirmed"
    while conn.next_event() is not None:
        pass
    return conn, s


def pump(conn, s, t, wait=0.15):
    """Flush what is queued, then absorb whatever comes back."""
    for d, _ in conn.datagrams_to_send(now=t):
        s.sendto(d, ADDR)
    s.settimeout(wait)
    try:
        while True:
            r, _ = s.recvfrom(4096)
            conn.receive_datagram(r, ADDR, now=t)
    except socket.timeout:
        pass


def serves(conn, s, t):
    """True if a GET on this connection still comes back 200."""
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"GET"), (b":path", b"/hello.txt"),
                               (b":scheme", b"https"), (b":authority", b"h3.test")])
    bidi = conn.get_next_available_stream_id()
    conn.send_stream_data(bidi, vlq(1) + vlq(len(fields)) + fields, end_stream=True)
    resp = b""
    deadline = time.time() + 4
    while not resp and time.time() < deadline:
        for d, _ in conn.datagrams_to_send(now=t):
            s.sendto(d, ADDR)
        t += 0.1
        s.settimeout(0.5)
        try:
            r, _ = s.recvfrom(4096)
        except socket.timeout:
            continue
        conn.receive_datagram(r, ADDR, now=t)
        ev = conn.next_event()
        while ev is not None:
            if isinstance(ev, StreamDataReceived) and ev.stream_id == bidi:
                resp += ev.data
            ev = conn.next_event()
    i = 0
    while i < len(resp):
        ty, i = rvlq(resp, i)
        ln, i = rvlq(resp, i)
        if ty == 1:
            _, headers = pylsqpack.Decoder(0, 0).feed_header(0, resp[i:i + ln])
            return dict(headers).get(b":status") == b"200"
        i += ln
    return False


def probe(chunks, stream_type_prefix=True):
    """Send control-stream chunks, one STREAM frame each. Returns (close_code,
    still_serves) — close_code is None when the connection was left open."""
    conn, s = handshake()
    uni = conn.get_next_available_stream_id(is_unidirectional=True)
    t = 0.4
    for n, c in enumerate(chunks):
        conn.send_stream_data(uni, c)
        pump(conn, s, t)
        t += 0.2
        if conn._close_event is not None:
            break
    code = None
    if conn._close_event is not None:
        ev = conn._close_event
        code = ev.error_code if isinstance(ev, ConnectionTerminated) else -1
    ok = False if code is not None else serves(conn, s, t)
    s.close()
    return code, ok


UNEXPECTED = 0x105          # H3_FRAME_UNEXPECTED
STREAM_CREATION = 0x103     # H3_STREAM_CREATION_ERROR
SETTINGS = b"\x00\x04\x00"  # control stream type, then an empty SETTINGS frame

# (label, control-stream chunks, expected close code or None for "keeps serving")
CASES = [
    # legal on a control stream: skipped by length, connection unharmed
    ("GREASE frame ignored", [SETTINGS + vlq(0x21) + vlq(2) + b"xx"], None),
    # PRIORITY_UPDATE (RFC 9218) is what Chrome actually puts on its control
    # stream, and its type is a FOUR-byte varint — the case that proves the walk
    # accumulates a multi-byte type, not just the one-byte types above
    ("PRIORITY_UPDATE ignored",
     [SETTINGS + vlq(0xF0700) + vlq(4) + b"0=\xe2\x81"], None),
    ("PRIORITY_UPDATE, type split across frames",
     [SETTINGS + vlq(0xF0700)[:2], vlq(0xF0700)[2:] + vlq(1) + b"0"], None),
    # a GREASE type at the top of the varint range: 8 bytes of type alone
    ("8-byte type varint ignored",
     [SETTINGS + (0xC000000000000000 | 0x1F * 7 + 0x21).to_bytes(8, "big")
      + vlq(1) + b"x"], None),
    ("CANCEL_PUSH accepted", [SETTINGS + b"\x03\x01\x00"], None),
    ("GOAWAY accepted", [SETTINGS + b"\x07\x01\x00"], None),
    ("MAX_PUSH_ID accepted", [SETTINGS + b"\x0d\x01\x00"], None),
    # a frame whose payload is longer than one STREAM frame is still skipped
    # whole, so the frame after it is read as a frame and not as payload
    ("long payload spans frames",
     [SETTINGS + b"\x0d\x20" + b"\x00" * 10, b"\x00" * 22 + b"\x03\x01\x00"], None),

    # request-stream frames have no business here (7.2.1, 7.2.2)
    ("DATA on the control stream", [SETTINGS + b"\x00\x01\x41"], UNEXPECTED),
    ("HEADERS on the control stream", [SETTINGS + b"\x01\x01\x41"], UNEXPECTED),
    # a server must never receive PUSH_PROMISE (7.2.5)
    ("PUSH_PROMISE on the control stream", [SETTINGS + b"\x05\x01\x00"], UNEXPECTED),
    # the types HTTP/2 used and HTTP/3 reserves (7.2.8)
    ("reserved h2 type 0x02", [SETTINGS + b"\x02\x00"], UNEXPECTED),
    ("reserved h2 type 0x06", [SETTINGS + b"\x06\x00"], UNEXPECTED),
    ("reserved h2 type 0x08", [SETTINGS + b"\x08\x00"], UNEXPECTED),
    ("reserved h2 type 0x09", [SETTINGS + b"\x09\x00"], UNEXPECTED),
    # SETTINGS appears exactly once (7.2.4)
    ("a second SETTINGS", [SETTINGS + b"\x04\x00"], UNEXPECTED),

    # the walk carries a frame header across a STREAM-frame boundary: the DATA
    # frame's type byte arrives alone, its length and payload in the next frame
    ("split header, illegal frame", [SETTINGS + b"\x00", b"\x01\x41"], UNEXPECTED),
    # and the same split on a legal opening SETTINGS must NOT read as a
    # violation — type byte in one frame, length in the next
    ("split header, legal frames",
     [b"\x00\x04", b"\x00" + vlq(0x21) + vlq(1) + b"z"], None),
]

fails = 0
for label, chunks, want in CASES:
    code, ok = probe(chunks)
    if want is None:
        good = code is None and ok
        got = "kept serving" if good else f"close={code and hex(code)} serves={ok}"
    else:
        good = code == want
        got = f"close={code and hex(code)}"
    print(f"{'ok  ' if good else 'FAIL'} {label}: {got}")
    fails += not good

# A push stream is server-initiated only: a client that opens one is a connection
# error of type H3_STREAM_CREATION_ERROR (6.2.2). It used to be ignored as an
# unknown stream type.
conn, s = handshake()
uni = conn.get_next_available_stream_id(is_unidirectional=True)
conn.send_stream_data(uni, b"\x01\x00")          # push stream type, then a push id
pump(conn, s, 0.4, wait=0.5)
ev = conn._close_event
code = ev.error_code if isinstance(ev, ConnectionTerminated) else None
s.close()
good = code == STREAM_CREATION
print(f"{'ok  ' if good else 'FAIL'} client-opened push stream: close={code and hex(code)}")
fails += not good

if fails:
    sys.exit(1)
print("ok")
