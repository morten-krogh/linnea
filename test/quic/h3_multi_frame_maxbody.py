#!/usr/bin/env python3
# max_body on the h3 REASSEMBLY path, at the boundary and across a frame split.
#
# h3_single_frame_maxbody.py pins the copy-free path: one offset-zero STREAM
# frame carrying HEADERS+DATA+FIN. That is a different cap check from this one.
# The reassembly path bounds each DATA frame's DECLARED length against the
# headroom that is LEFT (max_body - spill_len), so the interesting case is not
# one frame at the limit but a body SPLIT across frames whose sum crosses it:
# each frame is individually well under the cap and only the running total is
# not. Nothing exercised that -- the split is what makes the subtraction do any
# work, and a cap that only ever sees whole bodies cannot tell a correct
# accumulator from one that forgets.
#
# Also the boundary itself in all three positions audit-report-38 asks for: one
# byte below, exactly at, one byte above. `cmp/ja` and `cmp/jae` are one letter
# apart and refusing a body of exactly max_body is as wrong as accepting one
# past it.
#
# Usage: h3_multi_frame_maxbody.py <port> <max_body>.  Prints OK or a failure.
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

PORT = int(sys.argv[1])
CAP = int(sys.argv[2])


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
conn.connect(("127.0.0.1", PORT), now=0.0)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
clock = [0.0]


sent = [0]


def pump():
    n = 0
    for d, _ in conn.datagrams_to_send(now=clock[0]):
        s.sendto(d, ("127.0.0.1", PORT))
        n += 1
    sent[0] += n
    return n


pump()
for _ in range(4):
    try:
        r, _ = s.recvfrom(4096)
    except socket.timeout:
        break
    clock[0] += 0.1
    conn.receive_datagram(r, ("127.0.0.1", PORT), now=clock[0])
    pump()
    if conn._handshake_confirmed:
        break
assert conn._handshake_confirmed, "handshake not confirmed"
while conn.next_event() is not None:
    pass
clock[0] = 0.4


def post_chunks(sizes):
    """One DATA frame per entry in `sizes`, each in its own STREAM frame.

    pump() between sends is what keeps them separate: without it aioquic
    coalesces the queued bytes into one frame and this becomes the single-frame
    test again, quietly testing the path that was already covered."""
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"POST"), (b":path", b"/api/echo"),
                               (b":scheme", b"https"), (b":authority", b"localhost")])
    bidi = conn.get_next_available_stream_id()
    # datagrams that actually left, per send: this test is worthless if the
    # sends coalesce, because then it is the single-frame path wearing a
    # multi-frame label -- and it would PASS, since that path caps correctly
    # too. So the premise is asserted rather than assumed.
    flushes = []
    conn.send_stream_data(bidi, vlq(1) + vlq(len(fields)) + fields, end_stream=False)
    flushes.append(pump())
    clock[0] += 0.05
    for k, n in enumerate(sizes):
        last = k == len(sizes) - 1
        conn.send_stream_data(bidi, vlq(0) + vlq(n) + b"a" * n, end_stream=last)
        flushes.append(pump())
        clock[0] += 0.05
    if any(f == 0 for f in flushes):
        return f"COALESCED{flushes}"
    resp = b""
    s.settimeout(0.3)
    deadline = time.time() + 8
    while not resp and time.time() < deadline:
        pump()
        clock[0] += 0.2
        try:
            r, _ = s.recvfrom(4096)
        except socket.timeout:
            continue
        conn.receive_datagram(r, ("127.0.0.1", PORT), now=clock[0])
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
            return dict(headers).get(b":status", b"?").decode()
        i += ln
    return "no reply"


half = CAP // 2
CASES = [
    ("one frame, one byte below max_body", [CAP - 1], "200"),
    ("one frame, exactly max_body", [CAP], "200"),
    ("one frame, one byte above max_body", [CAP + 1], "413"),
    # the split cases: no single frame is near the cap, only the total
    ("two frames summing to exactly max_body", [half, CAP - half], "200"),
    ("two frames summing to one past max_body", [half, CAP - half + 1], "413"),
    ("four frames summing to exactly max_body",
     [CAP // 4] * 3 + [CAP - 3 * (CAP // 4)], "200"),
    ("four frames summing to one past max_body",
     [CAP // 4] * 3 + [CAP - 3 * (CAP // 4) + 1], "413"),
]

for label, sizes, want in CASES:
    got = post_chunks(sizes)
    if got.startswith("COALESCED"):
        print(f"{label}: sends did not leave as separate packets {got} -- "
              f"this case would have tested the single-frame path instead")
        sys.exit(1)
    if got != want:
        print(f"{label} (sizes {sizes}, sum {sum(sizes)}): want {want}, got {got}")
        sys.exit(1)
print("OK")
