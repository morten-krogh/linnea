#!/usr/bin/env python3
# Large responses over HTTP/3. A body over one packet is served as a sequence
# of STREAM-frame chunks, each in its own 1-RTT packet under the 1200-byte
# datagram floor, ack-clocked by the server's loss-recovery ring. This drives
# the real thing end to end:
#   1. a 600 KB file arrives intact (exact bytes, correct content-length) —
#      hundreds of chunks, so it also exercises the 2-byte packet numbers and
#      the receive-side packet-number expansion (the client's own numbers pass
#      256 while it acknowledges the transfer);
#   2. one server datagram is dropped mid-transfer — the lost chunk must be
#      rebuilt from the file and retransmitted after the PTO;
#   3. a small GET on another stream mid-transfer is answered inline while the
#      big response is still streaming;
#   4. a client whose flow-control window cannot take the file gets a 503
#      (refused, retryable) rather than a window overrun that would kill the
#      connection.
# Usage: h3_big_test.py <port>
import os
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

port = int(sys.argv[1])

# the served fixture: patterned, so any reordered/missing chunk breaks equality
BIG = bytes((i * 131 + (i >> 8) * 17 + 7) & 0xFF for i in range(600000))
with open(os.path.join(os.path.dirname(__file__), "..", "www", "h3big.bin"), "wb") as f:
    f.write(BIG)
with open(os.path.join(os.path.dirname(__file__), "..", "www", "hello.txt"), "rb") as f:
    HELLO = f.read()


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


def parse_h3(stream):
    frames = []
    i = 0
    while i < len(stream):
        ty, i = rvlq(stream, i)
        ln, i = rvlq(stream, i)
        frames.append((ty, stream[i:i + ln]))
        i += ln
    hdr = next(p for ty, p in frames if ty == 1)
    data = b"".join(p for ty, p in frames if ty == 0)
    dec = pylsqpack.Decoder(0, 0)
    _, headers = dec.feed_header(0, hdr)
    return dict(headers), data


def connect(**cfg_kwargs):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"], **cfg_kwargs)
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


def get(conn, stream_id, path):
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"GET"), (b":path", path),
                               (b":scheme", b"https"), (b":authority", b"h3.test")])
    conn.send_stream_data(stream_id, vlq(1) + vlq(len(fields)) + fields,
                          end_stream=True)


# --- 1 + 2 + 3: the big transfer, with one datagram dropped and a small GET
# interleaved mid-stream ---
conn, s = connect()
big_sid = conn.get_next_available_stream_id()
get(conn, big_sid, b"/h3big.bin")

streams = {}          # stream id -> (bytes, end_stream seen)
clock = [0.4]
dropped = False       # the loss injection: one server datagram never "arrives"
small_sid = None
small_sent_at = None  # bytes of big stream held when the small GET went out
s.settimeout(0.5)
deadline = time.time() + 60


def drain_events(conn):
    ev = conn.next_event()
    while ev is not None:
        if isinstance(ev, StreamDataReceived):
            data, fin = streams.get(ev.stream_id, (b"", False))
            streams[ev.stream_id] = (data + ev.data, fin or ev.end_stream)
        ev = conn.next_event()


while time.time() < deadline:
    for d, _ in conn.datagrams_to_send(now=clock[0]):
        s.sendto(d, ("127.0.0.1", port))
    clock[0] += 0.05
    try:
        r, _ = s.recvfrom(4096)
    except socket.timeout:
        clock[0] += 0.5   # let aioquic's own timers (ack sending) advance
        continue
    got = streams.get(big_sid, (b"", False))[0]
    if not dropped and len(got) > 30000 and not r[0] & 0x80:
        dropped = True    # swallow one data packet: the server must resend it
        # and, while the transfer now has a hole mid-flight, ask for a small
        # file on another stream: it is answered inline while the big response
        # is still streaming
        small_sid = conn.get_next_available_stream_id()
        small_sent_at = len(got)
        get(conn, small_sid, b"/hello.txt")
        continue
    conn.receive_datagram(r, ("127.0.0.1", port), now=clock[0])
    drain_events(conn)
    if streams.get(big_sid, (b"", False))[1] and (
            small_sid is None or streams.get(small_sid, (b"", False))[1]):
        break

assert dropped, "loss was never injected (transfer too small?)"
assert big_sid in streams and streams[big_sid][1], "big response incomplete"
hd, data = parse_h3(streams[big_sid][0])
assert hd.get(b":status") == b"200", hd
assert hd.get(b"content-length") == str(len(BIG)).encode(), hd
assert len(data) == len(BIG), f"got {len(data)} bytes, want {len(BIG)}"
assert data == BIG, "body corrupted"

assert small_sid is not None and streams[small_sid][1], "small response incomplete"
hd, data = parse_h3(streams[small_sid][0])
assert hd.get(b":status") == b"200", hd
assert data == HELLO, data
# the small GET went out mid-transfer, well before the big stream's end
assert small_sent_at < len(BIG) // 2, "small GET was not sent mid-transfer"
conn.close()
for d, _ in conn.datagrams_to_send(now=clock[0]):
    s.sendto(d, ("127.0.0.1", port))
s.close()

# --- 4: a window too small for the file is refused with a 503 ---
conn, s = connect(max_stream_data=4096)
sid = conn.get_next_available_stream_id()
get(conn, sid, b"/h3big.bin")
resp = b""
fin = False
s.settimeout(0.5)
deadline = time.time() + 10
while not fin and time.time() < deadline:
    for d, _ in conn.datagrams_to_send(now=clock[0]):
        s.sendto(d, ("127.0.0.1", port))
    clock[0] += 0.05
    try:
        r, _ = s.recvfrom(4096)
    except socket.timeout:
        continue
    conn.receive_datagram(r, ("127.0.0.1", port), now=clock[0])
    ev = conn.next_event()
    while ev is not None:
        if isinstance(ev, StreamDataReceived) and ev.stream_id == sid:
            resp += ev.data
            fin = fin or ev.end_stream
        ev = conn.next_event()
assert fin, "no response to the over-window request"
hd, data = parse_h3(resp)
assert hd.get(b":status") == b"503", hd
conn.close()
for d, _ in conn.datagrams_to_send(now=clock[0]):
    s.sendto(d, ("127.0.0.1", port))
s.close()
print("ok")
