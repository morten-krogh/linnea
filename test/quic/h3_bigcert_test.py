#!/usr/bin/env python3
# Large certificate chain over HTTP/3. A real chain (leaf + intermediates) makes
# the server's handshake flight far larger than one datagram. QUIC forbids IP
# fragmentation, so linnea must split the Certificate CRYPTO across several
# Handshake packets, each in its own <=MTU datagram (RFC 9000 s14.1). This test
# drives aioquic against a config whose chain is four certificates (~2.9 KB of
# TLS handshake), captures every datagram the server sends, and checks:
#   * the handshake completes (the client reassembled the split CRYPTO stream),
#   * the flight really was segmented (more than one substantial datagram), and
#   * no datagram exceeds the 1200-byte floor every QUIC endpoint must accept.
# Then it issues a GET to confirm the connection is fully usable afterwards.
# Usage: h3_bigcert_test.py <port>
import socket
import ssl
import sys

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

MTU_FLOOR = 1200                 # every QUIC endpoint must accept this; we stay under it

port = int(sys.argv[1])
addr = ("127.0.0.1", port)

cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
conn.connect(addr, now=0.0)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)

now = [0.0]


def flush():
    now[0] += 0.05
    for d, _ in conn.datagrams_to_send(now=now[0]):
        s.sendto(d, addr)


flush()                          # the client Initial (ClientHello), padded to 1200

# Drain the server's handshake flight. With a real chain it arrives as several
# datagrams; feed each to aioquic (which reassembles the CRYPTO stream) and keep
# flushing so the client Finished goes out once the whole chain has landed.
sizes = []
while not conn._handshake_confirmed:
    try:
        r, _ = s.recvfrom(4096)
    except socket.timeout:
        break
    sizes.append(len(r))
    now[0] += 0.05
    conn.receive_datagram(r, addr, now=now[0])
    flush()

assert conn._handshake_confirmed, f"handshake not confirmed; server datagrams={sizes}"

# The flight must have been split: a single ~3 KB datagram would mean linnea did
# not segment (and would be dropped on a real 1500-MTU path).
big = [n for n in sizes if n > 200]
assert len(big) >= 2, f"flight was not segmented across datagrams: {sizes}"

# And no datagram may exceed the QUIC floor, or a real path would fragment/drop it.
assert max(sizes) <= MTU_FLOOR, f"datagram over the {MTU_FLOOR} floor: {sizes}"


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


# The connection must be fully usable after the segmented handshake: fetch a file.
while conn.next_event() is not None:
    pass
enc = pylsqpack.Encoder()
enc.apply_settings(max_table_capacity=0, blocked_streams=0)
_, fields = enc.encode(0, [(b":method", b"GET"),
                           (b":path", b"/hello.txt"),
                           (b":scheme", b"https"),
                           (b":authority", b"h3.test")])
conn.send_stream_data(0, vlq(1) + vlq(len(fields)) + fields, end_stream=True)
flush()

resp = b""
deadline_reads = 0
while deadline_reads < 6:
    try:
        r, _ = s.recvfrom(4096)
    except socket.timeout:
        break
    now[0] += 0.05
    conn.receive_datagram(r, addr, now=now[0])
    ev = conn.next_event()
    while ev is not None:
        if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
            resp += ev.data
        ev = conn.next_event()
    flush()
    if resp:
        break
    deadline_reads += 1
s.close()

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
headers = dict(headers)
assert headers.get(b":status") == b"200", headers
assert body == open("test/www/hello.txt", "rb").read(), body

print(f"ok (flight in {len(sizes)} datagrams, max {max(sizes)} bytes)")
