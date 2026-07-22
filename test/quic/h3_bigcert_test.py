#!/usr/bin/env python3
# Large certificate chain over HTTP/3, with anti-amplification. A real chain
# (leaf + intermediates) makes the server's handshake flight both larger than one
# datagram AND larger than the 3x anti-amplification budget (RFC 9000 s8.1). So
# linnea must (a) split the Certificate CRYPTO across several <=MTU Handshake
# packets, and (b) send no more than 3x the bytes received until the client's
# address is validated, releasing the withheld tail once the client's first
# Handshake packet proves it is really there. With a chain this size the withheld
# tail spans several packets, so this also exercises a multi-packet resume.
#
# The test drives aioquic against a seven-cert config (~5.3 KB of TLS handshake)
# and checks, in order:
#   * the server's first burst (before we answer at all) stays within 3x what we
#     sent — the amplification limit is enforced;
#   * no datagram exceeds the 1200-byte floor every QUIC endpoint must accept;
#   * once we answer (validating our address) the handshake completes — so the
#     withheld tail was resumed — and the total the server sent exceeds 3x, which
#     it could only do after validation.
# Then it issues a GET to confirm the connection is fully usable afterwards.
#
# aioquic's clock is driven from real monotonic time: on loopback the whole
# exchange takes a few milliseconds, well under any PTO, so the client never
# spuriously retransmits its Initial and the multi-round resume stays orderly.
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
s.settimeout(0.3)

# aioquic's clock is virtual and advances only in small deliberate steps, decoupled
# from real time. That keeps it far below aioquic's ~1 s Initial-space PTO no matter
# how long real recvfrom's block, so the client never spuriously retransmits its
# Initial (which, addressed to a connection id the server has retired, would derail
# the handshake). The 30 ms step is above max_ack_delay, so a Handshake ACK the
# client deferred on one receive is emitted on the next flush — validating us and
# releasing the server's resume.
vt = [0.0]


def clk():
    vt[0] += 0.03
    return vt[0]


def flush():
    for d, _ in conn.datagrams_to_send(now=clk()):
        s.sendto(d, addr)


# Send the client Initial and note exactly how many bytes we sent: the server's
# budget is three times this until it validates our address.
client_sent = 0
for d, _ in conn.datagrams_to_send(now=clk()):
    s.sendto(d, addr)
    client_sent += len(d)

# Drain the server's first burst WITHOUT feeding aioquic and WITHOUT replying, so
# the server has no proof of our address and must stop at the amplification limit.
burst = []
while True:
    try:
        r, _ = s.recvfrom(4096)
    except socket.timeout:
        break
    burst.append(r)

assert burst, "server sent nothing"
server_burst = sum(len(r) for r in burst)
assert server_burst <= 3 * client_sent, \
    f"amplification: server sent {server_burst} > 3x{client_sent} before validation"
assert max(len(r) for r in burst) <= MTU_FLOOR, \
    f"datagram over the {MTU_FLOOR} floor: {[len(r) for r in burst]}"
assert len(burst) >= 2, f"flight not segmented: {[len(r) for r in burst]}"

# Now feed the burst and answer. Our ACK validates the address, so the server
# releases the part of the flight it held back and the handshake can complete.
for r in burst:
    conn.receive_datagram(r, addr, now=clk())

# Flush before each receive so a deferred ACK goes out, and keep going on a quiet
# round rather than giving up. On loopback the server answers each flush at once,
# so a healthy handshake finishes in a handful of rounds; the cap only bounds a
# genuinely stuck one (and keeps the virtual clock well under the Initial PTO).
server_total = server_burst
for _ in range(20):
    if conn._handshake_confirmed:
        break
    flush()
    try:
        r, _ = s.recvfrom(4096)
    except socket.timeout:
        continue
    server_total += len(r)
    conn.receive_datagram(r, addr, now=clk())

assert conn._handshake_confirmed, "handshake did not complete after we validated the address"
# The full flight is larger than the budget, so completing it required the server
# to send past 3x — which it may only do once validated. That is the resume.
assert server_total > 3 * client_sent, \
    f"server never exceeded the budget ({server_total} <= 3x{client_sent}); resume not exercised"


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


# The connection must be fully usable after the segmented, budget-limited
# handshake: fetch a file.
while conn.next_event() is not None:
    pass
enc = pylsqpack.Encoder()
enc.apply_settings(max_table_capacity=0, blocked_streams=0)
_, fields = enc.encode(0, [(b":method", b"GET"),
                           (b":path", b"/hello.txt"),
                           (b":scheme", b"https"),
                           (b":authority", b"h3.test")])
conn.send_stream_data(0, vlq(1) + vlq(len(fields)) + fields, end_stream=True)

resp = b""
for _ in range(20):
    if resp:
        break
    flush()
    try:
        r, _ = s.recvfrom(4096)
    except socket.timeout:
        continue
    conn.receive_datagram(r, addr, now=clk())
    ev = conn.next_event()
    while ev is not None:
        if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
            resp += ev.data
        ev = conn.next_event()
# close cleanly so the server reclaims the connection slot at once rather than
# waiting out its idle timeout — otherwise a rapid succession of handshakes would
# fill the pool
conn.close()
flush()
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

print(f"ok (burst {server_burst}B <= 3x{client_sent}, total {server_total}B in "
      f"{len(burst)}+ datagrams, all <= {MTU_FLOOR}B)")
