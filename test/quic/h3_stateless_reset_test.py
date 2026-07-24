#!/usr/bin/env python3
# Stateless reset (RFC 9000 §10.3). When a 1-RTT packet arrives for a connection
# id the server holds no state for (e.g. after the slot was idle-reclaimed or the
# worker restarted), the server sends a stateless reset so the peer tears the
# connection down immediately instead of waiting out its idle timeout. The reset is
# a short-header-shaped packet ending in the 16-byte reset token for that id, and
# must be shorter than the packet that triggered it (no amplification, no loop).
#
# This drives a real handshake (so the server's stateless_reset_token transport
# parameter must parse), then from a second socket sends a short-header packet with
# an unknown random connection id and checks the reply is a stateless-reset shape.
# Usage: h3_stateless_reset_test.py <port>
import os, socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

PORT = int(sys.argv[1])
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
vt = [0.0]
def clk():
    vt[0] += 0.002
    return vt[0]
conn.connect(("127.0.0.1", PORT), now=clk())
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.1)
def flush():
    for d, _ in conn.datagrams_to_send(now=clk()):
        s.sendto(d, ("127.0.0.1", PORT))
flush()
dl = time.time() + 8
while not conn._handshake_confirmed and time.time() < dl:
    try:
        r, _ = s.recvfrom(4096); conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
    except socket.timeout:
        conn.handle_timer(now=clk())
    flush()
assert conn._handshake_confirmed, "handshake failed (stateless_reset_token tp must parse)"

# Send short-header packets (fixed bit set) with an unknown connection id whose
# worker byte is 0, padded to 39 bytes. A worker only resets ids it issued (the
# first CID byte is the worker index), and without CAP_BPF the kernel spreads
# datagrams across workers by 4-tuple, so send from many source ports — at least
# one reaches worker 0, which resets it. (In production the BPF steers every id to
# its worker, so one packet suffices; this only works around the test environment.)
TRIGGER = bytes([0x40, 0x00]) + os.urandom(7) + os.urandom(30)   # 39 bytes, worker 0
reply = None
for _ in range(48):
    p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    p.bind(("127.0.0.1", 0))
    p.settimeout(0.15)
    p.sendto(TRIGGER, ("127.0.0.1", PORT))
    try:
        reply, _ = p.recvfrom(65535)
        p.close()
        break
    except socket.timeout:
        p.close()

if reply is None:
    print("FAIL: no stateless reset sent for an unknown connection id")
    sys.exit(1)
# short-header form: fixed bit (0x40) set, long-header bit (0x80) clear
if (reply[0] & 0xc0) != 0x40:
    print(f"FAIL: reply first byte {reply[0]:#04x} is not a short-header form")
    sys.exit(1)
# at least 21 bytes (min stateless reset) and shorter than the trigger (no loop/amp)
if not (21 <= len(reply) < len(TRIGGER)):
    print(f"FAIL: reply length {len(reply)} not in [21, {len(TRIGGER)})")
    sys.exit(1)
print(f"ok (stateless reset: {len(reply)} bytes, short-header form, shorter than the "
      f"{len(TRIGGER)}-byte trigger)")
