#!/usr/bin/env python3
# Regression for peer-address adoption from a REPLAYED packet (RFC 9000 §9.3, §12.3).
#
# h3_migration_spoof_test.py covers the forged half of this: a garbage 1-RTT packet
# cannot be AEAD-opened, so its source is never adopted. That fix drew the line at
# "the packet authenticated", and the comment in the source said so outright —
# "only an authenticated peer can move the address". Replay walks straight through
# that line. A datagram captured off the wire and sent again carries a perfectly
# valid AEAD tag, because it is a bit-for-bit copy of one that genuinely had one.
# So an attacker who had seen ONE 1-RTT datagram of a live connection could resend
# it from any source address and the server's sends followed them — a denial of
# service against the real client and a reflection primitive aimed at the spoofed
# address, with anti-amplification not re-armed and no path validation to undo it.
#
# The fix is freshness, not authenticity: RFC 9000 12.3 requires discarding a packet
# number already processed, and 9.3 allows only the highest-numbered packet to move
# the address. A conforming peer never reuses a packet number — a retransmission
# carries the same frames under a new one — so this can only drop duplicates.
#
# Here: start a large download, capture a genuine 1-RTT datagram we sent, then go
# quiet on socket 1 and replay that exact datagram from a SECOND source port. A
# buggy server opens it (the tag is valid), adopts the spoofed source, and pumps the
# rest of the 600 KB there. A fixed server discards it as already-processed.
#
# Then socket 1 resumes and the transfer must still complete: dropping duplicates
# must not cost us a packet we actually needed.
# Usage: h3_replay_spoof_test.py <port>
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived

PORT = int(sys.argv[1])
PATH, SIZE = "/h3big.bin", 600000

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

last_sent = [None]
def flush(capture=False):
    for d, _ in conn.datagrams_to_send(now=clk()):
        s.sendto(d, ("127.0.0.1", PORT))
        # Short header = high bit clear. Only a 1-RTT packet exercises the path
        # under test; handshake packets take a different branch entirely.
        if capture and d and not (d[0] & 0x80):
            last_sent[0] = d
flush()
dl = time.time() + 8
while not conn._handshake_confirmed and time.time() < dl:
    try:
        r, _ = s.recvfrom(4096); conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
    except socket.timeout:
        conn.handle_timer(now=clk())
    flush()
assert conn._handshake_confirmed, "handshake failed"

h3 = H3Connection(conn)
sid = conn.get_next_available_stream_id()
h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                      (b":authority", b"localhost"), (b":path", PATH.encode())],
                end_stream=True)
flush(capture=True)

# Drive the transfer far enough that chunks are flowing and most of the 600 KB is
# still to come, capturing our own 1-RTT datagrams (ACKs) as we go.
got = 0
dl = time.time() + 10
while got < 50000 and time.time() < dl:
    try:
        r, _ = s.recvfrom(65535)
        conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        for qe in iter(conn.next_event, None):
            for ev in h3.handle_event(qe):
                if isinstance(ev, DataReceived):
                    got += len(ev.data)
    except socket.timeout:
        conn.handle_timer(now=clk())
    flush(capture=True)
assert got >= 50000, f"transfer did not get going ({got} bytes)"

replay = last_sent[0]
assert replay, "captured no 1-RTT datagram to replay"

# Replay it verbatim from a second source port. Socket 1 stays quiet throughout —
# any genuine packet from it would legitimately re-adopt its address and mask the
# bug. Replaying immediately keeps the truncated packet number unambiguous, so the
# server expands it to the original value and the AEAD opens: this really is an
# authentic packet arriving from the wrong place, which is the whole point.
spoof = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
spoof.bind(("127.0.0.1", 0))
spoof.settimeout(0.1)

redirected = 0
end = time.time() + 2.0
while time.time() < end:
    spoof.sendto(replay, ("127.0.0.1", PORT))
    try:
        while True:
            d, _ = spoof.recvfrom(65535)
            redirected += len(d)
    except socket.timeout:
        pass

if redirected:
    print(f"FAIL: {redirected} bytes were redirected to the spoofed source — a "
          f"replayed packet moved the peer address (RFC 9000 9.3/12.3)")
    sys.exit(1)

# The connection must have survived all that: resume socket 1 and finish the file.
dl = time.time() + 20
while got < SIZE and time.time() < dl:
    try:
        r, _ = s.recvfrom(65535)
        conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        for qe in iter(conn.next_event, None):
            for ev in h3.handle_event(qe):
                if isinstance(ev, DataReceived):
                    got += len(ev.data)
    except socket.timeout:
        conn.handle_timer(now=clk())
    flush()

if got != SIZE:
    print(f"FAIL: transfer did not recover after the replay ({got}/{SIZE} bytes) — "
          f"discarding duplicates must not drop a packet we needed")
    sys.exit(1)
print(f"ok (replayed packet ignored, nothing sent to the spoofed source; "
      f"transfer completed {got}/{SIZE} bytes afterwards)")
