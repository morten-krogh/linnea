#!/usr/bin/env python3
# Regression for the unauthenticated peer-address adoption bug (RFC 9000 §9.3).
# The server used to overwrite the connection's peer address from the source of
# EVERY packet carrying a valid connection id, BEFORE decrypting it. So an on-path
# attacker who can see the (cleartext) connection id could inject one spoofed
# packet and redirect the server's full-rate stream to a third party.
#
# Here: start a large download, then from a SECOND socket (a different source
# port) send a garbage 1-RTT packet carrying the real connection id. The garbage
# cannot be AEAD-opened, so a fixed server must NOT adopt that source — the
# download must still complete on the original socket. A buggy server redirects
# its sends to the second socket and the original transfer stalls.
# Usage: h3_migration_spoof_test.py <port>
import os, socket, ssl, sys, time
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
assert conn._handshake_confirmed, "handshake failed"

# the connection id the client puts in its packets == the id the server issued
server_cid = conn._peer_cid.cid
assert len(server_cid) == 8, f"unexpected server CID length {len(server_cid)}"

h3 = H3Connection(conn)
sid = conn.get_next_available_stream_id()
h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                      (b":authority", b"localhost"), (b":path", PATH.encode())],
                end_stream=True)
flush()

# Drive the transfer far enough that chunks are flowing and the window has room
# (ack ~50 KB, leaving most of the 600 KB still to send).
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
    flush()
assert got >= 50000, f"transfer did not get going ({got} bytes)"

# From a SECOND source port, inject garbage short-header packets carrying the real
# connection id (0x40 fixed bit, then the 8-byte DCID, then random bytes). Then go
# quiet on socket 1 and watch socket 2: a buggy server adopts the spoofed source
# before it fails to decrypt, so its next pumped/retransmitted chunks arrive on
# socket 2. A fixed server ignores the unauthenticated source and sends nothing there.
spoof = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
spoof.bind(("127.0.0.1", 0))
spoof.settimeout(0.1)
for _ in range(5):
    spoof.sendto(bytes([0x40]) + server_cid + os.urandom(48), ("127.0.0.1", PORT))

# The server's rtx sweep pumps more of the 600 KB every ~50 ms; watch socket 2 for
# ~2 s. Do not touch socket 1 (any real packet from it would re-adopt its address).
redirected = 0
end = time.time() + 2.0
while time.time() < end:
    try:
        d, _ = spoof.recvfrom(65535)
        redirected += len(d)
    except socket.timeout:
        pass
    spoof.sendto(bytes([0x40]) + server_cid + os.urandom(48), ("127.0.0.1", PORT))

if redirected:
    print(f"FAIL: {redirected} bytes were redirected to the spoofed source — the "
          f"server adopted an unauthenticated peer address")
    sys.exit(1)
print("ok (server sent nothing to the spoofed source; unauthenticated address "
      "adoption rejected)")
