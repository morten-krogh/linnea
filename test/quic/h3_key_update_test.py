#!/usr/bin/env python3
# Regression for 1-RTT key update (RFC 9001 §6). A client may initiate a key
# update at any time: it flips the key-phase bit and switches to next-generation
# keys derived from the current traffic secret. The server MUST follow — derive
# the next secret ("quic ku"), decrypt with the new keys, and update its own send
# keys. A server that only ever holds phase-0 keys can no longer decrypt the
# client's packets after the update (its acks/requests are all lost), so the
# transfer wedges.
#
# Here: start a large download, receive part of it, trigger a client key update,
# then require the rest to arrive. A fixed server completes it; a server without
# key-update support stalls once the client's key phase flips.
# Usage: h3_key_update_test.py <port>
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

h3 = H3Connection(conn)
sid = conn.get_next_available_stream_id()
h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                      (b":authority", b"localhost"), (b":path", PATH.encode())],
                end_stream=True)
flush()

got = 0
updated = False
deadline = time.time() + 20
while got < SIZE and time.time() < deadline:
    try:
        r, _ = s.recvfrom(65535)
        conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        for qe in iter(conn.next_event, None):
            for ev in h3.handle_event(qe):
                if isinstance(ev, DataReceived):
                    got += len(ev.data)
    except socket.timeout:
        conn.handle_timer(now=clk())
    # once the transfer is well under way, initiate a key update; from here the
    # client's packets carry the flipped key phase and next-generation keys.
    if not updated and got > 100000:
        conn.request_key_update()
        updated = True
    flush()

if got != SIZE:
    print(f"FAIL: got {got} of {SIZE} bytes after a key update (updated={updated}) "
          f"— the server did not follow the 1-RTT key update")
    sys.exit(1)
print("ok (transfer completed across a client-initiated key update)")
