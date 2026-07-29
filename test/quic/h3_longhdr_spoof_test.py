#!/usr/bin/env python3
# Regression for peer-address adoption from an UNAUTHENTICATED long-header packet
# (RFC 9000 §9). h3_migration_spoof_test.py covers the short-header (1-RTT) half of
# this: the address is committed only once the AEAD opens. The long-header half was
# still open — every handshake-flight packet carrying a known connection id moved
# the peer address before anything about it was checked, and no long-header packet
# authenticates its sender (Initial keys are derived from the connection id, which
# travels in the clear). So an attacker who had seen one datagram of a connection
# could replay it from any source address and the server's sends would follow.
#
# Here: start a large download, then from a SECOND socket send long-header packets —
# one Initial-typed, one Handshake-typed — carrying the connection id the server
# issued. Both must leave the peer address alone: the download keeps arriving on the
# original socket and the spoofed source receives nothing.
#
# Both probes address the server's OWN connection id, which is what the eBPF
# reuseport program steers on, so they land on the worker holding the connection.
# Replaying the client's opening Initial verbatim would not: its destination id is
# the client's own random one, so the kernel hashes the spoofed 4-tuple to an
# arbitrary worker, which quite properly answers a ClientHello it has never seen
# with a fresh handshake — a new connection, not a redirected one.
# Usage: h3_longhdr_spoof_test.py <port>
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

server_cid = conn._peer_cid.cid
assert len(server_cid) == 8, f"unexpected server CID length {len(server_cid)}"


def long_pkt(first_byte, token=b""):
    # a QUIC v1 long header addressed to the id the server issued, with an empty
    # source id and a payload that cannot possibly open: well-formed enough to
    # route to the connection, never authentic. 0xC0 is Initial, 0xE0 Handshake.
    body = os.urandom(40)
    ln = bytes([0x40 | (len(body) >> 8), len(body) & 0xFF])   # a 2-byte varint
    return (bytes([first_byte]) + b"\x00\x00\x00\x01"
            + bytes([len(server_cid)]) + server_cid + b"\x00" + token + ln + body)


def spoof_burst():
    spoof.sendto(long_pkt(0xC0, token=b"\x00"), ("127.0.0.1", PORT))   # Initial
    spoof.sendto(long_pkt(0xE0), ("127.0.0.1", PORT))                  # Handshake


h3 = H3Connection(conn)
sid = conn.get_next_available_stream_id()
h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                      (b":authority", b"localhost"), (b":path", PATH.encode())],
                end_stream=True)
flush()

# get the transfer going, leaving most of the 600 KB still to send
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

# Inject from a second source port, then go quiet on socket 1: any real packet from
# it would re-adopt its address and hide the bug. The server pumps more of the file
# every ~50 ms, so a redirected connection shows up as bytes on socket 2.
spoof = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
spoof.bind(("127.0.0.1", 0))
spoof.settimeout(0.1)
for _ in range(3):
    spoof_burst()

redirected = 0
end = time.time() + 2.0
while time.time() < end:
    try:
        d, _ = spoof.recvfrom(65535)
        redirected += len(d)
    except socket.timeout:
        pass
    spoof_burst()

if redirected:
    print(f"FAIL: {redirected} bytes went to the spoofed source — the server adopted "
          f"a peer address from an unauthenticated long-header packet")
    sys.exit(1)

# and the real client still owns the connection: the rest of the file arrives on
# socket 1, which a redirected server could never deliver
dl = time.time() + 15
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
if got < SIZE:
    print(f"FAIL: download stalled at {got}/{SIZE} bytes after the spoofed packets")
    sys.exit(1)
print("ok (long-header packets from a spoofed source moved nothing; download intact)")
