#!/usr/bin/env python3
# A peer that sends more request-stream data than the window the server advertised
# (initial_max_stream_data_bidi_remote, bound to the reassembly buffer) commits a
# flow-control violation. The server must close the connection with a transport
# CONNECTION_CLOSE carrying FLOW_CONTROL_ERROR (0x03), not silently drop.
#
# aioquic is conformant, so we override its send-side flow-control limits after the
# handshake to make it send past the advertised window on one request stream, then
# require a ConnectionTerminated with the transport error code.
# Usage: h3_flow_violation_test.py <port>
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated

FLOW_CONTROL_ERROR = 0x03
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
assert conn._handshake_confirmed, "handshake failed"

# Send ~16 KB on one client-initiated bidi stream — well past the server's 8 KB
# request-stream window — with the send-side limits overridden so aioquic emits it.
sid = conn.get_next_available_stream_id()
conn.send_stream_data(sid, b"\x00" * 16000, end_stream=False)
conn._remote_max_data = 100_000_000
conn._remote_max_data_used = 0
conn._streams[sid].max_stream_data_remote = 100_000_000

terminated = None
deadline = time.time() + 8
while terminated is None and time.time() < deadline:
    flush()
    try:
        r, _ = s.recvfrom(65535)
        conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
    except socket.timeout:
        if conn._close_at is not None:
            conn.handle_timer(now=clk())
    for ev in iter(conn.next_event, None):
        if isinstance(ev, ConnectionTerminated):
            terminated = ev
            break

if terminated is None:
    print("FAIL: server did not close the connection on a flow-control violation")
    sys.exit(1)
if terminated.error_code != FLOW_CONTROL_ERROR:
    print(f"FAIL: closed with error {terminated.error_code:#x}, expected "
          f"FLOW_CONTROL_ERROR ({FLOW_CONTROL_ERROR:#x})")
    sys.exit(1)
print(f"ok (connection closed with FLOW_CONTROL_ERROR on an over-window request)")
