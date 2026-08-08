#!/usr/bin/env python3
# Start N HTTP/3 uploads, each big enough that its body is captured to a file,
# and walk away from every one of them without ever sending the FIN.
#
# There is nothing for this to assert from the client's side -- the point is
# what it leaves BEHIND on the server, which run_tests.sh measures by counting
# the worker's open descriptors on either side of the call. A capture file is an
# O_TMPFILE, so closing the descriptor is the only thing that gives the space
# back, and under PrivateTmp that space is RAM.
#
# Usage: h3_abandon_upload.py <port> <count>
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection

PORT = int(sys.argv[1])
COUNT = int(sys.argv[2])
ADDR = ("127.0.0.1", PORT)

for _ in range(COUNT):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    vt = [0.0]

    def clk():
        vt[0] += 0.001
        return vt[0]

    conn.connect(ADDR, now=clk())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.1)

    def pump():
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ADDR)

    pump()
    dl = time.time() + 10
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            conn.receive_datagram(s.recvfrom(4096)[0], ADDR, now=clk())
        except socket.timeout:
            pass
        pump()
    if not conn._handshake_confirmed:
        print("handshake failed")
        sys.exit(1)

    h3 = H3Connection(conn)
    sid = conn.get_next_available_stream_id()
    h3.send_headers(sid, [(b":method", b"POST"), (b":scheme", b"https"),
                          (b":authority", b"localhost"), (b":path", b"/api/echo"),
                          (b"content-length", b"100000")], end_stream=False)
    h3.send_data(sid, b"a" * 20000, end_stream=False)   # captured; no FIN, ever
    pump()
    for _ in range(20):                                  # let the server take it
        try:
            conn.receive_datagram(s.recvfrom(4096)[0], ADDR, now=clk())
        except socket.timeout:
            pass
        pump()
    s.close()                                            # and vanish
print("OK")
