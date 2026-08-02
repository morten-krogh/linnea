#!/usr/bin/env python3
# A critical stream must not be closed BY ANY MEANS (RFC 9114 6.2).
#
# Closing the control stream with a FIN was detected. Resetting it was not: the
# check looked only at the FIN flag, so a peer could RESET_STREAM its control
# stream and the connection carried on as though it still had one — the settings
# and any GOAWAY that stream would have carried gone, with nothing said.
#
# The QPACK streams have the same protection and needed their ids recording
# first: nothing reads their contents (our table capacity is 0, so a conforming
# encoder sends none), so there had been no reason to remember which stream was
# which.
#
# Usage: h3_critical_reset_test.py <port>
import socket
import ssl
import sys
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

PORT = int(sys.argv[1])
H3_CLOSED_CRITICAL_STREAM = 0x104


def open_and_reset(stream_type, reset=True, budget=8.0):
    """Open a uni stream of the given h3 type, then reset it (or not).

    -> the connection close code, or None.
    """
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
    s.settimeout(0.4)

    def flush():
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ("127.0.0.1", PORT))

    flush()
    dl = time.time() + budget
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
    assert conn._handshake_confirmed, "handshake failed"

    uni = conn.get_next_available_stream_id(is_unidirectional=True)
    payload = bytes([stream_type])
    if stream_type == 0x00:            # a control stream must open with SETTINGS
        payload += b"\x04\x00"
    conn.send_stream_data(uni, payload)
    flush()
    time.sleep(0.15)
    try:
        for _ in range(2):
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
    except socket.timeout:
        pass

    if reset:
        conn.reset_stream(uni, error_code=0x10c)   # H3_REQUEST_CANCELLED
        flush()

    dl = time.time() + 5
    while time.time() < dl and conn._close_event is None:
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        except socket.timeout:
            conn.handle_timer(now=clk())
        while conn.next_event() is not None:
            pass
        flush()
    code = conn._close_event.error_code if conn._close_event else None
    s.close()
    return code


fails = 0
for name, stype in (("the control stream", 0x00),
                    ("the QPACK encoder stream", 0x02),
                    ("the QPACK decoder stream", 0x03)):
    code = open_and_reset(stype)
    if code == H3_CLOSED_CRITICAL_STREAM:
        print(f"ok   resetting {name} ends the connection (0x{code:x})")
    elif code is None:
        print(f"FAIL resetting {name} was not noticed — the connection carried "
              f"on as though it still had one")
        fails += 1
    else:
        print(f"FAIL resetting {name} gave 0x{code:x}, want "
              f"0x{H3_CLOSED_CRITICAL_STREAM:x}")
        fails += 1

# ...and a stream that is NOT critical may be reset freely, so the check is not
# simply ending every connection that carries a reset
code = open_and_reset(0x21)            # a GREASE uni stream type
if code is None:
    print("ok   resetting a non-critical stream is fine")
else:
    print(f"FAIL resetting a GREASE stream ended the connection (0x{code:x})")
    fails += 1

sys.exit(1 if fails else 0)
