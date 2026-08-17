#!/usr/bin/env python3
# QUIC transport-parameter validation (audit Finding 13, RFC 9000 7.4/18.2). The
# parser used to treat malformed structure as a clean end of the list, ignore
# duplicate ids, accept integer payloads with trailing bytes, and skip
# out-of-range or client-forbidden parameters -- so a client could authenticate
# its source CID first and then append anything. Each malformed set below must
# now close the handshake with TRANSPORT_PARAMETER_ERROR (0x08).
#
# The malformed bytes are appended to aioquic's own (valid) transport parameters
# by wrapping _serialize_transport_parameters, so the source-CID parameter is
# present and valid and only the appended bytes are at fault.
#
# Usage: tp_validation.py <port>.  Prints ok/FAIL lines.
import socket
import ssl
import sys
import time

import aioquic.quic.connection as qc
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated

PORT = int(sys.argv[1])
TRANSPORT_PARAMETER_ERROR = 0x08
_orig = qc.QuicConnection._serialize_transport_parameters


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    if n < 2 ** 30:
        return (0x80000000 | n).to_bytes(4, "big")
    return (0xC000000000000000 | n).to_bytes(8, "big")


def tp(pid, value):
    return vlq(pid) + vlq(len(value)) + value


def close_code(extra):
    """Handshake with `extra` bytes appended to the transport parameters; return
    the transport error the server closed with, or None."""
    def patched(self):
        return _orig(self) + extra
    qc.QuicConnection._serialize_transport_parameters = patched
    try:
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
        cfg.verify_mode = ssl.CERT_NONE
        cfg.server_name = "localhost"
        conn = QuicConnection(configuration=cfg)
        vt = [0.0]

        def clk():
            vt[0] += 0.001
            return vt[0]

        conn.connect(("127.0.0.1", PORT), now=clk())
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)

        def flush():
            for d, _ in conn.datagrams_to_send(now=clk()):
                s.sendto(d, ("127.0.0.1", PORT))

        flush()
        code, dl = None, time.time() + 5
        while code is None and time.time() < dl:
            try:
                r, _ = s.recvfrom(4096)
                conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
            except socket.timeout:
                conn.handle_timer(now=clk())
            ce = getattr(conn, "_close_event", None)
            if isinstance(ce, ConnectionTerminated):
                code = ce.error_code
            for ev in iter(conn.next_event, None):
                if isinstance(ev, ConnectionTerminated):
                    code = ev.error_code
            flush()
        s.close()
        return code
    finally:
        qc.QuicConnection._serialize_transport_parameters = _orig


fails = 0


def check(name, got, want):
    global fails
    ok = got == want
    g = "none" if got is None else f"0x{got:02x}"
    print(("ok   " if ok else "FAIL ") + f"{name} (close={g}, want 0x{want:02x})")
    if not ok:
        fails += 1


# a truncated parameter (an id byte with no length/value)
check("truncated parameter", close_code(b"\x40"), TRANSPORT_PARAMETER_ERROR)
# a duplicate initial_max_data (0x04) -- aioquic already sent one
check("duplicate parameter", close_code(tp(0x04, vlq(1000))), TRANSPORT_PARAMETER_ERROR)
# a client-forbidden server-only parameter: stateless_reset_token (0x02)
check("server-only parameter", close_code(tp(0x02, b"\x00" * 16)), TRANSPORT_PARAMETER_ERROR)
# max_udp_payload_size (0x03, which aioquic does not send) with an integer plus a
# trailing byte -- the varint must fill the payload exactly
check("integer with trailing bytes",
      close_code(vlq(0x03) + vlq(3) + vlq(1300) + b"\x00"), TRANSPORT_PARAMETER_ERROR)
# max_udp_payload_size below its 1200 floor: an out-of-range value
check("out-of-range value", close_code(tp(0x03, vlq(1000))), TRANSPORT_PARAMETER_ERROR)

print("ok" if fails == 0 else f"FAIL ({fails})")
sys.exit(0 if fails == 0 else 1)
