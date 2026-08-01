#!/usr/bin/env python3
# RESET_STREAM's Final Size is ours, not the peer's (RFC 9000 19.4, 4.5).
#
# On a client-initiated bidirectional stream, a server RESET_STREAM ends only the
# server-to-client direction, and Final Size is "the final size of the stream by
# the RESET_STREAM sender". When a malformed request was reset, the server sent
# the length of the CLIENT's request instead — on the reasoning that the reset
# settles the credit those bytes hold, which is true of the receive direction and
# not of the one being reset.
#
# The peer therefore charged its connection-level flow-control window for up to
# LINNEA_QUIC_RA_BUF (8 KB) of data it would never be sent, on every malformed
# request. A long-lived connection leaks that credit permanently, and a client
# whose initial_max_stream_data_bidi_remote sits below the declared size MUST
# close the connection with FLOW_CONTROL_ERROR (4.5) — so a large enough
# malformed request is a way to make a conforming client hang up.
#
# The server had the right pattern in three other places: .sl_toolong and both
# teardown paths all report what WE sent. Only this one disagreed.
#
# Here: send a truncated request frame so the walk finds the request malformed,
# then read the Final Size straight out of the RESET_STREAM. It must be 0,
# because nothing has been sent in the direction being reset — and it must scale
# with nothing, so the same check runs against a much larger request body.
#
# Usage: h3_reset_final_size_test.py <port>
import pylsqpack
import socket
import ssl
import sys
import time

from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

PORT = int(sys.argv[1])
H3_MESSAGE_ERROR = 0x10E

captured = []
_orig = QuicConnection._handle_reset_stream_frame


def _capture(self, context, frame_type, buf):
    pos = buf.tell()
    sid = buf.pull_uint_var()
    err = buf.pull_uint_var()
    final = buf.pull_uint_var()
    captured.append({"stream_id": sid, "error": err, "final_size": final})
    buf.seek(pos)
    return _orig(self, context, frame_type, buf)


QuicConnection._handle_reset_stream_frame = _capture


def malformed_request(padding):
    """Open a request stream carrying a truncated frame, and collect the reset.

    The frame header claims a length its payload does not reach, so the walk —
    which only runs once the FIN has arrived — finds the request malformed. The
    padding rides in front so the stream really does carry a lot of client bytes,
    which is what used to be reported back as our final size.
    """
    captured.clear()
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
    dl = time.time() + 10
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
    assert conn._handshake_confirmed, "handshake failed"

    # An HTTP/3 frame of an unknown-but-skippable type carrying `padding` bytes,
    # then a COMPLETE HEADERS frame whose field section breaks a message rule:
    # a connection-specific field, which RFC 9114 4.2 forbids outright.
    #
    # This used to send a HEADERS frame whose declared length ran past the end
    # of the stream. That is now a CONNECTION error (7.1: a stream that
    # terminates cleanly with its last frame truncated), so it no longer reaches
    # the reset path this test exists to check. The property is unchanged — the
    # Final Size of a reset is what WE sent, not what the client sent — but it
    # has to be provoked by a request that is malformed rather than truncated.
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"GET"), (b":path", b"/hello.txt"),
                               (b":scheme", b"https"), (b":authority", b"h3.test"),
                               (b"connection", b"keep-alive")])
    body = b"\x21" + (0x4000 | padding).to_bytes(2, "big") + b"A" * padding
    body += b"\x01" + (0x4000 | len(fields)).to_bytes(2, "big") + fields

    sid = conn.get_next_available_stream_id()
    conn.send_stream_data(sid, body, end_stream=True)
    flush()

    dl = time.time() + 6
    while time.time() < dl and not captured:
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
            for _ in iter(conn.next_event, None):
                pass
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
        if conn._close_event is not None:
            break
    close_err = conn._close_event.error_code if conn._close_event else None
    s.close()
    return (captured[0] if captured else None), close_err, len(body)


fails = 0
for padding in (16, 4000):
    reset, close_err, sent = malformed_request(padding)
    if reset is None:
        print(f"FAIL {sent}-byte malformed request drew no RESET_STREAM "
              f"(connection close={close_err})")
        fails += 1
        continue
    if reset["final_size"] != 0:
        print(f"FAIL {sent}-byte malformed request: RESET_STREAM Final Size "
              f"{reset['final_size']} — that is what WE sent, and we sent nothing; "
              f"the peer now holds that much credit for data it will never get")
        fails += 1
        continue
    note = ""
    if reset["error"] != H3_MESSAGE_ERROR:
        note = f"  (error {reset['error']:#x}, expected H3_MESSAGE_ERROR)"
    print(f"ok   {sent}-byte malformed request: RESET_STREAM Final Size 0{note}")

sys.exit(1 if fails else 0)
