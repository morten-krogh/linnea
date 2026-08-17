#!/usr/bin/env python3
# The code a request stream fails with has to say WHICH thing went wrong, because
# a client acts on the difference (RFC 9114 4.1, 7.1, 8.1).
#
# Both of these used to be answered with a stream reset carrying
# H3_MESSAGE_ERROR, which claims the request itself was at fault:
#
#   the last frame is cut short   -> 7.1 is explicit: "When a stream terminates
#                                    cleanly, if the last frame on the stream was
#                                    truncated, this MUST be treated as a
#                                    connection error of type H3_FRAME_ERROR."
#                                    Nothing about the request was wrong; the
#                                    framing was, and the connection cannot be
#                                    trusted to carry the next one either.
#   the stream carried no HEADERS -> 4.1: the stream terminated without enough of
#                                    the message to answer, which is
#                                    H3_REQUEST_INCOMPLETE. That tells the client
#                                    it may RETRY. H3_MESSAGE_ERROR told it the
#                                    opposite, so a request lost to a truncated
#                                    upload was never sent again.
#
# A genuinely malformed request — one that decodes and then breaks a rule — keeps
# H3_MESSAGE_ERROR, and the third case here is what holds that line.
#
# Usage: h3_stream_codes_test.py <port>
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

PORT = int(sys.argv[1])
H3_FRAME_ERROR = 0x106
H3_REQUEST_INCOMPLETE = 0x10D
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


def send_request_stream(body):
    """Open one request stream carrying `body`, with FIN. -> (reset, close_code)"""
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
    s.settimeout(0.4)

    def flush():
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ("127.0.0.1", PORT))

    flush()
    dl = time.time() + 8
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
    assert conn._handshake_confirmed, "handshake failed"

    sid = conn.get_next_available_stream_id()
    conn.send_stream_data(sid, body, end_stream=True)
    flush()

    dl = time.time() + 6
    while time.time() < dl and not captured and conn._close_event is None:
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
            for _ in iter(conn.next_event, None):
                pass
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
    close = conn._close_event.error_code if conn._close_event else None
    s.close()
    return (captured[0] if captured else None), close


def headers_frame(extra_fields=()):
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    fields = [(b":method", b"GET"), (b":path", b"/hello.txt"),
              (b":scheme", b"https"), (b":authority", b"h3.test")]
    fields.extend(extra_fields)
    _, block = enc.encode(0, fields)
    return b"\x01" + (0x4000 | len(block)).to_bytes(2, "big") + block


fails = 0

# 1. the last frame on the stream is cut short: its declared length runs past
#    the bytes that arrived before the FIN
reset, close = send_request_stream(
    b"\x01" + (0x4000 | 4096).to_bytes(2, "big") + b"B" * 8)
if close == H3_FRAME_ERROR:
    print(f"ok   a truncated last frame ends the connection (0x{close:x})")
else:
    got = f"0x{close:x}" if close is not None else "no close"
    extra = f", reset error 0x{reset['error']:x}" if reset else ""
    print(f"FAIL a truncated last frame: {got}{extra}, want H3_FRAME_ERROR "
          f"0x{H3_FRAME_ERROR:x}")
    fails += 1

# 2. a stream that carries frames but never a HEADERS: there was never enough of
#    a message to answer, so the client may retry.
#
#    The frame has to be one that is legal here and skippable — an unknown type,
#    which 9 requires be ignored. A DATA frame would not do: 4.1 makes DATA
#    before any HEADERS an invalid SEQUENCE, which is H3_FRAME_UNEXPECTED and a
#    connection error, and the server already answers that correctly.
reset, close = send_request_stream(
    b"\x21" + (0x4000 | 4).to_bytes(2, "big") + b"grse")
if reset and reset["error"] == H3_REQUEST_INCOMPLETE:
    print(f"ok   a stream with no HEADERS is reset H3_REQUEST_INCOMPLETE "
          f"(0x{reset['error']:x}), so the client may retry")
elif reset:
    print(f"FAIL a stream with no HEADERS was reset 0x{reset['error']:x}, want "
          f"H3_REQUEST_INCOMPLETE 0x{H3_REQUEST_INCOMPLETE:x}")
    fails += 1
else:
    print(f"FAIL a stream with no HEADERS drew no reset (close={close})")
    fails += 1

# 3. ...and a request that decodes and then breaks a rule is still the request's
#    own fault, so it keeps H3_MESSAGE_ERROR
reset, close = send_request_stream(headers_frame([(b"connection", b"keep-alive")]))
if reset and reset["error"] == H3_MESSAGE_ERROR:
    print(f"ok   a malformed request keeps H3_MESSAGE_ERROR (0x{reset['error']:x})")
elif reset:
    print(f"FAIL a malformed request was reset 0x{reset['error']:x}, want "
          f"H3_MESSAGE_ERROR 0x{H3_MESSAGE_ERROR:x}")
    fails += 1
else:
    print(f"FAIL a malformed request drew no reset (close={close})")
    fails += 1


# --- nothing may follow the trailer section (RFC 9114 4.1) ----------------
# A request stream is HEADERS, then DATA, then at most ONE trailer section and
# nothing after it. A second HEADERS is a trailer, and any frame after it is an
# invalid sequence — a connection error, not a body byte.
#
# The trailer here must be a LEGAL trailer (no pseudo-header fields, RFC 9114
# 4.3): the server now decodes and validates the trailer section, so a trailer
# carrying pseudo-headers is a stream H3_MESSAGE_ERROR in its own right and would
# be caught before the following frame — which is a different rule, checked
# separately below. Reusing the request headers as the trailer conflated the two.
H3_FRAME_UNEXPECTED = 0x105


def trailer_frame():
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, block = enc.encode(0, [(b"x-checksum", b"deadbeef")])
    return b"\x01" + (0x4000 | len(block)).to_bytes(2, "big") + block


hdrs = headers_frame()
trailer = trailer_frame()
data = b"\x00" + (0x4000 | 4).to_bytes(2, "big") + b"body"

for label, body in (
        ("a third HEADERS after the trailers", hdrs + data + trailer + hdrs),
        ("DATA after the trailers", hdrs + data + trailer + data)):
    reset, close = send_request_stream(body)
    if close == H3_FRAME_UNEXPECTED:
        print(f"ok   {label} ends the connection (0x{close:x})")
    else:
        got = f"0x{close:x}" if close is not None else "no close"
        extra = f", reset 0x{reset['error']:x}" if reset else ""
        print(f"FAIL {label}: {got}{extra}, want H3_FRAME_UNEXPECTED "
              f"0x{H3_FRAME_UNEXPECTED:x}")
        fails += 1

# a trailer section carrying a pseudo-header is malformed (RFC 9114 4.3): a
# stream H3_MESSAGE_ERROR, and the connection survives
reset, close = send_request_stream(hdrs + data + headers_frame())
if close is None and reset and reset["error"] == H3_MESSAGE_ERROR:
    print(f"ok   a pseudo-header in a trailer is H3_MESSAGE_ERROR (0x{reset['error']:x})")
else:
    got = f"reset 0x{reset['error']:x}" if reset else "no reset"
    extra = f", close 0x{close:x}" if close is not None else ""
    print(f"FAIL a pseudo-header trailer: {got}{extra}, want stream "
          f"H3_MESSAGE_ERROR 0x{H3_MESSAGE_ERROR:x} and no close")
    fails += 1

# ...and a request WITH a legitimate trailer section is still served, so the
# check has not simply outlawed trailers: no connection close and no stream reset
reset, close = send_request_stream(hdrs + data + trailer)
if close is None and reset is None:
    print("ok   a request with one legitimate trailer section is still accepted")
else:
    got = f"reset 0x{reset['error']:x}" if reset else ""
    extra = f" close 0x{close:x}" if close is not None else ""
    print(f"FAIL a legitimate trailer section was not accepted:{got}{extra}")
    fails += 1

sys.exit(1 if fails else 0)
