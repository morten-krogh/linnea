#!/usr/bin/env python3
# HTTP/3 SETTINGS validation and MAX_FIELD_SECTION_SIZE (audit Finding 8).
#
#  (a) A SETTINGS payload larger than the capture buffer used to be skipped
#      unvalidated. A payload past the 64-byte old buffer with a truncated final
#      pair is now H3_FRAME_ERROR (0x0106), and one beyond the 256-byte policy
#      limit is H3_EXCESSIVE_LOAD (0x0107) rather than accepted in silence.
#  (b) Duplicate detection stopped after 32 identifiers. A repeat after 33 unique
#      identifiers is now H3_SETTINGS_ERROR (0x0109).
#  (c) The peer's SETTINGS_MAX_FIELD_SECTION_SIZE was read and discarded. A tiny
#      advertised limit now fails the response stream cleanly (RESET_STREAM,
#      H3_INTERNAL_ERROR 0x0102) instead of sending an oversized field section; a
#      generous limit serves normally.
#
# aioquic sends its own SETTINGS, so the control stream is hand-built and injected
# in 1-RTT packets with aioquic's own keys (as h3_critical_reorder.py does).
#
# Usage: h3_settings_validation.py <port>.  Prints ok/FAIL lines.
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated
from aioquic.tls import Epoch

PORT = int(sys.argv[1])
H3_FRAME_ERROR = 0x0106
H3_EXCESSIVE_LOAD = 0x0107
H3_SETTINGS_ERROR = 0x0109
H3_INTERNAL_ERROR = 0x0102

# capture the RESET_STREAM the server sends (aioquic does not surface it as an event)
resets = []
_orig_reset = QuicConnection._handle_reset_stream_frame


def _cap_reset(self, context, frame_type, buf):
    sid = buf.pull_uint_var()
    err = buf.pull_uint_var()
    buf.pull_uint_var()
    resets.append((sid, err))
    raise _StopInjectedParse()


class _StopInjectedParse(Exception):
    pass


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def settings_frame(pairs, extra=b""):
    body = b"".join(vlq(i) + vlq(v) for i, v in pairs) + extra
    return bytes([0x04]) + vlq(len(body)) + body   # H3 SETTINGS = 0x04


def control_stream(settings):
    return bytes([0x00]) + settings                # control stream type 0x00


def stream_frame(sid, off, data, fin):
    t = 0x08 | 0x04 | 0x02 | (0x01 if fin else 0)
    return bytes([t]) + vlq(sid) + vlq(off) + vlq(len(data)) + data


def h3_request(path=b"/hello.txt"):
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, block = enc.encode(0, [(b":method", b"GET"), (b":path", path),
                              (b":scheme", b"https"), (b":authority", b"h3.test")])
    return bytes([0x01]) + vlq(len(block)) + block   # HEADERS frame


def handshake():
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
    dl = time.time() + 8
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            r, _ = s.recvfrom(4096)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
    assert conn._handshake_confirmed, "handshake failed"
    return conn, s, clk


def inject(conn, s, frames, pn_bump):
    dcid = conn._peer_cid.cid
    send = conn._cryptos[Epoch.ONE_RTT].send
    pn = conn._packet_number + pn_bump
    header = bytes([0x43]) + dcid + pn.to_bytes(4, "big")
    s.sendto(send.encrypt_packet(header, frames, pn), ("127.0.0.1", PORT))


def drain(conn, s, clk, want_reset=False):
    """Return the connection close code, or -- when want_reset -- the reset error."""
    dl = time.time() + 3
    while time.time() < dl:
        try:
            r, _ = s.recvfrom(65535)
            try:
                conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
            except _StopInjectedParse:
                pass
            if want_reset and resets:
                return ("reset", resets[-1][1])
            for ev in iter(conn.next_event, None):
                if isinstance(ev, ConnectionTerminated):
                    return ("close", ev.error_code)
        except socket.timeout:
            conn.handle_timer(now=clk())
        ce = getattr(conn, "_close_event", None)
        if isinstance(ce, ConnectionTerminated):
            return ("close", ce.error_code)
    return (None, None)


fails = 0


def check(name, got, want_kind, want):
    global fails
    kind, code = got
    ok = kind == want_kind and code == want
    c = "none" if code is None else f"0x{code:04x}"
    w = "none" if want is None else f"0x{want:04x}"
    print(("ok   " if ok else "FAIL ") + f"{name} ({kind or 'none'}={c}, want {want_kind} {w})")
    if not ok:
        fails += 1


def check_quiet(name, got):
    # the connection must stay open: no close and no reset
    global fails
    kind, code = got
    ok = kind is None
    print(("ok   " if ok else "FAIL ") + f"{name} (stayed open)" if ok
          else f"FAIL {name} (got {kind}=0x{(code or 0):04x})")
    if not ok:
        fails += 1


def control_close(settings):
    conn, s, clk = handshake()
    inject(conn, s, stream_frame(2, 0, control_stream(settings), fin=False), 5000)
    out = drain(conn, s, clk)
    s.close()
    return out


# (a) a SETTINGS past the old 64-byte buffer with a truncated final pair (an id
# with no value at the very end) -> H3_FRAME_ERROR
grease = [(i, 0) for i in range(0x09, 0x09 + 40)]              # 40 pairs ~ 80 bytes
check("truncated large SETTINGS",
      control_close(settings_frame(grease, extra=vlq(0x30))), "close", H3_FRAME_ERROR)

# (a) a SETTINGS beyond the 256-byte policy limit -> H3_EXCESSIVE_LOAD
big = [(0x40 + i, 0) for i in range(140)]                      # ~2 bytes id + 1 value, >256
check("oversized SETTINGS", control_close(settings_frame(big)), "close", H3_EXCESSIVE_LOAD)

# (b) 33 unique identifiers then a repeat of the first -> H3_SETTINGS_ERROR
uniq = [(i, 0) for i in range(0x09, 0x09 + 33)]               # 33 distinct single-byte ids
check("duplicate after 33 identifiers",
      control_close(settings_frame(uniq + [(0x09, 0)])), "close", H3_SETTINGS_ERROR)

# a valid, empty SETTINGS is the control: the connection stays open
conn, s, clk = handshake()
inject(conn, s, stream_frame(2, 0, control_stream(settings_frame([])), fin=False), 5000)
out = drain(conn, s, clk)
check_quiet("valid empty SETTINGS accepted", out)
s.close()


# (c) MAX_FIELD_SECTION_SIZE
def request_after_settings(max_fss):
    resets.clear()
    conn, s, clk = handshake()
    inject(conn, s, stream_frame(2, 0, control_stream(settings_frame([(0x06, max_fss)])), fin=False), 5000)
    time.sleep(0.05)
    inject(conn, s, stream_frame(0, 0, h3_request(), fin=True), 5001)
    out = drain(conn, s, clk, want_reset=True)
    s.close()
    return out


# The raw-injected request stream, once served, draws a benign server
# STREAM_STATE_ERROR from an aioquic follow-up frame (true on the pre-fix binary
# too), so the distinguishing signal for MAX_FIELD_SECTION_SIZE is whether the
# server reset THIS stream with H3_INTERNAL_ERROR, captured directly.
QuicConnection._handle_reset_stream_frame = _cap_reset
try:
    # a tiny limit: the ~300-byte response exceeds it, so the stream is reset
    check("tiny MAX_FIELD_SECTION_SIZE resets the stream",
          request_after_settings(50), "reset", H3_INTERNAL_ERROR)
    # a generous limit serves normally: the stream is NOT reset for the limit
    request_after_settings(100000)
    fss_reset = any(err == H3_INTERNAL_ERROR for _, err in resets)
    print(("ok   " if not fss_reset else "FAIL ")
          + f"generous MAX_FIELD_SECTION_SIZE serves (fss_reset={fss_reset})")
    if fss_reset:
        fails += 1
finally:
    QuicConnection._handle_reset_stream_frame = _orig_reset

print("ok" if fails == 0 else f"FAIL ({fails})")
sys.exit(0 if fails == 0 else 1)
