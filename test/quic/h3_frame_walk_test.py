#!/usr/bin/env python3
# Frames coalesced ahead of a request must not hide it (RFC 9000 12.4).
#
# Six independent scanners each re-walked the packet with their own partial
# frame-length table, and each stopped dead at the first type its table did not
# list. Two things followed. A CONNECTION_CLOSE, which four of them had never
# heard of, hid every frame behind it. And a type none of them knew hid the rest
# of the packet from ALL six — so a peer that coalesced any extension, GREASE or
# DATAGRAM frame ahead of its STREAM frame lost the request outright. Worse, the
# packet was still acknowledged, so the client never resent it and the exchange
# simply stalled. Nothing on our side had to change for this to start happening:
# it waits for clients to adopt an extension.
#
# There is now one shared frame-length table. A type a given scanner does not
# handle is stepped over rather than ended on, and a genuinely unknown type
# draws the connection error 12.4 requires instead of silent truncation.
#
# The frames are spliced into the front of a real 1-RTT packet by hooking
# aioquic's packet builder, so they arrive coalesced ahead of the request's
# STREAM frame in the same protected packet — which is the arrangement that
# actually triggered the bug.
#
# Usage: h3_frame_walk_test.py <port>
import socket
import ssl
import sys
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.packet import QuicPacketType
from aioquic.quic.packet_builder import QuicPacketBuilder
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

PORT = int(sys.argv[1])
FRAME_ENCODING_ERROR = 0x07


def varint(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def inject_into_next_1rtt(frames):
    """Splice (type, payload) frames into the front of the next 1-RTT packet.

    Returns a restore callable. Hooking start_packet puts our bytes in before
    anything else the connection writes, which is what makes them *coalesced
    ahead of* the request rather than merely present somewhere.
    """
    original = QuicPacketBuilder.start_packet
    state = {"done": False}

    def patched(self, packet_type, crypto):
        original(self, packet_type, crypto)
        if state["done"] or packet_type != QuicPacketType.ONE_RTT:
            return
        for ftype, payload in frames:
            buf = self.start_frame(ftype, capacity=1 + len(payload))
            buf.push_bytes(payload)
        state["done"] = True

    QuicPacketBuilder.start_packet = patched
    return lambda: setattr(QuicPacketBuilder, "start_packet", original)


def run(frames, path="/hello.txt", budget=8.0):
    """Handshake, then GET with `frames` spliced ahead of the request."""
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

    h3 = H3Connection(conn)
    sid = conn.get_next_available_stream_id()
    h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                          (b":authority", b"localhost"), (b":path", path.encode())],
                    end_stream=True)

    restore = inject_into_next_1rtt(frames)
    try:
        flush()
    finally:
        restore()

    status, body, closed = None, b"", None
    dl = time.time() + budget
    while time.time() < dl:
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
            for qe in iter(conn.next_event, None):
                for ev in h3.handle_event(qe):
                    if isinstance(ev, HeadersReceived):
                        status = dict(ev.headers).get(b":status", b"?").decode()
                    if isinstance(ev, DataReceived):
                        body += ev.data
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
        if conn._close_event is not None:
            closed = conn._close_event.error_code
            break
        if body:
            break
    s.close()
    return status, body, closed


fails = 0

# --- 1: legal frames bundled ahead of the request ---------------------------
# A regression guard rather than a demonstration: the request path's own table
# already listed these, so this passed before the change too. It is here because
# the change replaced that table with a shared one, and getting a length wrong
# there would lose the request exactly as the old truncation did.
ncid = varint(7) + varint(0) + bytes([8]) + b"\xAA" * 8 + b"\xBB" * 16
status, body, closed = run([(0x12, varint(64)), (0x18, ncid)])
if status == "200" and b"hello" in body:
    print("ok   request served with NEW_CONNECTION_ID + MAX_STREAMS ahead of it")
else:
    print(f"FAIL bundled legal frames hid the request: status={status} "
          f"body={body[:40]!r} close={closed}")
    fails += 1

# --- 2: a CONNECTION_CLOSE hidden behind another frame ----------------------
# The close scanner knows only PADDING, PING, ACK and the two close types and
# used to stop at anything else, so one MAX_DATA in front of a CONNECTION_CLOSE
# made the close invisible and the connection lived on.
#
# The observable has to be chosen with care. Bundling the close into the same
# packet as a request proves nothing: before the change the request was hidden
# by the close and went unanswered, and after it the close is honoured and it
# goes unanswered — the same silence for opposite reasons. So the close is sent
# ALONE first, and a request follows on the same connection afterwards. A server
# that missed the close answers it; one that saw it has already let the
# connection go.
def close_then_request():
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

    # MAX_DATA, then the close, in a packet of their own
    close_payload = varint(0) + varint(0) + varint(0)
    restore = inject_into_next_1rtt([(0x10, varint(300)), (0x1c, close_payload)])
    try:
        conn.send_ping(1)                # give the builder a reason to emit one
        flush()
    finally:
        restore()
    time.sleep(0.3)

    # now ask for something on the connection the peer just tore down
    h3 = H3Connection(conn)
    sid = conn.get_next_available_stream_id()
    h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                          (b":authority", b"localhost"), (b":path", b"/hello.txt")],
                    end_stream=True)
    flush()
    body = b""
    dl = time.time() + 3
    while time.time() < dl and not body:
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
            for qe in iter(conn.next_event, None):
                for ev in h3.handle_event(qe):
                    if isinstance(ev, DataReceived):
                        body += ev.data
        except (socket.timeout, AssertionError, ValueError):
            try:
                conn.handle_timer(now=clk())
            except Exception:
                break
        except Exception:
            break
        try:
            flush()
        except Exception:
            break
    s.close()
    return body


served = close_then_request()
if not served:
    print("ok   CONNECTION_CLOSE behind a MAX_DATA is seen; the connection is gone")
else:
    print(f"FAIL a MAX_DATA hid the CONNECTION_CLOSE — the server kept serving "
          f"({served[:40]!r})")
    fails += 1

# --- 3: a type RFC 9000 does not define is a connection error ---------------
# 0x22 is unassigned. 12.4 makes this FRAME_ENCODING_ERROR; it used to be
# silence, with the packet acknowledged so the client never retried.
status, body, closed = run([(0x22, b"")], budget=6.0)
if closed == FRAME_ENCODING_ERROR:
    print("ok   unknown frame type draws FRAME_ENCODING_ERROR")
elif closed is not None:
    print(f"FAIL unknown frame type closed with {closed:#x}, want "
          f"{FRAME_ENCODING_ERROR:#x} (FRAME_ENCODING_ERROR)")
    fails += 1
else:
    print(f"FAIL unknown frame type drew no connection error at all "
          f"(status={status}, body={body[:40]!r}) — the rest of the packet was "
          f"silently dropped")
    fails += 1

# --- 4: a frame that runs past the end of its packet ------------------------
# A CRYPTO frame (0x06) at offset 0 declaring a 4 MB payload. The packet is
# ~1200 bytes, so the frame extends far beyond it however much follows in the
# same packet — which makes this deterministic wherever the injection lands.
#
# 12.4 makes an undecodable frame FRAME_ENCODING_ERROR. This used to stop the
# walk silently: everything behind the bad frame went unread while the packet
# was still acknowledged, so the peer never resent what it believed had arrived.
truncated = varint(0) + varint(4 * 1024 * 1024)
status, body, closed = run([(0x06, truncated)], budget=6.0)
if closed == FRAME_ENCODING_ERROR:
    print("ok   a frame running past the packet draws FRAME_ENCODING_ERROR")
elif closed is not None:
    print(f"FAIL a frame running past the packet closed with {closed:#x}, want "
          f"{FRAME_ENCODING_ERROR:#x} (FRAME_ENCODING_ERROR)")
    fails += 1
else:
    print(f"FAIL a frame running past the packet drew no connection error "
          f"(status={status}, body={body[:40]!r}) — the walk stopped quietly and "
          f"the packet was acknowledged anyway")
    fails += 1

sys.exit(1 if fails else 0)
