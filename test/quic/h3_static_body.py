#!/usr/bin/env python3
"""A static location does not accept request content, over HTTP/3.

Same rule as h1 and h2 (RFC 9110 9.3.1: content on GET/HEAD has no defined
semantics, and discarding announced bytes is the smuggling shape it names), but
h3 decides it on the CONTENT rather than on the declaration: it reassembles the
whole request before routing, so it knows what actually arrived.

That is also why one column here does not read 400. A content-length that
DISAGREES with the body is a malformed message, and RFC 9114 4.1.2 makes that a
stream error -- so those requests are reset before routing ever happens, and
turning them into a 400 response would be the non-conformant answer. h2 reaches
400 on the same requests because it refuses on the declaration and so never
detects the mismatch. Both are right for what each protocol knows; the point of
pinning it here is that neither serves the file.

usage: h3_static_body.py <port>
"""
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived, StreamReset

PORT = int(sys.argv[1])
STATIC = b"/hello.txt"
PROXIED = b"/api/echo"

fails = 0


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def rvlq(b, i):
    n = 1 << (b[i] >> 6)
    v = b[i] & 0x3F
    for k in range(1, n):
        v = (v << 8) | b[i + k]
    return v, i + n


cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
conn.connect(("127.0.0.1", PORT), now=0.0)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
clock = [0.0]


def pump():
    for d, _ in conn.datagrams_to_send(now=clock[0]):
        sock.sendto(d, ("127.0.0.1", PORT))


pump()
for _ in range(6):
    try:
        r, _ = sock.recvfrom(4096)
    except socket.timeout:
        break
    clock[0] += 0.1
    conn.receive_datagram(r, ("127.0.0.1", PORT), now=clock[0])
    pump()
    if conn._handshake_confirmed:
        break
assert conn._handshake_confirmed, "handshake not confirmed"
while conn.next_event() is not None:
    pass
clock[0] = 0.4


def request(path, method=b"GET", declared=None, body=None):
    """One request on its own stream.

    `body` of None sends no DATA frame at all. -> (:status string or "RESET",
    response body bytes seen).
    """
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    fields = [(b":method", method), (b":path", path),
              (b":scheme", b"https"), (b":authority", b"localhost")]
    if declared is not None:
        fields.append((b"content-length", str(declared).encode()))
    _, block = enc.encode(0, fields)
    stream = vlq(1) + vlq(len(block)) + block
    if body is not None:
        stream += vlq(0) + vlq(len(body)) + body
    bidi = conn.get_next_available_stream_id()
    conn.send_stream_data(bidi, stream, end_stream=True)
    resp, reset = b"", False
    sock.settimeout(0.3)
    deadline = time.time() + 10
    while not resp and not reset and time.time() < deadline:
        pump()
        clock[0] += 0.2
        try:
            r, _ = sock.recvfrom(4096)
        except socket.timeout:
            continue
        conn.receive_datagram(r, ("127.0.0.1", PORT), now=clock[0])
        ev = conn.next_event()
        while ev is not None:
            if isinstance(ev, StreamDataReceived) and ev.stream_id == bidi:
                resp += ev.data
            elif isinstance(ev, StreamReset) and ev.stream_id == bidi:
                reset = True
            ev = conn.next_event()
    if reset and not resp:
        return "RESET", 0
    if not resp:
        return "timeout", 0
    i, status, seen = 0, "no status", 0
    while i < len(resp):
        ty, i = rvlq(resp, i)
        ln, i = rvlq(resp, i)
        if ty == 1:
            _, h = pylsqpack.Decoder(0, 0).feed_header(0, resp[i:i + ln])
            status = dict(h).get(b":status", b"?").decode()
        elif ty == 0:
            seen += ln
        i += ln
    return status, seen


def check(name, ok, detail=""):
    global fails
    if ok:
        print(f"ok   {name}{detail}")
    else:
        print(f"FAIL {name}{detail}")
        fails += 1


# --- content the request actually carried: refused with 400 ------------------
for name, declared, body in [
        ("a matching content-length and 5 bytes of DATA", 5, b"XXXXX"),
        ("5 bytes of DATA with no content-length declared", None, b"XXXXX")]:
    st, _ = request(STATIC, declared=declared, body=body)
    check(f"static GET refused: {name}", st == "400", f" ({st})")

# --- a declared length that disagrees: a stream error, before routing ---------
for name, declared, body in [
        ("declared 5, sent 0", 5, b""),
        ("declared 5, sent 3", 5, b"XXX"),
        ("declared 5, sent 9", 5, b"XXXXXXXXX"),
        ("declared 5, no DATA frame at all", 5, None)]:
    st, _ = request(STATIC, declared=declared, body=body)
    check(f"static GET reset (RFC 9114 4.1.2): {name}", st == "RESET", f" ({st})")

# --- controls: what a static location still serves ---------------------------
st, seen = request(STATIC)
check("control: a plain static GET is served", st == "200" and seen > 0,
      f" ({st}, {seen} body bytes)")

st, seen = request(STATIC, declared=0)
check("control: content-length 0 is not content", st == "200" and seen > 0,
      f" ({st}, {seen} body bytes)")

st, _ = request(STATIC, method=b"HEAD")
check("control: a plain static HEAD is served", st == "200", f" ({st})")

# A POST to a static path is a METHOD fault, and must still say so.
st, _ = request(STATIC, method=b"POST", declared=5, body=b"XXXXX")
check("control: a POST to a static path is still 405, not 400", st == "405", f" ({st})")

# The refusal is the STATIC location's: a proxy location still takes content.
st, seen = request(PROXIED, method=b"POST", declared=5, body=b"hello")
check("control: a proxy location still takes a body", st == "200" and seen == 5,
      f" ({st}, {seen} body bytes)")

sys.exit(1 if fails else 0)
