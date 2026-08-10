#!/usr/bin/env python3
"""RFC 6455 exercise for linnea-ws, spoken directly to the backend.

This talks to the backend on loopback with no linnea in the middle, so a
failure here is the backend's framing or handshake and nothing else. The
proxy path is covered separately.

Usage: ws_backend_test.py [port] [path]   (default 61701, /ws)

Given linnea's port and a proxied location, it runs the identical battery
through the proxy — so a check that passes directly and fails here is
linnea's tunnel and not the backend.
"""
import base64
import hashlib
import json
import os
import socket
import struct
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 61701
PATH = sys.argv[2].encode() if len(sys.argv) > 2 else b"/ws"
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

failures = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (("  " + detail) if detail else ""))
    if not ok:
        failures.append(name)


def connect():
    s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    s.settimeout(5)
    return s


def handshake(sock, origin=None, extra_lines=b"", key=None, version=b"13"):
    """Send an upgrade request; return (status, headers, expected_accept)."""
    key = key if key is not None else base64.b64encode(os.urandom(16))
    req = b"GET " + PATH + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n"
    req += b"Upgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n"
    req += b"Sec-WebSocket-Key: " + key + b"\r\n"
    req += b"Sec-WebSocket-Version: " + version + b"\r\n"
    if origin is not None:
        req += b"Origin: " + origin + b"\r\n"
    req += extra_lines + b"\r\n"
    sock.sendall(req)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = lines[0] if lines else b""
    hdrs = {}
    for line in lines[1:]:
        if b":" in line:
            n, _, v = line.partition(b":")
            hdrs[n.strip().lower()] = v.strip()
    accept = base64.b64encode(hashlib.sha1(key + GUID).digest())
    return status, hdrs, accept, rest


def frame(payload, opcode=0x1, fin=True, mask=True, rsv=0):
    b0 = (0x80 if fin else 0) | (rsv << 4) | opcode
    n = len(payload)
    out = bytes([b0])
    m = 0x80 if mask else 0
    if n < 126:
        out += bytes([m | n])
    elif n < 65536:
        out += bytes([m | 126]) + struct.pack(">H", n)
    else:
        out += bytes([m | 127]) + struct.pack(">Q", n)
    if mask:
        k = os.urandom(4)
        out += k + bytes(b ^ k[i % 4] for i, b in enumerate(payload))
    else:
        out += payload
    return out


class Reader:
    """Reassembles server frames out of a byte stream."""

    def __init__(self, sock, initial=b""):
        self.sock = sock
        self.buf = initial

    def _fill(self):
        chunk = self.sock.recv(4096)
        if not chunk:
            raise EOFError("peer closed")
        self.buf += chunk

    def read_frame(self):
        while True:
            if len(self.buf) >= 2:
                b0, b1 = self.buf[0], self.buf[1]
                masked = b1 & 0x80
                n = b1 & 0x7F
                off = 2
                if n == 126:
                    if len(self.buf) < 4:
                        self._fill()
                        continue
                    n = struct.unpack(">H", self.buf[2:4])[0]
                    off = 4
                elif n == 127:
                    if len(self.buf) < 10:
                        self._fill()
                        continue
                    n = struct.unpack(">Q", self.buf[2:10])[0]
                    off = 10
                if masked:
                    off += 4
                if len(self.buf) >= off + n:
                    payload = self.buf[off:off + n]
                    self.buf = self.buf[off + n:]
                    return b0 & 0x0F, payload, bool(b0 & 0x80), bool(masked)
            self._fill()


def open_client(origin=None):
    s = connect()
    status, hdrs, accept, rest = handshake(s, origin=origin)
    return s, status, hdrs, accept, Reader(s, rest)


# ---- 1: the handshake -------------------------------------------------
s, status, hdrs, accept, r = open_client()
check("handshake returns 101", status == b"HTTP/1.1 101 Switching Protocols",
      status.decode(errors="replace"))
check("Sec-WebSocket-Accept is base64(sha1(key+GUID))",
      hdrs.get(b"sec-websocket-accept") == accept,
      "got %r want %r" % (hdrs.get(b"sec-websocket-accept"), accept))
check("Upgrade: websocket", hdrs.get(b"upgrade", b"").lower() == b"websocket")
check("Connection: Upgrade", hdrs.get(b"connection", b"").lower() == b"upgrade")

# ---- 2: the state arrives unasked ------------------------------------
op, payload, fin, masked = r.read_frame()
check("greeting is an unfragmented text frame", op == 1 and fin)
check("server frames are not masked", not masked)
try:
    st = json.loads(payload)
except Exception as e:
    st = {}
    check("greeting is JSON", False, str(e))
check("greeting carries count and clients", "count" in st and "clients" in st,
      payload.decode(errors="replace"))
check("this client is counted", st.get("clients") == 1, repr(st))
start = st.get("count", 0)

# ---- 3: inc, and the broadcast ---------------------------------------
s2, status2, _, _, r2 = open_client()
check("a second client also gets 101", status2 == b"HTTP/1.1 101 Switching Protocols")
op, payload, _, _ = r2.read_frame()
st2 = json.loads(payload)
check("the second client sees two clients", st2.get("clients") == 2, repr(st2))

s.sendall(frame(b"inc"))
op, payload, _, _ = r.read_frame()
st = json.loads(payload)
check("inc increments", st.get("count") == start + 1, repr(st))
op, payload, _, _ = r2.read_frame()
st2 = json.loads(payload)
check("the increment is broadcast to the other client",
      st2.get("count") == start + 1, repr(st2))

# a query answers the asker and nobody else
s2.sendall(frame(b"get"))
op, payload, _, _ = r2.read_frame()
check("a query answers the asker", json.loads(payload).get("count") == start + 1)
s.settimeout(0.4)
try:
    r.read_frame()
    check("a query is not broadcast", False, "the other client was told too")
except (socket.timeout, TimeoutError):
    check("a query is not broadcast", True)
s.settimeout(5)

# ---- 4: ping and pong -------------------------------------------------
s.sendall(frame(b"hello", opcode=0x9))
op, payload, _, _ = r.read_frame()
check("ping is answered with a pong carrying the payload",
      op == 0xA and payload == b"hello", "op=%s %r" % (op, payload))

# ---- 5: a close is echoed --------------------------------------------
s2.sendall(frame(struct.pack(">H", 1000), opcode=0x8))
op, payload, _, _ = r2.read_frame()
check("close is answered with a close", op == 0x8, "op=%s" % op)
check("the close carries a status code", len(payload) >= 2 and
      struct.unpack(">H", payload[:2])[0] == 1000, repr(payload))
s2.close()


def close_with(payload):
    """Close a fresh connection with this payload; return the code we get back."""
    c, _, _, _, rr = open_client()
    rr.read_frame()                               # its greeting
    c.sendall(frame(payload, opcode=0x8))
    op, body, _, _ = rr.read_frame()
    c.close()
    if op != 0x8 or len(body) < 2:
        return None
    return struct.unpack(">H", body[:2])[0]


# The code that comes back must be the one that was SENT: answering 1000 to
# everything told a client that closed with 1001 Going Away that we had
# understood something else. 3000-4999 is the private range, which a peer is
# entitled to use and we have no business judging.
check("a close with 1001 is echoed as 1001", close_with(struct.pack(">H", 1001)) == 1001)
check("a close in the private range is echoed",
      close_with(struct.pack(">H", 4321)) == 4321)
check("a close with no payload is answered 1000", close_with(b"") == 1000)
# ...and the ones RFC 6455 7.4.1 does not let a peer send. A single byte cannot
# hold a code at all; 1005 and 1006 exist only inside an implementation.
check("a one-byte close payload is a protocol error", close_with(b"\x03") == 1002)
check("a close with 1005 is a protocol error", close_with(struct.pack(">H", 1005)) == 1002)
check("a close with 1006 is a protocol error", close_with(struct.pack(">H", 1006)) == 1002)
check("a close with an unassigned code is a protocol error",
      close_with(struct.pack(">H", 2000)) == 1002)

# ---- 6: protocol errors ----------------------------------------------
s3, _, _, _, r3 = open_client()
r3.read_frame()                                   # its greeting
s3.sendall(frame(b"inc", mask=False))             # RFC 6455 5.1: must be masked
op, payload, _, _ = r3.read_frame()
check("an unmasked client frame is a protocol error",
      op == 0x8 and struct.unpack(">H", payload[:2])[0] == 1002,
      "op=%s %r" % (op, payload))
s3.close()

s4, _, _, _, r4 = open_client()
r4.read_frame()
s4.sendall(frame(b"inc", rsv=1))                  # no extension was negotiated
op, payload, _, _ = r4.read_frame()
check("a set RSV bit is a protocol error",
      op == 0x8 and struct.unpack(">H", payload[:2])[0] == 1002,
      "op=%s %r" % (op, payload))
s4.close()

s5, _, _, _, r5 = open_client()
r5.read_frame()
s5.sendall(frame(b"in", fin=False))               # a fragment
op, payload, _, _ = r5.read_frame()
check("a fragmented message is refused, not mishandled",
      op == 0x8 and struct.unpack(">H", payload[:2])[0] == 1003,
      "op=%s %r" % (op, payload))
s5.close()

s6, _, _, _, r6 = open_client()
r6.read_frame()
s6.sendall(frame(b"x" * 4000))                    # larger than the input buffer
op, payload, _, _ = r6.read_frame()
check("an oversized frame is refused",
      op == 0x8 and struct.unpack(">H", payload[:2])[0] == 1009,
      "op=%s %r" % (op, payload))
s6.close()

# ---- 7: handshakes that must not succeed ------------------------------
c = connect()
c.sendall(b"GET " + PATH + b" HTTP/1.1\r\nHost: x\r\n\r\n")
check("a plain GET is refused with 400", c.recv(200).startswith(b"HTTP/1.1 400"))
c.close()

c = connect()
status, _, _, _ = handshake(c, version=b"8")
check("version 8 is refused", status.startswith(b"HTTP/1.1 400"),
      status.decode(errors="replace"))
c.close()

c = connect()
status, _, _, _ = handshake(c, origin=b"https://evil.example")
check("an unlisted Origin is refused with 403",
      status.startswith(b"HTTP/1.1 403"), status.decode(errors="replace"))
c.close()

c = connect()
status, _, _, _ = handshake(c, origin=b"https://linnea.amberbio.com")
check("the page's own Origin is allowed", status.startswith(b"HTTP/1.1 101"),
      status.decode(errors="replace"))
c.close()

# A head too long to hold. Every other refusal here answers in HTTP; this one
# used to hang up mid-request, which reads to the client as a network fault
# rather than as a decision. Sent as one blob, since the point is the buffer
# filling before the blank line arrives.
c = connect()
c.sendall(b"GET " + PATH + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n"
          b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
          b"Sec-WebSocket-Version: 13\r\n"
          b"X-Padding: " + b"p" * 4000 + b"\r\n\r\n")
try:
    answer = c.recv(200)
except (ConnectionResetError, socket.timeout):
    answer = b""
check("an oversized request head is refused with 431, not a bare close",
      answer.startswith(b"HTTP/1.1 431"), repr(answer[:60]))
c.close()

# ---- 8: the count survives, and departures are noticed ----------------
s7, _, _, _, r7 = open_client()
st = json.loads(r7.read_frame()[1])
check("the counter kept its value across connections",
      st.get("count") == start + 1, repr(st))
s7.sendall(frame(b"inc"))
st = json.loads(r7.read_frame()[1])
check("clients that left are no longer counted", st.get("clients") == 2,
      repr(st))   # this one and the very first, which is still open
s.close()
s7.close()

# ---- 9: a burst of connections ---------------------------------------
# All of them opened before any is read, so they arrive together and the
# listener's backlog is what holds them. accept_client drains the queue rather
# than taking one per poll; either way every one of these must end up with a
# socket, and a broadcast must reach all of them.
burst = []
for _ in range(20):
    b = connect()
    b.sendall(b"GET " + PATH + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n"
              b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
              b"Sec-WebSocket-Key: " + base64.b64encode(os.urandom(16)) + b"\r\n"
              b"Sec-WebSocket-Version: 13\r\n\r\n")
    burst.append(b)
opened, readers = 0, []
for b in burst:
    try:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = b.recv(4096)
            if not chunk:
                break
            buf += chunk
        if buf.startswith(b"HTTP/1.1 101"):
            opened += 1
            rd = Reader(b, buf.partition(b"\r\n\r\n")[2])
            rd.read_frame()                       # its greeting
            readers.append(rd)
    except (socket.timeout, ConnectionResetError, EOFError):
        pass
check("a burst of 20 connections is all accepted", opened == 20, "%d of 20" % opened)
burst[0].sendall(frame(b"inc"))
reached = 0
for rd in readers:
    try:
        if rd.read_frame()[0] == 0x1:
            reached += 1
    except (socket.timeout, EOFError):
        pass
check("the broadcast reaches every one of them", reached == opened,
      "%d of %d" % (reached, opened))
for b in burst:
    b.close()

print()
if failures:
    print("%d FAILED: %s" % (len(failures), ", ".join(failures)))
    sys.exit(1)
print("all ok")
