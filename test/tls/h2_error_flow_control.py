#!/usr/bin/env python3
"""Inline error bodies are flow-controlled too (RFC 9113 6.9.1).

"The sender MUST NOT send a flow-controlled frame with a length that exceeds the
space available in either of the flow-control windows advertised by the receiver."

The 4xx/5xx pages, the 431 and the proxy's own errors wrote their DATA straight
at the out cursor and were charged against nothing. Two things followed:

  * a peer advertising a zero window was sent one anyway — the standard h2spec
    6.9.1 failure; and
  * the server's idea of the connection window drifted above the peer's real one
    by the sum of every error body it had ever sent, so a long-lived connection
    eventually overruns the peer's accounting and the peer, counting honestly,
    closes with FLOW_CONTROL_ERROR.

The contrast is what makes the first case unambiguous: under the same zero
window a NORMAL response has always correctly withheld its body, because it goes
through the scheduler. Only the inline paths did not.

The second case is checked by arithmetic rather than by waiting for a
disagreement: ask for many errors under a known window and require the server to
stop once it has spent it. A server charging nothing never stops.

usage: h2_error_flow_control.py <cafile> <port>
"""
import socket
import ssl
import struct
import sys

ca, port = sys.argv[1], int(sys.argv[2])
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def lit(n, v):
    return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v


def req(path):
    return (lit(b":method", b"GET") + lit(b":scheme", b"https")
            + lit(b":authority", b"localhost") + lit(b":path", path))


def connect(initial_window):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                        server_hostname="localhost")
    s.settimeout(3)
    s.sendall(PREFACE + fr(4, 0, 0, struct.pack(">HI", 4, initial_window)))
    return s


def collect(s):
    """Every frame the peer sends until it goes quiet."""
    frames, buf = [], b""
    try:
        while True:
            d = s.recv(65535)
            if not d:
                break
            buf += d
            while len(buf) >= 9:
                ln = int.from_bytes(buf[:3], "big")
                if len(buf) < 9 + ln:
                    break
                frames.append((buf[3], int.from_bytes(buf[5:9], "big") & 0x7fffffff,
                               buf[9:9 + ln]))
                buf = buf[9 + ln:]
    except (socket.timeout, ConnectionResetError, ssl.SSLError, OSError):
        pass
    return frames


def data_bytes(frames, sid=None):
    return sum(len(p) for t, s_, p in frames
               if t == 0 and (sid is None or s_ == sid))


def status_of(frames, sid):
    for t, s_, p in frames:
        if t == 1 and s_ == sid:
            for c in (b"200", b"400", b"404", b"405", b"431", b"502"):
                if c in p:
                    return c.decode()
    return None


fails = 0

# --- 1: a zero window must withhold the error body -------------------------
s = connect(0)
s.sendall(fr(1, 0x05, 1, req(b"/definitely-absent")))
frames = collect(s)
s.close()
sent = data_bytes(frames, 1)
st = status_of(frames, 1)
if st != "404":
    print(f"FAIL zero window: expected a 404, got {st}")
    fails += 1
elif sent:
    print(f"FAIL zero window: {sent} bytes of DATA sent although the peer "
          f"advertised no room — RFC 9113 6.9.1 forbids it")
    fails += 1
else:
    print("ok   zero window: the 404 arrives with no DATA")

# --- 2: the contrast — a normal response already behaved --------------------
s = connect(0)
s.sendall(fr(1, 0x05, 1, req(b"/hello.txt")))
frames = collect(s)
s.close()
if data_bytes(frames, 1):
    print("FAIL zero window: a normal 200 sent DATA too (a wider regression)")
    fails += 1
else:
    print("ok   zero window: a normal 200 withholds its body as it always did")

# --- 3: a window large enough passes the body through ----------------------
s = connect(65535)
s.sendall(fr(1, 0x05, 1, req(b"/definitely-absent")))
frames = collect(s)
s.close()
if status_of(frames, 1) == "404" and data_bytes(frames, 1) > 0:
    print(f"ok   ample window: the 404 body is delivered "
          f"({data_bytes(frames, 1)} bytes)")
else:
    print(f"FAIL ample window: the 404 body was withheld with room to spare")
    fails += 1

# --- 4: the stream window is respected at its boundary ---------------------
# A window of 10 is not zero, but the 404 body is 14 bytes. Withholding here can
# only come from comparing the two; nothing else distinguishes 10 from 100.
for window, want_body in ((10, False), (100, True)):
    s = connect(window)
    s.sendall(fr(1, 0x05, 1, req(b"/definitely-absent")))
    frames = collect(s)
    s.close()
    got = data_bytes(frames, 1)
    if status_of(frames, 1) != "404":
        print(f"FAIL window {window}: expected a 404")
        fails += 1
    elif bool(got) != want_body:
        print(f"FAIL window {window}: {got} bytes of DATA, expected "
              f"{'a body' if want_body else 'none'} for a 14-byte body")
        fails += 1
    else:
        print(f"ok   window {window}: {'body sent' if got else 'body withheld'} "
              f"for a 14-byte error page")

# --- 5: the connection window is actually DEBITED, not merely consulted -----
# The connection window starts at 65535 and the client never enlarges it, so a
# server that charges error bodies against it must stop after roughly
# 65535/14 of them. One that charges nothing keeps answering with a body
# forever. Per-stream room is ample here, so only the connection window binds.
WANT = 6000
s = connect(65535)
try:
    for i in range(WANT):
        s.sendall(fr(1, 0x05, 1 + 2 * i, req(b"/definitely-absent")))
except (ssl.SSLError, OSError):
    pass
frames = collect(s)
s.close()
total = data_bytes(frames)
answered = sum(1 for t, _s, _p in frames if t == 1)
if answered < 100:
    print(f"SKIP debit check: only {answered} streams answered")
elif total > 65535:
    print(f"FAIL debit check: {total} bytes of error DATA against a 65535-byte "
          f"connection window over {answered} streams — the window is not being "
          f"charged, so the server's accounting drifts above the peer's")
    fails += 1
else:
    print(f"ok   debit check: {answered} errors answered, {total} bytes of DATA, "
          f"inside the 65535-byte connection window")

sys.exit(1 if fails else 0)
