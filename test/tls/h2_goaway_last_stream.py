#!/usr/bin/env python3
"""GOAWAY must name the highest stream we might have acted on (RFC 9113 6.8).

Every protocol-error GOAWAY hardcoded a last-stream-id of 0, which tells the
client we processed nothing at all. A client reading that is entitled to retry
everything that was in flight — and for a proxied POST the upstream has already
executed, that is a duplicate of non-idempotent work, not a recovery.

The value was never unavailable: h2_last_stream is tracked per connection and
the graceful-drain GOAWAY has always reported it correctly. Only the error path
disagreed.

The direction of any residual error matters, so it is asserted here too: the id
must be at least the highest stream we opened. Reporting too HIGH is benign —
the client simply does not retry a request it could have — while reporting too
LOW is what causes duplicate execution.

Each case below serves real requests first, so h2_last_stream is genuinely
advanced, then trips a distinct connection error and reads the GOAWAY back.

usage: h2_goaway_last_stream.py <cafile> <port>
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


def req(path=b"/hello.txt"):
    return (lit(b":method", b"GET") + lit(b":scheme", b"https")
            + lit(b":authority", b"localhost") + lit(b":path", path))


def connect():
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                        server_hostname="localhost")
    s.settimeout(4)
    s.sendall(PREFACE + fr(4, 0, 0))
    return s


def drain(s):
    """Collect frames until the peer goes quiet or closes."""
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


def goaway_of(frames):
    for t, _sid, p in frames:
        if t == 7:
            return (int.from_bytes(p[:4], "big") & 0x7fffffff,
                    int.from_bytes(p[4:8], "big"))
    return None


fails = 0


def case(label, streams, trip):
    """Serve `streams` requests, then run `trip` to cause a connection error."""
    global fails
    s = connect()
    sid = 1
    highest = 0
    for _ in range(streams):
        s.sendall(fr(1, 0x05, sid, req()))
        highest = sid
        sid += 2
    # let the responses come back, so the streams really were processed
    served = 0
    try:
        buf = b""
        while served < streams:
            d = s.recv(65535)
            if not d:
                break
            buf += d
            while len(buf) >= 9:
                ln = int.from_bytes(buf[:3], "big")
                if len(buf) < 9 + ln:
                    break
                if buf[3] == 1:
                    served += 1
                buf = buf[9 + ln:]
    except (socket.timeout, ssl.SSLError, OSError):
        pass

    trip(s, sid)
    ga = goaway_of(drain(s))
    s.close()

    if ga is None:
        print(f"FAIL {label}: no GOAWAY (expected a connection error)")
        fails += 1
        return
    last, err = ga
    if last < highest:
        print(f"FAIL {label}: GOAWAY last-stream-id {last}, but stream {highest} "
              f"was served — a client would retry work we already did")
        fails += 1
        return
    print(f"ok   {label}: served up to stream {highest}, GOAWAY says {last} "
          f"(err={err})")


# Three unrelated ways into the same GOAWAY path, so the fix is not tied to one
# trigger. A zero WINDOW_UPDATE on stream 0, a PING of the wrong length, and
# CONTINUATION with no HEADERS to continue.
case("zero WINDOW_UPDATE on stream 0", 3,
     lambda s, nxt: s.sendall(fr(8, 0, 0, struct.pack(">I", 0))))
case("PING with a bad length", 2,
     lambda s, nxt: s.sendall(fr(6, 0, 0, b"1234")))
case("CONTINUATION without HEADERS", 4,
     lambda s, nxt: s.sendall(fr(9, 4, nxt, req())))

# A connection that never opened a stream has nothing to report, and 0 is then
# the honest answer rather than a placeholder.
s = connect()
s.sendall(fr(8, 0, 0, struct.pack(">I", 0)))
ga = goaway_of(drain(s))
s.close()
if ga is None:
    print("FAIL no-streams: no GOAWAY")
    fails += 1
elif ga[0] != 0:
    print(f"FAIL no-streams: GOAWAY last-stream-id {ga[0]}, want 0 — no stream "
          f"was ever opened")
    fails += 1
else:
    print("ok   no streams opened: GOAWAY says 0")

sys.exit(1 if fails else 0)
