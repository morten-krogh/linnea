#!/usr/bin/env python3
"""RFC 9113 6.3: a wrong-length PRIORITY is a STREAM error (report 145).

PRIORITY alters no connection state, so 4.2's connection-error clause does not
reach it: the frame must draw RST_STREAM(FRAME_SIZE_ERROR) for the stream it
names, leaving every other stream on the connection running. We used to send
GOAWAY, so one malformed 4-byte frame aborted the requests multiplexed beside
it.

The scope is honoured only for a stream the peer has opened. 5.1 has a peer
treat any frame but HEADERS/PRIORITY on an IDLE stream as a connection error,
and nghttp2 enforces it -- curl drops the connection on an RST_STREAM naming an
idle stream -- so an idle target keeps the connection error it had. Case 3
pins that deliberately, and nginx 1.30 does the same for every length error.

Paired throughout: every "the bad frame is refused" has a well-formed twin that
must still be served, so an implementation that reset (or closed) everything
fails here.

usage: h2_priority_scope.py <cafile> <port>
"""
import socket
import ssl
import struct
import sys

ca, port = sys.argv[1], int(sys.argv[2])
FT_DATA, FT_HEADERS, FT_RST, FT_SETTINGS, FT_PRIORITY, FT_GOAWAY = 0, 1, 3, 4, 2, 7
PROTOCOL_ERROR, FRAME_SIZE_ERROR = 0x1, 0x6


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def lit(n, v):
    return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v


def get(sid, path=b"/hello.txt"):
    return fr(FT_HEADERS, 0x05, sid,
              lit(b":method", b"GET") + lit(b":scheme", b"https")
              + lit(b":authority", b"localhost") + lit(b":path", path))


def exchange(payload, wait=2.0):
    """Send preface + SETTINGS + payload, read until the peer stops. Returns the
    frame list as (type, flags, stream, payload)."""
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                        server_hostname="localhost")
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(FT_SETTINGS, 0, 0) + payload)
    s.settimeout(wait)
    buf = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
    except (socket.timeout, TimeoutError, OSError):
        pass
    s.close()
    out, pos = [], 0
    while pos + 9 <= len(buf):
        ln = int.from_bytes(buf[pos:pos + 3], "big")
        if len(buf) < pos + 9 + ln:
            break
        out.append((buf[pos + 3], buf[pos + 4],
                    int.from_bytes(buf[pos + 5:pos + 9], "big") & 0x7fffffff,
                    buf[pos + 9:pos + 9 + ln]))
        pos += 9 + ln
    return out


def rst_codes(frames, sid):
    return [int.from_bytes(p[:4], "big") for t, _, s, p in frames
            if t == FT_RST and s == sid]


def goaways(frames):
    return [int.from_bytes(p[4:8], "big") for t, _, _, p in frames if t == FT_GOAWAY]


def completed(frames, sid):
    """The stream got a header block and a body ending in END_STREAM."""
    hdr = any(t == FT_HEADERS and s == sid for t, _, s, _ in frames)
    end = any(t == FT_DATA and s == sid and fl & 0x01 for t, fl, s, _ in frames)
    return hdr and end


fails = 0


def check(name, ok, detail):
    global fails
    print(("ok   " if ok else "FAIL ") + f"{name}: {detail}")
    fails += not ok


# --- 1: wrong length on an OPEN stream resets that stream only ---------------
# stream 1 is opened by the HEADERS ahead of it, so it is not idle; the request
# on stream 3 behind the bad frame is the one that used to be lost.
f = exchange(get(1) + fr(FT_PRIORITY, 0, 1, b"\x00\x00\x00\x00") + get(3))
check("wrong-length PRIORITY resets its own stream",
      rst_codes(f, 1) == [FRAME_SIZE_ERROR], f"RST on stream 1: {rst_codes(f, 1)}")
check("the connection survives it", goaways(f) == [], f"GOAWAYs: {goaways(f)}")
check("the request behind it is still served", completed(f, 3),
      f"stream 3 frames: {[(t, s) for t, _, s, _ in f if s == 3]}")

# --- 2: control -- a well-formed PRIORITY is ignored and resets nothing -------
f = exchange(get(1) + fr(FT_PRIORITY, 0, 1, b"\x00\x00\x00\x00\x10") + get(3))
check("a valid 5-byte PRIORITY resets nothing",
      not any(t == FT_RST for t, _, _, _ in f) and goaways(f) == [],
      f"RST/GOAWAY seen: {[(t, s) for t, _, s, _ in f if t in (FT_RST, FT_GOAWAY)]}")
check("both streams are served across a valid PRIORITY",
      completed(f, 1) and completed(f, 3),
      f"stream1={completed(f, 1)} stream3={completed(f, 3)}")

# --- 3: an IDLE target keeps the connection error (5.1; nginx agrees) --------
f = exchange(fr(FT_PRIORITY, 0, 3, b"\x00\x00\x00\x00") + get(1))
check("wrong-length PRIORITY on an idle stream is a connection error",
      goaways(f) == [FRAME_SIZE_ERROR] and not rst_codes(f, 3),
      f"GOAWAYs: {goaways(f)}, RSTs: {rst_codes(f, 3)}")

# --- 4: stream 0 is still a PROTOCOL_ERROR, and a plain request still works --
f = exchange(fr(FT_PRIORITY, 0, 0, b"\x00\x00\x00\x00\x10") + get(1))
check("PRIORITY on stream 0 is a connection PROTOCOL_ERROR",
      goaways(f) == [PROTOCOL_ERROR], f"GOAWAYs: {goaways(f)}")
f = exchange(get(1))
check("control: a plain request on a clean connection is served",
      completed(f, 1) and goaways(f) == [], f"stream1={completed(f, 1)}")

print("ok" if fails == 0 else f"FAIL ({fails})")
sys.exit(0 if fails == 0 else 1)
