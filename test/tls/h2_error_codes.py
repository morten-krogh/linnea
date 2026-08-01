#!/usr/bin/env python3
# A connection error must carry the code RFC 9113 names for it, not a blanket
# PROTOCOL_ERROR.
#
# Every fault that ended the connection reported PROTOCOL_ERROR (0x1), because
# the reason was never threaded through to the one site that writes the GOAWAY —
# the code said as much. It matters on the wire: a peer told FRAME_SIZE_ERROR
# knows its framing is wrong, where PROTOCOL_ERROR sends it auditing its request
# semantics instead; and COMPRESSION_ERROR specifically tells it the HPACK state
# is unusable, so reusing the encoder on a new connection is not safe.
#
# Usage: h2_error_codes.py <cafile> <port>
import socket
import ssl
import struct
import sys

ca, port = sys.argv[1], int(sys.argv[2])

NO_ERROR = 0x0
PROTOCOL_ERROR = 0x1
FLOW_CONTROL_ERROR = 0x3
FRAME_SIZE_ERROR = 0x6
COMPRESSION_ERROR = 0x9
ENHANCE_YOUR_CALM = 0xB

NAMES = {NO_ERROR: "NO_ERROR", PROTOCOL_ERROR: "PROTOCOL_ERROR",
         FLOW_CONTROL_ERROR: "FLOW_CONTROL_ERROR", 0x2: "INTERNAL_ERROR",
         FRAME_SIZE_ERROR: "FRAME_SIZE_ERROR", COMPRESSION_ERROR: "COMPRESSION_ERROR",
         ENHANCE_YOUR_CALM: "ENHANCE_YOUR_CALM"}

FT_DATA, FT_HEADERS, FT_RST, FT_SETTINGS = 0x0, 0x1, 0x3, 0x4
FT_PING, FT_GOAWAY, FT_WINDOW, FT_CONT = 0x6, 0x7, 0x8, 0x9


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def connect():
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                        server_hostname="localhost")
    assert s.selected_alpn_protocol() == "h2", "server did not negotiate h2"
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(FT_SETTINGS, 0, 0))
    return s


def goaway_code(payload, budget=3.0):
    """Send payload after the preface; return the GOAWAY error code, or None."""
    s = connect()
    try:
        s.sendall(payload)
    except OSError:
        pass
    s.settimeout(budget)
    buf = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            while len(buf) >= 9:
                ln = int.from_bytes(buf[:3], "big")
                if len(buf) < 9 + ln:
                    break
                ftype, body = buf[3], buf[9:9 + ln]
                buf = buf[9 + ln:]
                if ftype == FT_GOAWAY and len(body) >= 8:
                    return int.from_bytes(body[4:8], "big")
    except (socket.timeout, OSError):
        pass
    finally:
        s.close()
    return None


def estr(b):
    return bytes([len(b)]) + b


def hdr(n, v):
    return b"\x00" + estr(n.encode()) + estr(v.encode())


# A header block the HPACK decoder cannot make sense of: 0x80 is an indexed
# field with index 0, which RFC 7541 6.1 forbids outright.
HPACK_ROT = b"\x80"

CASES = [
    ("PING with a 7-byte payload",
     fr(FT_PING, 0, 0, b"1234567"), FRAME_SIZE_ERROR),
    ("SETTINGS whose length is not a multiple of 6",
     fr(FT_SETTINGS, 0, 0, b"\x00\x03\x00\x00\x00"), FRAME_SIZE_ERROR),
    ("SETTINGS ACK carrying a payload",
     fr(FT_SETTINGS, 0x1, 0, b"\x00"), FRAME_SIZE_ERROR),
    ("WINDOW_UPDATE with a 3-byte payload",
     fr(FT_WINDOW, 0, 0, b"\x00\x00\x01"), FRAME_SIZE_ERROR),
    ("HEADERS with PADDED set but an empty payload",
     fr(FT_HEADERS, 0x8, 1, b""), FRAME_SIZE_ERROR),
    ("SETTINGS_INITIAL_WINDOW_SIZE above 2^31-1",
     fr(FT_SETTINGS, 0, 0, b"\x00\x04\xff\xff\xff\xff"), FLOW_CONTROL_ERROR),
    ("WINDOW_UPDATE pushing the connection window past 2^31-1",
     fr(FT_WINDOW, 0, 0, struct.pack(">I", 0x7fffffff)), FLOW_CONTROL_ERROR),
    ("a header block the HPACK decoder cannot read",
     fr(FT_HEADERS, 0x4 | 0x1, 1, HPACK_ROT), COMPRESSION_ERROR),
    ("a HEADERS frame with PRIORITY set but no room for it",
     fr(FT_HEADERS, 0x20, 1, b"\x00\x00"), FRAME_SIZE_ERROR),
    # controls: these were already right and must stay PROTOCOL_ERROR
    ("CONTINUATION not preceded by HEADERS",
     fr(FT_CONT, 0x4, 1, b""), PROTOCOL_ERROR),
    ("RST_STREAM on stream 0",
     fr(FT_RST, 0, 0, struct.pack(">I", PROTOCOL_ERROR)), PROTOCOL_ERROR),
]


def stream_error(payload, budget=3.0):
    """Send payload; return ("rst", code) or ("goaway", code) — whichever comes."""
    s = connect()
    try:
        s.sendall(payload)
    except OSError:
        pass
    s.settimeout(budget)
    buf = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            while len(buf) >= 9:
                ln = int.from_bytes(buf[:3], "big")
                if len(buf) < 9 + ln:
                    break
                ftype, body = buf[3], buf[9:9 + ln]
                buf = buf[9 + ln:]
                if ftype == FT_RST and len(body) >= 4:
                    s.close()
                    return "rst", int.from_bytes(body[:4], "big")
                if ftype == FT_GOAWAY and len(body) >= 8:
                    s.close()
                    return "goaway", int.from_bytes(body[4:8], "big")
    except (socket.timeout, OSError):
        pass
    s.close()
    return None, None


fails = 0

# RFC 9113 6.9: a zero increment is a STREAM error; only one on the connection
# window is a connection error. Getting this wrong means one misbehaving stream
# destroys every concurrent stream on the connection.
kind, code = stream_error(fr(FT_WINDOW, 0, 1, struct.pack(">I", 0)))
if kind == "rst" and code == PROTOCOL_ERROR:
    print("ok   a zero WINDOW_UPDATE on a stream resets that stream")
else:
    print(f"FAIL a zero WINDOW_UPDATE on a stream gave {kind} "
          f"{NAMES.get(code, code)}, want rst PROTOCOL_ERROR")
    fails += 1

kind, code = stream_error(fr(FT_WINDOW, 0, 0, struct.pack(">I", 0)))
if kind == "goaway" and code == PROTOCOL_ERROR:
    print("ok   ...and on the connection window it is still fatal")
else:
    print(f"FAIL a zero WINDOW_UPDATE on stream 0 gave {kind} "
          f"{NAMES.get(code, code)}, want goaway PROTOCOL_ERROR")
    fails += 1

for name, payload, want in CASES:
    got = goaway_code(payload)
    if got == want:
        print(f"ok   {name} -> {NAMES[want]}")
    elif got is None:
        print(f"FAIL {name}: no GOAWAY at all (want {NAMES[want]})")
        fails += 1
    else:
        print(f"FAIL {name}: got {NAMES.get(got, hex(got))}, want {NAMES[want]}")
        fails += 1

sys.exit(1 if fails else 0)
