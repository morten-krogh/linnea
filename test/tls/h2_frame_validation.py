#!/usr/bin/env python3
# HTTP/2 frame structural validation (audit Findings 25, 26, 27). A client
# MUST NOT send PUSH_PROMISE (RFC 9113 8.4); a PRIORITY frame is exactly 5 bytes
# and never on stream 0 (6.3); a GOAWAY is only on stream 0 and carries at least
# 8 bytes (6.8); and a CONTINUATION over the advertised 16 KiB frame size is a
# FRAME_SIZE_ERROR (4.2/6.10). Each malformed frame must draw a GOAWAY carrying
# the RFC's error code, not be silently ignored or drain the connection.
#
# Usage: h2_frame_validation.py <ca> <port>.  Prints ok/FAIL lines.
import socket
import ssl
import struct
import sys

ca, port = sys.argv[1], int(sys.argv[2])
FT_HEADERS, FT_SETTINGS, FT_GOAWAY = 0x1, 0x4, 0x7
PROTOCOL_ERROR, FRAME_SIZE_ERROR, COMPRESSION_ERROR = 0x1, 0x6, 0x9


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def goaway_code(frames):
    """Send preface + SETTINGS + frames; return the error code of the GOAWAY the
    server replies with, or None if it never sends one."""
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                        server_hostname="localhost")
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(FT_SETTINGS, 0, 0) + frames)
    s.settimeout(4.0)
    buf = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
            while len(buf) >= 9:
                ln = int.from_bytes(buf[:3], "big")
                if len(buf) < 9 + ln:
                    break
                ftype, payload = buf[3], buf[9:9 + ln]
                buf = buf[9 + ln:]
                if ftype == FT_GOAWAY and ln >= 8:
                    s.close()
                    return int.from_bytes(payload[4:8], "big")
    except (socket.timeout, OSError):
        pass
    s.close()
    return None


fails = 0


def check(name, got, want):
    global fails
    ok = got == want
    code = "none" if got is None else f"0x{got:02x}"
    print(("ok   " if ok else "FAIL ") + f"{name} (goaway={code}, want 0x{want:02x})")
    if not ok:
        fails += 1


# Finding 25: client PUSH_PROMISE -> PROTOCOL_ERROR
check("client PUSH_PROMISE rejected",
      goaway_code(fr(0x5, 0, 1, b"\x00\x00\x00\x02")), PROTOCOL_ERROR)

# Finding 27: PRIORITY of the wrong length -> FRAME_SIZE_ERROR
check("PRIORITY wrong length rejected",
      goaway_code(fr(0x2, 0, 1, b"\x00\x00\x00\x00")), FRAME_SIZE_ERROR)

# Finding 27: PRIORITY on stream 0 -> PROTOCOL_ERROR
check("PRIORITY on stream 0 rejected",
      goaway_code(fr(0x2, 0, 0, b"\x00\x00\x00\x00\x10")), PROTOCOL_ERROR)

# Finding 27: GOAWAY on a nonzero stream -> PROTOCOL_ERROR
check("GOAWAY on nonzero stream rejected",
      goaway_code(fr(FT_GOAWAY, 0, 1, b"\x00\x00\x00\x00\x00\x00\x00\x00")),
      PROTOCOL_ERROR)

# Finding 27: short GOAWAY -> FRAME_SIZE_ERROR
check("short GOAWAY rejected",
      goaway_code(fr(FT_GOAWAY, 0, 0, b"\x00\x00\x00\x00")), FRAME_SIZE_ERROR)

# Finding 26: a CONTINUATION over 16 KiB -> FRAME_SIZE_ERROR. A HEADERS without
# END_HEADERS (a small valid-looking fragment) then an oversized CONTINUATION.
hdr = fr(FT_HEADERS, 0x0, 1, b"\x00\x00")            # no END_HEADERS
cont = fr(0x9, 0x4, 1, b"\x00" * 16385)              # END_HEADERS, 16385 bytes
check("oversized CONTINUATION rejected", goaway_code(hdr + cont), FRAME_SIZE_ERROR)

# Finding 29: an HPACK dynamic-table size update after a field is a
# COMPRESSION_ERROR (RFC 7541 4.2). Block = indexed :method (0x82) then a
# size-update-to-0 (0x20).
check("HPACK size update after a field rejected",
      goaway_code(fr(FT_HEADERS, 0x4, 1, b"\x82\x20")), COMPRESSION_ERROR)

print("ok" if fails == 0 else f"FAIL ({fails})")
sys.exit(0 if fails == 0 else 1)
