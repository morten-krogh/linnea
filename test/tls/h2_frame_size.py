#!/usr/bin/env python3
# HTTP/2 control frames with the wrong length must be a connection error
# (FRAME_SIZE_ERROR), not an over-read. A zero-length PING in particular used to
# read 8 bytes past the frame and echo them — stale in_buf bytes — to the peer.
# Usage: h2_frame_size.py <cafile> <port>. Exits 0 on success.
import ssl, socket, struct, sys

ca, port = sys.argv[1], int(sys.argv[2])


def h2():
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=8),
                        server_hostname="localhost")
    if s.selected_alpn_protocol() != "h2":
        print("no h2"); sys.exit(1)
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(4, 0, 0))
    return s


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def read_all(s, t=2):
    s.settimeout(t); out = b""
    try:
        while True:
            d = s.recv(4096)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    return out


def has_goaway(buf):
    i = 0
    while i + 9 <= len(buf):
        ln = int.from_bytes(buf[i:i+3], "big")
        if buf[i+3] == 7:                 # GOAWAY
            return True
        i += 9 + ln
    return False


ok = True

# zero-length PING (must be 8): connection error, and no 8-byte echo
s = h2(); s.sendall(fr(6, 0, 0, b"")); buf = read_all(s); s.close()
if not has_goaway(buf):
    print("FAIL: zero-length PING was not a connection error:", buf[:40]); ok = False

# zero-length WINDOW_UPDATE (must be 4): connection error
s = h2(); s.sendall(fr(8, 0, 0, b"")); buf = read_all(s); s.close()
if not has_goaway(buf):
    print("FAIL: zero-length WINDOW_UPDATE was not a connection error:", buf[:40]); ok = False

# a valid PING is still answered, echoing its 8 bytes
s = h2(); s.sendall(fr(6, 0, 0, b"ABCDEFGH")); buf = read_all(s); s.close()
if b"ABCDEFGH" not in buf:
    print("FAIL: valid PING not echoed:", buf[:40]); ok = False

sys.exit(0 if ok else 1)
