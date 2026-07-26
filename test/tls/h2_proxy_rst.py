#!/usr/bin/env python3
# HTTP/2 RST_STREAM must not crash a worker in two ways the suite missed:
#
#  1. Resetting a proxied stream whose upstream socket is live and INFLIGHT
#     runs h2p_kill, which closes the upstream with a syscall. If its loop
#     counter lived in a caller-saved register the syscall would clobber it and
#     the scan would run off the slot pool (SIGSEGV, and it closes other
#     connections' upstream fds on the way).
#
#  2. RST_STREAM on stream 0 must be a connection error, not a slot lookup:
#     id 0 is the free-slot marker, so a lookup for it returns a reaped stream
#     slot whose stale file_base would be munmap'd a second time.
#
# The script drives both; the suite decides pass/fail by watching worker PIDs.
# Needs tls.json (/api -> the proxy backend, /big.txt served) with the backend
# up so /api/slow keeps an upstream connected but unanswered.
# Usage: h2_proxy_rst.py <cafile> <port>
import ssl, socket, struct, sys, time

ca, port = sys.argv[1], int(sys.argv[2])


def connect():
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=15),
                        server_hostname="localhost")
    if s.selected_alpn_protocol() != "h2":
        raise SystemExit("no h2")
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(4, 0, 0))
    return s


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def estr(b):
    return bytes([len(b)]) + b


def hdr(n, v):
    return b"\x00" + estr(n.encode()) + estr(v.encode())


def req(path):
    return (hdr(":method", "GET") + hdr(":scheme", "https")
            + hdr(":authority", "localhost") + hdr(":path", path))


def rst(sid, code=8):
    return fr(3, 0, sid, struct.pack(">I", code))


def rd(s, timeout=3):
    s.settimeout(timeout)
    h = b""
    try:
        while len(h) < 9:
            d = s.recv(9 - len(h))
            if not d:
                return None
            h += d
    except socket.timeout:
        return None
    ln = int.from_bytes(h[:3], "big")
    p = b""
    while len(p) < ln:
        try:
            d = s.recv(ln - len(p))
        except socket.timeout:
            break
        if not d:
            break
        p += d
    return h[3], h[4], int.from_bytes(h[5:9], "big") & 0x7fffffff, p


# 1. reset live, INFLIGHT proxied streams
for _ in range(6):
    try:
        s = connect()
        sid = 1
        for _ in range(6):
            s.sendall(fr(1, 0x5, sid, req("/api/slow")))   # END_HEADERS|END_STREAM
            sid += 2
        time.sleep(0.8)                                    # upstream goes INFLIGHT
        sid = 1
        for _ in range(6):
            s.sendall(rst(sid))
            sid += 2
        s.sendall(rst(1001))
        time.sleep(0.2)
        s.close()
    except OSError:
        pass

# 2. RST_STREAM on stream 0 after a reaped static stream
for _ in range(6):
    try:
        s = connect()
        s.sendall(fr(1, 0x5, 1, req("/big.txt")))
        for _ in range(20):
            if rd(s) is None:
                break
        s.sendall(rst(0))
        s.sendall(rst(0))
        s.sendall(fr(1, 0x5, 3, req("/big.txt")))
        s.sendall(rst(0))
        for _ in range(6):
            if rd(s) is None:
                break
        s.close()
    except OSError:
        pass

print("drove proxied-stream RST + RST-stream-0 storms")
