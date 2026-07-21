#!/usr/bin/env python3
# HTTP/2 conformance hardening (M20): strict stream-id validation (odd and
# monotonically increasing, RFC 9113 5.1.1) and honouring the peer's
# SETTINGS_INITIAL_WINDOW_SIZE (6.5.2 / 6.9.2). Exits 0 on success.
# Usage: h2_conformance.py <cafile> <port>   (server serves /big.txt = 100000)
import ssl, socket, struct, sys

ca, port = sys.argv[1], int(sys.argv[2])


def connect():
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                        server_hostname="localhost")
    assert s.selected_alpn_protocol() == "h2"
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(4, 0, 0))
    return s


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def estr(b):
    return bytes([len(b)]) + b


def hdr(n, v):
    return b"\x00" + estr(n.encode()) + estr(v.encode())


def req(path="/big.txt"):
    return (hdr(":method", "GET") + hdr(":scheme", "https")
            + hdr(":authority", "localhost") + hdr(":path", path))


def rd(s):
    h = b""
    while len(h) < 9:
        d = s.recv(9 - len(h))
        if not d:
            return None
        h += d
    ln = int.from_bytes(h[:3], "big")
    p = b""
    while len(p) < ln:
        d = s.recv(ln - len(p))
        if not d:
            break
        p += d
    return h[3], h[4], int.from_bytes(h[5:9], "big") & 0x7fffffff, p


def saw_goaway(extra):
    s = connect()
    s.sendall(extra)
    got = False
    s.settimeout(2)
    try:
        for _ in range(40):
            r = rd(s)
            if r is None:
                break
            if r[0] == 7:
                got = True
                break
    except socket.timeout:
        pass
    s.close()
    return got


# stream-id validation
assert saw_goaway(fr(1, 0x05, 2, req())), "even stream id not rejected"
assert saw_goaway(fr(1, 0x05, 3, req()) + fr(1, 0x05, 1, req())), "decreasing id not rejected"
assert saw_goaway(fr(1, 0x05, 1, req()) + fr(1, 0x05, 1, req())), "reused id not rejected"
assert not saw_goaway(fr(1, 0x05, 1, req("/hello.txt")) + fr(1, 0x05, 3, req("/hello.txt"))
                      + fr(1, 0x05, 5, req("/hello.txt"))), "valid increasing ids rejected"

# SETTINGS_INITIAL_WINDOW_SIZE: a small window must throttle the server's send
s = connect()
s.sendall(fr(4, 0, 0, struct.pack(">HI", 0x04, 150)))     # INITIAL_WINDOW_SIZE = 150
s.sendall(fr(1, 0x05, 1, req("/big.txt")))
got = 0
s.settimeout(2)
try:
    while True:
        r = rd(s)
        if r is None:
            break
        if r[0] == 0:
            got += len(r[3])
            if r[1] & 1:
                break
except socket.timeout:
    pass
s.close()
assert got <= 200, "server ignored INITIAL_WINDOW_SIZE=150 (sent %d before stalling)" % got

print("ok")
