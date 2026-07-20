#!/usr/bin/env python3
# HTTP/2 connection bring-up (M15): ALPN h2, preface + SETTINGS exchange,
# PING/PING-ACK, and a request frame drawing a graceful GOAWAY. Exits 0
# on success. Usage: h2_bringup.py <cafile> <port>
import ssl, socket, struct, sys

ca, port = sys.argv[1], int(sys.argv[2])
ctx = ssl.create_default_context(cafile=ca)
ctx.check_hostname = False
ctx.set_alpn_protocols(["h2"])
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5),
                    server_hostname="localhost")
assert s.selected_alpn_protocol() == "h2", s.selected_alpn_protocol()


def frame(typ, flags, sid, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([typ, flags]) \
        + struct.pack(">I", sid) + payload


def readframe():
    h = b""
    while len(h) < 9:
        d = s.recv(9 - len(h))
        if not d:
            return None
        h += d
    ln = int.from_bytes(h[0:3], "big")
    p = b""
    while len(p) < ln:
        p += s.recv(ln - len(p))
    return h[3], h[4], int.from_bytes(h[5:9], "big") & 0x7fffffff, p


# client preface + empty SETTINGS
s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0))

t, f, sid, p = readframe()
assert t == 4, f"expected server SETTINGS, got type {t}"
t, f, sid, p = readframe()
assert t == 4 and f & 1, f"expected SETTINGS ACK, got type {t} flags {f}"

# PING must be answered with an ACK echoing the payload
s.sendall(frame(6, 0, 0, b"linnea!!"))
t, f, sid, p = readframe()
assert t == 6 and f & 1 and p == b"linnea!!", f"bad PING ACK: {t} {f} {p!r}"

# a request (HEADERS) is not served yet: expect a graceful GOAWAY, close
s.sendall(frame(1, 0x05, 1, b"\x82"))
saw_goaway = False
while True:
    fr = readframe()
    if fr is None:
        break
    if fr[0] == 7:
        saw_goaway = True
assert saw_goaway, "expected GOAWAY on an unservable request"
s.close()
print("ok")
