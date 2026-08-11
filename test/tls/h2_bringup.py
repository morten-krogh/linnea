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
# The server's opening SETTINGS carries the per-stream receive window, but the
# CONNECTION window can only be moved by a WINDOW_UPDATE (RFC 9113 6.9.2), so
# bring-up sends one before it gets round to acking our SETTINGS. Read to the
# ACK rather than assuming it comes second, and require that what precedes it
# is that grant — the ordering used to be asserted by accident, and the grant
# is the thing worth checking is there.
saw_conn_window = 0
while True:
    t, f, sid, p = readframe()
    if t == 4:
        assert f & 1, f"expected SETTINGS ACK, got SETTINGS flags {f}"
        break
    assert t == 8 and sid == 0, f"unexpected frame {t} on stream {sid} at bring-up"
    saw_conn_window += int.from_bytes(p[:4], "big") & 0x7fffffff
assert saw_conn_window >= 262144, \
    f"connection window raised by only {saw_conn_window} at bring-up"

# PING must be answered with an ACK echoing the payload
s.sendall(frame(6, 0, 0, b"linnea!!"))
t, f, sid, p = readframe()
assert t == 6 and f & 1 and p == b"linnea!!", f"bad PING ACK: {t} {f} {p!r}"

# A HEADERS carrying only :method (indexed \x82) has no path and no
# authority, so it is a malformed REQUEST — and since Q124 that fails its own
# stream (RFC 9113 8.1.1) instead of taking the connection down with it: the
# field block decoded fine, so nothing about the connection is in doubt.
s.sendall(frame(1, 0x05, 1, b"\x82"))
saw_rst = False
saw_goaway = False
while True:
    fr = readframe()
    if fr is None:
        break
    if fr[0] == 3 and fr[2] == 1:
        saw_rst = True
        break
    if fr[0] == 7:
        saw_goaway = True
        break
assert not saw_goaway, "a malformed request took the whole connection down"
assert saw_rst, "expected RST_STREAM on a malformed request"

# and the connection still works: a well-formed request on a new stream
def hdr(n, v):
    return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v

s.sendall(frame(1, 0x05, 3, hdr(b":method", b"GET") + hdr(b":scheme", b"https")
                + hdr(b":authority", b"localhost") + hdr(b":path", b"/hello.txt")))
served = False
while True:
    fr = readframe()
    if fr is None:
        break
    if fr[0] == 1 and fr[2] == 3 and b"200" in fr[3]:
        served = True
        break
assert served, "the connection was unusable after the stream error"
s.close()
print("ok")
