#!/usr/bin/env python3
# Q117: an in-flight h2 response must arrive COMPLETELY on drain, even at a
# client that reads slower than the server writes. The worker used to free the
# connection once the last body byte reached the kernel — and close(2) with
# unread inbound (a downloading client is always sending WINDOW_UPDATEs)
# answers with an RST that discards the untransmitted tail of the send buffer,
# so a slow reader got ~90% of the body and a connection reset. The lingering
# close shuts down the write side instead (the FIN queues behind the data) and
# drains reads until the peer has everything and closes.
# Usage: h2_drain_slow.py <cafile> <port> <master_pid>
#        (the server serves /h2drain.bin = 3000000 bytes)
import os
import signal
import socket
import ssl
import struct
import sys
import time

ca, port, master = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
SIZE = 3000000
ctx = ssl.create_default_context(cafile=ca)
ctx.check_hostname = False
ctx.set_alpn_protocols(["h2"])
raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# a small receive buffer, set before connect: the TCP window stays tiny, so
# the body backs up in the SERVER's send buffer — the bytes the RST discarded
raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
raw.settimeout(10)
raw.connect(("127.0.0.1", port))
s = ctx.wrap_socket(raw, server_hostname="localhost")
assert s.selected_alpn_protocol() == "h2"


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def estr(b):
    return bytes([len(b)]) + b


def hdr(n, v):
    return b"\x00" + estr(n.encode()) + estr(v.encode())


def rd():
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


# default windows, replenished per DATA frame like any real client: the
# WINDOW_UPDATEs keep flowing while the tail is still in the server's send
# buffer, and it is exactly those unread updates that made close(2) an RST
s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(4, 0, 0))
s.sendall(fr(1, 0x05, 1, hdr(":method", "GET") + hdr(":scheme", "https")
              + hdr(":authority", "localhost") + hdr(":path", "/h2drain.bin")))
got = 0
ended = False
goaway = False
drained = False
try:
    while True:
        r = rd()
        if r is None:
            break
        t, fl, sid, p = r
        if t == 0 and sid == 1:
            got += len(p)
            s.sendall(fr(8, 0, 1, struct.pack(">I", len(p))))
            s.sendall(fr(8, 0, 0, struct.pack(">I", len(p))))
            if not drained and got >= 200000:
                os.kill(master, signal.SIGTERM)   # the drain lands mid-transfer
                drained = True
            if drained:
                time.sleep(0.002)                 # a reader slower than the writer
            if fl & 1:
                ended = True
                break
        elif t == 7:
            goaway = True
except (socket.timeout, OSError):
    pass
s.close()
assert drained, "the transfer finished before the drain landed"
assert got == SIZE, "in-flight body was cut at %d/%d" % (got, SIZE)
assert ended, "final DATA lacked END_STREAM"
assert goaway, "no GOAWAY was sent on drain"
print("ok")
