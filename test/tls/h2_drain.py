#!/usr/bin/env python3
# HTTP/2 graceful drain (M19): while a response body is in flight, the worker
# is sent SIGTERM (the same signal M13's hot upgrade uses to retire an old
# worker). The connection must receive GOAWAY and the in-flight stream must
# still complete (END_STREAM), rather than being cut. Exits 0 on success.
# Usage: h2_drain.py <cafile> <port> <worker_pid>   (server serves /big.txt=100000)
import ssl, socket, struct, sys, os, signal

ca, port, wk = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
ctx = ssl.create_default_context(cafile=ca)
ctx.check_hostname = False
ctx.set_alpn_protocols(["h2"])
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                    server_hostname="localhost")
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


s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(4, 0, 0))
s.sendall(fr(1, 0x05, 1, hdr(":method", "GET") + hdr(":scheme", "https")
              + hdr(":authority", "localhost") + hdr(":path", "/big.txt")))
got = 0
goaway = False
ended = False
drained = False
s.settimeout(10)
try:
    while True:
        r = rd()
        if r is None:
            break
        t, fl, sid, p = r
        if t == 0:
            got += len(p)
            # replenish windows so the in-flight body can finish during drain
            s.sendall(fr(8, 0, 1, struct.pack(">I", len(p))))
            s.sendall(fr(8, 0, 0, struct.pack(">I", len(p))))
            if got >= 30000 and not drained:
                os.kill(wk, signal.SIGTERM)      # retire the worker mid-stream
                drained = True
            if fl & 1:
                ended = True
                break
        elif t == 7:
            goaway = True
except (socket.timeout, OSError):
    pass
s.close()
assert got == 100000, "in-flight body was cut at %d/100000" % got
assert ended, "final DATA lacked END_STREAM"
assert goaway, "no GOAWAY was sent on drain"
print("ok")
