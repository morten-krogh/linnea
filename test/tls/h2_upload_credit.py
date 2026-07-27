#!/usr/bin/env python3
# An aborted streaming upload must still return its connection-level flow
# control. Request-body bytes are debited from the 65535-byte connection
# window as they arrive, and credited back only once they have gone upstream
# — so a stream reset mid-upload used to strand both the forwarded-but-
# uncredited bytes and whatever was still in the FIFO. Four rounds of ~16 KB
# then exhaust the window and every later request body on the connection
# hangs for good. The stream is gone by then, so the credit can only be
# returned on stream 0.
# Usage: h2_upload_credit.py <cafile> <port>   (a /api proxy location)
import ssl, socket, struct, sys

ca, port = sys.argv[1], int(sys.argv[2])
ROUNDS = 4
CHUNK = 16384


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def estr(b):
    return bytes([len(b)]) + b


def hdr(n, v):
    return b"\x00" + estr(n.encode()) + estr(v.encode())


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


ctx = ssl.create_default_context(cafile=ca)
ctx.check_hostname = False
ctx.set_alpn_protocols(["h2"])
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                    server_hostname="localhost")
assert s.selected_alpn_protocol() == "h2", "ALPN did not select h2"
s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(4, 0, 0))

sent = 0
for i in range(ROUNDS):
    sid = 1 + 2 * i
    block = (hdr(":method", "POST") + hdr(":scheme", "https")
             + hdr(":authority", "localhost") + hdr(":path", "/api/echo")
             + hdr("content-length", "1000000"))
    s.sendall(fr(1, 0x4, sid, block)                 # HEADERS, END_HEADERS
              + fr(0, 0, sid, b"x" * CHUNK)          # one DATA chunk
              + fr(3, 0, sid, struct.pack(">I", 8)))  # RST_STREAM(CANCEL)
    sent += CHUNK

# drain whatever the server has to say, tallying connection-level credit
credited = 0
s.settimeout(3)
try:
    while True:
        f = rd(s)
        if f is None:
            break
        typ, _, fsid, payload = f
        if typ == 8 and fsid == 0:                   # WINDOW_UPDATE, stream 0
            credited += int.from_bytes(payload[:4], "big") & 0x7fffffff
        elif typ == 7:                               # GOAWAY
            break
        if credited >= sent:
            break
except (socket.timeout, ssl.SSLError, ConnectionError):
    pass
s.close()

if credited < sent:
    raise SystemExit(
        f"connection window leaked: sent={sent} credited={credited} "
        f"deficit={sent - credited}")
print(f"ok (sent={sent} credited={credited})")
