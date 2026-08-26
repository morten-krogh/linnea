"""A minimal HTTP/2 server that never DECODES a request -- it answers the first
HEADERS frame it sees. Our test fixture decodes the request block to dispatch on
path, and cannot read nghttp2's huffman-coded literals, so nghttp2 gets no reply
from it for any route. This exists so the reference client can be asked what it
does with a given server behaviour."""
import socket, struct, sys

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
port, mode = int(sys.argv[1]), sys.argv[2]
status = sys.argv[3] if len(sys.argv) > 3 else "200"
# argv[4]: the content-length to DECLARE, independently of what is sent.
# "auto" (the default) declares the true length.
declare = sys.argv[4] if len(sys.argv) > 4 else "auto"


def frame(ft, fl, sid, pay=b""):
    return struct.pack(">I", len(pay))[1:] + bytes([ft, fl]) + struct.pack(">I", sid) + pay


def lit(name, value):                      # literal, no indexing, no huffman
    n, v = name.encode(), value.encode()
    return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(4)
c, _ = srv.accept()
c.settimeout(8)
buf = b""
while len(buf) < len(PREFACE):
    buf += c.recv(4096)
buf = buf[len(PREFACE):]

if mode == "prefping":
    c.sendall(frame(0x06, 0x00, 0, b"ABCDEFGH"))
elif mode == "prefwin":
    c.sendall(frame(0x08, 0x00, 0, struct.pack(">I", 1024)))
elif mode == "prefack":
    c.sendall(frame(0x04, 0x01, 0, b""))
if mode == "prefempty":
    c.sendall(frame(0x04, 0x00, 0, b""))
elif mode != "prefnone":
    c.sendall(frame(0x04, 0x00, 0, struct.pack(">HI", 0x04, 65535)))

body = b"probe\n"
answered = False
try:
    while True:
        while len(buf) < 9:
            buf += c.recv(65536)
        ln = int.from_bytes(buf[0:3], "big")
        while len(buf) < 9 + ln:
            buf += c.recv(65536)
        ft, fl = buf[3], buf[4]
        sid = struct.unpack(">I", buf[5:9])[0] & 0x7fffffff
        buf = buf[9 + ln:]
        if ft == 0x04 and not (fl & 0x01):
            c.sendall(frame(0x04, 0x01, 0, b""))       # ACK theirs
        if ft == 0x01 and not answered:                # HEADERS: answer blind
            answered = True
            blk = lit(":status", status) + lit("content-type", "text/plain")
            blk += lit("content-length",
                       str(len(body)) if declare == "auto" else declare)
            c.sendall(frame(0x01, 0x04, sid, blk))
            c.sendall(frame(0x00, 0x01, sid, body))
except Exception:
    pass
