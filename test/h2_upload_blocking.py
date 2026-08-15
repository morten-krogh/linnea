#!/usr/bin/env python3
# A proxied GET must be answered WHILE an upload on the same h2 connection is
# still arriving.
#
# h2 used to open the upstream socket at head parse and then feed the backend
# at the client's pace, so one 40 MB upload over a 4 MB/s uplink held a backend
# connection for nine seconds and everything else queued behind it. h1 and h3
# never did this: they forward a body they already have. The fix made h2 agree
# with them -- the body is captured first and the socket opens at END_STREAM.
#
# THE BACKEND HERE IS DELIBERATELY SERIAL, one connection at a time, and that
# is the whole reason this test can see anything. test/proxy_backend.py is
# threaded, so it answers the GET on a second connection no matter how long
# linnea holds the first: against a concurrent backend BOTH builds pass and the
# test proves nothing. Serial is also not a strawman -- linnea-api, the real
# backend behind /api on the live site, is exactly this loop.
#
# Against the pre-fix binary the GET waits out the rest of the upload
# (measured: 3.146s of a 3.11s remainder). After it, 0.049s.
#
# Usage: h2_upload_blocking.py <tls-port> <size> <bytes-per-sec>
import os
import socket
import ssl
import struct
import sys
import threading
import time

_PB = int(os.environ.get("LINNEA_TEST_PORT_BASE", 61000))
BACKEND_PORT = _PB + (61198 - 61000)        # matches the /serial location

PORT, SIZE, RATE = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
DATA, HEADERS, RST, SETTINGS, PING, GOAWAY, WINDOW_UPDATE = 0, 1, 3, 4, 6, 7, 8
END_STREAM, END_HEADERS = 0x1, 0x4
UP, GET = 1, 3

lit = lambda n, v: b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v
frame = lambda t, f, s, p: struct.pack(">I", len(p))[1:] + bytes([t, f]) + \
    struct.pack(">I", s) + p


def serial_backend(ready):
    """One connection at a time: read the whole request, answer, close, next."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", BACKEND_PORT))
    srv.listen(64)
    ready.set()
    while True:
        conn, _ = srv.accept()
        try:
            conn.settimeout(60)
            buf = b""
            while b"\r\n\r\n" not in buf:
                b = conn.recv(65536)
                if not b:
                    break
                buf += b
            head, _, rest = buf.partition(b"\r\n\r\n")
            want = 0
            for line in head.split(b"\r\n")[1:]:
                k, _, v = line.partition(b":")
                if k.strip().lower() == b"content-length":
                    want = int(v.strip())
            got = len(rest)
            while got < want:
                b = conn.recv(65536)
                if not b:
                    break
                got += len(b)
            body = b"ok %d" % got
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                         b"Content-Type: text/plain\r\n\r\n%s" % (len(body), body))
        except Exception:
            pass
        finally:
            conn.close()


def decode_status(payload):
    if not payload:
        return "none"
    b0 = payload[0]
    if b0 == 0x88:
        return "200"
    if b0 in (0x08, 0x48):
        ln = payload[1] & 0x7F
        return payload[2:2 + ln].decode("latin1")
    return "?0x%02x" % b0


ready = threading.Event()
threading.Thread(target=serial_backend, args=(ready,), daemon=True).start()
if not ready.wait(10):
    print("serial backend did not bind %d" % BACKEND_PORT)
    sys.exit(2)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2"])
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", PORT), timeout=60),
                    server_hostname="localhost")
if s.selected_alpn_protocol() != "h2":
    print("server did not select h2")
    sys.exit(2)

s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
s.sendall(frame(SETTINGS, 0, 0, b""))
s.sendall(frame(WINDOW_UPDATE, 0, 0, struct.pack(">I", 1 << 24)))

conn_win, win, status, done, buf = 65535, {UP: 65535, GET: 65535}, {}, set(), b""
t_get_sent, t_get_done = [None], [None]
s.settimeout(60)


def pump(block):
    global buf, conn_win
    try:
        if not block:
            s.settimeout(0.01)
        chunk = s.recv(65536)
        if not chunk:
            return False
        buf += chunk
    except (socket.timeout, ssl.SSLWantReadError):
        return True
    finally:
        s.settimeout(60)
    while len(buf) >= 9:
        ln = int.from_bytes(buf[0:3], "big")
        if len(buf) < 9 + ln:
            break
        typ, flags = buf[3], buf[4]
        sid = struct.unpack(">I", buf[5:9])[0] & 0x7FFFFFFF
        payload, buf = buf[9:9 + ln], buf[9 + ln:]
        if typ == SETTINGS and not (flags & 0x1):
            for i in range(0, len(payload), 6):
                ident, val = struct.unpack(">HI", payload[i:i + 6])
                if ident == 0x4:
                    win[UP] = win[GET] = val
            s.sendall(frame(SETTINGS, 0x1, 0, b""))
        elif typ == WINDOW_UPDATE:
            inc = struct.unpack(">I", payload)[0] & 0x7FFFFFFF
            if sid == 0:
                conn_win += inc
            elif sid in win:
                win[sid] += inc
        elif typ == HEADERS:
            status[sid] = decode_status(payload)
            if sid == GET and t_get_done[0] is None:
                t_get_done[0] = time.monotonic()
            if flags & END_STREAM:
                done.add(sid)
        elif typ == DATA:
            if len(payload):
                s.sendall(frame(WINDOW_UPDATE, 0, 0, struct.pack(">I", len(payload))))
                s.sendall(frame(WINDOW_UPDATE, 0, sid, struct.pack(">I", len(payload))))
            if flags & END_STREAM:
                done.add(sid)
        elif typ == RST:
            status.setdefault(sid, "RST")
            if sid == GET and t_get_done[0] is None:
                t_get_done[0] = time.monotonic()
            done.add(sid)
        elif typ == PING and not (flags & 0x1):
            s.sendall(frame(PING, 0x1, 0, payload))
        elif typ == GOAWAY:
            return False
    return True


body = bytes((i * 7 + 11) & 0xFF for i in range(SIZE))
s.sendall(frame(HEADERS, END_HEADERS, UP,
                lit(b":method", b"POST") + lit(b":scheme", b"https") +
                lit(b":authority", b"localhost") + lit(b":path", b"/serial/upload") +
                lit(b"content-length", str(SIZE).encode())))
s.sendall(frame(WINDOW_UPDATE, 0, UP, struct.pack(">I", 1 << 24)))

t0, sent, alive = time.monotonic(), 0, True
while alive and sent < SIZE:
    behind = sent - (time.monotonic() - t0) * RATE
    if behind > 0:
        time.sleep(min(behind / RATE, 0.05))
    n = min(16384, SIZE - sent, win[UP], conn_win)
    if n > 0:
        end = END_STREAM if sent + n == SIZE else 0
        s.sendall(frame(DATA, end, UP, body[sent:sent + n]))
        sent += n
        win[UP] -= n
        conn_win -= n
    if t_get_sent[0] is None and sent > SIZE // 3:
        s.sendall(frame(HEADERS, END_HEADERS | END_STREAM, GET,
                        lit(b":method", b"GET") + lit(b":scheme", b"https") +
                        lit(b":authority", b"localhost") + lit(b":path", b"/serial/quick")))
        s.sendall(frame(WINDOW_UPDATE, 0, GET, struct.pack(">I", 1 << 24)))
        t_get_sent[0] = time.monotonic()
    alive = pump(n <= 0)

t_body_in = time.monotonic()
reads = 0
while alive and len(done) < 2 and reads < 20000:
    alive = pump(True)
    reads += 1
s.close()

if t_get_sent[0] is None:
    print("the GET was never issued")
    sys.exit(2)
if status.get(UP) != "200" or status.get(GET) != "200":
    print("upload %s, GET %s (both must be 200)" % (status.get(UP), status.get(GET)))
    sys.exit(1)

waited = (t_get_done[0] - t_get_sent[0]) if t_get_done[0] else float("inf")
remaining = t_body_in - t_get_sent[0]
# blocked: the GET waits out the rest of the upload. free: milliseconds.
if waited < remaining / 2:
    print("GET answered in %.3fs with %.2fs of upload still to come" % (waited, remaining))
    sys.exit(0)
print("GET waited %.3fs for an upload with %.2fs left: the backend was held"
      % (waited, remaining))
sys.exit(1)
