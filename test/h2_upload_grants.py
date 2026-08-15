#!/usr/bin/env python3
# How many times does an h2 upload have to STOP to be given more window?
#
# This asserts a ROUND-TRIP COUNT, not a throughput, and that is the whole
# point. linnea_h2_handle cannot run while a client send is in flight
# (h2_tx_busy), so every batch of WINDOW_UPDATE frames is a point where the
# connection stops reading the upload. On loopback that pause is free and the
# throughput looks perfect however many of them there are; at a real RTT each
# one costs, and the upload slows in proportion to how many the server chose to
# take.
#
# 0884402 moved every upload onto the collect path, which credits where the
# bytes are consumed -- once per DATA frame. That is 2 WINDOW_UPDATE frames per
# 16 KiB instead of per LINNEA_H2P_GRANT_MIN (256 KiB), a 15x increase in stops,
# and it cost a real client 4.4 MB/s -> 1.4 MB/s on a 40 MB upload while every
# loopback test in this suite stayed green. Hence this one: it measures the
# thing loopback CAN see.
#
# The client is PACED, and that is not incidental. Blasting at full loopback
# speed delivers dozens of DATA frames per read, so the server handles them in
# one pass and the WINDOW_UPDATEs coalesce -- the per-frame version scores the
# same as the batched one and the check proves nothing. A real client is slower
# than the server, so its frames arrive one at a time and each one gets its own
# grant. Pacing is what reproduces that here.
#
# Usage: h2_upload_grants.py <port> <bytes> [bytes-per-sec]
import socket, ssl, struct, sys, time

PORT, SIZE = int(sys.argv[1]), int(sys.argv[2])
RATE = int(sys.argv[3]) if len(sys.argv) > 3 else 4000000
GRANT_MIN = 262144          # LINNEA_H2P_GRANT_MIN
FRAME = 16384
# Two frames (stream + connection) per grant, plus slack for the bring-up
# grant, the odd flush at END_STREAM, and any coalescing that splits one.
BUDGET = 2 * (SIZE // GRANT_MIN + 4)

DATA, HEADERS, RST, SETTINGS, PING, GOAWAY, WINDOW_UPDATE = 0, 1, 3, 4, 6, 7, 8
END_STREAM, END_HEADERS = 0x1, 0x4

lit = lambda n, v: b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v
frame = lambda t, f, s, p: struct.pack(">I", len(p))[1:] + bytes([t, f]) + \
    struct.pack(">I", s) + p

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
s.sendall(frame(HEADERS, END_HEADERS, 1,
                lit(b":method", b"POST") + lit(b":scheme", b"https") +
                lit(b":authority", b"localhost") + lit(b":path", b"/api/simple") +
                lit(b"content-length", str(SIZE).encode())))
s.sendall(frame(WINDOW_UPDATE, 0, 1, struct.pack(">I", 1 << 24)))

body = bytes((i * 7 + 11) & 0xFF for i in range(1 << 16))
wu, status, sent, win, cwin, buf = 0, None, 0, 65535, 65535, b""


def consume(chunk):
    global buf, win, cwin, status, wu
    buf += chunk
    while len(buf) >= 9:
        ln = int.from_bytes(buf[0:3], "big")
        if len(buf) < 9 + ln:
            break
        typ, flags = buf[3], buf[4]
        sid = struct.unpack(">I", buf[5:9])[0] & 0x7FFFFFFF
        payload, buf = buf[9:9 + ln], buf[9 + ln:]
        if typ == WINDOW_UPDATE:
            inc = struct.unpack(">I", payload)[0] & 0x7FFFFFFF
            if sid == 0:
                cwin += inc
            else:
                win += inc
            wu += 1
        elif typ == SETTINGS and not (flags & 0x1):
            for j in range(0, len(payload), 6):
                ident, val = struct.unpack(">HI", payload[j:j + 6])
                if ident == 0x4:
                    win = val - sent
            s.sendall(frame(SETTINGS, 0x1, 0, b""))
        elif typ == HEADERS and sid == 1:
            b0 = payload[0] if payload else 0
            status = "200" if b0 == 0x88 else (
                payload[2:2 + (payload[1] & 0x7F)].decode("latin1")
                if b0 in (0x08, 0x48) else "?%02x" % b0)
        elif typ == PING and not (flags & 0x1):
            s.sendall(frame(PING, 0x1, 0, payload))
        elif typ == GOAWAY:
            status = status or "GOAWAY"


s.settimeout(0.005)
deadline = time.monotonic() + 120
t0 = time.monotonic()
while sent < SIZE and time.monotonic() < deadline:
    behind = sent - (time.monotonic() - t0) * RATE
    if behind > 0:
        time.sleep(min(behind / RATE, 0.02))
    n = min(FRAME, SIZE - sent, win, cwin)
    if n > 0:
        end = END_STREAM if sent + n == SIZE else 0
        s.sendall(frame(DATA, end, 1, body[:n]))
        sent += n
        win -= n
        cwin -= n
    try:
        c = s.recv(65536)
        if c:
            consume(c)
    except (socket.timeout, ssl.SSLWantReadError):
        pass

s.settimeout(30)
while status is None and time.monotonic() < deadline:
    try:
        c = s.recv(65536)
    except (socket.timeout, ssl.SSLWantReadError):
        break
    if not c:
        break
    consume(c)
s.close()

frames = (SIZE + FRAME - 1) // FRAME
ok = status == "200" and sent == SIZE and wu <= BUDGET
print("%d bytes in %d DATA frames: status %s, %d WINDOW_UPDATE (budget %d, "
      "%.2f per frame)" % (SIZE, frames, status, wu, BUDGET, wu / max(frames, 1)))
sys.exit(0 if ok else 1)
