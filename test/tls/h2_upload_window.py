#!/usr/bin/env python3
# HTTP/2 upload flow control: how many ROUND TRIPS a body costs.
#
# The correctness of an upload was already covered — a 300000-byte body is
# echoed back and compared — and it passed while uploads were, in practice,
# unusable from anywhere but loopback. The server advertised no
# SETTINGS_INITIAL_WINDOW_SIZE, so a stream started on the RFC default of
# 65535, and it returned credit as bytes drained upstream one 16 KiB DATA
# frame at a time. Steady state was therefore 16 KiB per round trip. With no
# RTT that finishes instantly and every byte is correct; at a laptop's 30 ms
# it is 546 KB/s, and the 8 MiB the config allows took a quarter of a minute.
#
# A throughput assertion could not catch that here, because on loopback the
# broken server is fast. The ROUND TRIP COUNT can: it is a property of the
# server's flow-control policy alone and is identical at any RTT. That is what
# this asserts, along with the two grants the policy is built from.
#
# Usage: h2_upload_window.py <cafile> <port> [bytes]
import hashlib
import socket
import ssl
import struct
import sys

ca, port = sys.argv[1], int(sys.argv[2])
total = int(sys.argv[3]) if len(sys.argv) > 3 else 4 << 20

# Bytes of body per credit round trip. The old policy managed 16384 (one DATA
# frame); the current one clears 500 KB. 128 KiB sits far enough above the
# first to fail loudly on a regression and far enough below the second to
# survive an unrelated change in framing or grant step.
MIN_BYTES_PER_RT = 128 * 1024
MIN_INITIAL_WINDOW = 256 * 1024


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def estr(b):
    b = b if isinstance(b, bytes) else b.encode()
    return bytes([len(b)]) + b


def hdr(n, v):
    return b"\x00" + estr(n) + estr(v)


ctx = ssl.create_default_context(cafile=ca)
ctx.check_hostname = False
ctx.set_alpn_protocols(["h2"])
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=30),
                    server_hostname="localhost")
assert s.selected_alpn_protocol() == "h2", s.selected_alpn_protocol()
s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(4, 0, 0))

body = bytes((i * 31 + 7) & 0xff for i in range(total))
want = hashlib.md5(body).hexdigest()

s.sendall(fr(1, 0x04, 1,
             hdr(":method", "POST") + hdr(":scheme", "https")
             + hdr(":authority", "localhost") + hdr(":path", "/api/echo")
             + hdr("content-length", str(total))))

# RFC 9113 defaults until the server says otherwise. The connection window is
# fixed at 65535 and only a WINDOW_UPDATE can move it: SETTINGS cannot carry
# it, so a server that raises only the stream window has raised nothing.
conn_win = 65535
strm_win = 65535
max_frame = 16384
init_window = None
conn_grant = 0
saw_settings = False
# The bring-up grant is the stream-0 credit that arrives before any is being
# returned for body bytes. Credit grants always come as a stream/connection
# pair, so the first stream-1 WINDOW_UPDATE marks where bring-up ends —
# a rule that does not depend on when the client happens to read.
returning_credit = False

sent = 0
stalls = 0
buf = b""
echoed = b""
status = None
s.settimeout(30)


def drain(block, timeout=30):
    """Read frames; apply flow control. Returns False on EOF."""
    global buf, conn_win, strm_win, max_frame, init_window, conn_grant
    global echoed, status, saw_settings, returning_credit
    s.setblocking(True) if block else s.setblocking(False)
    if block:
        s.settimeout(timeout)
    try:
        d = s.recv(262144)
        if not d:
            return False
        buf += d
    except (BlockingIOError, ssl.SSLWantReadError):
        pass
    finally:
        s.setblocking(True)
        s.settimeout(30)
    while len(buf) >= 9:
        ln = int.from_bytes(buf[:3], "big")
        if len(buf) < 9 + ln:
            break
        typ, flags = buf[3], buf[4]
        sid = int.from_bytes(buf[5:9], "big") & 0x7fffffff
        pay = buf[9:9 + ln]
        buf = buf[9 + ln:]
        if typ == 0x08:                                     # WINDOW_UPDATE
            inc = int.from_bytes(pay[:4], "big") & 0x7fffffff
            if sid == 0:
                conn_win += inc
                if not returning_credit:
                    conn_grant += inc                       # the bring-up grant
            else:
                strm_win += inc
                returning_credit = True
        elif typ == 0x04 and not (flags & 1):               # SETTINGS
            saw_settings = True
            for i in range(0, len(pay), 6):
                k = int.from_bytes(pay[i:i + 2], "big")
                v = int.from_bytes(pay[i + 2:i + 6], "big")
                if k == 4:
                    init_window = v
                    strm_win = v
                elif k == 5:
                    max_frame = v
            s.sendall(fr(4, 1, 0))                          # ACK
        elif typ == 0x01:
            status = pay
        elif typ == 0x00:
            echoed += pay
            s.sendall(fr(8, 0, 0, struct.pack(">I", max(1, len(pay)))))
            s.sendall(fr(8, 0, sid, struct.pack(">I", max(1, len(pay)))))
        elif typ == 0x07:
            print("GOAWAY code %d" % int.from_bytes(pay[4:8], "big"))
            sys.exit(1)
        elif typ == 0x03:
            print("RST_STREAM code %d" % int.from_bytes(pay[:4], "big"))
            sys.exit(1)
    return True


# Read the server's opening SETTINGS before sending a byte, the way a real
# client does — the windows granted there are the ones the upload runs under.
while not saw_settings:
    if not drain(True):
        break
# The bring-up WINDOW_UPDATE is written into the same buffer as those SETTINGS,
# but a record boundary may still split them, so give it one short read. It
# must not be REQUIRED here: a server that sends none has to fail the
# assertion below rather than hang this loop.
try:
    drain(True, timeout=1.0)
except socket.timeout:
    pass

while sent < total:
    room = min(conn_win, strm_win, max_frame, total - sent)
    if room <= 0:
        stalls += 1                       # one credit round trip
        if not drain(True):
            print("connection closed at %d of %d bytes" % (sent, total))
            sys.exit(1)
        continue
    s.sendall(fr(0, 0, 1, body[sent:sent + room]))
    sent += room
    conn_win -= room
    strm_win -= room
    if not drain(False):
        break
s.sendall(fr(0, 0x01, 1, b""))

while status is None or len(echoed) < total:
    if not drain(True):
        break
s.close()

bad = []
# 1. the stream window has to be advertised: without it every stream starts at
#    65535 whatever the buffer behind it can hold
if init_window is None:
    bad.append("no SETTINGS_INITIAL_WINDOW_SIZE advertised")
elif init_window < MIN_INITIAL_WINDOW:
    bad.append("SETTINGS_INITIAL_WINDOW_SIZE is %d, want >= %d"
               % (init_window, MIN_INITIAL_WINDOW))
# 2. ...and so has the connection window, or it is the binding constraint and
#    the stream window above buys nothing
if conn_grant < MIN_INITIAL_WINDOW:
    bad.append("connection window raised by only %d at bring-up, want >= %d"
               % (conn_grant, MIN_INITIAL_WINDOW))
# 3. the body still has to arrive intact
if len(echoed) != total:
    bad.append("echoed %d of %d bytes" % (len(echoed), total))
elif hashlib.md5(echoed).hexdigest() != want:
    bad.append("echoed %d bytes but the content differs" % len(echoed))
# 4. ...at a sane number of round trips
per_rt = total / max(1, stalls)
if per_rt < MIN_BYTES_PER_RT:
    bad.append("%d bytes over %d credit round trips = %d B/RT, want >= %d"
               % (total, stalls, per_rt, MIN_BYTES_PER_RT))

if bad:
    print("; ".join(bad))
    sys.exit(1)
print("ok (%d bytes, window %d, conn +%d, %d round trips, %d B/RT)"
      % (total, init_window, conn_grant, stalls, per_rt))
