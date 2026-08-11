#!/usr/bin/env python3
# An HTTP/3 upload LARGER than the per-stream window, checked byte-for-byte.
#
# Every other h3 upload test uses a body under 7 KB, and that blind spot let a
# deadlock ship: while a DATA payload is being written straight to the capture
# file the reassembly base does not move, so a window measured from it was
# fixed for the payload's lifetime and anything longer than
# LINNEA_QUIC_RA_WINDOW could never finish. The peer sent up to the ceiling and
# stopped; the server was waiting for bytes it had told the peer not to send.
# 8 MB against a 4 MiB window hung for 180s and returned nothing.
#
# So the size here must stay comfortably ABOVE that window for this to test
# anything: it is the crossing that matters, not the volume.
#
# Usage: h3_upload_big.py <host> <bytes> [port]
import hashlib, socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

host, n = sys.argv[1], int(sys.argv[2])
ADDR = ("127.0.0.1", int(sys.argv[3])) if len(sys.argv) > 3 else (socket.gethostbyname(host), 443)
body = bytes((i * 37 + 11) & 0xFF for i in range(n))
want = hashlib.sha256(body).hexdigest()

cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.server_name = host
if len(sys.argv) > 3: cfg.verify_mode = ssl.CERT_NONE
conn = QuicConnection(configuration=cfg)
conn.connect(ADDR, now=time.time())
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.05)


def flush():
    for d, _ in conn.datagrams_to_send(now=time.time()):
        s.sendto(d, ADDR)


flush()
dl = time.time() + 15
while not conn._handshake_confirmed and time.time() < dl:
    try:
        conn.receive_datagram(s.recvfrom(2048)[0], ADDR, now=time.time())
    except socket.timeout:
        pass
    flush()
if not conn._handshake_confirmed:
    print("handshake failed")
    sys.exit(1)

h3 = H3Connection(conn)
sid = conn.get_next_available_stream_id()
h3.send_headers(sid, [(b":method", b"POST"), (b":scheme", b"https"),
                      (b":authority", host.encode()),
                      (b":path", b"/api/echo"),
                      
                      (b"content-length", str(n).encode())], end_stream=False)
t0 = time.time()
h3.send_data(sid, body, end_stream=True)
flush()

status, data, done = None, b"", False
end = time.time() + 60   # a working upload of this size takes ~3s
while time.time() < end and not done:
    try:
        conn.receive_datagram(s.recvfrom(2048)[0], ADDR, now=time.time())
    except socket.timeout:
        pass
    while True:
        ev = conn.next_event()
        if ev is None:
            break
        for e in h3.handle_event(ev):
            if isinstance(e, HeadersReceived):
                status = dict(e.headers).get(b":status", b"?").decode()
                done = done or e.stream_ended
            elif isinstance(e, DataReceived):
                data += e.data
                done = done or e.stream_ended
    flush()
dt = time.time() - t0
s.close()

# /api/echo returns the body verbatim, so the comparison is the body itself —
# a byte placed at the wrong file offset shows up as a wrong answer rather
# than as a request that merely completed.
if status != "200":
    print("status %s after %.1fs (want 200)" % (status, dt))
    sys.exit(1)
if len(data) != n:
    print("echoed %d of %d bytes after %.1fs" % (len(data), n, dt))
    sys.exit(1)
if hashlib.sha256(data).hexdigest() != want:
    print("echoed %d bytes but the content differs" % len(data))
    sys.exit(1)
print("ok (%d bytes, %.2fs, byte-exact)" % (n, dt))
