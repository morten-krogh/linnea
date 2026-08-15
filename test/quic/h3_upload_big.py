#!/usr/bin/env python3
# An HTTP/3 upload big enough to be written straight to the capture file rather
# than held in the RAM reassembly buffer, checked byte-for-byte.
#
# Every other h3 upload test uses a body under 7 KB, which never leaves the RAM
# path -- so none of them reaches this code, and that blind spot let two
# deadlocks ship. Both stalled the same way, with the peer sitting at a ceiling
# the server would never raise again while the server waited for bytes it had
# told the peer not to send:
#
#   - the ceiling was measured from the reassembly base, which does not move
#     while a payload is being written to the file, so it was fixed for the
#     payload's whole life and anything past LINNEA_QUIC_RA_WINDOW could never
#     finish;
#   - and then, with the ceiling following body_hi properly, the LAST step up to
#     the payload's end was dropped whenever it came to less than RA_GRANT
#     (16 KiB), which the grant path skipped as not worth a packet.
#
# The size therefore decides WHICH fault this exercises, and neither one is
# about volume. See the sizes run in test/run_tests.sh.
#
# Which path a size takes is DERIVED FROM THE SERVER and printed, never assumed
# from a number written here. When RA_BUF went 32768 -> 131072 the 40000-byte
# case stopped reaching the capture file altogether, and the suite went on
# reporting "goes to the capture file and echoes back" for a body that never
# left RAM. The second fault's band -- a payload just over RA_BUF, where the
# last grant step up to the cap fell under RA_GRANT and was suppressed -- also
# moved, and then closed: a payload shorter than RA_WINDOW now has its whole
# ceiling granted in one step at take-over, so only a payload past RA_WINDOW
# reaches the grant loop that fault lived in at all.
#
# Usage: h3_upload_big.py <host> <bytes> [port] [--path ram|file]
import hashlib, socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

host, n = sys.argv[1], int(sys.argv[2])
WANT_PATH = sys.argv[sys.argv.index("--path") + 1] if "--path" in sys.argv else None
have_port = len(sys.argv) > 3 and not sys.argv[3].startswith("--")
ADDR = ("127.0.0.1", int(sys.argv[3])) if have_port else (socket.gethostbyname(host), 443)
body = bytes((i * 37 + 11) & 0xFF for i in range(n))
want = hashlib.sha256(body).hexdigest()

cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.server_name = host
if have_port: cfg.verify_mode = ssl.CERT_NONE
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

# Which ingest path this size takes, decided by the window the SERVER advertises
# (initial_max_stream_data_bidi_remote, which is RA_BUF): a DATA payload the
# window already covers stays in RAM, a larger one opens a region written
# straight to the capture file.
window = conn._remote_max_stream_data_bidi_remote
path = "capture-file" if n > window else "RAM"
if WANT_PATH and path != {"ram": "RAM", "file": "capture-file"}[WANT_PATH]:
    print("%d bytes takes the %s path against the server's %d-byte stream window, "
          "not the %s path this case is for" % (n, path, window, WANT_PATH))
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
print("ok (%d bytes, %.2fs, byte-exact, %s path)" % (n, dt, path))
