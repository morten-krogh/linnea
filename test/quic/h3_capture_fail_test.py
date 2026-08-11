#!/usr/bin/env python3
# An upload the server cannot capture must not be reported as one the client
# sent too much of.
#
# A request body larger than the reassembly buffer is written to a capture file,
# and four different things can stop that: the file cannot be opened, a write
# fails, the filesystem is full, or the peer fragments the payload past the
# range list. All four returned a bare -1, and the caller turned every -1 into
# the same verdict as a body past max_body — so the client was told 413, "your
# body is too large", when the truth was that the server could not write it.
# Once that answer went to an upload whose capture file another connection had
# closed, and the access line named no method and no path (the head had not
# parsed), so there was nothing in the log to tell the two apart at all.
#
# The four cases now say 500 and log which one it was, with its errno; only
# max_body still says 413. This walks the whole split in one connection's worth
# of requests:
#
#   under the cap                -> 200
#   over the cap                 -> 413   (the peer's, and unchanged)
#   capture dir made unwritable  -> 500   (ours, and it used to say 413)
#   dir writable again           -> 200   (the failure was not sticky)
#
# The last case matters as much as the third: a server that answered 500 for
# ever afterwards would pass a check that only looked for the 500.
#
# Usage: h3_capture_fail_test.py <port> <spill_dir>
import os, socket, ssl, stat, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

PORT = int(sys.argv[1])
SPILL = sys.argv[2]
ADDR = ("127.0.0.1", PORT)
# Past LINNEA_QUIC_RA_BUF (32768) so the body needs a capture file at all.
UNDER = 40000
OVER = 400000          # the fixture's max_body is 200000


def upload(n):
    """POST n bytes over a fresh h3 connection -> the status as a string."""
    body = bytes((i * 37 + 11) & 0xFF for i in range(n))
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    conn.connect(ADDR, now=time.time())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.05)

    def flush():
        for d, _ in conn.datagrams_to_send(now=time.time()):
            sock.sendto(d, ADDR)

    flush()
    dl = time.time() + 15
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            conn.receive_datagram(sock.recvfrom(2048)[0], ADDR, now=time.time())
        except socket.timeout:
            pass
        flush()
    if not conn._handshake_confirmed:
        return "handshake-failed"

    h3 = H3Connection(conn)
    sid = conn.get_next_available_stream_id()
    h3.send_headers(sid, [(b":method", b"POST"), (b":scheme", b"https"),
                          (b":authority", b"localhost"), (b":path", b"/api/echo"),
                          (b"content-length", str(n).encode())], end_stream=False)
    h3.send_data(sid, body, end_stream=True)
    flush()

    status, ended = None, False
    dl = time.time() + 45
    while time.time() < dl and not ended:
        try:
            conn.receive_datagram(sock.recvfrom(2048)[0], ADDR, now=time.time())
        except socket.timeout:
            pass
        while True:
            ev = conn.next_event()
            if ev is None:
                break
            if type(ev).__name__ == "ConnectionTerminated":
                sock.close()
                return "closed-0x%x" % ev.error_code
            for e in h3.handle_event(ev):
                if isinstance(e, HeadersReceived):
                    status = dict(e.headers).get(b":status", b"?").decode()
                    ended = ended or e.stream_ended
                elif isinstance(e, DataReceived):
                    ended = ended or e.stream_ended
        flush()
    sock.close()
    return status or "no-answer"


if os.geteuid() == 0:
    # root writes through a mode that would stop anyone else, so the capture
    # could not be made to fail this way. Say so rather than pass quietly.
    print("skipped (running as root: an unwritable directory would not stop it)")
    sys.exit(0)

mode = stat.S_IMODE(os.stat(SPILL).st_mode)
bad = []

s = upload(UNDER)
if s != "200":
    bad.append("under the cap gave %s, want 200" % s)

s = upload(OVER)
if s != "413":
    bad.append("past max_body gave %s, want 413" % s)

os.chmod(SPILL, 0o555)                 # O_TMPFILE cannot create here any more
try:
    s = upload(UNDER)
    if s != "500":
        bad.append("an uncapturable body gave %s, want 500 (413 is the old "
                   "collapse: it blames the client for the server's failure)" % s)
finally:
    os.chmod(SPILL, mode)

s = upload(UNDER)
if s != "200":
    bad.append("after the directory was writable again, %s, want 200" % s)

if bad:
    print("; ".join(bad))
    sys.exit(1)
print("ok (200 under the cap, 413 past it, 500 when the capture fails, 200 again after)")
