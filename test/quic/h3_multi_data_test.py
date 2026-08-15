#!/usr/bin/env python3
# A request body split across SEVERAL DATA frames, where a non-final frame is
# large enough to take the direct-to-file path.
#
# Closing a payload region slides the reassembly base to the payload's end and
# leaves through the done-check, and on that pass there is nothing to feed the
# walk and no FIN yet. The grant lived only on the feed's tail, so no
# MAX_STREAM_DATA went out -- and the ceiling the peer holds is the payload's
# end, which is now exactly the base. It had no credit for the next frame's
# header, could not send the byte that would have let the server grant more, and
# both sides waited for ever. The trace read adv == base with the whole first
# frame already captured.
#
# A single-frame body hides this completely, because there the FIN arrives with
# the payload's last bytes and that pass completes the request instead of
# needing more of the stream. Every other h3 upload check in the suite sends one
# DATA frame, which is also what aioquic and browsers do for a body they have in
# hand -- a streaming upload (fetch with a ReadableStream) is what splits it.
#
# The small-first-frame case is a control, not decoration: it takes the RAM path
# and has always worked, so if BOTH cases fail the fault is the fixture or the
# backend rather than the grant. Only the large one failing is this bug.
#
# Usage: h3_multi_data_test.py <port>
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)
# The two cases are sized as MULTIPLES of the window the server advertises,
# learned from the connection after the handshake, so neither one can drift out
# of the path it is for. It used to be a constant copied from the server, and
# when the server's moved the file-path case quietly became a second RAM-path
# case with its label intact -- and then moved again when the buffer became a
# small inline one plus a big borrowed one.
SECOND = bytes((i * 11 + 37) & 0xFF for i in range(20000))


def echo(size_of, label, want_file_path, drain_between=True):
    """POST first_len bytes then SECOND, as two DATA frames. -> None, or why not.

    want_file_path says which of the two ingest paths the first frame is meant
    to take, and the window the server advertises is what decides it. Asserting
    that here is not ceremony: this file had RA_BUF written into it as 32768,
    and when the server's went to 131072 the "capture-file path" case quietly
    became a second RAM-path case. Both cases passed, the label still said
    otherwise, and the multi-frame file path -- the one with a payload region,
    a straddling frame and a split -- went untested through two rewrites of it.

    drain_between=False queues both frames before anything is sent, which is
    what a browser does and what produces a STREAM frame carrying the END of one
    DATA payload and the START of the next. The server has to split that frame,
    writing the first half to the capture file and buffering the second, and an
    off-by-one in the split shows up here as a body that differs rather than as
    anything failing loudly. Draining between the frames -- which is all this
    test used to do -- never produces one.
    """

    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    conn.connect(ADDR, now=time.time())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.02)

    def flush():
        for d, _ in conn.datagrams_to_send(now=time.time()):
            sock.sendto(d, ADDR)

    def pump(seconds, until=lambda: False):
        dl = time.time() + seconds
        while time.time() < dl and not until():
            try:
                conn.receive_datagram(sock.recvfrom(2048)[0], ADDR, now=time.time())
            except socket.timeout:
                pass
            flush()

    flush()
    dl = time.time() + 15
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            conn.receive_datagram(sock.recvfrom(2048)[0], ADDR, now=time.time())
        except socket.timeout:
            pass
        flush()
    if not conn._handshake_confirmed:
        return "%s: handshake failed" % label

    # A DATA frame the reassembly window already covers stays on the RAM path
    # deliberately; only one larger than it opens a payload region written
    # straight to the capture file.
    window = conn._remote_max_stream_data_bidi_remote
    first_len = size_of(window)
    part1 = bytes((i * 37 + 11) & 0xFF for i in range(first_len))
    body = part1 + SECOND
    if want_file_path and first_len <= window:
        return ("%s: a first frame of %d does not exceed the server's stream "
                "window %d, so it takes the RAM path and this case is a "
                "duplicate of the control" % (label, first_len, window))
    if not want_file_path and first_len > window:
        return ("%s: a first frame of %d exceeds the server's stream window %d, "
                "so the control is not on the RAM path" % (label, first_len, window))

    h3 = H3Connection(conn)
    sid = conn.get_next_available_stream_id()
    h3.send_headers(sid, [(b":method", b"POST"), (b":scheme", b"https"),
                          (b":authority", b"localhost"), (b":path", b"/api/echo"),
                          (b"content-length", str(len(body)).encode())], end_stream=False)
    h3.send_data(sid, part1, end_stream=False)      # the first DATA frame
    if drain_between:
        flush()
        pump(0.5)                                   # ...fully ingested before the next
    h3.send_data(sid, SECOND, end_stream=True)      # the frame that needs fresh credit
    flush()

    status, data, ended = None, b"", False
    dl = time.time() + 25
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
                return "%s: the server closed the connection: error 0x%x %r" % (
                    label, ev.error_code, ev.reason_phrase)
            for e in h3.handle_event(ev):
                if isinstance(e, HeadersReceived):
                    status = dict(e.headers).get(b":status", b"?").decode()
                    ended = ended or e.stream_ended
                elif isinstance(e, DataReceived):
                    data += e.data
                    ended = ended or e.stream_ended
        flush()
    sock.close()

    if status != "200":
        return ("%s: status %s (want 200) -- the peer was left with no credit for "
                "the second frame" % (label, status))
    if data != body:
        return ("%s: echoed %d of %d bytes and the content %s"
                % (label, len(data), len(body),
                   "differs" if len(data) == len(body) else "is short"))
    return None


bad = echo(lambda w: w // 2, "small first frame (control, RAM path)", False)
if bad:
    print(bad)
    sys.exit(1)
bad = echo(lambda w: w * 3, "large first frame (capture-file path)", True)
if bad:
    print(bad)
    sys.exit(1)
bad = echo(lambda w: w * 3,
           "large first frame, both queued at once (straddling frame)",
           True, drain_between=False)
if bad:
    print(bad)
    sys.exit(1)
print("ok (a body in two DATA frames completes byte-exact: RAM path, capture-file "
      "path, and a frame straddling the boundary between them)")
