#!/usr/bin/env python3
# A request BODY whose STREAM frames arrive out of order, or twice.
#
# h3_reorder_test.py already reorders a request whose field SECTION spans
# packets, which covers the reassembler's bitmap and its offsets. This is the
# other half: a body spanning packets, echoed back by the backend and compared
# by checksum, so a byte placed at the wrong offset shows up as a wrong answer
# rather than as a header that happens to still parse. It also delivers every
# datagram TWICE in two of the cases, which the sibling does not -- a
# retransmit into a reordered path is the shape that actually occurs.
#
# The datagrams are collected and delivered in an order of this test's
# choosing. Nothing is dropped, so no retransmission covers for a mistake: a
# wrong answer is the reassembly being wrong, not the network being slow.
#
# It matters most for what comes next. Consuming a stream as it arrives means
# sliding the buffer out from under exactly these cases -- moving what has not
# been consumed yet, and the seen-map with it -- and getting that wrong
# corrupts a body rather than raising an error. This is the test that notices.
#
# Usage: h3_reorder_body_test.py <port>
import hashlib, socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)

# Big enough to span several datagrams (the path floor is 1200 bytes), small
# enough for the request-stream window as it stands today.
BODY = bytes((i * 31 + 7) % 251 for i in range(6800))


def echo(reorder, label):
    """POST the body, deliver the request's datagrams in the order `reorder`
    chooses, and return what came back."""
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    vt = [0.0]

    def clk():
        vt[0] += 0.001
        return vt[0]

    conn.connect(ADDR, now=clk())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.1)

    def flush():
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ADDR)

    flush()
    dl = time.time() + 10
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            conn.receive_datagram(s.recvfrom(4096)[0], ADDR, now=clk())
        except socket.timeout:
            pass
        flush()
    if not conn._handshake_confirmed:
        s.close()
        return None, "handshake failed"

    h3 = H3Connection(conn)
    sid = conn.get_next_available_stream_id()
    h3.send_headers(sid, [(b":method", b"POST"), (b":scheme", b"https"),
                          (b":authority", b"localhost"),
                          (b":path", b"/api/echo"),
                          (b"content-length", str(len(BODY)).encode())],
                    end_stream=False)
    h3.send_data(sid, BODY, end_stream=True)

    # Take the request's datagrams rather than sending them, reorder, then send.
    dgrams = [d for d, _ in conn.datagrams_to_send(now=clk())]
    if len(dgrams) < 3:
        s.close()
        return None, f"expected several datagrams, got {len(dgrams)}"
    for i in reorder(len(dgrams)):
        s.sendto(dgrams[i], ADDR)

    status, data, done = None, b"", False
    end = time.time() + 20
    while time.time() < end and not done:
        try:
            conn.receive_datagram(s.recvfrom(4096)[0], ADDR, now=clk())
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
    s.close()
    return status, data


ORDERS = [
    ("in order", lambda n: list(range(n))),
    # the whole request backwards: every frame but the last arrives before the
    # bytes in front of it, so the prefix advances only on the final datagram
    ("reversed", lambda n: list(range(n - 1, -1, -1))),
    # the first datagram last, which is the shape a single early loss takes:
    # everything is buffered against a gap at offset zero, then filled
    ("head last", lambda n: list(range(1, n)) + [0]),
    # one in the middle held back to the end
    ("middle last", lambda n: [i for i in range(n) if i != n // 2] + [n // 2]),
    # every datagram twice, in order: the duplicates must change nothing
    ("duplicated", lambda n: [i for i in range(n) for _ in (0, 1)]),
    # reordered AND duplicated, which is what a retransmit into a reordered
    # path actually looks like
    ("reversed + duplicated",
     lambda n: [i for i in range(n - 1, -1, -1) for _ in (0, 1)]),
]

want = hashlib.sha256(BODY).hexdigest()
bad = []
for label, order in ORDERS:
    st, got = echo(order, label)
    if st != "200":
        bad.append(f"{label}: status {st} ({got!r:.40})")
    elif hashlib.sha256(got).hexdigest() != want:
        bad.append(f"{label}: body differs ({len(got)} of {len(BODY)} bytes)")

print("OK" if not bad else "; ".join(bad))
sys.exit(0 if not bad else 1)
