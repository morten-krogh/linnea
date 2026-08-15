#!/usr/bin/env python3
# A stream ENDED at exactly the flow-control limit, with the FIN in its own
# empty STREAM frame, arriving while a gap remains in the payload.
#
# Both halves are things a conforming peer may do. RFC 9000 4.1 lets a sender
# end a stream at a final size equal to the limit it was granted, and nothing
# obliges it to carry the FIN on a frame that also carries data. Inside a DATA
# payload the limit we grant IS the payload's end, so "ended at the limit"
# means an empty frame at that offset -- and a reassembly base pinned at the
# payload's start makes that offset look like it lands a whole payload past the
# window. It closed the connection with FLOW_CONTROL_ERROR against a peer that
# had done nothing wrong.
#
# Both cases below put a frame at exactly that offset while the payload is
# still incomplete, and they differ only in whether it carries bytes. That is
# the whole distinction the server has to draw:
#
#   fin   an empty frame ending the stream    -> must be ACCEPTED, request completes
#   data  64 bytes past the payload's end     -> must still be REFUSED, 0x03
#
# The second is here so the fix cannot be "stop checking the bound". A test for
# the accepted case alone would pass just as well against a server that let
# anything through.
#
# The ordering is forced, not hoped for. Two things make it deterministic:
#
#   - the datagrams held back are the LAST ones, so there are no packets sent
#     after them and aioquic's ACK-based loss detection (which needs a later
#     packet to be acknowledged) can never declare them lost. Only a PTO timer
#     could fill the gap, and the frame under test goes out microseconds after
#     the payload is framed, with no network wait in between;
#   - nothing leaves this process unless the test asks for it, so "hold" really
#     means held. Two earlier probe designs let aioquic's own pacing run and
#     both filled the gap before the FIN landed, which reads as a pass.
#
# Which is why the fin case refuses to pass without evidence its own setup
# worked: it waits with the gap still open, and a request that COMPLETES there
# means no gap was ever created and the check tested nothing. That is reported
# as a failure, not as an ok.
#
# Usage: h3_fin_at_limit_test.py <port>
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)
# N MUST EXCEED LINNEA_QUIC_RA_BUF, so the body takes the direct-to-file path
# and the payload's end sits more than a window above the pinned base -- which is
# what turns the offset into an apparent violation. Under that, the whole payload
# plus the 64 bytes past it fits inside base + RA_BUF, accepting them is correct,
# and the data case below tests nothing.
#
# It broke exactly that way when RA_BUF went 32768 -> 131072 and N was 40000: the
# check reported "the bound is not being enforced" against a server enforcing it
# perfectly at a higher offset. Keep this comfortably above RA_BUF, and if that
# constant moves again, this number moves with it.
N = 200000
BODY = bytes((i * 37 + 11) & 0xFF for i in range(N))
HOLD = 2
FLOW_CONTROL_ERROR = 0x03


class Upload:
    """A body-mode upload with every byte framed and the last HOLD datagrams
    held back here, so the server's payload is knowably incomplete."""

    def __init__(self):
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
        cfg.verify_mode = ssl.CERT_NONE
        cfg.server_name = "localhost"
        self.conn = QuicConnection(configuration=cfg)
        self.conn.connect(ADDR, now=time.time())
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(0.02)
        self.held = []
        self.status, self.data, self.ended = None, b"", False

        self.emit()
        dl = time.time() + 15
        while not self.conn._handshake_confirmed and time.time() < dl:
            self.recv()
            self.emit()
        if not self.conn._handshake_confirmed:
            raise SystemExit("handshake failed")

        self.h3 = H3Connection(self.conn)
        self.sid = self.conn.get_next_available_stream_id()
        self.h3.send_headers(self.sid,
                             [(b":method", b"POST"), (b":scheme", b"https"),
                              (b":authority", b"localhost"), (b":path", b"/api/echo"),
                              (b"content-length", str(N).encode())], end_stream=False)
        self.h3.send_data(self.sid, BODY, end_stream=False)   # payload; no FIN yet

        sender = self.conn._streams[self.sid].sender
        target = sender._buffer_stop                          # the request's final size
        dl = time.time() + 20
        while sender.next_offset < target and time.time() < dl:
            self.emit(hold=True)
            self.recv()
        if sender.next_offset < target:
            raise SystemExit("setup: only %d of %d bytes were framed in 20s"
                             % (sender.next_offset, target))
        if not self.held:
            raise SystemExit("setup: nothing was held back, so no gap was opened")

    def emit(self, hold=False):
        """Hand the connection's datagrams to the socket. With hold=True the most
        recent HOLD of them stay here instead, which is what opens the gap."""
        for d, _ in self.conn.datagrams_to_send(now=time.time()):
            if hold:
                self.held.append(d)
                while len(self.held) > HOLD:
                    self.sock.sendto(self.held.pop(0), ADDR)
            else:
                self.sock.sendto(d, ADDR)

    def recv(self):
        try:
            self.conn.receive_datagram(self.sock.recvfrom(2048)[0], ADDR, now=time.time())
        except socket.timeout:
            if self.conn._close_at is not None:
                self.conn.handle_timer(now=time.time())

    def events(self):
        """-> a (code, frame_type, reason) triple if the server closed, else None.
        Never sends."""
        while True:
            ev = self.conn.next_event()
            if ev is None:
                return None
            if type(ev).__name__ == "ConnectionTerminated":
                return (ev.error_code, ev.frame_type, ev.reason_phrase)
            for e in self.h3.handle_event(ev):
                if isinstance(e, HeadersReceived):
                    self.status = dict(e.headers).get(b":status", b"?").decode()
                    self.ended = self.ended or e.stream_ended
                elif isinstance(e, DataReceived):
                    self.data += e.data
                    self.ended = self.ended or e.stream_ended

    def send_now(self):
        for d, _ in self.conn.datagrams_to_send(now=time.time()):
            self.sock.sendto(d, ADDR)

    def release(self):
        for d in self.held:
            self.sock.sendto(d, ADDR)

    def wait(self, seconds, until=lambda u: False):
        closed, dl = None, time.time() + seconds
        while time.time() < dl and closed is None and not until(self):
            self.recv()
            closed = self.events()
        return closed


def case_fin():
    """An empty frame ending the stream at the limit: must be accepted."""
    u = Upload()
    # The FIN, alone, at the offset the payload ends -- which is exactly the
    # limit the server granted for it. It goes out ahead of the bytes it ends.
    u.conn.send_stream_data(u.sid, b"", end_stream=True)
    # Taken ONCE and kept: datagrams_to_send() dequeues, so asking whether it
    # produced anything and then sending is asking it to throw the FIN away.
    fin_dgrams = [d for d, _ in u.conn.datagrams_to_send(now=time.time())]
    if not fin_dgrams:
        return "setup: the FIN produced no datagram of its own"
    for d in fin_dgrams:
        u.sock.sendto(d, ADDR)

    # Hold the gap open a moment. A server that closes here is the fault this
    # checks for; a server that ANSWERS here had the whole payload already, so
    # the gap never existed and nothing was tested.
    closed = u.wait(0.4)
    if closed:
        return ("the server closed the connection on a FIN at the limit: "
                "error 0x%x frame 0x%x %r" % closed)
    if u.ended or u.status is not None:
        return ("setup: the request completed with %d datagram(s) still held, so "
                "no gap was ever open and this tested nothing" % len(u.held))

    u.release()                                   # and now the bytes it ends
    dl = time.time() + 20
    while time.time() < dl and not u.ended:
        closed = u.wait(0.2, until=lambda x: x.ended)
        if closed:
            return ("the server closed the connection after the gap was filled: "
                    "error 0x%x frame 0x%x %r" % closed)
        u.emit()
    u.sock.close()
    if u.status != "200":
        return "status %s (want 200)" % u.status
    if u.data != BODY:
        return ("echoed %d of %d bytes and the content %s"
                % (len(u.data), N, "differs" if len(u.data) == N else "is short"))
    return None


def case_data():
    """64 bytes PAST the payload's end: must still be a flow-control violation.
    aioquic is conformant and would never send them, so its send-side limits are
    lifted the way h3_flow_violation_test.py lifts them."""
    u = Upload()
    u.conn.send_stream_data(u.sid, b"\x01" * 64, end_stream=True)
    u.conn._remote_max_data = 100_000_000
    u.conn._remote_max_data_used = 0
    u.conn._streams[u.sid].max_stream_data_remote = 100_000_000
    u.send_now()

    closed = u.wait(8.0)
    u.sock.close()
    if closed is None:
        return ("64 bytes past the payload's end drew no CONNECTION_CLOSE "
                "(status %s) -- the bound is not being enforced" % u.status)
    if closed[0] != FLOW_CONTROL_ERROR:
        return ("closed with error 0x%x frame 0x%x %r, want FLOW_CONTROL_ERROR 0x3"
                % closed)
    return None


bad = case_fin()
if bad:
    print("fin: " + bad)
    sys.exit(1)
bad = case_data()
if bad:
    print("data: " + bad)
    sys.exit(1)
print("ok (%d bytes: a bare FIN at the limit completes byte-exact, "
      "64 bytes past it is still 0x3)" % N)
