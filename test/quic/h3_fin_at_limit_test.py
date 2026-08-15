#!/usr/bin/env python3
# A stream ENDED at exactly the flow-control limit, with the FIN in its own
# empty STREAM frame, arriving while a gap remains in the payload.
#
# Both halves are things a conforming peer may do. RFC 9000 4.1 lets a sender
# end a stream at a final size equal to the limit it was granted, and nothing
# obliges it to carry the FIN on a frame that also carries data. So a bare FIN
# at the payload's end must be accepted -- and it was not: a reassembly base
# pinned at the payload's START made that offset look like it landed a whole
# payload past the window, and the connection closed with FLOW_CONTROL_ERROR
# against a peer that had done nothing wrong.
#
# Both cases below put a frame past the payload while it is still incomplete,
# and they differ only in how far past. That is the whole distinction the server
# has to draw:
#
#   fin   an empty frame ending the stream at the payload's end -> ACCEPTED
#   data  bytes past the CEILING THE SERVER GRANTED             -> REFUSED, 0x3
#
# The second is here so the fix cannot be "stop checking the bound". A test for
# the accepted case alone would pass just as well against a server that let
# anything through.
#
# WHERE THAT BOUND SITS IS NOT A CONSTANT AND MUST NOT BE WRITTEN AS ONE. It
# used to be the payload's end, because nothing beyond the payload had anywhere
# to go while the region was open. Now base moves to the payload's END when the
# region opens, so the buffer holds what FOLLOWS the payload and the peer is
# invited a whole RA_BUF past the frame -- which is what stops a browser
# stalling at every DATA frame boundary. Bytes 64 past the payload's end became
# perfectly legal, and this check duly went red saying "the bound is not being
# enforced" against a server enforcing it exactly one buffer higher up.
#
# So the data case asks the connection what it was actually granted and steps
# over THAT. It needs no edit the next time the window moves.
#
# The ordering is forced, not hoped for. Three things make it deterministic:
#
#   - nothing leaves this process unless the test asks for it, so "hold" really
#     means held. Two earlier probe designs let aioquic's own pacing run and
#     both filled the gap before the FIN landed, which reads as a pass;
#   - the fin case sends nothing after the held datagrams, so aioquic's
#     ACK-based loss detection (which needs a LATER packet acknowledged) can
#     never declare them lost, and its frame goes out microseconds after the
#     payload is framed with no network wait in between;
#   - the data case DOES send after them, a whole window of it, and so supplies
#     exactly the condition that lets loss detection fire. It therefore makes
#     the body unretransmittable up front (see Upload.__init__). Without that
#     the gap closed behind the overrun, the payload completed, and the server
#     answered H3_FRAME_UNEXPECTED -- correct for what it was sent, and nothing
#     to do with the bound under test.
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
from aioquic.quic.packet_builder import QuicDeliveryState

PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)
# N MUST EXCEED LINNEA_QUIC_RA_BUF, or there is no payload region to test: a
# DATA frame the reassembly window already covers deliberately stays on the RAM
# path, and none of the body-mode offsets below then exist. Keep this comfortably
# above RA_BUF, and if that constant moves again, this number moves with it.
#
# It went red exactly that way once when RA_BUF went 32768 -> 131072 and N was
# 40000. Only this line depends on the constant now; the data case derives its
# offset from the ceiling the server grants.
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
        # THE GAP HAS TO STAY OPEN, and holding datagrams back is only half of
        # that: aioquic's loss detection declares a packet lost once later ones
        # are acknowledged, and retransmits it. The data case sends a whole
        # window after the held packets, so it supplies exactly that condition
        # -- the gap closed behind it, the payload completed, and the server
        # then read the overrun as a frame header and said H3_FRAME_UNEXPECTED.
        # A true answer to what it was actually sent, and nothing about the
        # bound under test.
        #
        # So the body is made unretransmittable. It has to be done HERE, before
        # a byte of it is queued: the delivery handler is captured into each
        # packet as that packet is BUILT, so patching the sender afterwards
        # leaves every packet already on the wire holding the original.
        #
        # ONLY THE BODY. Suppressing every retransmit on the stream was enough
        # while the overrun was 64 bytes, and stopped being enough the moment
        # the server's window grew: the data case now has to push most of a
        # megabyte past a 1 MiB ceiling, and a burst that size drops packets on
        # loopback. With nothing able to resend them the offending byte simply
        # never arrived, and the check reported "the bound is not being
        # enforced" against a server enforcing it perfectly. The body keeps its
        # hole; everything past it retransmits normally.
        sender = self.conn._streams[self.sid].sender
        deliver = sender.on_data_delivery
        body_end = [None]                                     # set once the body is queued

        def hold_the_gap(delivery, start, stop, fin):
            if delivery != QuicDeliveryState.ACKED and body_end[0] is not None:
                if stop <= body_end[0]:
                    return                                    # wholly body: let it stay lost
                if start < body_end[0]:
                    start = body_end[0]                       # resend only the part past it
            return deliver(delivery, start, stop, fin)

        sender.on_data_delivery = hold_the_gap
        self.h3.send_data(self.sid, BODY, end_stream=False)   # payload; no FIN yet

        target = sender._buffer_stop                          # the request's final size
        body_end[0] = target
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

    def wait(self, seconds, until=lambda u: False, sending=False):
        """Wait for the server to close, or for `until`. With sending=True the
        connection's own outbound queue is drained as it goes -- needed whenever
        what is under test is more than one datagram's worth, because congestion
        control hands it over a burst at a time and a wait that never sends
        leaves the rest of it sitting in the client. The HELD datagrams are not
        touched either way: only release() lets those go."""
        closed, dl = None, time.time() + seconds
        while time.time() < dl and closed is None and not until(self):
            if sending:
                self.emit()
            self.recv()
            closed = self.events()
        return closed


def why(closed):
    """Format a (code, frame_type, reason) close. frame_type is None for an
    APPLICATION close, and a bare 0x%x on it raises TypeError -- which replaces
    the failure being reported with a traceback about formatting it."""
    return ("error 0x%x frame %s %r"
            % (closed[0], "application" if closed[1] is None else hex(closed[1]),
               closed[2]))


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
                + why(closed))
    if u.ended or u.status is not None:
        return ("setup: the request completed with %d datagram(s) still held, so "
                "no gap was ever open and this tested nothing" % len(u.held))

    u.release()                                   # and now the bytes it ends
    dl = time.time() + 20
    while time.time() < dl and not u.ended:
        closed = u.wait(0.2, until=lambda x: x.ended)
        if closed:
            return ("the server closed the connection after the gap was filled: "
                    + why(closed))
        u.emit()
    u.sock.close()
    if u.status != "200":
        return "status %s (want 200)" % u.status
    if u.data != BODY:
        return ("echoed %d of %d bytes and the content %s"
                % (len(u.data), N, "differs" if len(u.data) == N else "is short"))
    return None


def case_data():
    """Bytes past the ceiling the server granted: must still be a flow-control
    violation. aioquic is conformant and would never send them, so its send-side
    limits are lifted the way h3_flow_violation_test.py lifts them."""
    u = Upload()
    stream = u.conn._streams[u.sid]
    body_end = stream.sender._buffer_stop
    # What the server has actually invited, read off its MAX_STREAM_DATA rather
    # than recomputed from a constant here -- the point is to run past the
    # server's own bound, wherever the server currently puts it.
    ceiling = stream.max_stream_data_remote
    # THE CEILING MOVES WHILE WE SEND, so overshooting the one we can see is not
    # enough. The server grants base + capacity, and base slides as it consumes
    # the body -- so by the time these bytes land it has granted more than it had
    # when this line ran. Reading it once and adding 64 put the last byte inside
    # the window the server had grown into, and the check called that "the bound
    # is not being enforced" against a server behaving correctly.
    #
    # base cannot pass the gap, and the gap cannot be later than the body's end,
    # so the ceiling can never rise by more than one body length. Overshoot by
    # that and the last byte is past it whatever the server has granted.
    over = ceiling + body_end + 64 - stream.sender._buffer_stop
    if over <= 0:
        return ("setup: the ceiling (%d) is already behind what has been queued "
                "(%d), so nothing here would be past it"
                % (ceiling, stream.sender._buffer_stop))
    u.conn.send_stream_data(u.sid, b"\x01" * over, end_stream=True)
    u.conn._remote_max_data = 1_000_000_000
    u.conn._remote_max_data_used = 0
    stream.max_stream_data_remote = 1_000_000_000
    u.send_now()

    # sending=True: the overrun is a whole window wide now, not the 64 bytes it
    # was when the ceiling stopped at the payload's end, so it does not leave in
    # one burst. Waiting without sending left most of it queued in the client and
    # read as "the bound is not being enforced" against a server that had simply
    # never been sent the offending byte.
    closed = u.wait(15.0, sending=True)
    u.sock.close()
    if closed is None:
        return ("%d bytes, ending 64 past the granted ceiling %d, drew no "
                "CONNECTION_CLOSE (status %s) -- the bound is not being enforced"
                % (over, ceiling, u.status))
    if closed[0] != FLOW_CONTROL_ERROR:
        return "closed with " + why(closed) + ", want FLOW_CONTROL_ERROR 0x3"
    return None


bad = case_fin()
if bad:
    print("fin: " + bad)
    sys.exit(1)
bad = case_data()
if bad:
    print("data: " + bad)
    sys.exit(1)
print("ok (%d bytes: a bare FIN at the payload's end completes byte-exact, "
      "and running past the granted ceiling is still 0x3)" % N)
