#!/usr/bin/env python3
# An upload in progress must survive other connections ending.
#
# A request whose body goes to a capture file holds that descriptor for as long
# as the request lasts. Tearing a connection down releases all of ITS reassembly
# contexts unconditionally -- which is right, because a context whose stream
# completed has already given its slot back and still holds a file -- and the
# release closes any descriptor the context has. "Has" was spelled != -1, but a
# connection slot is ZEROED when it is allocated, and zero is a perfectly good
# descriptor. So every connection that ended closed fd 0 once for each of the
# RA_CTXS contexts it never used.
#
# The worker closes stdin, so fd 0 is routinely the capture file of a request on
# a DIFFERENT connection. That upload's next write then failed with EBADF, and
# the client got a 413 naming no method and no path -- the request head had not
# been parsed yet, so there was nothing to name.
#
# Nothing exotic is needed to reach it: no loss, no misbehaving peer. One upload
# that spans a little time -- which is what an upload IS -- while other
# connections come and go, which is what a server does. It was found only
# because it made a neighbouring check flaky about one run in eight.
#
# The upload is held mid-payload across the churn by keeping its last datagrams
# in this process, so the capture file is open and half-written throughout. The
# echo is compared byte for byte: a descriptor pointing somewhere else could
# just as easily have succeeded and written the body into the wrong file.
#
# Usage: h3_capture_fd_test.py <port>
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)
# Past LINNEA_QUIC_RA_BUF (32768), so the body takes the capture-file path at
# all -- a smaller one never opens a descriptor for anything to steal.
N = 40000
BODY = bytes((i * 37 + 11) & 0xFF for i in range(N))
HOLD = 2


class Upload:
    """An upload with every byte framed and the last HOLD datagrams held back
    here, so the server's payload -- and its capture file -- stay open."""

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
        self.h3.send_data(self.sid, BODY, end_stream=True)    # ordinary FIN

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
            raise SystemExit("setup: nothing was held back, so the upload did not stay open")

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



# An upload whose capture file is OPEN and waiting (the tail is held), while
# other connections are opened and closed underneath it. Each teardown releases
# all RA_CTXS contexts, and an unused one whose spill_fd is still the zeroed 0
# closes fd 0 -- which is this upload's capture file.
CHURN = 6
u = Upload()
for _ in range(CHURN):
    c = QuicConnection(configuration=QuicConfiguration(
        is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE, server_name="localhost"))
    c.connect(ADDR, now=time.time())
    s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s2.settimeout(0.05)
    for d, _ in c.datagrams_to_send(now=time.time()):
        s2.sendto(d, ADDR)
    dl = time.time() + 3
    while not c._handshake_confirmed and time.time() < dl:
        try:
            c.receive_datagram(s2.recvfrom(2048)[0], ADDR, now=time.time())
        except socket.timeout:
            pass
        for d, _ in c.datagrams_to_send(now=time.time()):
            s2.sendto(d, ADDR)
    c.close()                       # make the server tear it down NOW
    for d, _ in c.datagrams_to_send(now=time.time()):
        s2.sendto(d, ADDR)
    s2.close()
    u.wait(0.05)

u.release()
dl = time.time() + 25
while time.time() < dl and not u.ended:
    closed = u.wait(0.2, until=lambda x: x.ended)
    if closed:
        print("closed: 0x%x" % closed[0]); sys.exit(1)
    u.emit()
u.sock.close()
if u.status != "200":
    print("status %s after %d connections came and went (want 200): the capture "
          "file was closed under the upload" % (u.status, CHURN))
    sys.exit(1)
if u.data != BODY:
    print("echoed %d of %d bytes and the content %s"
          % (len(u.data), N, "differs" if len(u.data) == N else "is short"))
    sys.exit(1)
print("ok (%d bytes byte-exact across %d connection teardowns)" % (N, CHURN))
