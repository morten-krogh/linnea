#!/usr/bin/env python3
# How a request stream ENDS, and what happens to one that never does.
#
# Both halves are about the same shift: a request stream is consumed as it
# arrives now, so the reassembly context is a resource with a lifetime rather
# than a buffer that is filled and then read.
#
#   * The FIN may arrive on a frame carrying no bytes at all -- a bare empty
#     STREAM frame, which is what a client that closes the stream separately
#     from writing to it sends. Completion is reached only by feeding the frame
#     walk, and the walk is fed only when the contiguous prefix GAINS bytes, so
#     such a request was buffered for ever: no response, no reset, nothing.
#     Browsers put the FIN on the last frame, which is why this hid.
#
#   * A context is held until its stream completes or faults. A client that
#     opens a request stream and walks away does neither, so RA_CTXS of them
#     took every context on the connection and every later multi-frame request
#     was dropped in silence. Single-frame GETs kept working -- they take a
#     copy-free path that needs no context -- which is what made it invisible.
#     An abandoned context is reclaimed once it has been silent long enough.
#
# Usage: h3_stream_end_test.py <port>
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived

PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)
# must exceed the server's LINNEA_QUIC_RA_STALE_MS
STALE_WAIT = 7.0
CONTEXTS = 6                      # LINNEA_QUIC_RA_CTXS
H3_REQUEST_REJECTED = 0x10b
HDRS = [(b":method", b"GET"), (b":scheme", b"https"),
        (b":authority", b"localhost"), (b":path", b"/hello.txt")]

bad = []


def want(label, cond, detail=""):
    if not cond:
        bad.append(f"{label}: {detail}")


class Peer:
    """One QUIC connection, driven by hand: these tests are about frames the
    h3 layer would not choose to send."""

    def __init__(self):
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
        cfg.verify_mode = ssl.CERT_NONE
        cfg.server_name = "localhost"
        self.conn = QuicConnection(configuration=cfg)
        self.vt = 0.0
        self.conn.connect(ADDR, now=self.clk())
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.settimeout(0.1)
        self.status = {}
        self.reset = {}                # stream id -> the code it was reset with
        self.reset_n = {}              # ...and how many times, which is the
                                       # question for a stream refused once
        self.h3 = None                # nothing to hand events to until ALPN
        self.pump()
        dl = time.time() + 10
        while not self.conn._handshake_confirmed and time.time() < dl:
            self.turn(1)
        assert self.conn._handshake_confirmed, "handshake failed"
        self.h3 = H3Connection(self.conn)

    def clk(self):
        self.vt += 0.001
        return self.vt

    def pump(self):
        for d, _ in self.conn.datagrams_to_send(now=self.clk()):
            self.s.sendto(d, ADDR)

    def turn(self, n=3):
        for _ in range(n):
            try:
                self.conn.receive_datagram(self.s.recvfrom(4096)[0], ADDR,
                                           now=self.clk())
            except socket.timeout:
                pass
            self.pump()
            self.drain()

    def drain(self):
        while True:
            ev = self.conn.next_event()
            if ev is None:
                return
            if type(ev).__name__ == "StreamReset":
                self.reset[ev.stream_id] = ev.error_code
                self.reset_n[ev.stream_id] = self.reset_n.get(ev.stream_id, 0) + 1
                continue
            if self.h3 is None:
                continue
            for e in self.h3.handle_event(ev):
                if isinstance(e, HeadersReceived):
                    self.status[e.stream_id] = \
                        dict(e.headers).get(b":status", b"?").decode()

    def await_status(self, sid, seconds=8):
        end = time.time() + seconds
        while time.time() < end and sid not in self.status:
            self.turn(4)
        return self.status.get(sid)

    def close(self):
        self.s.close()


# --- the FIN on a frame of its own ---------------------------------------
p = Peer()
sid = p.conn.get_next_available_stream_id()
p.h3.send_headers(sid, HDRS, end_stream=True)          # the ordinary shape
p.pump()
want("FIN on the HEADERS frame", p.await_status(sid) == "200",
     str(p.status.get(sid)))

sid = p.conn.get_next_available_stream_id()
p.h3.send_headers(sid, HDRS, end_stream=False)
p.pump()
p.turn(3)
p.conn.send_stream_data(sid, b"", end_stream=True)     # a bare empty FIN
p.pump()
want("FIN on an empty STREAM frame of its own", p.await_status(sid) == "200",
     str(p.status.get(sid)))
p.close()

# --- a context that is never given back ----------------------------------
p = Peer()
stalled = []
for _ in range(CONTEXTS):
    sid = p.conn.get_next_available_stream_id()
    stalled.append(sid)
    p.h3.send_headers(sid, HDRS, end_stream=False)     # ...and nothing more
    p.pump()
    p.turn(2)


def multi_frame_request(fin=True):
    """A request that needs a reassembly context: two STREAM frames, so it
    cannot take the whole-request-in-one-frame path."""
    sid = p.conn.get_next_available_stream_id()
    p.h3.send_headers(sid, HDRS, end_stream=False)
    p.pump()
    p.turn(3)
    p.h3.send_data(sid, b"" if fin else b"body", end_stream=fin)
    p.pump()
    return sid


# A single-frame GET is unaffected either way -- it needs no context, which is
# exactly why the starvation went unnoticed. Check it stays unaffected.
sid = p.conn.get_next_available_stream_id()
p.h3.send_headers(sid, HDRS, end_stream=True)
p.pump()
want("a single-frame GET is served while every context is held",
     p.await_status(sid) == "200", str(p.status.get(sid)))

# Every context is claimed and NONE is stale yet, so there is genuinely nowhere
# to put this request -- as there was before. What must not happen is the thing
# that used to: its frames dropped in silence, leaving the client on a stream
# that would never be answered. H3_REQUEST_REJECTED says nothing of it was
# processed and it may be retried, which is the truth and is actionable.
busy = multi_frame_request(fin=False)          # no FIN: more can follow it
end = time.time() + 6
while time.time() < end and busy not in p.reset and busy not in p.status:
    p.turn(4)
want("a request with every context busy is refused, not dropped",
     p.reset.get(busy) == H3_REQUEST_REJECTED,
     f"reset={p.reset.get(busy)} status={p.status.get(busy)}")
# ...once. The rest of a request is usually still in flight when it is refused,
# and each of its datagrams must not earn another RESET_STREAM. Counted for THIS
# stream rather than over all of them: an abandoned context going stale during
# these few seconds resets a different stream, and that is not this question.
for _ in range(5):
    p.conn.send_stream_data(busy, b"more", end_stream=False)
    p.pump()
    p.turn(3)
want("a refused stream is not refused again per datagram",
     p.reset_n.get(busy, 0) == 1, f"reset {p.reset_n.get(busy, 0)} times")

# ...and now let the abandoned ones go stale, with the connection kept alive.
end = time.time() + STALE_WAIT
ping = 0
while time.time() < end:
    ping += 1
    p.conn.send_ping(ping)
    p.pump()
    p.turn(4)

sid = multi_frame_request()
want("a multi-frame request once the abandoned contexts are stale",
     p.await_status(sid) == "200", str(p.status.get(sid)))
# ...and the client of the one that was taken back is told, rather than left
# holding a stream that will never be answered
reclaimed = set(p.reset) & set(stalled)
want("the reclaimed stream is reset", len(reclaimed) >= 1,
     f"{len(reclaimed)} of {CONTEXTS} reset")
p.close()

print("OK" if not bad else "; ".join(bad))
sys.exit(0 if not bad else 1)
