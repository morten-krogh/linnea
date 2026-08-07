#!/usr/bin/env python3
# A cancelled HTTP/3 request must let its upstream leg go, not run it to
# completion.
#
# Dropping the answer at delivery was always correct -- the generation check
# catches a connection that has gone -- but the leg kept a connection slot and
# an upstream socket for as long as the backend took to answer. A client that
# abandons a page's worth of requests held one of each per request, which is
# how a proxy runs out of the resources it was sized for while doing nothing.
#
# The observable is the ceiling itself. max_upstream is 1 in this fixture, so a
# single leg that has not been released blocks every later proxied request with
# a 503. The backend's /api/linger route sleeps 1.5s, which is the window: the
# request is cancelled at ~0.2s and the next one asked immediately after. Before
# the fix that answers 503; after it, 200.
#
# Both ways a stream can be cancelled are covered, because they reach the leg
# through different paths: RESET_STREAM/STOP_SENDING on one stream of a live
# connection, and a CONNECTION_CLOSE that takes the whole connection with it.
#
# Usage: h3_cancel_test.py <port>
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)


class Conn:
    """One QUIC connection, driven by hand so a request can be abandoned
    part-way rather than run to completion."""

    def __init__(self):
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
        cfg.verify_mode = ssl.CERT_NONE
        cfg.server_name = "localhost"
        self.q = QuicConnection(configuration=cfg)
        self.t = [0.0]
        self.q.connect(ADDR, now=self.clk())
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.settimeout(0.05)
        self.pump()
        dl = time.time() + 10
        while not self.q._handshake_confirmed and time.time() < dl:
            self.drain()
        self.h3 = H3Connection(self.q)

    def clk(self):
        self.t[0] += 0.001
        return self.t[0]

    def pump(self):
        for d, _ in self.q.datagrams_to_send(now=self.clk()):
            self.s.sendto(d, ADDR)

    def drain(self):
        try:
            self.q.receive_datagram(self.s.recvfrom(4096)[0], ADDR, now=self.clk())
        except socket.timeout:
            pass
        self.pump()

    def send(self, path):
        sid = self.q.get_next_available_stream_id()
        self.h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                                   (b":authority", b"localhost"),
                                   (b":path", path.encode())], end_stream=True)
        self.pump()
        return sid

    def answer(self, sid, seconds=8):
        """Wait for the response on one stream -> (status, body)."""
        status, body, done = None, b"", False
        end = time.time() + seconds
        while time.time() < end and not done:
            self.drain()
            while True:
                ev = self.q.next_event()
                if ev is None:
                    break
                for e in self.h3.handle_event(ev):
                    if isinstance(e, HeadersReceived) and e.stream_id == sid:
                        status = dict(e.headers).get(b":status", b"?").decode()
                        done = done or e.stream_ended
                    elif isinstance(e, DataReceived) and e.stream_id == sid:
                        body += e.data
                        done = done or e.stream_ended
        return status, body.decode(errors="replace")

    def close(self):
        self.q.close(error_code=0)
        self.pump()
        self.s.close()


bad = []


def want(label, cond, detail=""):
    if not cond:
        bad.append(f"{label}: {detail}")


# --- a cancelled STREAM on a connection that stays up ---------------------
c = Conn()
slow = c.send("/api/linger")
time.sleep(0.2)                      # the request is upstream by now
c.q.reset_stream(slow, 0x010c)       # H3_REQUEST_CANCELLED
c.q.stop_stream(slow, 0x010c)        # ...and STOP_SENDING: both reach the leg
c.pump()
time.sleep(0.2)                      # let the reap happen
st, body = c.answer(c.send("/api/simple"))
want("stream cancel frees the leg", st == "200",
     f"{st} {body[:40]!r} — the cancelled leg still held the only upstream slot")
c.close()

# --- a cancelled CONNECTION ------------------------------------------------
# Wait out the first linger so the ceiling starts clear either way; what is
# being measured is the SECOND one, not leftovers from the first.
time.sleep(1.6)
c1 = Conn()
c1.send("/api/linger")
time.sleep(0.2)
c1.close()                           # CONNECTION_CLOSE: the stream is gone
time.sleep(0.2)
c2 = Conn()
st, body = c2.answer(c2.send("/api/simple"))
want("connection close frees the leg", st == "200",
     f"{st} {body[:40]!r} — the abandoned connection's leg still held the slot")
c2.close()

# --- and the ceiling still bites when it should ---------------------------
# A leg nobody cancelled must still hold its slot: a fix that simply released
# every leg early, or never counted them, would pass the two checks above.
time.sleep(1.6)
c3 = Conn()
c3.send("/api/linger")               # left running on purpose
time.sleep(0.3)
c4 = Conn()
st, body = c4.answer(c4.send("/api/simple"), seconds=3)
want("an uncancelled leg still holds its slot", st == "503",
     f"{st} — max_upstream is 1 and a request is genuinely in flight")
c3.close()
c4.close()

print("OK" if not bad else "; ".join(bad))
sys.exit(0 if not bad else 1)
