#!/usr/bin/env python3
# RFC 9002 7.6: a path that stops delivering for long enough is persistent
# congestion, and the window must go to its floor rather than merely halve.
#
# This exists because of what it replaces. The PTO resend used to call
# cc_on_loss — "a timeout is a congestion signal" — which 7.6.1 forbids in as
# many words, and which trapped a transfer: once cwnd reached its floor only
# two to four chunks were in flight, fewer than LOSS_THRESH, so ACK-based
# detection could no longer fire and every recovery came from a PTO, each of
# which halved the window again. Removing that left nothing at all to answer a
# genuinely dead path. This is what answers it now, so it has to be shown
# FIRING, not merely shown not to misfire.
#
# The provocation: read normally for a moment, then stop reading entirely for
# well over 3x the PTO (~26 ms here, so a second is many times over). The
# kernel receive buffer fills, everything the server sends is dropped, and when
# reading resumes the acks reveal one long loss episode. That is precisely the
# RFC's condition.
#
# Two assertions, because either alone is worth little:
#   - the server logged the persistent-congestion line, so the mechanism ran;
#   - the transfer still COMPLETED, byte-counted, so the response to it is a
#     recovery and not a stall. A window at the floor with ssthresh left above
#     it recovers in slow start; that is the difference between a pause and a
#     dead connection.
#
# Needs the qdbg trigger, which it creates and removes; the sweep re-reads it
# about once a second, hence the wait.
#
# Usage: h3_persistent_congestion_test.py <port> <path> <logfile>
import os, socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

PORT, PATH, LOG = int(sys.argv[1]), sys.argv[2], sys.argv[3]
ADDR = ("127.0.0.1", PORT)
# in the run's own directory, which is the server's working directory now:
# a shared trigger switched QUIC tracing on in a concurrent run's servers
TRIGGER = os.path.join(os.environ.get("LINNEA_TEST_RUNDIR", "."), "linnea-qdbg")
# Must be MUCH longer than 3x the PTO, which is the RFC's threshold. 1.0 was
# chosen against a PTO of ~78 ms measured on an idle machine, and that is the
# trap: the PTO is derived from RTT samples, so anything else running inflates
# it, and a second suite on this box pushed 3x PTO past a one-second pause --
# the episode then measured under the threshold and nothing was declared. The
# number wants headroom over a LOADED machine's PTO, not an idle one's; three
# seconds is still a fraction of the 90s budget this check runs under.
PAUSE = 3.0

created = not os.path.exists(TRIGGER)
if created:
    open(TRIGGER, "w").close()
time.sleep(1.3)                 # the sweep polls the trigger about once a second
try:
    mark = os.path.getsize(LOG) if os.path.exists(LOG) else 0

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
        print("handshake failed")
        sys.exit(1)

    h3 = H3Connection(conn)
    sid = conn.get_next_available_stream_id()
    h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                          (b":authority", b"localhost"),
                          (b":path", PATH.encode())], end_stream=True)
    flush()

    status, got, done, paused = None, 0, False, False
    t0 = time.time()
    dl = time.time() + 90
    while time.time() < dl and not done:
        try:
            conn.receive_datagram(sock.recvfrom(2048)[0], ADDR, now=time.time())
        except socket.timeout:
            conn.handle_timer(now=time.time())
        while True:
            ev = conn.next_event()
            if ev is None:
                break
            if type(ev).__name__ == "ConnectionTerminated":
                print("the server closed the connection: 0x%x" % ev.error_code)
                sys.exit(1)
            for e in h3.handle_event(ev):
                if isinstance(e, HeadersReceived):
                    status = dict(e.headers).get(b":status", b"?").decode()
                    done = done or e.stream_ended
                elif isinstance(e, DataReceived):
                    got += len(e.data)
                    done = done or e.stream_ended
        flush()
        # Once some of it is moving, go deaf for a while. Nothing is read, so
        # the socket buffer fills and every packet after it is dropped.
        if not paused and got > 400000:
            paused = True
            time.sleep(PAUSE)
    sock.close()
    dt = time.time() - t0

    tail = ""
    if os.path.exists(LOG):
        with open(LOG, "r", errors="replace") as f:
            f.seek(mark)
            tail = f.read()
    fired = "persistent congestion" in tail

    if not paused:
        print("setup: never reached the pause, so nothing was provoked")
        sys.exit(1)
    if not fired:
        print("the loss episode did not declare persistent congestion "
              "(%d bytes in %.1fs) -- a dead path now has nothing to answer it"
              % (got, dt))
        sys.exit(1)
    if not done:
        print("persistent congestion fired but the transfer never finished: "
              "%d bytes in %.1fs -- the floor should be recovered from, not "
              "stalled at" % (got, dt))
        sys.exit(1)
    if status != "200":
        print("status %s (want 200)" % status)
        sys.exit(1)
    print("ok (a %.1fs deaf spell declared persistent congestion, and the "
          "transfer still finished: %d bytes in %.1fs)" % (PAUSE, got, dt))
finally:
    if created:
        os.unlink(TRIGGER)
