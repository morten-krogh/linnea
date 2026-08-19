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
# well over 3x the PTO (~27 ms here, so seconds is many times over). The kernel
# receive buffer fills, everything the server sends is dropped, and when reading
# resumes the acks reveal one long loss episode. That is precisely the RFC's
# condition.
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
# ---------------------------------------------------------------------------
# WHY THIS RETRIES, and what is NOT known.
#
# The provocation is unreliable under load: measured 2 failures in 4 loaded runs
# and 2 in 6, against 0 in ~25 idle ones. Three explanations were tested and ALL
# THREE ARE WRONG. They are recorded so nobody spends the afternoon again:
#
#   - "load inflates the PTO past the pause." No. Measured under CPU hogs on
#     this two-core box, the client PTO moved 0.027s -> 0.031s, so 3x PTO is
#     ~0.09s against a pause of seconds. The comment that used to sit here
#     asserted this and raised PAUSE 1.0 -> 3.0 on the strength of it, which
#     fixed nothing -- a wrong theory, written down confidently, that cost the
#     next person the same investigation.
#   - "the log is read before the line is flushed." No. Polled: when the marker
#     appears, it appears within ~5 ms of the transfer ending.
#   - "the server goes flow-control blocked and stops sending mid-pause." This
#     one is visible in a failing run's own trace -- fc=562100/1048576, aioquic
#     defaulting both windows to 1 MiB and raising them only as the application
#     READS, which this test deliberately stops doing. It looked certain.
#     Granting 64 MiB up front still failed 2 of 6 loaded runs, so it is at most
#     a contributing confounder. The grant is kept because it removes that
#     confounder from any future diagnosis, NOT because it fixed anything.
#
# So the root cause is undetermined, and the provocation is treated as what it
# demonstrably is: probabilistic. It is attempted up to three times.
#
# This does NOT weaken the assertion. The mechanism must still fire, and a
# server that genuinely stopped declaring persistent congestion fails every
# attempt and fails the check. Retrying costs time, and only in the failing
# case. What it buys is a deploy gate that is not a coin toss -- this check cost
# two full suite runs in a single day before it retried.
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
PAUSE = 3.0
ATTEMPTS = 3
# See the note above: this removes the flow-control confounder from the picture,
# it does not fix the flake. aioquic defaults both windows to 1 MiB.
CLIENT_FC = 64 * 1024 * 1024
# Insurance rather than a known race -- measured at ~5 ms -- because reading a
# log exactly once is the kind of thing that becomes a flake on other hardware.
MARKER_WAIT = 2.0


def attempt():
    """Provoke once. -> (fired, done, status, got, seconds, pto, closed)."""
    mark = os.path.getsize(LOG) if os.path.exists(LOG) else 0

    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
                            max_data=CLIENT_FC, max_stream_data=CLIENT_FC)
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
        sock.close()
        print("handshake failed")
        sys.exit(1)

    h3 = H3Connection(conn)
    sid = conn.get_next_available_stream_id()
    h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                          (b":authority", b"localhost"),
                          (b":path", PATH.encode())], end_stream=True)
    flush()

    status, got, done, paused, pto, closed = None, 0, False, False, 0.0, None
    t0 = time.time()
    dl = time.time() + 90
    while time.time() < dl and not done and closed is None:
        try:
            conn.receive_datagram(sock.recvfrom(2048)[0], ADDR, now=time.time())
        except socket.timeout:
            conn.handle_timer(now=time.time())
        while True:
            ev = conn.next_event()
            if ev is None:
                break
            if type(ev).__name__ == "ConnectionTerminated":
                # A close mid-provocation is a lost ATTEMPT, not a verdict --
                # retrying is the point, so this must not exit.
                closed = ev.error_code
                break
            for e in h3.handle_event(ev):
                if isinstance(e, HeadersReceived):
                    status = dict(e.headers).get(b":status", b"?").decode()
                    done = done or e.stream_ended
                elif isinstance(e, DataReceived):
                    got += len(e.data)
                    done = done or e.stream_ended
        if closed is not None:
            break
        flush()
        # Once some of it is moving, go deaf for a while. Nothing is read, so
        # the socket buffer fills and every packet after it is dropped. The PTO
        # is captured here, at the moment it matters, so a failure carries the
        # number rather than a theory about it.
        if not paused and got > 400000:
            paused = True
            pto = conn._loss.get_probe_timeout()
            time.sleep(PAUSE)
    sock.close()
    dt = time.time() - t0

    if not paused and closed is None:
        print("setup: never reached the pause, so nothing was provoked")
        sys.exit(1)

    fired = False
    deadline = time.time() + MARKER_WAIT
    while time.time() < deadline and closed is None:
        if os.path.exists(LOG):
            with open(LOG, "r", errors="replace") as f:
                f.seek(mark)
                if "persistent congestion" in f.read():
                    fired = True
                    break
        time.sleep(0.05)
    return fired, done, status, got, dt, pto, closed


created = not os.path.exists(TRIGGER)
if created:
    open(TRIGGER, "w").close()
time.sleep(1.3)                 # the sweep polls the trigger about once a second
try:
    tried, fired, done, status, got, dt, pto = [], False, False, None, 0, 0.0, 0.0
    for _ in range(ATTEMPTS):
        fired, done, status, got, dt, pto, closed = attempt()
        tried.append("closed:0x%x" % closed if closed is not None
                     else ("fired" if fired else "no"))
        if fired:
            break

    if not fired:
        print("the loss episode did not declare persistent congestion in %d "
              "attempts [%s] (%d bytes in %.1fs; pto %.3fs, so the RFC "
              "threshold was %.3fs against a %.1fs pause) -- either a dead path "
              "has nothing to answer it, or the provocation itself stopped "
              "working; ask first whether the server kept SENDING across the "
              "pause, which the qdbg log's fc= and cw= answer"
              % (ATTEMPTS, ", ".join(tried), got, dt, pto, 3 * pto, PAUSE))
        sys.exit(1)
    if not done:
        print("persistent congestion fired but the transfer never finished: "
              "%d bytes in %.1fs -- the floor should be recovered from, not "
              "stalled at" % (got, dt))
        sys.exit(1)
    if status != "200":
        print("status %s (want 200)" % status)
        sys.exit(1)
    print("ok (%s: a %.1fs deaf spell declared persistent congestion, and the "
          "transfer still finished: %d bytes in %.1fs, pto %.3fs)"
          % ("/".join(tried), PAUSE, got, dt, pto))
finally:
    if created:
        os.unlink(TRIGGER)
