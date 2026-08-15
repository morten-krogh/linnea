#!/usr/bin/env python3
# A browser-shaped h3 upload: a body sent as several LARGE DATA frames.
#
# This is the shape a Chrome netlog showed for a 1 MB upload -- three frames of
# 371,712 bytes -- and it is the shape that stalls, because the stall lives at
# the frame BOUNDARY. Inside a payload the ceiling runs ahead of what has
# landed, so a single-frame upload is never blocked and every other upload check
# in this suite is single-frame or small.
#
# WHAT IS UNDER TEST IS WHERE THE CEILING STOPS RELATIVE TO A FRAME. A peer
# crossing a boundary needs credit for the next frame's header before it has
# finished sending the current frame's payload; if the ceiling stops at the
# payload's end it cannot have any, so it stops there and waits a round trip for
# the grant that follows the payload's last byte. Chrome said so five times in
# one 1 MB upload, as STREAM_DATA_BLOCKED, and sat idle ~390 ms of a 3.1 s
# upload.
#
# Two checks:
#
#   1. NO GRANTED CEILING MAY LAND ON A PAYLOAD'S END. This is the mechanism
#      itself and it is exact: the client knows every payload's stream offset
#      because it wrote them. It needs no timing, no bandwidth and no round
#      trip, so it says the same thing on a loaded box as on an idle one. It is
#      also the only one of the two that separates the builds: run against the
#      server before the fix it names every payload end, by offset.
#   2. the client never sent STREAM_DATA_BLOCKED -- the browser-visible symptom,
#      and the count a Chrome netlog gave when this was found.
#
# THERE IS DELIBERATELY NO TIMING ASSERTION, and this is the second time that
# conclusion has had to be reached here. It is not for want of trying:
#
#   - elapsed time on loopback says nothing, because a grant returns in
#     microseconds however small the window is;
#   - --rtt-ms holds the client's RECEIVE path back, the way h3_tail_loss.py
#     injects loss, and that does reproduce the round-trip dependency -- but
#     aioquic then paces its own sending at cwnd/rtt, and THAT, not our window,
#     is the limit: 0.9 MB/s either way, boundaries costing 4% of a run the
#     server was not driving;
#   - --fast-client lifts the congestion window and the pacer, which puts the
#     client at ~19 MB/s and makes the cost real. Both servers up at once, rtt
#     40ms, 4 MB each way:
#
#         1 frame  (0 boundaries)   before 0.208s   after 0.214s
#         3 frames (2 boundaries)   before 0.277s   after 0.193s
#         10 frames (9 boundaries)  before 0.931s   after 0.565s
#
#     But normalising that to round trips per boundary -- (multi - control) /
#     (rtt x boundaries), the unit the cost is actually paid in -- gave 1.4-2.6
#     after over five runs, against ~2.0-2.6 before. The ranges OVERLAP: the
#     control's own time swings 0.10-0.21s and it is in the numerator. No bound
#     drawn through that means anything, and one drawn wide enough to be safe
#     would pass anything.
#
# So --fast-client stays, because driving the boundary-crossing path at ~19 MB/s
# with real straddling frames is worth doing, and the checks above run over it.
# The timing is worth printing and is not worth asserting.
#
# Usage: h3_upload_frames.py <host> <port> <frames> <frame-bytes>
#            [--max-blocked N] [--rtt-ms N] [--fast-client] [--expect-borrow]
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.congestion.base import (QuicCongestionControl,
                                          register_congestion_control)
from aioquic.quic.logger import QuicLogger
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

host, port = sys.argv[1], int(sys.argv[2])
NFRAMES, FSIZE = int(sys.argv[3]), int(sys.argv[4])
argv = sys.argv[5:]
MAXG = int(argv[argv.index("--max-blocked") + 1]) if "--max-blocked" in argv else -1
RTT = float(argv[argv.index("--rtt-ms") + 1]) / 1000.0 if "--rtt-ms" in argv else 0.0
FAST = "--fast-client" in argv
BORROW = "--expect-borrow" in argv
ADDR = ("127.0.0.1", port)
body = bytes((i * 37 + 11) & 0xFF for i in range(FSIZE))

UNLIMITED = 1 << 30


class Unlimited(QuicCongestionControl):
    """No congestion limit: the server's flow control is then the only brake,
    which is the thing being measured. Paired with the pacer being switched off
    below -- leaving either one in place hides the boundary cost entirely."""

    def __init__(self, *, max_datagram_size):
        super().__init__(max_datagram_size=max_datagram_size)
        self.congestion_window = UNLIMITED

    def on_packet_acked(self, *, now, packet):
        self.congestion_window = UNLIMITED

    def on_packet_sent(self, *, packet):
        pass

    def on_packets_expired(self, *, packets):
        pass

    def on_packets_lost(self, *, now, packets):
        self.congestion_window = UNLIMITED

    def on_rtt_measurement(self, *, now, rtt):
        pass


register_congestion_control(
    "unlimited", lambda *, max_datagram_size: Unlimited(max_datagram_size=max_datagram_size))


def upload(nframes, fsize):
    """One request: nframes DATA frames of fsize bytes. Returns a dict."""
    logger = QuicLogger()
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"], quic_logger=logger)
    cfg.server_name = host
    cfg.verify_mode = ssl.CERT_NONE
    if FAST:
        cfg.congestion_control_algorithm = "unlimited"
    conn = QuicConnection(configuration=cfg)

    # Record the stream ceiling after every MAX_STREAM_DATA. aioquic binds its
    # frame handlers into a table in __init__, so assigning the method
    # afterwards changes nothing the dispatcher reads; the table entry is what
    # has to be wrapped.
    ceilings, grants = [], [0]
    tbl = conn._QuicConnection__frame_handlers
    entry = list(tbl[0x11])
    inner = entry[0]

    def wrap(fn=inner):
        def f(*a, **kw):
            grants[0] += 1
            r = fn(*a, **kw)
            for st in conn._streams.values():
                if st.stream_id is not None and st.stream_id % 4 == 0:
                    ceilings.append(st.max_stream_data_remote)
            return r
        return f
    entry[0] = wrap()
    tbl[0x11] = tuple(entry)

    conn.connect(ADDR, now=time.time())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if FAST:
        # An unpaced client outruns its OWN receive queue. At ~19 MB/s the
        # default 208 KB buffer overflows while this process is busy in the send
        # loop, and what it drops includes the server's response -- and then the
        # retransmits of it, for the same reason, so the upload hangs for ever
        # with the server's log already showing "200". That is a client fault
        # start to finish and it cost an hour of hunting it in the server, where
        # an independent client (curl/ngtcp2) had no trouble at all.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 << 20)
    s.settimeout(0.002)
    inflight, status, done, h3 = [], [None], [False], [None]

    def pump():
        """One turn: collect, release what is due, drain events, send."""
        # Drain the socket, always. Taking one datagram per turn was enough when
        # the client was paced, and hangs outright once it is not: at ~19 MB/s
        # the server's acks and grants arrive faster than one per turn, the
        # receive queue overflows, and the client stalls on losses it caused
        # itself. --fast-client alone hung here for 100s while --fast-client with
        # --rtt-ms finished in 0.6s, purely because the rtt path already drained.
        try:
            while True:
                inflight.append((time.time() + RTT, s.recvfrom(4096)[0]))
        except (socket.timeout, BlockingIOError):
            pass
        now = time.time()
        while inflight and inflight[0][0] <= now:
            conn.receive_datagram(inflight.pop(0)[1], ADDR, now=now)
        while True:
            ev = conn.next_event()
            if ev is None:
                break
            if h3[0] is None:
                continue                      # still handshaking: nothing to decode
            for e in h3[0].handle_event(ev):
                if isinstance(e, HeadersReceived):
                    status[0] = dict(e.headers).get(b":status", b"?").decode()
                    done[0] = done[0] or e.stream_ended
                elif isinstance(e, DataReceived):
                    done[0] = done[0] or e.stream_ended
        if FAST:
            # The pacer's rate is cwnd/rtt, so an unlimited window alone does not
            # unpace it: packet_time is still set and datagrams_to_send hands
            # over a bucket at a time. With this cleared the client reaches
            # ~19 MB/s under an injected RTT instead of ~0.9.
            conn._loss._pacer.packet_time = None
        for d, _ in conn.datagrams_to_send(now=time.time()):
            s.sendto(d, ADDR)

    dl = time.time() + 20
    while not conn._handshake_confirmed and time.time() < dl:
        pump()
    if not conn._handshake_confirmed:
        raise SystemExit("handshake failed")

    # The reassembly buffer, taken from the server rather than written here as a
    # constant. A frame SMALLER than this never opens a payload region at all --
    # it stays on the RAM path, where there is no boundary of the kind under
    # test -- so a test run below it would measure nothing and say so.
    window = conn._remote_max_stream_data_bidi_remote
    if fsize <= window and not BORROW:
        raise SystemExit("frame size %d does not exceed the server's stream window "
                         "%d, so no payload region opens and this tests nothing"
                         % (fsize, window))

    h3[0] = H3Connection(conn)
    sid = conn.get_next_available_stream_id()
    h3[0].send_headers(sid, [(b":method", b"POST"), (b":scheme", b"https"),
                             (b":authority", host.encode()), (b":path", b"/api/simple"),
                             (b"content-length", str(nframes * fsize).encode())],
                       end_stream=False)
    t0 = time.time()
    # EVERY frame is queued up front, which is what a browser does: it hands the
    # whole body to the transport and lets flow control set the pace. Feeding one
    # frame at a time and draining each before queueing the next hides the defect
    # completely -- the client then never has data waiting while it lacks credit,
    # so it never blocks and never reports doing so, and every build measures the
    # same. That is how the first version of this test came to pass against a
    # server it was written to fail against.
    #
    # _buffer_stop after each one is that payload's end as a stream offset, which
    # is the offset a ceiling must never stop on.
    ends = []
    sender = None
    for i in range(nframes):
        h3[0].send_data(sid, body[:fsize], end_stream=(i == nframes - 1))
        sender = sender or conn._streams[sid].sender
        ends.append(sender._buffer_stop)
    end = time.time() + 180
    while time.time() < end and not done[0]:
        pump()
    dt = time.time() - t0
    s.close()
    conn.close()

    blocked = 0
    for trace in logger.to_dict().get("traces", []):
        for e in trace.get("events", []):
            d = (e[3] if isinstance(e, list) and len(e) > 3
                 else (e.get("data", {}) if isinstance(e, dict) else {}))
            for f in (d or {}).get("frames", []) or []:
                if "blocked" in str(f.get("frame_type", "")):
                    blocked += 1
    return {"dt": dt, "status": status[0], "grants": grants[0], "blocked": blocked,
            "ceilings": ceilings, "ends": ends, "bytes": nframes * fsize,
            "window": window}


r = upload(NFRAMES, FSIZE)
msg = ("%d frames x %d bytes: status %s in %.2fs (%.2f MB/s), %d grants, "
       "client blocked %d times"
       % (NFRAMES, FSIZE, r["status"], r["dt"], r["bytes"] / r["dt"] / 1e6,
          r["grants"], r["blocked"]))
if r["status"] != "200":
    print(msg + "  (want 200)")
    sys.exit(1)

# 1. The mechanism. A ceiling that lands exactly on a payload's end is the
#    server saying "you may send this frame and not one byte more", which is
#    the stall: the peer cannot start the next frame until this one is whole
#    and a grant has come back for it.
stopped = sorted(set(r["ceilings"]) & set(r["ends"]))
if stopped:
    print(msg + "  -- %d grant(s) stopped ON a payload's end (%s): a peer given "
                "one of these cannot cross the boundary without waiting for the "
                "next grant" % (len(stopped), ", ".join(str(x) for x in stopped)))
    sys.exit(1)

# 2. A body must be given a REAL window however the peer chopped it up. The
#    server lends a big buffer for the duration of a body and grants half of
#    whatever buffer a stream holds, so a ceiling step wider than the advertised
#    initial window is proof the lend happened. A client whose frames are all
#    smaller than that window used to miss it entirely and be held to 16 KiB for
#    the whole upload -- 40 MB took 91 s in Firefox against 13.6 s in Chrome.
if BORROW:
    seq = sorted(set(r["ceilings"]))
    steps = [b - a for a, b in zip(seq, seq[1:])]
    widest = max(steps) if steps else 0
    msg += ", widest ceiling step %d against an advertised window of %d" % (
        widest, r["window"])
    if widest <= r["window"]:
        print(msg + "  -- the stream never got more than the window it started "
                    "with, so no buffer was lent to it")
        sys.exit(1)

# 3. The browser-visible symptom.
if MAXG >= 0 and r["blocked"] > MAXG:
    print(msg + "  -- over the %d blocked-frame bound" % MAXG)
    sys.exit(1)

print(msg)
