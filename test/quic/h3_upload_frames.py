#!/usr/bin/env python3
# A browser-shaped h3 upload: a body sent as several LARGE DATA frames.
#
# This is the shape a Chrome netlog showed for a 1 MB upload -- three frames of
# 371,712 bytes -- and it is the shape that stalls, because the stall lives at
# the frame BOUNDARY. Inside a payload the ceiling runs body_hi + RA_WINDOW, so
# a single-frame upload is never blocked and every earlier upload test in this
# suite is single-frame or small. Between frames the ceiling drops to
# base + RA_BUF, and a client whose bandwidth x RTT exceeds that stalls once per
# boundary. Chrome did, five times, for ~390 ms of a 3.1 s upload.
#
# WHAT IT ASSERTS IS THAT THE CLIENT NEVER BLOCKED, counted the same way the
# Chrome netlog that found this counted it: STREAM_DATA_BLOCKED frames the
# client felt the need to send. Five of those in one 1 MB upload is what the
# defect looked like from outside; zero is what the fix looks like.
#
# --rtt-ms IS WHAT MAKES IT VISIBLE, and without it this test proves nothing.
# The defect is a round-trip dependency: the client cannot be invited past a
# frame until the frame is complete, so it stops and waits for a grant. On
# loopback that grant returns in microseconds and the stall costs nothing -- both
# builds report zero blocked frames and finish in 0.1 s. Delaying the client's
# RECEIVE path by a few tens of milliseconds reproduces the real condition
# exactly, with no root and no netem, the same way h3_tail_loss.py injects loss
# rather than waiting for a network to supply it.
#
# Neither the grant count nor the ceiling's step size works as a signal: the
# counts are identical, and the step got SMALLER with the fix because the ceiling
# now advances during a payload instead of jumping at its end.
#
# Usage: h3_upload_frames.py <host> <port> <frames> <frame-bytes>
#            [--max-blocked N] [--rtt-ms N]
import hashlib, socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

host, port = sys.argv[1], int(sys.argv[2])
NFRAMES, FSIZE = int(sys.argv[3]), int(sys.argv[4])
argv = sys.argv[5:]
MAXG = int(argv[argv.index("--max-blocked") + 1]) if "--max-blocked" in argv else -1
RTT = float(argv[argv.index("--rtt-ms") + 1]) / 1000.0 if "--rtt-ms" in argv else 0.0
ADDR = ("127.0.0.1", port)
body = bytes((i * 37 + 11) & 0xFF for i in range(FSIZE))
total = NFRAMES * FSIZE

from aioquic.quic.logger import QuicLogger
logger = QuicLogger()
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"], quic_logger=logger)
cfg.server_name = host
cfg.verify_mode = ssl.CERT_NONE
conn = QuicConnection(configuration=cfg)

# Record the stream ceiling after every MAX_STREAM_DATA. The COUNT of grants
# does not discriminate -- measured identical at both buffer sizes -- because on
# loopback the grants coalesce the same way regardless. The STEP does: it is
# literally the credit a client is given to cross a frame boundary on, and a
# client whose bandwidth x RTT exceeds it stalls there.
#
# aioquic binds its frame handlers into a table in __init__, so assigning the
# method afterwards changes nothing the dispatcher reads; the table entry is
# what has to be wrapped.
ceilings = []
grants = {"stream": 0, "conn": 0}
tbl = conn._QuicConnection__frame_handlers
for code, key in ((0x11, "stream"), (0x10, "conn")):
    entry = list(tbl[code])
    inner = entry[0]

    def wrap(fn=inner, k=key):
        def f(*a, **kw):
            grants[k] += 1
            r = fn(*a, **kw)
            if k == "stream":
                for st in conn._streams.values():
                    if st.stream_id is not None and st.stream_id % 4 == 0:
                        ceilings.append(st.max_stream_data_remote)
            return r
        return f
    entry[0] = wrap()
    tbl[code] = tuple(entry)

conn.connect(ADDR, now=time.time())
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.002)

# Datagrams are held for RTT before the connection sees them, which is what a
# real return path does and a loopback one does not.
inflight = []
status = [None]
done = [False]
h3 = None


def pump():
    """One turn: collect, release what is due, drain events, send."""
    try:
        while True:
            inflight.append((time.time() + RTT, s.recvfrom(4096)[0]))
            if not RTT:
                break
    except (socket.timeout, BlockingIOError):
        pass
    now = time.time()
    while inflight and inflight[0][0] <= now:
        conn.receive_datagram(inflight.pop(0)[1], ADDR, now=now)
    while True:
        ev = conn.next_event()
        if ev is None:
            break
        if h3 is None:
            continue                      # still handshaking: nothing to decode
        for e in h3.handle_event(ev):
            if isinstance(e, HeadersReceived):
                status[0] = dict(e.headers).get(b":status", b"?").decode()
                done[0] = done[0] or e.stream_ended
            elif isinstance(e, DataReceived):
                done[0] = done[0] or e.stream_ended
    for d, _ in conn.datagrams_to_send(now=time.time()):
        s.sendto(d, ADDR)


dl = time.time() + 20
while not conn._handshake_confirmed and time.time() < dl:
    pump()
if not conn._handshake_confirmed:
    print("handshake failed")
    sys.exit(2)

globals()['h3'] = H3Connection(conn)
sid = conn.get_next_available_stream_id()
h3.send_headers(sid, [(b":method", b"POST"), (b":scheme", b"https"),
                      (b":authority", host.encode()), (b":path", b"/api/simple"),
                      (b"content-length", str(total).encode())], end_stream=False)
t0 = time.time()
end = time.time() + 180
# EVERY frame is queued up front, which is what a browser does: it hands the
# whole body to the transport and lets flow control set the pace. Feeding one
# frame at a time and draining each before queueing the next hides the defect
# completely -- the client then never has data waiting while it lacks credit, so
# it never blocks and never reports doing so, and every build measures the same.
# That is how the first version of this test came to pass against a server it
# was written to fail against.
for i in range(NFRAMES):
    h3.send_data(sid, body, end_stream=(i == NFRAMES - 1))   # one DATA frame each
while time.time() < end and not done[0]:
    pump()
dt = time.time() - t0
s.close()

conn.close()
blocked = 0
for trace in logger.to_dict().get("traces", []):
    for e in trace.get("events", []):
        d = e[3] if isinstance(e, list) and len(e) > 3 else (e.get("data", {}) if isinstance(e, dict) else {})
        for f in (d or {}).get("frames", []) or []:
            if "blocked" in str(f.get("frame_type", "")):
                blocked += 1
seq = sorted(set(ceilings))
steps = [b - a for a, b in zip(seq, seq[1:])]
smallest = min(steps) if steps else 0
msg = ("%d frames x %d bytes: status %s in %.2fs, %d grants, "
       "client blocked %d times (smallest ceiling step %d)"
       % (NFRAMES, FSIZE, status[0], dt, grants["stream"], blocked, smallest))
if status[0] != "200":
    print(msg + "  (want 200)")
    sys.exit(1)
# the assertion that matters: the client never had to say it was blocked
if MAXG >= 0 and blocked > MAXG:
    print(msg + "  -- over the %d blocked-frame bound" % MAXG)
    sys.exit(1)
print(msg)
