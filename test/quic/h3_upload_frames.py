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
# WHAT IT ASSERTS IS A SIZE, NOT A TIME. On loopback the grant returns in
# microseconds, so the stall costs nothing and the upload looks perfect however
# small the window is -- the same blind spot that hid the h2 flow-control
# regression earlier the same day. Nor does the grant COUNT discriminate:
# measured identical (5 and 5) at both buffer sizes, because on loopback they
# coalesce the same way. What loopback CAN see is the smallest STEP the ceiling
# moves in, which IS the credit a client crosses a boundary on -- 32768 before,
# 131072 after.
#
# Usage: h3_upload_frames.py <host> <port> <frames> <frame-bytes> [--min-step N]
import hashlib, socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

host, port = sys.argv[1], int(sys.argv[2])
NFRAMES, FSIZE = int(sys.argv[3]), int(sys.argv[4])
argv = sys.argv[5:]
MAXG = int(argv[argv.index("--min-step") + 1]) if "--min-step" in argv else 0
ADDR = ("127.0.0.1", port)
body = bytes((i * 37 + 11) & 0xFF for i in range(FSIZE))
total = NFRAMES * FSIZE

cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
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
s.settimeout(0.02)


def flush():
    for d, _ in conn.datagrams_to_send(now=time.time()):
        s.sendto(d, ADDR)


flush()
dl = time.time() + 15
while not conn._handshake_confirmed and time.time() < dl:
    try:
        conn.receive_datagram(s.recvfrom(4096)[0], ADDR, now=time.time())
    except socket.timeout:
        pass
    flush()
if not conn._handshake_confirmed:
    print("handshake failed")
    sys.exit(2)

h3 = H3Connection(conn)
sid = conn.get_next_available_stream_id()
h3.send_headers(sid, [(b":method", b"POST"), (b":scheme", b"https"),
                      (b":authority", host.encode()), (b":path", b"/api/simple"),
                      (b"content-length", str(total).encode())], end_stream=False)
t0 = time.time()
status, done = None, False
end = time.time() + 120
for i in range(NFRAMES):
    h3.send_data(sid, body, end_stream=(i == NFRAMES - 1))   # one DATA frame each
    flush()
    # let credit come back before queueing the next frame
    while time.time() < end:
        try:
            conn.receive_datagram(s.recvfrom(4096)[0], ADDR, now=time.time())
        except socket.timeout:
            flush()
            break
        while True:
            ev = conn.next_event()
            if ev is None:
                break
            for e in h3.handle_event(ev):
                if isinstance(e, HeadersReceived):
                    status = dict(e.headers).get(b":status", b"?").decode()
                    done = done or e.stream_ended
                elif isinstance(e, DataReceived):
                    done = done or e.stream_ended
        flush()

while time.time() < end and not done:
    try:
        conn.receive_datagram(s.recvfrom(4096)[0], ADDR, now=time.time())
    except socket.timeout:
        flush()
        continue
    while True:
        ev = conn.next_event()
        if ev is None:
            break
        for e in h3.handle_event(ev):
            if isinstance(e, HeadersReceived):
                status = dict(e.headers).get(b":status", b"?").decode()
                done = done or e.stream_ended
            elif isinstance(e, DataReceived):
                done = done or e.stream_ended
    flush()
dt = time.time() - t0
s.close()

seq = sorted(set(ceilings))
steps = [b - a for a, b in zip(seq, seq[1:])]
smallest = min(steps) if steps else 0
msg = ("%d frames x %d bytes: status %s in %.2fs, %d grants, "
       "smallest ceiling step %d bytes"
       % (NFRAMES, FSIZE, status, dt, grants["stream"], smallest))
if status != "200":
    print(msg + "  (want 200)")
    sys.exit(1)
# --min-step is the assertion that matters: the runway at a frame boundary
if MAXG and smallest < MAXG:
    print(msg + "  -- under the %d byte floor" % MAXG)
    sys.exit(1)
print(msg)
