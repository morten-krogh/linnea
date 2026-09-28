#!/usr/bin/env python3
# Many long-lived proxied streams at once on ONE HTTP/2 connection.
#
# A browser shares one h2 connection per origin across all its tabs, and each
# Vefruna tab holds a server-sent-events stream (GET /events) for as long as it
# is open. So "how many proxied streams can one h2 connection relay at once" is
# "how many tabs work". It was 8 (LINNEA_H2P_SLOTS), while the server advertised
# SETTINGS_MAX_CONCURRENT_STREAMS 100: the ninth tab's stream was refused with
# REFUSED_STREAM. This opens N event streams on one connection -- the backend's
# /forever route, which never ends by itself -- and holds every one of them open
# until each has delivered an event, so the N were genuinely concurrent rather
# than served one after another. Then it resets them all and checks the
# connection still serves a request.
#
# curl cannot express this: --parallel caps at its own limit and still reads
# each response to its end. Hand-rolled for the same reasons as
# test/h2_concurrent_upload.py (no h2 module here; literal HPACK needs no table).
#
# Usage: h2_many_streams.py <port> <streams> <want-ok> <want-refused> [path]
#   want-ok       streams that must answer 200 and deliver an event
#   want-refused  streams that must be refused (REFUSED_STREAM, or a 503),
#                 cleanly: the connection lives on and serves a request after.
#                 "any" accepts any split so long as ok + refused == streams.
# Prints one "ok ..." line, or the failures, and exits non-zero on failure.
import socket
import ssl
import struct
import sys
import time

PORT = int(sys.argv[1])
N = int(sys.argv[2])
WANT_OK = sys.argv[3]
WANT_REFUSED = sys.argv[4]
PATH = (sys.argv[5] if len(sys.argv) > 5 else "/sse/forever?gap=0.3").encode()

DATA, HEADERS, RST, SETTINGS, PING, GOAWAY, WINDOW_UPDATE = 0, 1, 3, 4, 6, 7, 8
END_STREAM, END_HEADERS = 0x1, 0x4
REFUSED_STREAM = 7


def lit(name, value):
    return b"\x00" + bytes([len(name)]) + name + bytes([len(value)]) + value


def frame(typ, flags, sid, payload):
    return struct.pack(">I", len(payload))[1:] + bytes([typ, flags]) + \
        struct.pack(">I", sid) + payload


def decode_status(payload):
    # see test/h2_concurrent_upload.py: linnea writes :status first, as a
    # literal with an indexed name (0x08/0x48) or fully indexed (0x88 = 200)
    if not payload:
        return "none"
    b0 = payload[0]
    if b0 == 0x88:
        return "200"
    if b0 in (0x08, 0x48) and not payload[1] & 0x80:
        ln = payload[1] & 0x7F
        return payload[2:2 + ln].decode("latin1")
    return "?0x%02x" % b0


ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2"])
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", PORT), timeout=20),
                    server_hostname="localhost")
if s.selected_alpn_protocol() != "h2":
    print("not ok: server did not select h2")
    sys.exit(1)
s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(SETTINGS, 0, 0, b"") +
          frame(WINDOW_UPDATE, 0, 0, struct.pack(">I", 1 << 30)))

buf = b""
status, events, ended, rst = {}, {}, set(), {}
max_streams = None
goaway = False


def pump(timeout):
    """Read and dispatch frames for up to `timeout` seconds."""
    global buf, max_streams, goaway
    s.settimeout(timeout)
    try:
        chunk = s.recv(1 << 16)
    except (socket.timeout, ssl.SSLWantReadError):
        return True
    if not chunk:
        return False
    buf += chunk
    while len(buf) >= 9:
        ln = int.from_bytes(buf[0:3], "big")
        if len(buf) < 9 + ln:
            break
        typ, flags = buf[3], buf[4]
        sid = struct.unpack(">I", buf[5:9])[0] & 0x7FFFFFFF
        payload, buf = buf[9:9 + ln], buf[9 + ln:]
        if typ == SETTINGS and not flags & 1:
            for i in range(0, len(payload), 6):
                ident, val = struct.unpack(">HI", payload[i:i + 6])
                if ident == 3:
                    max_streams = val
            s.sendall(frame(SETTINGS, 1, 0, b""))
        elif typ == HEADERS:
            status[sid] = decode_status(payload)
            if flags & END_STREAM:
                ended.add(sid)
        elif typ == DATA:
            if b"data: event" in payload:
                events[sid] = events.get(sid, 0) + 1
            if payload:
                s.sendall(frame(WINDOW_UPDATE, 0, sid,
                                struct.pack(">I", len(payload))))
            if flags & END_STREAM:
                ended.add(sid)
        elif typ == RST:
            rst[sid] = struct.unpack(">I", payload)[0]
            ended.add(sid)
        elif typ == PING and not flags & 1:
            s.sendall(frame(PING, 1, 0, payload))
        elif typ == GOAWAY:
            goaway = True
            return False
    return True


def head(sid, path):
    return frame(HEADERS, END_STREAM | END_HEADERS, sid,
                 lit(b":method", b"GET") + lit(b":scheme", b"https") +
                 lit(b":authority", b"localhost") + lit(b":path", path))


# the server's SETTINGS first, so MAX_CONCURRENT_STREAMS is known
t0 = time.time()
while max_streams is None and time.time() - t0 < 5:
    if not pump(0.5):
        break
sids = [1 + 2 * i for i in range(N)]
s.sendall(b"".join(head(sid, PATH) for sid in sids))
for sid in sids:
    s.sendall(frame(WINDOW_UPDATE, 0, sid, struct.pack(">I", 1 << 20)))


def settled(sid):
    # delivered an event while still open, or refused/answered and ended
    return (sid in events and sid not in ended) or sid in ended


alive = True
deadline = time.time() + 30
while alive and time.time() < deadline and not all(settled(x) for x in sids):
    alive = pump(0.5)
ok = [x for x in sids if status.get(x) == "200" and x in events and x not in ended]
refused = [x for x in sids if rst.get(x) == REFUSED_STREAM or
           (status.get(x) == "503" and x in ended)]
other = [x for x in sids if x not in ok and x not in refused]

# every stream that got through is STILL open here -- that is the concurrency.
# Reset them all, then the connection must still serve a plain request.
for x in ok:
    s.sendall(frame(RST, 0, x, struct.pack(">I", 8)))       # CANCEL
# A reset stream whose upstream read is in flight keeps its backend connection
# (and its place under max_upstream) until that read completes, so right after
# the resets a probe may meet the ceiling and be answered 503: that is the
# ceiling working, not the connection failing. Try a few fresh streams.
probe = sids[-1]
probe_ok = False
for attempt in range(20):
    probe += 2
    s.sendall(head(probe, b"/sse/events?n=1&gap=0"))
    deadline = time.time() + 15
    while alive and time.time() < deadline and probe not in ended:
        alive = pump(0.5)
    probe_ok = status.get(probe) == "200" and probe in ended and probe not in rst
    if probe_ok or not alive or status.get(probe) != "503":
        break
    time.sleep(0.25)
s.close()

bad = []
if WANT_REFUSED == "any":
    if other:
        bad.append("%d streams neither served nor cleanly refused: %s" % (
            len(other), ", ".join("%d:%s/%s" % (x, status.get(x), rst.get(x))
                                  for x in other[:5])))
    if not ok:
        bad.append("no stream was served at all")
else:
    if len(ok) != int(WANT_OK):
        bad.append("%d streams served concurrently, want %s" % (len(ok), WANT_OK))
    if len(refused) != int(WANT_REFUSED):
        bad.append("%d refused, want %s" % (len(refused), WANT_REFUSED))
    if other:
        bad.append("%d other (first: %s)" % (len(other), ", ".join(
            "%d:%s/rst=%s" % (x, status.get(x), rst.get(x)) for x in other[:5])))
if goaway:
    bad.append("the server sent GOAWAY")
if not probe_ok:
    bad.append("the connection did not serve a request afterwards")
if bad:
    print("not ok: " + "; ".join(bad) + " (MAX_CONCURRENT_STREAMS %s)" % max_streams)
    sys.exit(1)
n_rst = sum(1 for x in refused if rst.get(x) == REFUSED_STREAM)
print("ok: %d of %d concurrent event streams on one h2 connection, %d refused "
      "cleanly (%d REFUSED_STREAM, %d 503), connection still serving "
      "(MAX_CONCURRENT_STREAMS %s)"
      % (len(ok), N, len(refused), n_rst, len(refused) - n_rst, max_streams))
