#!/usr/bin/env python3
"""RFC 9218 response prioritisation over HTTP/2.

h2 parsed the request's `priority` field and then ignored it: concurrent
responses were round-robined regardless, so a request that asked to be served
first was not, and a default-priority request — which RFC 9218 says is
NON-incremental, i.e. "give me this one in full before the others" — was
interleaved with its peers anyway.

The scheduler now applies the same policy h3's pump does. Three things follow,
and each is checked here by watching the order DATA frames arrive in:

  sequential  with the default priority, concurrent responses complete in
              arrival order, one at a time. When the first finishes, the last
              has barely started.
  urgency     a request marked `u=0` jumps ahead of default-urgency peers even
              though it was asked for last.
  incremental `i` opts back in to sharing the window, so those streams do
              interleave — which is what the old scheduler did for everything.

Needs /big.txt (100000 B) in the document root.
usage: h2_priority.py <cafile> <port>
"""
import socket
import ssl
import struct
import sys

ca, port = sys.argv[1], int(sys.argv[2])
SIZE = 100000


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def lit(n, v):
    return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v


def rd(s):
    hd = b""
    while len(hd) < 9:
        d = s.recv(9 - len(hd))
        if not d:
            return None
        hd += d
    ln = int.from_bytes(hd[:3], "big")
    p = b""
    while len(p) < ln:
        d = s.recv(ln - len(p))
        if not d:
            break
        p += d
    return hd[3], hd[4], int.from_bytes(hd[5:9], "big") & 0x7fffffff, p


def connect():
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=20),
                        server_hostname="localhost")
    s.settimeout(20)
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(4, 0, 0))
    return s


def request(s, sid, priority=None):
    f = (lit(b":method", b"GET") + lit(b":scheme", b"https")
         + lit(b":authority", b"localhost") + lit(b":path", b"/big.txt"))
    if priority is not None:
        f += lit(b"priority", priority)
    s.sendall(fr(1, 0x05, sid, f))


def drive(order):
    """Ask for /big.txt on each (sid, priority), return the order streams FINISH
    and, at the moment the first finishes, how much each has received."""
    s = connect()
    sids = [sid for sid, _ in order]
    for sid, prio in order:
        request(s, sid, prio)
    got = {sid: 0 for sid in sids}
    done, snapshot = [], None
    while len(done) < len(sids):
        r = rd(s)
        if r is None:
            break
        t, fl, sid, p = r
        if t == 0 and sid in got:
            got[sid] += len(p)
            if p:
                # replenish both windows by what just arrived, so flow control
                # never becomes what decides the order
                s.sendall(fr(8, 0, sid, struct.pack(">I", len(p))))
                s.sendall(fr(8, 0, 0, struct.pack(">I", len(p))))
            if fl & 0x01 and sid not in done:
                if not done:
                    snapshot = dict(got)
                done.append(sid)
    s.close()
    return done, snapshot, got


fails = 0


def report(label, ok, detail):
    global fails
    print(f"{'ok  ' if ok else 'FAIL'} {label}: {detail}")
    fails += not ok


# --- 1: default priority is NOT incremental, so responses complete in order --
order, snap, got = drive([(1, None), (3, None), (5, None), (7, None)])
report("default priority completes in arrival order", order == [1, 3, 5, 7],
       f"finish order {order}")
report("all four arrived intact", all(v == SIZE for v in got.values()),
       f"{[got[k] for k in sorted(got)]}")
# when the first finished, the last should barely have started — that is what
# separates "one at a time" from "round-robin"
if snap:
    report("the last stream had barely started when the first finished",
           snap[7] * 4 < snap[1], f"stream 1 had {snap[1]}B, stream 7 had {snap[7]}B")

# --- 2: u=0 jumps the queue even though it was asked for last ----------------
order, _, got = drive([(1, None), (3, None), (5, b"u=0")])
report("a u=0 request served first though asked last", order[0] == 5,
       f"finish order {order}")
report("all three arrived intact", all(v == SIZE for v in got.values()),
       f"{[got[k] for k in sorted(got)]}")

# --- 3: i opts back in to sharing the window --------------------------------
# with every stream incremental they interleave, so when the first finishes the
# others are already well advanced — the opposite of case 1
order, snap, got = drive([(1, b"u=3, i"), (3, b"u=3, i"), (5, b"u=3, i")])
report("incremental streams share the window", all(v == SIZE for v in got.values()),
       f"finish order {order}, {[got[k] for k in sorted(got)]}")
if snap:
    report("an incremental peer was well advanced when the first finished",
           snap[5] * 4 > snap[1], f"stream 1 had {snap[1]}B, stream 5 had {snap[5]}B")

if fails:
    sys.exit(1)
print("ok")
