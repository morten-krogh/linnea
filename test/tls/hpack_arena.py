#!/usr/bin/env python3
"""The HPACK arena: an entry must be stored wherever the ring cursor lands.

The arena was a bump allocator that reclaimed space only when the table emptied
completely. MEASURED consequence, with the cursor near the end of the arena: an
entry the peer's encoder DID store was silently not stored by us, and the
connection carried on — so our table sat one entry behind the peer's and every
later dynamic index resolved to the wrong header. Same desync class as Q152,
arriving from the allocator instead of the decode path, and just as quiet.

(I had expected the old allocator to kill the connection instead, via the
"arena exhausted" branch. It does not, at any fill level tested — hence the
churn case below passes on both. The silent mis-store is the real defect.)

Two things are checked, both against a peer that ignores our advertised
SETTINGS_HEADER_TABLE_SIZE = 0 and inserts anyway:

  churn  far more bytes than the arena holds, over one connection. A guard
         against the ring regressing into refusing entries; it passed before
         this change too, so it demonstrates nothing on its own.

  wrap   an entry placed so it STRADDLES the end of the ring, then read back by
         dynamic index. The cursor advances by the bytes inserted, so filling
         exactly K bytes puts the next entry at offset K. The entry is
         `range: bytes=0-4`, so a correct read turns the response into a 206
         and a mis-stored or mis-read one leaves it a 200. Against the previous
         commit, K = 4090 and K = 4095 both come back 200.

usage: hpack_arena.py <cafile> <port>
"""
import socket
import ssl
import struct
import sys

ca, port = sys.argv[1], int(sys.argv[2])
CAP = 4096                      # LINNEA_HPACK_DYN_CAP


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def lit(n, v):                  # literal, never indexed: no table effect
    return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v


def lit_idx(n, v):              # literal with incremental indexing: inserts
    return b"\x40" + bytes([len(n)]) + n + bytes([len(v)]) + v


def idx(i):                     # indexed field line
    return bytes([0x80 | i])


PSEUDO = (lit(b":method", b"GET") + lit(b":scheme", b"https")
          + lit(b":authority", b"localhost") + lit(b":path", b"/hello.txt"))


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
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=8),
                        server_hostname="localhost")
    s.settimeout(8)
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(4, 0, 0))
    return s


def outcome(s, sid):
    """What the server did with that stream: a status, a reset, or a GOAWAY."""
    for _ in range(16):
        r = rd(s)
        if r is None:
            return "connection closed"
        t, fl, rsid, p = r
        if t == 7:
            return "GOAWAY err=%d" % int.from_bytes(p[4:8], "big")
        if t == 3 and rsid == sid:
            return "RST err=%d" % int.from_bytes(p[:4], "big")
        if t == 1 and rsid == sid:
            for c in (b"200", b"206", b"400", b"404", b"431"):
                if c in p:
                    return c.decode()
            return "?"
    return "no reply"


def filler(nbytes):
    """One insert occupying exactly nbytes of arena (name + value)."""
    assert 8 <= nbytes <= 200
    name = b"x-f" + b"a" * (nbytes // 2 - 3)
    value = b"v" * (nbytes - len(name))
    return lit_idx(name, value), len(name) + len(value)


fails = 0


def report(label, ok, detail):
    global fails
    print(f"{'ok  ' if ok else 'FAIL'} {label}: {detail}")
    fails += not ok


# --- churn: many times the arena, over one connection ------------------------
s = connect()
sid = 1
served = 0
verdict = "ok"
total = 0
for i in range(120):
    body, n = filler(40 + (i % 60))
    total += n
    s.sendall(fr(1, 0x05, sid, PSEUDO + body))
    r = outcome(s, sid)
    if r != "200":
        verdict = f"stream {sid} after {total} bytes -> {r}"
        break
    served += 1
    sid += 2
s.close()
report("sustained insertion survives the arena wrapping",
       verdict == "ok",
       f"{served} requests, {total} bytes through a {CAP}-byte arena "
       f"({total / CAP:.1f}x)" if verdict == "ok" else verdict)


# --- wrap: an entry straddling the end of the ring, read back by index -------
# The cursor advances by the bytes inserted, so K bytes of filler put the next
# entry at offset K. 'range' + 'bytes=0-4' is 14 bytes: at 4090 it straddles.
MARKER_BYTES = len(b"range") + len(b"bytes=0-4")
for label, start in (("mid-arena (control)", 1000),
                     ("straddling the wrap", CAP - 6),
                     ("one byte before the end", CAP - 1),
                     ("exactly at the end", CAP - MARKER_BYTES)):
    s = connect()
    sid = 1
    # fill exactly `start` bytes, in chunks the encoder can express simply
    left = start
    while left:
        n = min(left, 200)
        if left - n and left - n < 8:      # never leave an unencodable remainder
            n -= 8
        body, got = filler(n)
        s.sendall(fr(1, 0x05, sid, PSEUDO + body))
        if outcome(s, sid) != "200":
            break
        left -= got
        sid += 2
    # place the marker: it is the newest entry, so dynamic index 62
    s.sendall(fr(1, 0x05, sid, PSEUDO + lit_idx(b"range", b"bytes=0-4")))
    pre = outcome(s, sid)
    sid += 2
    # and read it back: a correct read applies the range and yields a 206
    s.sendall(fr(1, 0x05, sid, PSEUDO + idx(62)))
    got = outcome(s, sid)
    s.close()
    report(f"entry {label} reads back byte-exact", got == "206",
           f"insert -> {pre}, reference index 62 -> {got} (want 206)")

if fails:
    sys.exit(1)
print("ok")
