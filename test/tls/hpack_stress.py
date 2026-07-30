#!/usr/bin/env python3
"""Hammer the HPACK dynamic table, as enabling it would.

We advertise SETTINGS_HEADER_TABLE_SIZE, and while that was 0 a conforming
encoder never inserted, so the table's machinery — the ring, eviction, the
entry-slot ceiling, the copy-out on reference — was carried but never exercised
by real traffic. Turning it on makes all of it load-bearing at once. This drives
it the way an encoder that uses its full allowance would, and harder:

  sizes       entries from 0 bytes to near the whole table, so eviction runs
              from "drop one" to "drop everything";
  slots       hundreds of minimum-size entries — a one-byte name and an empty
              value, 33 against the table's size — which is as close as anything
              legal gets to the 128-slot ceiling that .di_drop guards (4096/33 =
              124, so it stays out of reach);
  updates     dynamic table size updates that shrink the table to nothing and
              grow it back, evicting on the way down;
  readback    after every phase, a `range: bytes=0-4` marker is inserted and
              then referenced by dynamic index 62. A correct read applies the
              range and the response is a 206; any mis-store, mis-read or
              off-by-one in the index space leaves it a 200.

The connection must survive all of it: .di_drop is a COMPRESSION_ERROR, so a
GOAWAY here means the table refused an entry the peer's encoder had stored, and
enabling it would break real clients the same way.

usage: hpack_stress.py <cafile> <port>
"""
import random
import socket
import ssl
import struct
import sys

ca, port = sys.argv[1], int(sys.argv[2])
random.seed(11)


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def istr(n, prefix_bits, mask):
    """HPACK integer with a prefix, for lengths that exceed the prefix."""
    limit = (1 << prefix_bits) - 1
    if n < limit:
        return bytes([mask | n])
    out = bytes([mask | limit])
    n -= limit
    while n >= 128:
        out += bytes([(n & 0x7F) | 0x80])
        n >>= 7
    return out + bytes([n])


def lit(n, v):                      # literal, never indexed
    return b"\x00" + istr(len(n), 7, 0) + n + istr(len(v), 7, 0) + v


def lit_idx(n, v):                  # literal with incremental indexing: inserts
    return b"\x40" + istr(len(n), 7, 0) + n + istr(len(v), 7, 0) + v


def idx(i):
    return bytes([0x80 | i]) if i < 127 else b"\xff" + bytes([i - 127])


def tsize(n):                       # dynamic table size update
    return istr(n, 5, 0x20)


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


class Conn:
    def __init__(self):
        ctx = ssl.create_default_context(cafile=ca)
        ctx.check_hostname = False
        ctx.set_alpn_protocols(["h2"])
        self.s = ctx.wrap_socket(
            socket.create_connection(("127.0.0.1", port), timeout=15),
            server_hostname="localhost")
        self.s.settimeout(15)
        self.s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(4, 0, 0))
        self.sid = 1

    def send(self, block):
        self.s.sendall(fr(1, 0x05, self.sid, block))
        got = "no reply"
        for _ in range(16):
            r = rd(self.s)
            if r is None:
                got = "connection closed"
                break
            t, fl, rsid, p = r
            if t == 7:
                got = "GOAWAY err=%d" % int.from_bytes(p[4:8], "big")
                break
            if t == 3 and rsid == self.sid:
                got = "RST err=%d" % int.from_bytes(p[:4], "big")
                break
            if t == 1 and rsid == self.sid:
                got = next((c.decode() for c in (b"200", b"206", b"404") if c in p), "?")
                break
        self.sid += 2
        return got

    def close(self):
        self.s.close()


def entry(nbytes):
    """An insert occupying exactly nbytes of name+value.

    The floor is 1, not 0: a field name is a token and so never empty, which
    emit_field refuses (Q148). So the smallest entry the table can legally be
    given is a one-byte name with an empty value, costing 1 + 32 against the
    table's size — which puts the slot ceiling at 4096/33 = 124 entries, under
    the 128 slots, so the slot guard in .di_drop stays out of reach.
    """
    nbytes = max(1, nbytes)
    name = b"x" * max(1, nbytes // 2)
    return lit_idx(name, b"v" * (nbytes - len(name)))


fails = 0


def report(label, ok, detail):
    global fails
    print(f"{'ok  ' if ok else 'FAIL'} {label}: {detail}")
    fails += not ok


def readback(c, label):
    """Insert a marker, then reference it: a correct read gives a 206."""
    a = c.send(PSEUDO + lit_idx(b"range", b"bytes=0-4"))
    b = c.send(PSEUDO + idx(62))
    report(label, a in ("206", "200") and b == "206",
           f"insert -> {a}, reference index 62 -> {b} (want 206)")


# --- sizes: from the smallest legal entry to ones that fill the table -------
c = Conn()
bad = None
for i in range(400):
    n = random.choice([1, 2, 7, 31, 32, 63, 100, 200, 500, 1000, 2000, 4000])
    r = c.send(PSEUDO + entry(n))
    if r != "200":
        bad = f"entry of {n} bytes at step {i} -> {r}"
        break
report("400 entries from 1 to 4000 bytes", bad is None, bad or "all served")
readback(c, "readback after mixed sizes")
c.close()

# --- slots: minimum-size entries, the only way toward the 128-slot ceiling ---
c = Conn()
bad = None
for i in range(600):
    r = c.send(PSEUDO + entry(1))
    if r != "200":
        bad = f"minimum entry {i} -> {r}"
        break
report("600 minimum-size entries (the 128-slot ceiling)", bad is None,
       bad or "all served")
readback(c, "readback after filling the slots")
c.close()

# --- updates: shrink the table to nothing and grow it back ------------------
c = Conn()
bad = None
for i in range(120):
    blk = PSEUDO + entry(random.choice([40, 120, 900]))
    if i % 5 == 0:
        blk = tsize(random.choice([0, 256, 4096])) + blk
    r = c.send(blk)
    if r != "200":
        bad = f"step {i} -> {r}"
        break
report("size updates shrinking to 0 and back", bad is None, bad or "all served")
# a size update must precede the block, so end at the full size for the readback
c.send(tsize(4096) + PSEUDO)
readback(c, "readback after size updates")
c.close()

# --- churn: one long connection doing all of it ----------------------------
c = Conn()
bad = None
for i in range(500):
    blk = PSEUDO
    if i % 7 == 0:
        blk = tsize(4096) + blk
    blk += entry(random.randint(1, 300))
    if i % 3 == 0:
        blk += idx(62)                  # reference the newest as we go
    r = c.send(blk)
    if r not in ("200", "206"):
        bad = f"step {i} -> {r}"
        break
report("500 mixed operations on one connection", bad is None, bad or "all served")
readback(c, "readback after sustained churn")
c.close()

# --- the payoff: a fat header costs its bytes once, then one byte ----------
# This is what advertising the table buys. A browser's cookie is identical on
# every request of a page load; indexed, the second and later requests carry a
# single byte for it. The server must serve both forms identically.
c = Conn()
cookie = b"s=" + b"a" * 900
first = PSEUDO + lit_idx(b"cookie", cookie)          # literal: pays in full
later = PSEUDO + idx(62)                             # indexed: one byte
r1 = c.send(first)
r2 = c.send(later)
report("a fat header indexed on the next request is served the same",
       r1 == "200" and r2 == "200",
       f"literal ({len(first)} B block) -> {r1}, indexed ({len(later)} B block) -> {r2}; "
       f"the cookie costs {len(first) - len(later)} bytes fewer once indexed")
c.close()

if fails:
    sys.exit(1)
print("ok")
