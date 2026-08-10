#!/usr/bin/env python3
# HTTP/2 multiplexing (M18): concurrent streams all make progress and complete,
# rapid-reset defense, and pool exhaustion. Exits 0 on success.
#
# This does NOT test interleaving, despite how the check below reads: at ~7 DATA
# frames per 100 KB stream, several streams show up in any 24-frame window
# whether they are interleaved or run one after another. What it does test is
# that no stream starves. The scheduling policy itself — sequential by default,
# interleaved when `i` is set, urgency first — is h2_priority.py.
# Usage: h2_multiplex.py <cafile> <port>   (server must serve /big.txt = 100000 B)
import ssl, socket, struct, sys

ca, port = sys.argv[1], int(sys.argv[2])


def connect():
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=15),
                        server_hostname="localhost")
    assert s.selected_alpn_protocol() == "h2", s.selected_alpn_protocol()
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(4, 0, 0))
    return s


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def estr(b):
    return bytes([len(b)]) + b          # non-Huffman literal string, len < 127


def hdr(n, v):
    return b"\x00" + estr(n.encode()) + estr(v.encode())   # literal name + value


def req(path):
    return (hdr(":method", "GET") + hdr(":scheme", "https")
            + hdr(":authority", "localhost") + hdr(":path", path))


def rd(s):
    h = b""
    while len(h) < 9:
        d = s.recv(9 - len(h))
        if not d:
            return None
        h += d
    ln = int.from_bytes(h[:3], "big")
    p = b""
    while len(p) < ln:
        d = s.recv(ln - len(p))
        if not d:
            break
        p += d
    return h[3], h[4], int.from_bytes(h[5:9], "big") & 0x7fffffff, p


def advertised_max_streams(s):
    """Read SETTINGS_MAX_CONCURRENT_STREAMS off the server's own SETTINGS.

    Taken from the wire rather than written here: this test used to assert a
    literal 16, so raising the pool turned a passing check into a failing one
    that was testing nothing but the old number. Asking the server means the
    ceiling and the test move together.
    """
    for _ in range(10):
        r = rd(s)
        if r is None:
            break
        if r[0] == 4 and not (r[1] & 0x01):        # SETTINGS, not the ACK
            for i in range(0, len(r[3]), 6):
                k, v = struct.unpack(">HI", r[3][i:i + 6])
                if k == 3:
                    return v
    raise AssertionError("server never sent MAX_CONCURRENT_STREAMS")


def test_concurrent():
    s = connect()
    ids = list(range(1, 13, 2))         # 6 concurrent streams
    for sid in ids:
        s.sendall(fr(1, 0x05, sid, req("/big.txt")))   # END_HEADERS|END_STREAM
    got = {i: 0 for i in ids}
    order = []
    done = set()
    while len(done) < len(ids):
        r = rd(s)
        if r is None:
            break
        t, fl, sid, p = r
        if t == 0 and sid in got:
            got[sid] += len(p)
            if p:
                order.append(sid)
                # replenish stream + connection windows so nothing stalls
                s.sendall(fr(8, 0, sid, struct.pack(">I", len(p))))
                s.sendall(fr(8, 0, 0, struct.pack(">I", len(p))))
            if fl & 1:
                done.add(sid)
        elif t == 7:
            break
    s.close()
    assert all(v == 100000 for v in got.values()), got
    assert len(set(order[:24])) > 1, "only one stream made progress: %r" % order[:24]


def test_rapid_reset():
    s = connect()
    goaway = False
    sid = 1
    for _ in range(260):
        s.sendall(fr(1, 0x04, sid, req("/hello.txt")))       # HEADERS, no END_STREAM
        s.sendall(fr(3, 0, sid, b"\x00\x00\x00\x08"))        # RST_STREAM CANCEL
        sid += 2
        s.settimeout(0.05)
        try:
            while True:
                r = rd(s)
                if r is None or r[0] == 7:
                    goaway = goaway or (r is not None and r[0] == 7)
                    break
        except socket.timeout:
            pass
        s.settimeout(15)
        if goaway:
            break
    s.close()
    assert goaway, "rapid reset did not draw a GOAWAY"


def test_pool_exhaustion():
    s = connect()
    limit = advertised_max_streams(s)
    s.sendall(fr(8, 0, 0, struct.pack(">I", 1 << 30)))
    n = limit + 6                       # comfortably over, whatever the limit is
    for i in range(n):
        s.sendall(fr(1, 0x05, 1 + 2 * i, req("/big.txt")))
    served, refused = set(), 0
    s.settimeout(4)
    try:
        for _ in range(5000):
            r = rd(s)
            if r is None:
                break
            if r[0] == 1:
                served.add(r[2])
            elif r[0] == 3:
                refused += 1
    except socket.timeout:
        pass
    s.close()
    assert len(served) <= limit, ("served %d, more than the advertised limit of %d"
                                  % (len(served), limit))
    assert refused >= 1, "excess streams were not refused"
    # and the pool really does go as wide as it claims — advertising a ceiling
    # the server cannot reach would be worse than the low one it replaced
    assert len(served) >= limit - 2, ("only %d of an advertised %d streams were "
                                      "served" % (len(served), limit))


test_concurrent()
test_rapid_reset()
test_pool_exhaustion()
print("ok")
