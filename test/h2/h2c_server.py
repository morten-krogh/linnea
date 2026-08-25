#!/usr/bin/env python3
"""A tiny, dependency-free HTTP/2 cleartext (h2c, prior-knowledge) server.

The box has no h2 server (nghttpd/nghttpx) and no Python h2 library, so this is
the test oracle for linnea's *backend* h2 client (Tier 1): it speaks just enough
correct h2 framing + a minimal HPACK codec to prove the client's wire — preface,
SETTINGS exchange, HEADERS/DATA both ways, flow control, PING/RST/GOAWAY — over
plaintext, decoupled from TLS (mirrors how openssl s_server proved the TLS
client). It is NOT a general h2 server: it decodes only the HPACK forms the
linnea client emits (static-index pseudo-headers, literal name-index / literal
name, raw string values; no Huffman, no dynamic table on requests).

Routes (by :path):
  /hello        -> 200, "hello from h2c\n"
  /echo         -> 200, body = the request body verbatim (round-trip integrity)
  /big?n=N      -> 200, body = 'B'*N  (spans many DATA frames / windows)
  /status/NNN   -> NNN, small body
  /trailers     -> 200 + DATA (no END_STREAM) + a response TRAILER section
  /trailers-frag-> the same, trailer split across HEADERS + CONTINUATION
  /trailers-noes-> MALFORMED: a trailer block with no END_STREAM, then DATA
  /interim      -> a 103 informational HEADERS block, then the final 200
  /interim-two  -> two informational blocks (103, 100), then the final 200
  /interim-late -> MALFORMED: a 1xx block AFTER the final response, then DATA
  /cont-first        -> MALFORMED: CONTINUATION with no header block open
  /cont-interleaved  -> MALFORMED: PING between HEADERS and its CONTINUATION
  /cont-data-between -> MALFORMED: DATA between HEADERS and its CONTINUATION
  /cont-wrong-stream -> MALFORMED: CONTINUATION on a different stream
  /ping-ok / -ack / -flag  -> a legal PING / ACK / unused-flag PING before the
                   response; the body reports what the client sent back
  /ping7 / -sid    -> MALFORMED: 7-octet PING, and a PING naming a stream
  /push            -> a PUSH_PROMISE after the client said ENABLE_PUSH 0
  /win-ok          -> legal WINDOW_UPDATEs, on the stream and the connection
  /win3 /win0 /win-sid /win-max -> MALFORMED: 3 octets, a zero increment, an
                   unrelated stream, and an increment past 2^31-1
  /set-ok          -> a legal later SETTINGS
  /set-sid /set-acklen /set-len5 /set-maxwin -> MALFORMED SETTINGS
  /set-push0 /set-mf-ok -> LEGAL values for known settings
  /set-push1 /set-push2 /set-mf-low /set-mf-high -> values outside 6.5.2's bounds
  /fsz-ok /fsz-big /fsz-hdr /fsz-split -> DATA of exactly 16384, of 16385,
                   an oversized HEADERS frame, and the same head split legally
                   across HEADERS + CONTINUATION (4.2 bounds each FRAME)
  /sid-hdr0 /sid-hdr3 /sid-data0 /sid-data3 -> a HEADERS or DATA frame on a
                   stream this leg never opened, before/inside a good response
  /term-rstok /term-rst3 /term-rst0 -> RST_STREAM: legal, short, stream 0
  /term-gook /term-goshort /term-gosid -> GOAWAY: legal, short, naming a stream
  /pad-ok          -> legal PADDED HEADERS and PADDED DATA
  /pad-h0 /pad-d0 /pad-over /prio-short -> MALFORMED padding / priority
  anything else -> 404

Usage: h2c_server.py <port> [mode]
  mode "smallwin"  advertise a 5-byte INITIAL_WINDOW_SIZE and dribble
                   WINDOW_UPDATEs, forcing the client's body sender to wait.
                   A stress rather than a realistic peer: at five bytes a frame
                   two BLOCKING peers deadlock on their socket buffers before
                   the protocol is at fault, so drive it from a client that
                   always reads.
  mode "throttle"  the same idea at 1024, which a real body can cross.
  mode "wdelta"    advertise 8192, let the client spend it, then LOWER
                   INITIAL_WINDOW_SIZE to 1024 granting nothing; the response
                   body reports how many bytes arrived afterwards (6.9.2).
  Modes are comma-separated: "tls,throttle" is both.
  mode "goaway"    send GOAWAY instead of a response (negative test).
  mode "rst"       send RST_STREAM instead of a response (negative test).
  mode "tls"       serve the same over TLS 1.3 with ALPN h2 (a proxy_h2 BACKEND;
                   it sends NewSessionTickets, which the backend leg must skip).
"""
import socket
import struct
import time
import sys

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# HPACK static table (RFC 7541 Appendix A), 1-indexed. (name, value).
STATIC = [
    (":authority", ""), (":method", "GET"), (":method", "POST"),
    (":path", "/"), (":path", "/index.html"), (":scheme", "http"),
    (":scheme", "https"), (":status", "200"), (":status", "204"),
    (":status", "206"), (":status", "304"), (":status", "400"),
    (":status", "404"), (":status", "500"), ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"), ("accept-language", ""),
    ("accept-ranges", ""), ("accept", ""), ("access-control-allow-origin", ""),
    ("age", ""), ("allow", ""), ("authorization", ""), ("cache-control", ""),
    ("content-disposition", ""), ("content-encoding", ""),
    ("content-language", ""), ("content-length", ""), ("content-location", ""),
    ("content-range", ""), ("content-type", ""), ("cookie", ""), ("date", ""),
    ("etag", ""), ("expect", ""), ("expires", ""), ("from", ""), ("host", ""),
    ("if-match", ""), ("if-modified-since", ""), ("if-none-match", ""),
    ("if-range", ""), ("if-unmodified-since", ""), ("last-modified", ""),
    ("link", ""), ("location", ""), ("max-forwards", ""),
    ("proxy-authenticate", ""), ("proxy-authorization", ""), ("range", ""),
    ("referer", ""), ("refresh", ""), ("retry-after", ""), ("server", ""),
    ("set-cookie", ""), ("strict-transport-security", ""),
    ("transfer-encoding", ""), ("user-agent", ""), ("vary", ""), ("via", ""),
    ("www-authenticate", ""),
]
STATUS_INDEX = {s[1]: i + 1 for i, s in enumerate(STATIC) if s[0] == ":status"}


def hpack_int(buf, pos, prefix):
    """Decode an HPACK integer with `prefix` bits at buf[pos]. -> (value, pos)."""
    mask = (1 << prefix) - 1
    val = buf[pos] & mask
    pos += 1
    if val < mask:
        return val, pos
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        val += (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            return val, pos


def hpack_str(buf, pos):
    """Decode an HPACK string literal (raw only; Huffman is rejected)."""
    huff = buf[pos] & 0x80
    length, pos = hpack_int(buf, pos, 7)
    s = buf[pos:pos + length]
    pos += length
    if huff:
        raise ValueError("Huffman-coded request string not supported by fixture")
    return s.decode("latin1"), pos


def hpack_decode(buf):
    """Decode a request header block into a list of (name, value). Handles the
    forms the linnea client emits: indexed (static), literal name-index /
    literal-name, without/never/incremental indexing, table-size update."""
    headers = []
    pos = 0
    n = len(buf)
    while pos < n:
        b = buf[pos]
        if b & 0x80:                          # 6.1 indexed
            idx, pos = hpack_int(buf, pos, 7)
            headers.append(STATIC[idx - 1])
        elif b & 0x40:                        # 6.2.1 literal, incremental index
            idx, pos = hpack_int(buf, pos, 6)
            name = STATIC[idx - 1][0] if idx else None
            if name is None:
                name, pos = hpack_str(buf, pos)
            val, pos = hpack_str(buf, pos)
            headers.append((name, val))
        elif b & 0x20:                        # 6.3 dynamic table size update
            _, pos = hpack_int(buf, pos, 5)
        else:                                 # 6.2.2/6.2.3 without/never index
            idx, pos = hpack_int(buf, pos, 4)
            name = STATIC[idx - 1][0] if idx else None
            if name is None:
                name, pos = hpack_str(buf, pos)
            val, pos = hpack_str(buf, pos)
            headers.append((name, val))
    return headers


def enc_int(val, prefix, first_bits):
    mask = (1 << prefix) - 1
    if val < mask:
        return bytes([first_bits | val])
    out = bytes([first_bits | mask])
    val -= mask
    while val >= 0x80:
        out += bytes([(val & 0x7F) | 0x80])
        val >>= 7
    return out + bytes([val])


def enc_str(s):
    b = s.encode("latin1")
    return enc_int(len(b), 7, 0x00) + b          # raw (H=0)


def enc_header(name, value, indexed=False):
    """Literal header, literal name + literal value. `indexed` = add to the
    dynamic table (exercises the client decoder's hpack_dyn_insert)."""
    first = 0x40 if indexed else 0x00
    prefix = 6 if indexed else 4
    return enc_int(0, prefix, first) + enc_str(name) + enc_str(value)


def enc_status(code):
    idx = STATUS_INDEX.get(str(code))
    if idx:
        return enc_int(idx, 7, 0x80)             # indexed static :status
    return enc_header(":status", str(code))      # literal :status


def frame(ftype, flags, sid, payload):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + \
        struct.pack(">I", sid) + payload


class Conn:
    def __init__(self, sock, mode):
        self.s = sock
        self.mode = mode
        self.modes = set(mode.split(","))
        self.lowered = False       # wdelta: the lowering SETTINGS has gone out
        self.after = 0             # ...and the DATA bytes that arrived after it
        self.buf = b""

    def recv_exact(self, n):
        while len(self.buf) < n:
            chunk = self.s.recv(65536)
            if not chunk:
                raise ConnectionError("peer closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def read_frame(self):
        hdr = self.recv_exact(9)
        length = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2]
        ftype, flags = hdr[3], hdr[4]
        sid = struct.unpack(">I", hdr[5:9])[0] & 0x7FFFFFFF
        payload = self.recv_exact(length) if length else b""
        return ftype, flags, sid, payload

    def send(self, data):
        self.s.sendall(data)


def serve_one(sock, mode):
    c = Conn(sock, mode)
    if c.recv_exact(len(PREFACE)) != PREFACE:
        return
    # our SETTINGS: a small INITIAL_WINDOW_SIZE in smallwin mode.
    # smallwin: 5, which is a stress of the client's body sender rather than a
    # realistic peer -- it makes one DATA frame per five bytes and two
    # WINDOW_UPDATEs per frame, and two blocking peers will deadlock on their
    # own socket buffers long before the protocol is at fault. throttle: 1024,
    # small enough that the sender must genuinely wait for credit and large
    # enough to carry a real body in reasonable time.
    modes = set(mode.split(","))
    init_win = 5 if "smallwin" in modes else (1024 if "throttle" in modes else 65535)
    if "wdelta" in modes:
        init_win = 8192
    c.send(frame(0x04, 0x00, 0, struct.pack(">HI", 0x04, init_win)))

    hdr_block = b""
    body = b""
    method = path = None
    end_stream = False
    got_headers = False
    while True:
        try:
            ftype, flags, sid, payload = c.read_frame()
        except OSError:
            # wdelta: the client has (correctly) stopped sending. Report how
            # much arrived after the lowering SETTINGS.
            if "wdelta" in c.modes and c.lowered:
                rb = ("AFTER=%d\n" % c.after).encode()
                blk = enc_status(200) + enc_header("content-type", "text/plain")
                blk += enc_header("content-length", str(len(rb)))
                c.send(frame(0x01, 0x04, 1, blk))
                c.send(frame(0x00, 0x01, 1, rb))
            return
        if ftype == 0x04:                         # SETTINGS
            if not (flags & 0x01):
                c.send(frame(0x04, 0x01, 0, b""))  # ACK
        elif ftype == 0x08:                       # WINDOW_UPDATE (ignore)
            pass
        elif ftype == 0x06:                       # PING
            if not (flags & 0x01):
                c.send(frame(0x06, 0x01, 0, payload))  # ACK
        elif ftype == 0x01:                       # HEADERS
            blk = payload
            if flags & 0x20:                      # PRIORITY present
                blk = blk[5:]
            hdr_block += blk
            got_headers = True
            if flags & 0x01:
                end_stream = True
            if flags & 0x04:                      # END_HEADERS
                hdrs = hpack_decode(hdr_block)
                d = dict(hdrs)
                method, path = d.get(":method"), d.get(":path")
        elif ftype == 0x00:                       # DATA
            if "wdelta" in c.modes:
                # RFC 9113 6.9.2: a change to INITIAL_WINDOW_SIZE adjusts every
                # open stream's CURRENT window by the DIFFERENCE. Let the client
                # spend its whole 8192, then lower the setting to 1024 and grant
                # NOTHING. Correct: 0 + (1024 - 8192) is negative, so not one
                # further byte may be sent, and the body says AFTER=0. Assigning
                # the new value outright instead says AFTER=1024; assigning a
                # correct delta but comparing windows unsigned says AFTER=21808,
                # which is how this fixture caught the second bug.
                if not c.lowered:
                    body += payload
                    if len(body) >= 8192:
                        c.send(frame(0x04, 0x00, 0,
                                     struct.pack(">HI", 0x04, 1024)))
                        c.lowered = True
                        c.s.settimeout(1.2)
                else:
                    c.after += len(payload)
                if flags & 0x01:
                    end_stream = True
                continue
            body += payload
            # grant the client more window as we drain (smallwin path)
            if payload:
                inc = len(payload)
                c.send(frame(0x08, 0x00, 0, struct.pack(">I", inc)))
                c.send(frame(0x08, 0x00, sid, struct.pack(">I", inc)))
            if flags & 0x01:
                end_stream = True
        elif ftype == 0x03:                       # RST_STREAM from client
            return
        elif ftype == 0x07:                       # GOAWAY
            return
        if got_headers and end_stream:
            respond(c, sid, method, path, body)
            # Drain until the client closes, so OUR close is a clean FIN. A real
            # h2 server keeps the connection open; closing here while the
            # client's SETTINGS-ACK sits unread would RST and lose the in-flight
            # response DATA before the client reads it.
            try:
                c.s.settimeout(3)
                while c.s.recv(4096):
                    pass
            except OSError:
                pass
            return


def respond(c, sid, method, path, body):
    if "goaway" in c.modes:
        c.send(frame(0x07, 0x00, 0, struct.pack(">II", 0, 0)))
        return
    if "rst" in c.modes:
        c.send(frame(0x03, 0x00, sid, struct.pack(">I", 8)))  # CANCEL
        return

    q = ""
    if path and "?" in path:
        path, q = path.split("?", 1)
    if path.startswith("/trailers"):
        respond_trailers(c, sid, path)
        return
    if path.startswith("/fsz"):
        respond_framesize(c, sid, path)
        return
    if path.startswith("/sid-"):
        respond_wrongstream(c, sid, path)
        return
    if path.startswith("/term"):
        respond_terminal(c, sid, path)
        return
    if path.startswith("/pad") or path == "/prio-short":
        respond_padded(c, sid, path)
        return
    if path.startswith("/set"):
        respond_settings(c, sid, path)
        return
    if path.startswith("/win"):
        respond_window(c, sid, path)
        return
    if path == "/push":
        respond_push(c, sid)
        return
    if path.startswith("/ping"):
        respond_ping(c, sid, path)
        return
    if path.startswith("/cont-"):
        respond_frames(c, sid, path)
        return
    if path.startswith("/interim") or path in ("/no-status", "/data-first"):
        respond_interim(c, sid, path)
        return
    status, rbody, ctype = route(path, q, body)

    block = enc_status(status)
    block += enc_header("content-type", ctype)
    block += enc_header("content-length", str(len(rbody)))
    # one dynamically-indexed header, to exercise the client's dyn-table insert
    block += enc_header("x-h2c-server", "linnea-fixture", indexed=True)
    c.send(frame(0x01, 0x04, sid, block))         # HEADERS, END_HEADERS

    # body in <=chunk-sized DATA frames; last carries END_STREAM. The client
    # advertises a large receive window, so the response is never throttled;
    # smallwin only throttles the client's upload (our small initial window).
    chunk = 16384
    if not rbody:
        c.send(frame(0x00, 0x01, sid, b""))
        return
    i = 0
    while i < len(rbody):
        piece = rbody[i:i + chunk]
        i += len(piece)
        last = i >= len(rbody)
        c.send(frame(0x00, 0x01 if last else 0x00, sid, piece))


def respond_trailers(c, sid, path):
    """A 200 whose body DATA does NOT end the stream, followed by a response
    TRAILER section (RFC 9113 8.1): a second HEADERS block carrying END_STREAM.
    /trailers-frag splits that trailer across HEADERS + CONTINUATION, so
    END_STREAM rides the HEADERS frame and END_HEADERS the CONTINUATION."""
    rbody = b"hello with trailers\n"
    block = enc_status(200)
    block += enc_header("content-type", "text/plain")
    block += enc_header("content-length", str(len(rbody)))
    block += enc_header("x-h2c-server", "linnea-fixture", indexed=True)
    c.send(frame(0x01, 0x04, sid, block))         # HEADERS, END_HEADERS only
    c.send(frame(0x00, 0x00, sid, rbody))         # DATA, NO END_STREAM

    tr = enc_header("x-checksum", "abc") + enc_header("grpc-status", "0")
    if path == "/trailers-cl":
        tr = enc_header("content-length", "5")
    elif path == "/trailers-status":
        tr = enc_status(500) + enc_header("x-checksum", "abc")
    if path == "/trailers-noes":
        # MALFORMED: a trailer section must carry END_STREAM (RFC 9113 8.1).
        # This one does not, and DATA follows it and ends the stream instead.
        c.send(frame(0x01, 0x04, sid, tr))        # HEADERS, END_HEADERS only
        c.send(frame(0x00, 0x01, sid, b"more"))   # DATA, END_STREAM
    elif path != "/trailers-frag":
        c.send(frame(0x01, 0x05, sid, tr))        # HEADERS, END_HEADERS|END_STREAM
    else:
        cut = len(tr) // 2
        c.send(frame(0x01, 0x01, sid, tr[:cut]))  # HEADERS, END_STREAM only
        c.send(frame(0x09, 0x04, sid, tr[cut:]))  # CONTINUATION, END_HEADERS


def respond_framesize(c, sid, path):
    """Frame size (RFC 9113 4.2). The client advertises no
    SETTINGS_MAX_FRAME_SIZE, so the protocol default of 16384 bounds every frame
    this backend may send. /fsz-ok sits exactly on the boundary and must relay;
    a byte more must not, and neither must an oversized HEADERS frame -- the
    limit is per FRAME, which is what CONTINUATION exists for, and /fsz-split
    is the control that says so: the same oversized head, legally framed."""
    blk = enc_status(200) + enc_header("content-type", "text/plain")
    if path == "/fsz-hdr":            # one HEADERS frame past the limit
        c.send(frame(0x01, 0x04, sid, blk + enc_header("x-pad", "z" * 20000)))
        c.send(frame(0x00, 0x01, sid, b"big-head\n"))
        return
    if path == "/fsz-split":          # the same head, legally split
        one = blk + enc_header("x-pad", "z" * 9000)
        two = enc_header("x-pad2", "z" * 9000)
        c.send(frame(0x01, 0x00, sid, one))     # no END_HEADERS
        c.send(frame(0x09, 0x04, sid, two))     # CONTINUATION, END_HEADERS
        c.send(frame(0x00, 0x01, sid, b"split-head\n"))
        return
    c.send(frame(0x01, 0x04, sid, blk))
    c.send(frame(0x00, 0x01, sid, b"U" * (16384 if path == "/fsz-ok" else 16385)))


def respond_wrongstream(c, sid, path):
    """Stream ownership (RFC 9113 6.1, 6.2). This leg is single-stream: the
    request went out on stream 1, so a HEADERS or DATA frame naming any other
    stream -- 0, or a stream we never opened -- cannot belong to this response.

    Every route here ends with a perfectly good stream-1 response. That is the
    point: before audit-report-53 the wrong-stream frames were skipped as though
    they had never arrived, so the exchange succeeded and nothing downstream
    could tell that the backend had sent them."""
    blk = enc_status(200) + enc_header("content-type", "text/plain")
    if path == "/sid-hdr0":           # a response head on stream 0
        c.send(frame(0x01, 0x04, 0, blk))
    elif path == "/sid-hdr3":         # a whole response on a stream we never opened
        c.send(frame(0x01, 0x04, 3, blk))
        c.send(frame(0x00, 0x01, 3, b"ignored\n"))
    elif path == "/sid-hdr3-dyn":
        # The same wrong-stream HEADERS, but its block INSERTS into the HPACK
        # dynamic table, and the stream-1 response that follows references the
        # inserted entry by index. HPACK state is per CONNECTION, so a block
        # that is skipped instead of decoded desynchronises every later block.
        c.send(frame(0x01, 0x04, 3,
                     blk + enc_header("x-ghost", "ghost", indexed=True)))
        c.send(frame(0x01, 0x04, sid, blk + enc_int(62, 7, 0x80)))
        c.send(frame(0x00, 0x01, sid, b"real\n"))
        return
    elif path == "/sid-dyn-ok":
        # The skew route with the wrong-stream frame REMOVED: the same two
        # insertions, all on stream 1, and the final head names BOTH of them.
        # 62 is the MOST RECENT insertion, so this must come back as
        # "x-b: bbb" then "x-a: aaa" -- the row that fails if a fix breaks
        # dynamic indexing rather than the stream check.
        c.send(frame(0x01, 0x04, sid, enc_status(100)
                     + enc_header("x-a", "aaa", indexed=True)
                     + enc_header("x-b", "bbb", indexed=True)))
        c.send(frame(0x01, 0x04, sid, blk
                     + enc_int(62, 7, 0x80) + enc_int(63, 7, 0x80)))
        c.send(frame(0x00, 0x01, sid, b"real\n"))
        return
    elif path == "/sid-hdr3-skew":
        # The same desync, arranged so the bad index lands INSIDE our table
        # instead of past its end. An informational 1xx inserts two entries, the
        # skipped stream-3 block inserts a third, and the final head then names
        # index 63. With that third insertion the backend means x-b: bbb; a
        # decoder that skipped it resolves 63 one slot early, to x-a: aaa, and
        # relays THAT under a clean 200. Same wire bytes, different header.
        c.send(frame(0x01, 0x04, sid, enc_status(100)
                     + enc_header("x-a", "aaa", indexed=True)
                     + enc_header("x-b", "bbb", indexed=True)))
        c.send(frame(0x01, 0x04, 3, enc_header("x-ghost", "ghost", indexed=True)))
        c.send(frame(0x01, 0x04, sid, blk + enc_int(63, 7, 0x80)))
        c.send(frame(0x00, 0x01, sid, b"real\n"))
        return
    elif path == "/sid-data0":        # body bytes on stream 0, mid-response
        c.send(frame(0x01, 0x04, sid, blk))
        c.send(frame(0x00, 0x00, 0, b"ignored\n"))
        c.send(frame(0x00, 0x01, sid, b"real\n"))
        return
    elif path == "/sid-data3":        # body bytes on another stream, mid-response
        c.send(frame(0x01, 0x04, sid, blk))
        c.send(frame(0x00, 0x00, 3, b"ignored\n"))
        c.send(frame(0x00, 0x01, sid, b"real\n"))
        return
    c.send(frame(0x01, 0x04, sid, blk))
    c.send(frame(0x00, 0x01, sid, b"real\n"))


def respond_terminal(c, sid, path):
    """RST_STREAM (6.4) and GOAWAY (6.8) instead of a response. Four octets on a
    nonzero stream; at least eight on stream 0.

    These do not discriminate the validation added for audit-report-51: a VALID
    reset already ends the exchange in a 502, so a malformed one did too, and
    both look identical from outside. They are here because backend terminal
    frames had no coverage at all -- nothing said a reset produces a gateway
    error rather than a hang."""
    if path == "/term-rstok":       # a legal reset
        c.send(frame(0x03, 0x00, sid, struct.pack(">I", 8)))
    elif path == "/term-rst3":      # three octets
        c.send(frame(0x03, 0x00, sid, b"\x00\x00\x00"))
    elif path == "/term-rst0":      # naming stream 0
        c.send(frame(0x03, 0x00, 0, struct.pack(">I", 8)))
    elif path == "/term-gook":      # a legal goaway
        c.send(frame(0x07, 0x00, 0, struct.pack(">II", 1, 0)))
    elif path == "/term-goshort":   # an empty payload
        c.send(frame(0x07, 0x00, 0, b""))
    elif path == "/term-gosid":     # naming a stream
        c.send(frame(0x07, 0x00, 1, struct.pack(">II", 0, 0)))


def respond_padded(c, sid, path):
    """PADDED and PRIORITY frames (RFC 9113 6.1, 6.2). A padded frame's payload
    STARTS with a Pad Length octet, so a padded frame with an empty payload is
    malformed -- and the octet must not be read before that is established.

    Note what these can and cannot show. All four malformed cases were already
    REFUSED before the ordering was fixed, because the append helpers reject the
    negative length that results. They are controls for the refusal, not
    evidence about the read. /pad-ok is the one that was genuinely uncovered:
    nothing exercised padded backend frames at all, so nothing said padding
    WORKS."""
    blk = enc_status(200) + enc_header("content-type", "text/plain")
    body = b"pad-body\n"
    if path == "/pad-ok":          # legal padding on both frames
        c.send(frame(0x01, 0x04 | 0x08, sid, b"\x04" + blk + b"\x00" * 4))
        c.send(frame(0x00, 0x01 | 0x08, sid, b"\x03" + body + b"\x00" * 3))
        return
    if path == "/pad-h0":          # PADDED HEADERS, empty payload
        c.send(frame(0x01, 0x04 | 0x08, sid, b""))
    elif path == "/pad-over":      # pad length past what remains
        c.send(frame(0x01, 0x04 | 0x08, sid, b"\x40" + blk))
    elif path == "/prio-short":    # PRIORITY set, payload shorter than 5
        c.send(frame(0x01, 0x04 | 0x20, sid, b"\x00\x00"))
    else:                          # /pad-d0: good head, then padded empty DATA
        c.send(frame(0x01, 0x04, sid, blk))
        c.send(frame(0x00, 0x01 | 0x08, sid, b""))
        return
    c.send(frame(0x00, 0x01, sid, body))


def respond_settings(c, sid, path):
    """SETTINGS structure (RFC 9113 6.5): a connection frame on stream 0, an ACK
    with no payload, a non-ACK payload that is a whole number of six-octet
    records, and INITIAL_WINDOW_SIZE within 2^31-1. /set-ok is the control: a
    perfectly legal later SETTINGS must still be applied and acknowledged."""
    if path == "/set-sid":        # naming a stream
        c.send(frame(0x04, 0x00, 1, struct.pack(">HI", 0x04, 65535)))
    elif path == "/set-acklen":   # an ACK carrying a payload
        c.send(frame(0x04, 0x01, 0, b"\x00"))
    elif path == "/set-len5":     # not a multiple of six
        c.send(frame(0x04, 0x00, 0, b"\x00\x04\x00\x00\x00"))
    elif path == "/set-maxwin":   # INITIAL_WINDOW_SIZE above 2^31-1
        c.send(frame(0x04, 0x00, 0, struct.pack(">HI", 0x04, 0xffffffff)))
    elif path == "/set-push2":     # ENABLE_PUSH = 2: not 0 or 1
        c.send(frame(0x04, 0x00, 0, struct.pack(">HI", 0x02, 2)))
    elif path == "/set-push1":     # ENABLE_PUSH = 1: a SERVER may not send this,
        c.send(frame(0x04, 0x00, 0, struct.pack(">HI", 0x02, 1)))  # and a client
    elif path == "/set-push0":     # must reject it. 0 is the only legal value
        c.send(frame(0x04, 0x00, 0, struct.pack(">HI", 0x02, 0)))  # from a server
    elif path == "/set-mf-low":    # MAX_FRAME_SIZE below 2^14
        c.send(frame(0x04, 0x00, 0, struct.pack(">HI", 0x05, 1)))
    elif path == "/set-mf-high":   # MAX_FRAME_SIZE above 2^24-1
        c.send(frame(0x04, 0x00, 0, struct.pack(">HI", 0x05, 16777216)))
    elif path == "/set-mf-ok":     # BOTH ends of the legal range -- 16777215 is
        c.send(frame(0x04, 0x00, 0, struct.pack(">HI", 0x05, 16384)))    # what
        c.send(frame(0x04, 0x00, 0, struct.pack(">HI", 0x05, 16777215)))  # nginx
    elif path == "/set-ok":                                               # sends

        c.send(frame(0x04, 0x00, 0, struct.pack(">HI", 0x04, 32768)))
    body = b"set-body\n"
    block = enc_status(200) + enc_header("content-type", "text/plain")
    block += enc_header("content-length", str(len(body)))
    c.send(frame(0x01, 0x04, sid, block))
    c.send(frame(0x00, 0x01, sid, body))


def respond_window(c, sid, path):
    """WINDOW_UPDATE framing and flow control (RFC 9113 6.9). Exactly four
    octets, a nonzero increment, stream 0 or the request stream, and a window
    that stays within 2^31-1. /win-ok is the control: legal updates, one on the
    stream and one on the connection, must still be applied and the response
    relayed."""
    if path == "/win3":         # three octets: FRAME_SIZE_ERROR
        c.send(frame(0x08, 0x00, sid, b"\x00\x00\x01"))
    elif path == "/win0":       # a zero increment: PROTOCOL_ERROR
        c.send(frame(0x08, 0x00, sid, struct.pack(">I", 0)))
    elif path == "/win-sid":    # an unrelated stream, credited to ours
        c.send(frame(0x08, 0x00, 3, struct.pack(">I", 1)))
    elif path == "/win-max":    # two of these put the window past 2^31-1
        c.send(frame(0x08, 0x00, sid, struct.pack(">I", 0x7fffffff)))
        c.send(frame(0x08, 0x00, sid, struct.pack(">I", 0x7fffffff)))
    elif path == "/win-ok":
        c.send(frame(0x08, 0x00, sid, struct.pack(">I", 1024)))
        c.send(frame(0x08, 0x00, 0, struct.pack(">I", 1024)))
    body = b"win-body\n"
    block = enc_status(200) + enc_header("content-type", "text/plain")
    block += enc_header("content-length", str(len(body)))
    c.send(frame(0x01, 0x04, sid, block))
    c.send(frame(0x00, 0x01, sid, body))


def respond_push(c, sid):
    """A PUSH_PROMISE after we advertised ENABLE_PUSH 0. RFC 9113 8.4 makes
    receiving one a connection error for an endpoint that disabled push, so the
    client must fail the exchange rather than quietly drop the promise."""
    c.send(frame(0x05, 0x04, sid,
                 struct.pack(">I", 2) + enc_header(":path", "/pushed")))
    block = enc_status(200) + enc_header("content-type", "text/plain")
    c.send(frame(0x01, 0x04, sid, block))
    c.send(frame(0x00, 0x01, sid, b"body\n"))


def respond_ping(c, sid, path):
    """A control frame before the response. RFC 9113 6.7: a PING is exactly 8
    octets on stream 0, an ACK is never answered, and 4.1 requires unused flag
    bits to be IGNORED rather than rejected.

    The PING goes out alone and the response follows a moment later, so the
    client parses it in a pass of its own -- otherwise the response completes in
    the same pass and a staged ACK never reaches the wire, which is exactly how
    an echo of out-of-frame bytes stays invisible.

    /ping-ok and /ping-ack assert what came BACK, not just that a response
    arrived: the body says whether the client answered as it should."""
    want_ack = False
    if path == "/ping7":         # one octet short: FRAME_SIZE_ERROR
        c.send(frame(0x06, 0x00, 0, b"1234567"))
    elif path == "/ping-sid":    # legal payload, illegal stream: PROTOCOL_ERROR
        c.send(frame(0x06, 0x00, 1, b"ABCDEFGH"))
    elif path == "/ping-flag":   # an unused flag bit: must be ignored, not refused
        c.send(frame(0x06, 0x08, 0, b"ABCDEFGH"))
        want_ack = True
    elif path == "/ping-ok":     # a legal PING: must be echoed with ACK
        c.send(frame(0x06, 0x00, 0, b"ABCDEFGH"))
        want_ack = True
    elif path == "/ping-ack":    # already an ACK: must NOT be answered
        c.send(frame(0x06, 0x01, 0, b"ABCDEFGH"))
    time.sleep(0.35)
    got = None
    c.s.settimeout(0.6)
    try:
        while True:
            h = c.recv_exact(9)
            ln = int.from_bytes(h[0:3], "big")
            pay = c.recv_exact(ln) if ln else b""
            if h[3] == 0x06 and (h[4] & 0x01):
                got = pay
                break
    except Exception:
        pass
    c.s.settimeout(15)
    if want_ack:
        body = b"PING-ACKED\n" if got == b"ABCDEFGH" else b"PING-NOACK\n"
    else:
        body = b"NO-REACK\n" if got is None else b"REACKED\n"
    block = enc_status(200) + enc_header("content-type", "text/plain")
    block += enc_header("content-length", str(len(body)))
    c.send(frame(0x01, 0x04, sid, block))
    c.send(frame(0x00, 0x01, sid, body))


def respond_frames(c, sid, path):
    """Malformed HEADER-BLOCK FRAMING (RFC 9113 6.10): a CONTINUATION must
    immediately follow a HEADERS/CONTINUATION whose block is still open, on the
    same stream, with no frame of any kind in between."""
    block = enc_status(200) + enc_header("content-type", "text/plain")
    if path == "/cont-first":
        # no open block at all: a CONTINUATION out of nowhere
        c.send(frame(0x09, 0x04, sid, block))     # CONTINUATION, END_HEADERS
        c.send(frame(0x00, 0x01, sid, b"body"))   # DATA, END_STREAM
        return
    cut = len(block) // 2
    if path == "/cont-interleaved":
        c.send(frame(0x01, 0x00, sid, block[:cut]))   # HEADERS, block left OPEN
        c.send(frame(0x06, 0x00, 0, b"12345678"))     # PING in between
        c.send(frame(0x09, 0x04, sid, block[cut:]))   # CONTINUATION, END_HEADERS
        c.send(frame(0x00, 0x01, sid, b"body"))
        return
    if path == "/cont-data-between":
        c.send(frame(0x01, 0x00, sid, block[:cut]))   # HEADERS, block left OPEN
        c.send(frame(0x00, 0x00, sid, b"mid"))        # DATA in between
        c.send(frame(0x09, 0x04, sid, block[cut:]))
        c.send(frame(0x00, 0x01, sid, b"body"))
        return
    if path == "/cont-wrong-stream":
        c.send(frame(0x01, 0x00, sid, block[:cut]))   # HEADERS on stream 1, OPEN
        c.send(frame(0x09, 0x04, sid + 2, block[cut:]))  # CONTINUATION elsewhere
        c.send(frame(0x00, 0x01, sid, b"body"))
        return


def respond_interim(c, sid, path):
    """An INFORMATIONAL response before the final one: RFC 9113 8.1 allows zero
    or more 1xx HEADERS blocks ahead of the single final response. Legal, common
    (103 Early Hints, 100 Continue), and a later HEADERS block that is NOT a
    trailer."""
    rbody = b"final after interim\n"
    if path == "/no-status":
        # MALFORMED: a response header section must carry :status.
        c.send(frame(0x01, 0x04, sid, enc_header("content-type", "text/plain")))
        c.send(frame(0x00, 0x01, sid, b"nostatus"))
        return
    if path == "/data-first":
        # MALFORMED: DATA before any response header block.
        c.send(frame(0x00, 0x00, sid, b"early"))
        block = enc_status(200) + enc_header("content-type", "text/plain")
        c.send(frame(0x01, 0x04, sid, block))
        c.send(frame(0x00, 0x01, sid, b"late"))
        return
    if path == "/interim-late":
        # MALFORMED: an informational response cannot follow the final response
        # it informs about, and a post-final block is a trailer section, which
        # may carry no pseudo-header at all.
        block = enc_status(200)
        block += enc_header("content-type", "text/plain")
        c.send(frame(0x01, 0x04, sid, block))     # the FINAL head, first
        c.send(frame(0x00, 0x00, sid, b"body"))   # DATA, no END_STREAM
        c.send(frame(0x01, 0x04, sid,             # a LATE 1xx: not legal here
                     enc_status(103) + enc_header("link", "</late>")))
        c.send(frame(0x00, 0x01, sid, b"more"))   # DATA, END_STREAM
        return
    c.send(frame(0x01, 0x04, sid, enc_status(103) + enc_header("link", "</s.css>")))
    if path == "/interim-two":
        c.send(frame(0x01, 0x04, sid, enc_status(100)))
    block = enc_status(200)
    block += enc_header("content-type", "text/plain")
    block += enc_header("content-length", str(len(rbody)))
    c.send(frame(0x01, 0x04, sid, block))         # the FINAL response head
    c.send(frame(0x00, 0x01, sid, rbody))         # DATA, END_STREAM


def route(path, q, body):
    if path == "/hello":
        return 200, b"hello from h2c\n", "text/plain"
    if path == "/echo":
        return 200, body, "application/octet-stream"
    if path == "/big":
        n = 100000
        for kv in q.split("&"):
            if kv.startswith("n="):
                n = int(kv[2:])
        return 200, b"B" * n, "application/octet-stream"
    if path and path.startswith("/status/"):
        try:
            code = int(path[len("/status/"):])
        except ValueError:
            code = 400
        return code, b"x\n", "text/plain"
    return 404, b"not found\n", "text/plain"


def main():
    port = int(sys.argv[1])
    # comma-separated, so "tls,throttle" can be both a TLS backend and a
    # flow-controlled one -- the combination the proxy_h2 upload path needs
    mode = sys.argv[2] if len(sys.argv) > 2 else ""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    # tiny window the smallwin body-writer chunks by
    Conn.win = 5
    # mode "tls": the same server behind TLS 1.3 with ALPN h2, so it can stand in
    # for a real h2 BACKEND behind a proxy_h2 location (which requires proxy_tls).
    # Python/OpenSSL also sends NewSessionTickets, which linnea's leg must skip.
    tls_ctx = None
    if "tls" in set(mode.split(",")):
        import os
        import ssl
        here = os.path.dirname(os.path.abspath(__file__))
        crt = os.environ.get("LINNEA_TEST_CRT", os.path.join(here, "..", "tls", "server.crt"))
        key = os.environ.get("LINNEA_TEST_KEY", os.path.join(here, "..", "tls", "server.key"))
        tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_ctx.load_cert_chain(crt, key)
        tls_ctx.set_alpn_protocols(["h2"])
    while True:
        conn, _ = srv.accept()
        conn.settimeout(15)
        try:
            if tls_ctx is not None:
                conn = tls_ctx.wrap_socket(conn, server_side=True)
            serve_one(conn, mode)
        except (ConnectionError, OSError, ValueError, IndexError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


if __name__ == "__main__":
    main()
