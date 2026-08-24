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
  anything else -> 404

Usage: h2c_server.py <port> [mode]
  mode "smallwin"  advertise a tiny INITIAL_WINDOW_SIZE and dribble
                   WINDOW_UPDATEs, forcing the client's body sender to wait.
  mode "goaway"    send GOAWAY instead of a response (negative test).
  mode "rst"       send RST_STREAM instead of a response (negative test).
  mode "tls"       serve the same over TLS 1.3 with ALPN h2 (a proxy_h2 BACKEND;
                   it sends NewSessionTickets, which the backend leg must skip).
"""
import socket
import struct
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
    init_win = 5 if mode == "smallwin" else 65535
    c.send(frame(0x04, 0x00, 0, struct.pack(">HI", 0x04, init_win)))

    hdr_block = b""
    body = b""
    method = path = None
    end_stream = False
    got_headers = False
    while True:
        ftype, flags, sid, payload = c.read_frame()
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
    if c.mode == "goaway":
        c.send(frame(0x07, 0x00, 0, struct.pack(">II", 0, 0)))
        return
    if c.mode == "rst":
        c.send(frame(0x03, 0x00, sid, struct.pack(">I", 8)))  # CANCEL
        return

    q = ""
    if path and "?" in path:
        path, q = path.split("?", 1)
    if path.startswith("/trailers"):
        respond_trailers(c, sid, path)
        return
    if path.startswith("/interim"):
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


def respond_interim(c, sid, path):
    """An INFORMATIONAL response before the final one: RFC 9113 8.1 allows zero
    or more 1xx HEADERS blocks ahead of the single final response. Legal, common
    (103 Early Hints, 100 Continue), and a later HEADERS block that is NOT a
    trailer."""
    rbody = b"final after interim\n"
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
    if mode == "tls":
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
