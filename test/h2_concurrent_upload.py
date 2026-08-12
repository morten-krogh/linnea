#!/usr/bin/env python3
# Two large uploads running AT THE SAME TIME on ONE HTTP/2 connection.
#
# This exists because curl cannot express it: --parallel opens a second
# connection, so every "concurrent upload" test written with it silently
# measures two independent connections and proves nothing about the case that
# matters. The log gives it away — two "accepted connection" lines.
#
# The case matters because the streaming upload buffer is per CONNECTION. The
# first upload claims it and streams; a second one that genuinely overlaps it
# finds the claim held and falls back to the collecting path — which used to
# be capped at LINNEA_H2P_BODY_MAX (8 KiB) whatever max_body said, so the
# second of two simultaneous uploads was refused 413 at 8 KiB. It is captured
# to a file now, like h1 and h3, and runs to max_body.
#
# Both bodies are checked byte-exact, not just for a 200: the point of the
# capture is that what reaches the backend is what the client sent, and a
# capture written at the wrong offset would still answer 200.
#
# Deliberately hand-rolled: no h2 or httpx module on this box, and HPACK
# literal-without-indexing needs no table and no Huffman.
#
# Usage: h2_concurrent_upload.py <port> <size> [expect-status]
import hashlib
import socket
import ssl
import struct
import sys

PORT = int(sys.argv[1])
SIZE = int(sys.argv[2])
WANT = sys.argv[3] if len(sys.argv) > 3 else "200"

DATA, HEADERS, RST, SETTINGS, PING, GOAWAY, WINDOW_UPDATE = 0, 1, 3, 4, 6, 7, 8
END_STREAM, END_HEADERS = 0x1, 0x4


def hpack_literal(name, value):
    """Literal header field without indexing, new name — no table, no Huffman."""
    out = b"\x00" + bytes([len(name)]) + name + bytes([len(value)]) + value
    return out


def decode_status(payload):
    """The :status of a response HEADERS block — the first field, always.

    Linnea writes it as a literal with an indexed name: 0x08 is "literal
    without indexing, name = static index 8 (:status)", then a length-prefixed
    value. 0x88 is the fully-indexed form for 200, which a different server
    might use. Verified against what the server actually sends rather than
    assumed: b'\\x08\\x03200...'.
    """
    if not payload:
        return "none"
    b0 = payload[0]
    if b0 == 0x88:
        return "200"
    if b0 in (0x08, 0x48):
        if payload[1] & 0x80:                      # Huffman: not used here
            return "?huffman"
        ln = payload[1] & 0x7F
        return payload[2:2 + ln].decode("latin1")
    return "?0x%02x" % b0


def frame(typ, flags, sid, payload):
    return struct.pack(">I", len(payload))[1:] + bytes([typ, flags]) + \
        struct.pack(">I", sid) + payload


ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2"])
raw = socket.create_connection(("127.0.0.1", PORT), timeout=20)
s = ctx.wrap_socket(raw, server_hostname="localhost")
if s.selected_alpn_protocol() != "h2":
    print("server did not select h2")
    sys.exit(1)

s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
s.sendall(frame(SETTINGS, 0, 0, b""))
# a generous receive window of our own, so the responses are never the thing
# that stalls: connection-level, then per stream as each is opened
s.sendall(frame(WINDOW_UPDATE, 0, 0, struct.pack(">I", 1 << 24)))

body = bytes((i * 7 + 11) & 0xFF for i in range(SIZE))
want_md5 = hashlib.md5(body).hexdigest()

hdrs = (hpack_literal(b":method", b"POST") +
        hpack_literal(b":scheme", b"https") +
        hpack_literal(b":authority", b"localhost") +
        hpack_literal(b":path", b"/api/echo") +
        hpack_literal(b"content-length", str(SIZE).encode()))

STREAMS = [1, 3]
for sid in STREAMS:
    s.sendall(frame(HEADERS, END_HEADERS, sid, hdrs))
    s.sendall(frame(WINDOW_UPDATE, 0, sid, struct.pack(">I", 1 << 24)))

# Flow control: start from the protocol defaults and let the server's SETTINGS
# and WINDOW_UPDATEs move them. Sending past a window is a protocol error, and
# the server would be right to kill the connection for it.
conn_win = 65535
win = {sid: 65535 for sid in STREAMS}
sent = {sid: 0 for sid in STREAMS}
status = {}
got = {sid: b"" for sid in STREAMS}
done = set()
buf = b""
s.settimeout(30)


def pump(block):
    """Read whatever has arrived; return False on GOAWAY or a closed socket."""
    global buf, conn_win
    try:
        if not block:
            s.settimeout(0.05)
        chunk = s.recv(65536)
        if not chunk:
            return False
        buf += chunk
    except (socket.timeout, ssl.SSLWantReadError):
        return True
    finally:
        s.settimeout(30)
    while len(buf) >= 9:
        ln = int.from_bytes(buf[0:3], "big")
        if len(buf) < 9 + ln:
            break
        typ, flags = buf[3], buf[4]
        sid = struct.unpack(">I", buf[5:9])[0] & 0x7FFFFFFF
        payload = buf[9:9 + ln]
        buf = buf[9 + ln:]
        if typ == SETTINGS and not (flags & 0x1):
            for i in range(0, len(payload), 6):
                ident, val = struct.unpack(">HI", payload[i:i + 6])
                if ident == 0x4:                       # INITIAL_WINDOW_SIZE
                    for st in STREAMS:
                        win[st] = val - sent[st]
            s.sendall(frame(SETTINGS, 0x1, 0, b""))    # ACK
        elif typ == WINDOW_UPDATE:
            inc = struct.unpack(">I", payload)[0] & 0x7FFFFFFF
            if sid == 0:
                conn_win += inc
            elif sid in win:
                win[sid] += inc
        elif typ == HEADERS:
            status[sid] = decode_status(payload)
            if flags & END_STREAM:
                done.add(sid)
        elif typ == DATA:
            got[sid] += payload
            if len(payload):
                s.sendall(frame(WINDOW_UPDATE, 0, 0,
                                struct.pack(">I", len(payload))))
                s.sendall(frame(WINDOW_UPDATE, 0, sid,
                                struct.pack(">I", len(payload))))
            if flags & END_STREAM:
                done.add(sid)
        elif typ == RST:
            status.setdefault(sid, "RST")
            done.add(sid)
        elif typ == PING and not (flags & 0x1):
            s.sendall(frame(PING, 0x1, 0, payload))
        elif typ == GOAWAY:
            return False
    return True


# Interleave: one chunk to stream 1, one to stream 3, round and round, so the
# two bodies genuinely overlap rather than one finishing before the other opens.
CHUNK = 4096
alive = True
while alive and any(sent[sid] < SIZE for sid in STREAMS):
    progress = False
    for sid in STREAMS:
        if sent[sid] >= SIZE:
            continue
        n = min(CHUNK, SIZE - sent[sid], win[sid], conn_win)
        if n <= 0:
            continue
        end = END_STREAM if sent[sid] + n == SIZE else 0
        s.sendall(frame(DATA, end, sid, body[sent[sid]:sent[sid] + n]))
        sent[sid] += n
        win[sid] -= n
        conn_win -= n
        progress = True
    alive = pump(not progress)

deadline_reads = 0
while alive and len(done) < len(STREAMS) and deadline_reads < 4000:
    alive = pump(True)
    deadline_reads += 1

s.close()

bad = []
for sid in STREAMS:
    st = status.get(sid, "none")
    if st != WANT:
        bad.append("stream %d: status %s (want %s)" % (sid, st, WANT))
    elif WANT == "200":
        md5 = hashlib.md5(got[sid]).hexdigest()
        if md5 != want_md5:
            bad.append("stream %d: %d bytes back, not byte-exact"
                       % (sid, len(got[sid])))
if bad:
    print("; ".join(bad))
    sys.exit(1)
print("ok (two %d-byte uploads interleaved on one connection, both %s)"
      % (SIZE, WANT))
