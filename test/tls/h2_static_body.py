#!/usr/bin/env python3
"""A static location does not accept request content, over HTTP/2.

A static location serves a file. h2 never reads the content of one: a DATA frame
on a stream no proxy slot is collecting is credited to flow control and DROPPED.
Serving the file regardless therefore means discarding bytes the client
announced -- the request-smuggling shape RFC 9110 9.3.1 names -- and it also
left h2 the one protocol here that never noticed a content-length disagreeing
with its body. h3 reconciles the two before routing and h1 waits for the whole
declared body; h2 answers at the HEADERS frame and never counts what follows.

So the test h2 makes is on the DECLARATION and the FRAMING, both of which it
knows at the HEADERS frame: a nonzero content-length, or a HEADERS frame that
does not end the message. The second half matters -- testing only the
content-length would be bypassed by sending DATA without declaring one.

usage: h2_static_body.py <cafile> <port>
"""
import socket
import ssl
import struct
import sys

ca, port = sys.argv[1], int(sys.argv[2])
FT_DATA, FT_HEADERS, FT_RST, FT_SETTINGS = 0x0, 0x1, 0x3, 0x4
FLAG_END_STREAM, FLAG_END_HEADERS = 0x1, 0x4

STATIC = b"/hello.txt"
PROXIED = b"/api/echo"

fails = 0


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def estr(b):
    return bytes([len(b)]) + b


def hdr(n, v):
    return b"\x00" + estr(n) + estr(v)


def request(path, method=b"GET", declared=None, datas=None, budget=8.0):
    """One request on a fresh connection.

    `datas` is a list of DATA payloads, the last carrying END_STREAM; None puts
    END_STREAM on the HEADERS frame instead and sends no DATA at all.
    -> the :status seen, "RST" for a stream error, or "timeout".
    """
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                        server_hostname="localhost")
    assert s.selected_alpn_protocol() == "h2"
    block = (hdr(b":method", method) + hdr(b":scheme", b"https")
             + hdr(b":authority", b"localhost") + hdr(b":path", path))
    if declared is not None:
        block += hdr(b"content-length", str(declared).encode())
    if datas is None:
        wire = fr(FT_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, block)
    else:
        wire = fr(FT_HEADERS, FLAG_END_HEADERS, 1, block)
        for i, d in enumerate(datas):
            wire += fr(FT_DATA, FLAG_END_STREAM if i == len(datas) - 1 else 0, 1, d)
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(FT_SETTINGS, 0, 0) + wire)
    s.settimeout(budget)
    # Read to the END of the response, not to its HEADERS frame: the body
    # arrives in DATA frames after it, and stopping at the status would report
    # every response as bodiless -- which is exactly what the controls here are
    # meant to catch.
    buf, status, rst, body, done = b"", None, False, 0, False
    try:
        while not done and not rst:
            d = s.recv(65536)
            if not d:
                break
            buf += d
            while len(buf) >= 9:
                ln = int.from_bytes(buf[:3], "big")
                if len(buf) < 9 + ln:
                    break
                ftype, flags, payload = buf[3], buf[4], buf[9:9 + ln]
                buf = buf[9 + ln:]
                if ftype == FT_RST:
                    rst = True
                if ftype == FT_DATA:
                    body += len(payload)
                if ftype == FT_HEADERS:
                    # our encoder writes :status as a literal with an indexed
                    # name; the value is the first three digits in the block
                    for i in range(len(payload) - 2):
                        chunk = payload[i:i + 3]
                        if chunk.isdigit():
                            status = int(chunk)
                            break
                if ftype in (FT_DATA, FT_HEADERS) and flags & FLAG_END_STREAM:
                    done = True
    except (socket.timeout, OSError):
        pass
    s.close()
    if status is None:
        return ("RST" if rst else "timeout"), body
    return status, body


def check(name, ok, detail=""):
    global fails
    if ok:
        print(f"ok   {name}{detail}")
    else:
        print(f"FAIL {name}{detail}")
        fails += 1


# --- content on a static location is refused --------------------------------
REFUSED = [
    ("content-length: 5 with END_STREAM on the HEADERS frame", 5, None),
    ("content-length: 5 with a matching 5-byte DATA frame", 5, [b"XXXXX"]),
    ("content-length: 5 with a short 3-byte DATA frame", 5, [b"XXX"]),
    ("content-length: 5 with an over-long 9-byte DATA frame", 5, [b"XXXXXXXXX"]),
    ("DATA with no content-length declared at all", None, [b"XXXXX"]),
    ("a HEADERS frame that does not end the message", None, [b""]),
]
for name, declared, datas in REFUSED:
    st, _ = request(STATIC, declared=declared, datas=datas)
    check(f"static GET refused: {name}", st == 400, f" ({st})")

# --- controls: what a static location still serves ---------------------------
st, body = request(STATIC)
check("control: a plain static GET is served", st == 200 and body > 0,
      f" ({st}, {body} body bytes)")

st, body = request(STATIC, declared=0)
check("control: content-length 0 is not content", st == 200 and body > 0,
      f" ({st}, {body} body bytes)")

st, _ = request(STATIC, method=b"HEAD")
check("control: a plain static HEAD is served", st == 200, f" ({st})")

# A POST to a static path is a METHOD fault, and must still say so: answering
# 400 for it would report the wrong thing about the request.
st, _ = request(STATIC, method=b"POST", declared=5, datas=[b"XXXXX"])
check("control: a POST to a static path is still 405, not 400", st == 405, f" ({st})")

# The refusal is the STATIC location's, not the server's: a proxy location has a
# backend that may well define semantics for the content, and still takes it.
st, body = request(PROXIED, method=b"POST", declared=5, datas=[b"hello"])
check("control: a proxy location still takes a body", st == 200 and body == 5,
      f" ({st}, {body} body bytes)")

sys.exit(1 if fails else 0)
