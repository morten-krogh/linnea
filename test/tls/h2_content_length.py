#!/usr/bin/env python3
"""content-length must equal the DATA actually sent (RFC 9113 8.1.1).

    "A request or response that is defined as having content when it has a
     Content-Length header field that does not equal the sum of the DATA frame
     payload lengths ... is malformed."

Two halves, and only one was checked. A body that OVERRAN the declared length
was already refused. A body that stopped SHORT was not noticed at all: the
streaming path never looked at END_STREAM, so the request simply never
completed — it sat holding an upstream slot until the body clock timed it out at
408, several seconds later, reporting a timeout for what was a framing fault the
server could see immediately. The collecting path did not know the declared
length at all: it measured what arrived and forwarded that, quietly rewriting
the client's own framing on the way to the backend.

usage: h2_content_length.py <cafile> <port>
"""
import socket
import ssl
import struct
import sys
import time

ca, port = sys.argv[1], int(sys.argv[2])
FT_DATA, FT_HEADERS, FT_SETTINGS = 0x0, 0x1, 0x4
FLAG_END_STREAM, FLAG_END_HEADERS = 0x1, 0x4


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def estr(b):
    return bytes([len(b)]) + b


def hdr(n, v):
    return b"\x00" + estr(n) + estr(v)


FT_RST = 0x3


def exchange(declared, body, path=b"/api/echo", budget=8.0):
    """POST with a declared content-length and a body that may disagree.

    `declared` is one value, or a list of them for a repeated field; None omits
    the field. `body` of None means END_STREAM rides the HEADERS frame and no
    DATA is sent at all.

    -> (status, seconds) — the status the client eventually saw, or "RST" when
    the stream was reset without one (which is what RFC 9113 8.1.1 asks for).
    """
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                        server_hostname="localhost")
    assert s.selected_alpn_protocol() == "h2"
    if declared is None:
        declared = []
    elif not isinstance(declared, (list, tuple)):
        declared = [declared]
    block = (hdr(b":method", b"POST") + hdr(b":scheme", b"https")
             + hdr(b":authority", b"localhost") + hdr(b":path", path))
    for d in declared:
        block += hdr(b"content-length", str(d).encode())
    if body is None:
        frames = fr(FT_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, block)
    else:
        frames = (fr(FT_HEADERS, FLAG_END_HEADERS, 1, block)
                  + fr(FT_DATA, FLAG_END_STREAM, 1, body))
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(FT_SETTINGS, 0, 0) + frames)
    s.settimeout(budget)
    start, buf, status, rst = time.time(), b"", None, False
    try:
        while status is None and not rst:
            d = s.recv(65536)
            if not d:
                break
            buf += d
            while len(buf) >= 9:
                ln = int.from_bytes(buf[:3], "big")
                if len(buf) < 9 + ln:
                    break
                ftype, body_b = buf[3], buf[9:9 + ln]
                buf = buf[9 + ln:]
                if ftype == FT_RST:
                    rst = True
                if ftype == FT_HEADERS:
                    # :status is a literal with an indexed name; the value is
                    # the last three digits in the block for our own encoder
                    for i in range(len(body_b) - 2):
                        chunk = body_b[i:i + 3]
                        if chunk.isdigit():
                            status = int(chunk)
                            break
    except (socket.timeout, OSError):
        pass
    s.close()
    if status is None and rst:
        return "RST", time.time() - start
    return status, time.time() - start


fails = 0

# the honest case still works
status, secs = exchange(5, b"hello")
if status == 200:
    print(f"ok   a body matching its content-length is served ({status})")
else:
    print(f"FAIL a matching body gave {status}")
    fails += 1

# ...and one that stops short is refused promptly, not timed out
status, secs = exchange(10, b"hello")
if status == 400 and secs < 5:
    print(f"ok   a body shorter than declared is refused ({status}) in {secs:.2f}s")
elif status == 408 or secs >= 5:
    print(f"FAIL a short body gave {status} after {secs:.2f}s — that is the body "
          f"clock timing out, not the framing fault being detected")
    fails += 1
else:
    print(f"FAIL a short body gave {status} after {secs:.2f}s, want 400")
    fails += 1

# a body that overruns was already refused; keep it pinned
status, secs = exchange(2, b"hello")
if status in (400, 413):
    print(f"ok   a body longer than declared is refused ({status})")
else:
    print(f"FAIL an over-long body gave {status}")
    fails += 1


# --- audit-report-5 Finding 1: the parse itself ------------------------------
#
# The value has to be REJECTED before it is compared, not merely compared. The
# old parser guarded its multiply by asking whether the product had come out
# SMALLER — which (2^61+1)*10 does not — and never checked the digit's carry at
# all, so 18446744073709551616 parsed as 0. Zero is exactly the DATA sum of a
# request that sends no body, so the one value that "obviously cannot match"
# was the one that matched: a POST declaring 2^64 bytes and sending none was
# served, and on a proxy location it reached the backend as a normal empty
# POST. The reply is a stream error, so "RST" and 400 are both a refusal; a
# 200 is the defect.
def refused(status):
    return status == "RST" or (isinstance(status, int) and 400 <= status < 500)


OVERFLOW = [
    ("2^64 with no DATA at all", "18446744073709551616", None),
    ("2^64 with an empty DATA frame", "18446744073709551616", b""),
    ("2^64 + 5 with 5 DATA bytes", "18446744073709551621", b"hello"),
    ("2^64 + 1 with no DATA", "18446744073709551617", None),
    ("forty digits with no DATA", "1" * 40, None),
    ("10^20 with no DATA", "1" + "0" * 20, None),
]
for name, declared, body in OVERFLOW:
    status, _ = exchange(declared, body)
    if refused(status):
        print(f"ok   content-length {name} is refused ({status})")
    else:
        print(f"FAIL content-length {name} gave {status}, want a refusal — the "
              f"value wrapped and the request was accepted against it")
        fails += 1

# 18446744073709551615 is a LEGAL content-length, and the boundary the parser
# has to get right in the other direction: the old one reported its own faults
# by returning -1, could not tell UINT64_MAX from one, and took the
# "unparseable — collect the body and re-derive the length" branch. The
# client's declaration was then replaced by our measured count on the way to
# the backend, which is the substitution this whole check exists to stop. It
# must be refused for disagreeing with the 5 bytes sent (or for exceeding
# max_body), never served.
status, _ = exchange("18446744073709551615", b"hello")
if refused(status):
    print(f"ok   content-length UINT64_MAX with 5 DATA bytes is refused ({status})")
else:
    print(f"FAIL content-length UINT64_MAX with 5 DATA bytes gave {status} — a "
          f"legal-but-huge declaration was mistaken for an unparseable one")
    fails += 1

# --- and duplicates ----------------------------------------------------------
#
# The shared field collector kept the LAST content-length and nothing else, so
# "0" then "1" silently resolved the contradiction in the client's favour. Two
# lengths cannot both equal the body whether or not they agree with each other,
# and HTTP/1 has refused a repeated Content-Length since it was written.
DUPES = [
    ("0 then 1", ["0", "1"], b"a"),
    ("1 then 0", ["1", "0"], b"a"),
    ("5 then 5 (identical)", ["5", "5"], b"hello"),
]
for name, declared, body in DUPES:
    status, _ = exchange(declared, body)
    if refused(status):
        print(f"ok   a repeated content-length ({name}) is refused ({status})")
    else:
        print(f"FAIL a repeated content-length ({name}) gave {status}, want a "
              f"refusal — one of the two declarations was silently dropped")
        fails += 1

# The controls, so none of the above can pass on a server that refuses
# everything: an honest single declaration is still served, and so is a request
# that declares nothing at all.
status, _ = exchange("5", b"hello")
if status == 200:
    print(f"ok   control: one honest content-length is still served ({status})")
else:
    print(f"FAIL control: content-length 5 with 5 DATA bytes gave {status}")
    fails += 1
status, _ = exchange(None, b"hello")
if status == 200:
    print(f"ok   control: a body with no content-length is still served ({status})")
else:
    print(f"FAIL control: a body with no content-length gave {status}")
    fails += 1

sys.exit(1 if fails else 0)
