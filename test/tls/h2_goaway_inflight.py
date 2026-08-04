#!/usr/bin/env python3
# h2-14: a GOAWAY received from the client must not abandon streams that are
# already running. RFC 9113 6.8 is explicit that GOAWAY "allows an endpoint to
# gracefully stop accepting new streams while still finishing processing of
# previously established streams" — the sender is announcing it will open no
# NEW streams, not discarding the ones in flight. linnea used to close the
# connection the moment a GOAWAY arrived, so a response already being built was
# thrown away and the client saw nothing at all for a request the server had
# accepted.
#
# The test opens a request and sends GOAWAY immediately behind it, in the same
# write, so the GOAWAY is certain to be processed while the response is still
# in flight — then checks the response arrives anyway (HEADERS plus a non-empty
# DATA body on that stream). Pre-fix this reads back nothing; the connection is
# gone before the response is written.
#
# It also checks the connection then closes on its own rather than lingering to
# the idle timeout: draining means finish-then-close, not finish-then-wait.
# Usage: h2_goaway_inflight.py <ca> <port>
import socket
import ssl
import struct
import sys

CA, PORT = sys.argv[1], int(sys.argv[2])


def frame(ftype, flags, sid, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + \
        struct.pack(">I", sid) + payload


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(CA)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    sock = ctx.wrap_socket(socket.create_connection(("127.0.0.1", PORT), timeout=10),
                           server_hostname="localhost")

    # preface + SETTINGS, then GET / on stream 1, then GOAWAY(last=1, NO_ERROR)
    # :method GET (2), :scheme https (7), :path / (4), :authority literal (41)
    block = bytes([0x82, 0x87, 0x84, 0x41, 0x09]) + b"localhost"
    sock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                 + frame(4, 0, 0)
                 + frame(1, 0x05, 1, block)
                 + frame(7, 0, 0, struct.pack(">II", 1, 0)))

    sock.settimeout(5)
    buf = b""
    closed = False
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                closed = True          # server finished and closed: what we want
                break
            buf += chunk
    except (socket.timeout, ssl.SSLError, OSError):
        pass
    sock.close()

    saw_headers = False
    body = b""
    i = 0
    while i + 9 <= len(buf):
        ln = int.from_bytes(buf[i:i + 3], "big")
        ftype = buf[i + 3]
        sid = int.from_bytes(buf[i + 5:i + 9], "big") & 0x7fffffff
        payload = buf[i + 9:i + 9 + ln]
        if sid == 1 and ftype == 1:
            saw_headers = True
        elif sid == 1 and ftype == 0:
            body += payload
        i += 9 + ln

    if not saw_headers:
        print("no response HEADERS on stream 1: the GOAWAY dropped it")
        return 1
    if not body:
        print("response HEADERS but no DATA: the body was dropped")
        return 1
    if not closed:
        print("response delivered but the connection never closed")
        return 1
    print("in-flight response survived the client GOAWAY (%d body bytes)" % len(body))
    return 0


if __name__ == "__main__":
    sys.exit(main())
