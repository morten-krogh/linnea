#!/usr/bin/env python3
# Q125: a ClientHello split across TLS records must complete the handshake.
# A handshake message is a byte stream carried by records, not something a
# record contains one of (RFC 8446 5.1): a client may fragment its
# ClientHello however it likes, and one larger than 2^14 bytes MUST be
# fragmented. linnea used to read the first record's payload as the whole
# message, so any fragmented hello failed outright — which also meant a
# hello too big for one record could never be accepted at all.
#
# The hello is borrowed from a real handshake: python's ssl builds it, we
# capture the bytes, then replay them fragmented across records. Each case
# must reach a ServerHello.
# Usage: fragmented_ch.py <port>
import socket
import ssl
import sys

port = int(sys.argv[1])


def capture_clienthello():
    """One real ClientHello, taken off a memory BIO so nothing is sent."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname="localhost")
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    rec = out.read()
    assert rec[0] == 0x16, "not a handshake record"
    body = rec[5:]
    assert body[0] == 0x01, "not a ClientHello"
    return body                      # the handshake message, unframed


def records(body, sizes):
    """Frame the message as handshake records of the given fragment sizes."""
    out = b""
    off = 0
    for n in sizes:
        chunk = body[off:off + n]
        if not chunk:
            break
        out += b"\x16\x03\x03" + len(chunk).to_bytes(2, "big") + chunk
        off += n
    if off < len(body):
        rest = body[off:]
        out += b"\x16\x03\x03" + len(rest).to_bytes(2, "big") + rest
    return out


def try_hello(name, wire, expect_sh=True):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(5)
    try:
        s.sendall(wire)
        head = b""
        while len(head) < 6:
            d = s.recv(6 - len(head))
            if not d:
                break
            head += d
    except (socket.timeout, OSError):
        head = b""
    s.close()
    got_sh = len(head) >= 6 and head[0] == 0x16 and head[5] == 0x02
    got_alert = len(head) >= 6 and head[0] == 0x15
    if expect_sh:
        assert got_sh, f"{name}: no ServerHello (got {head[:6]!r})"
    else:
        assert got_alert, f"{name}: expected an alert, got {head[:6]!r}"
    print(f"  {name}: {'ServerHello' if got_sh else 'alert'}")


body = capture_clienthello()
assert len(body) > 40, "captured hello looks too short"

# the ordinary case must keep working
try_hello("whole hello in one record", records(body, [len(body)]))
# split right after the handshake header, so the length arrives alone
try_hello("split after the 4-byte header", records(body, [4]))
# a byte at a time for the first few records: the header itself is spread
try_hello("header split byte by byte", records(body, [1, 1, 1, 1, 1]))
# a middle split, the common shape a fragmenting client produces
try_hello("split mid-message", records(body, [len(body) // 2]))
# many small fragments
try_hello("many small fragments", records(body, [7] * 40))

# a hello that claims more than the server can ever assemble is refused
# cleanly (an alert), not left hanging: 3-byte length = 0xFFFFFF
huge = b"\x01\xff\xff\xff" + b"\x00" * 64
try_hello("absurd declared length", records(huge, [len(huge)]), expect_sh=False)
print("ok")
