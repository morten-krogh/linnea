#!/usr/bin/env python3
"""Regression test: the record bound in the WAIT_FIN state.

After linnea sends its handshake flight it waits for the client Finished,
decrypting each record into hs.msg_buf. linnea_tls_open writes the
plaintext out BEFORE it authenticates the tag, so the length of a record
from an unauthenticated peer decides how much is written -- and msg_buf is
smaller than the largest record in_buf can hold. Without a bound, a client
that has done nothing but send a valid ClientHello could run a record off
the end of msg_buf, which is the last field of the handshake state, which
is itself overlaid on the connection's up_buf: the spill lands in the next
connection in the pool.

The fuzzer never reaches this: it only ever sends ClientHellos, so the
state machine stays in WAIT_CH.

linnea refuses an over-long fragment as soon as the 5-byte record header
arrives, so the two cases here are:

  huge   a header claiming more than in_buf could ever hold. The bound
         makes this an immediate alert; without it linnea waits for a
         record that can never finish arriving and answers nothing until
         the idle timeout, which is what this test measures.
  spill  a fragment that does fit in_buf but not msg_buf -- the case that
         actually overflowed. Behaviourally it looks like the bad-MAC
         rejection it also gets without the bound, so the assertion is
         that the server survives it and keeps serving.

usage: oversized_record.py <cafile> <port> <clienthello.bin>
"""
import socket
import ssl
import sys

# Well under the 5s idle timeout, so a stalled server is unambiguous:
# a reply this fast can only mean the header itself was refused.
REPLY_TIMEOUT = 2.0


def send_ch_then(port, ch, tail):
    """Handshake far enough to reach WAIT_FIN, send tail, await a reply.

    Returns True if the server answered (or closed) promptly.
    """
    s = socket.socket()
    s.settimeout(REPLY_TIMEOUT)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall(ch)
        # The flight (ServerHello .. Finished) proves we reached WAIT_FIN.
        if not s.recv(4096):
            raise AssertionError("no server flight: the ClientHello was rejected")
        s.sendall(tail)
        try:
            s.recv(4096)   # a sealed alert, or a clean EOF: either is a reply
            return True
        except socket.timeout:
            return False   # stalled: waiting for a record it cannot receive
    finally:
        s.close()


def still_serving(port, cafile):
    ctx = ssl.create_default_context(cafile=cafile)
    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as s:
            s.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
            assert b"200 OK" in s.recv(4096), "server stopped serving"


def main():
    cafile, port, chfile = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    ch = open(chfile, "rb").read()

    # 60000 bytes claimed, none sent: longer than in_buf, so waiting for the
    # rest could never terminate.
    huge = bytes([23, 3, 3, 0xEA, 0x60])
    if not send_ch_then(port, ch, huge):
        print("FAIL: no reply to an over-long record header (server stalled "
              "waiting for a record larger than in_buf)")
        return 1

    # 8000 bytes, fully sent: fits in_buf, overflows msg_buf.
    spill = bytes([23, 3, 3, 0x1F, 0x40]) + b"A" * 8000
    if not send_ch_then(port, spill, b""):
        print("FAIL: no reply to an over-long record")
        return 1

    try:
        still_serving(port, cafile)
    except Exception as e:
        print(f"FAIL: server unhealthy after oversized records: {e}")
        return 1

    print("PASS: oversized records refused, server still serving")
    return 0


if __name__ == "__main__":
    sys.exit(main())
