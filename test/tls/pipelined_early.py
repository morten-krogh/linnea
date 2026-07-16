#!/usr/bin/env python3
"""Exercise linnea_tls_drain_early: records pipelined behind the Finished.

A TLS 1.3 client sends its request straight after its Finished without
waiting for anything, so both can land in linnea's in_buf together. Those
records arrive while the keys are still in userspace, so linnea has to
decrypt them itself, compact the plaintext to the front of in_buf, and tell
the kernel which record sequence to resume RX from.

An ordinary client cannot be made to do this on demand: ssl.wrap_socket
sends the Finished during the handshake, and by the time it writes the
request the server has usually read the Finished already, so the early path
never runs. Driving the handshake through MemoryBIO puts the wire bytes
under our control instead, so the Finished and the request can be bundled
into one send -- and, for the split case, cut at a chosen offset.

The split case is the one that matters: the first segment of a pipelined
request routinely arrives without the rest of it, and linnea cannot hand a
half-received record to the kernel, which can only take over on a record
boundary. It has to wait for the rest instead of dropping the connection.
Loopback hides this -- a whole write lands in one segment -- so the split
is forced explicitly here.

usage: pipelined_early.py <cafile> <port>
"""
import socket
import ssl
import sys
import time

HOST = "localhost"
REQUEST_DEADLINE = 5.0


def connect_pending_finished(ca, port):
    """Handshake until the client's Finished is written but not yet sent.

    Returns (sock, obj, incoming, outgoing); the Finished sits in outgoing
    for the caller to bundle with whatever it writes next.
    """
    ctx = ssl.create_default_context(cafile=ca)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=HOST)
    sock = socket.create_connection((HOST, port), timeout=5)
    while True:
        try:
            obj.do_handshake()
            return sock, obj, incoming, outgoing
        except ssl.SSLWantReadError:
            pending = outgoing.read()
            if pending:
                sock.sendall(pending)
            data = sock.recv(65536)
            if not data:
                raise AssertionError("server closed during the handshake")
            incoming.write(data)


def read_response(sock, obj, incoming):
    buf = b""
    deadline = time.time() + REQUEST_DEADLINE
    while b"hello from linnea" not in buf and time.time() < deadline:
        try:
            buf += obj.read(4096)
            continue
        except ssl.SSLWantReadError:
            pass
        data = sock.recv(65536)
        if not data:
            break
        incoming.write(data)
    return buf


def pipelined(ca, port, pad, cut=None):
    """Send Finished || request; cut splits the send at that offset.

    Returns the decrypted response bytes.
    """
    sock, obj, incoming, outgoing = connect_pending_finished(ca, port)
    try:
        obj.write(b"GET /hello.txt HTTP/1.1\r\nHost: localhost\r\n"
                  b"X-Pad: " + b"X" * pad + b"\r\n\r\n")
        wire = outgoing.read()          # Finished || the request record
        if cut is None:
            sock.sendall(wire)
        else:
            # What an MSS boundary mid-record looks like to the server: the
            # Finished and a fragment now, the remainder once it has had to
            # decide what to do with the fragment.
            sock.sendall(wire[:cut])
            time.sleep(0.3)
            sock.sendall(wire[cut:])
        return read_response(sock, obj, incoming)
    finally:
        sock.close()


def main():
    ca, port = sys.argv[1], int(sys.argv[2])

    for name, pad, cut in (
        ("small pipelined request", 32, None),
        ("large pipelined request", 4000, None),
        ("pipelined request split mid-record", 3000, 1400),
    ):
        resp = pipelined(ca, port, pad, cut)
        if b"200 OK" not in resp:
            print(f"FAIL: {name}: {resp[:120]!r}")
            return 1

    print("PASS: pipelined early records served (whole and split)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
