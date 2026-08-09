#!/usr/bin/env python3
"""RFC 8446 7.4.2 / RFC 7748 6: a degenerate X25519 key share.

Every one of these was ACCEPTED before the check went in, on both the TCP and
the QUIC handshake — the server keyed the session from a shared secret that is
all-zero whatever its private key is. Nothing was exploitable by it (the server
authenticates with ECDSA, the client already holds its own session keys,
clamping clears the cofactor so no scalar leaks, and the ephemeral key is fresh
per handshake) but it is a MUST, and contributory behaviour is the property it
buys.

  "For X25519 and X448, ... implementations MUST check whether the computed
   Diffie-Hellman shared secret is the all-zero value and abort if so."

A client key share that is a low-order point drives the shared secret to zero
whatever the server's private key is. The server must abort. What this asks is
only: does it abort, or does it carry on and send a ServerHello?

Usage: lowsecret.py <host> <port>
"""
import os
import socket
import struct
import sys

HOST, PORT = sys.argv[1], int(sys.argv[2])


def ext(kind, body):
    return struct.pack(">HH", kind, len(body)) + body


def client_hello(pub):
    exts = ext(43, bytes([2]) + struct.pack(">H", 0x0304))
    exts += ext(10, struct.pack(">HH", 2, 0x001d))
    share = struct.pack(">HH", 0x001d, len(pub)) + pub
    exts += ext(51, struct.pack(">H", len(share)) + share)
    exts += ext(13, struct.pack(">HH", 2, 0x0403))
    body = (struct.pack(">H", 0x0303) + os.urandom(32) + bytes([32]) + os.urandom(32)
            + struct.pack(">HH", 2, 0x1301) + bytes([1, 0])
            + struct.pack(">H", len(exts)) + exts)
    return bytes([1]) + len(body).to_bytes(3, "big") + body


def rec(kind, body):
    return bytes([kind]) + b"\x03\x03" + struct.pack(">H", len(body)) + body


def read_record(s):
    head = b""
    while len(head) < 5:
        c = s.recv(5 - len(head))
        if not c:
            return None
        head += c
    n = struct.unpack(">H", head[3:5])[0]
    body = b""
    while len(body) < n:
        c = s.recv(n - len(body))
        if not c:
            return None
        body += c
    return head[0], body


# the eight low-order points of Curve25519, as u-coordinates
LOW_ORDER = {
    "0 (order 1)": bytes(32),
    "1 (order 4)": bytes([1]) + bytes(31),
    "order 8 (a)": bytes.fromhex(
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    "order 8 (b)": bytes.fromhex(
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
    "p-1 (order 2)": bytes.fromhex(
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    "p (= 0)": bytes.fromhex(
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    "p+1 (= 1)": bytes.fromhex(
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
}

accepted = []
for label, pub in LOW_ORDER.items():
    s = socket.create_connection((HOST, PORT), timeout=6)
    s.settimeout(6)
    s.sendall(rec(22, client_hello(pub)))
    verdict = "connection closed with no reply"
    try:
        r = read_record(s)
        if r is None:
            verdict = "closed"
        elif r[0] == 21:
            verdict = "ALERT %d — aborted, as 7.4.2 requires" % r[1][1]
        elif r[0] == 22 and r[1][:1] == b"\x02":
            verdict = "SERVERHELLO — the handshake carried on"
            accepted.append(label)
        else:
            verdict = "record type %d" % r[0]
    except socket.timeout:
        verdict = "timeout"
    s.close()
    print("%-16s -> %s" % (label, verdict))

print()
if accepted:
    print("%d of %d low-order shares were ACCEPTED: %s"
          % (len(accepted), len(LOW_ORDER), ", ".join(accepted)))
    sys.exit(1)
print("every low-order share was refused")
