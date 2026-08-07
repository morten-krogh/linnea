#!/usr/bin/env python3
"""A proxied HTTP/2 response must not carry the backend's connection fields.

RFC 9110 7.6.1 makes them hop-by-hop: they describe the backend's connection to
us, not ours to the client. RFC 9113 8.2.2 goes further for HTTP/2 -- a message
carrying a connection-specific field is MALFORMED, and TE is allowed only with
the exact value "trailers". So relaying one is not merely untidy; it is us
emitting a message the peer is entitled to reject.

The response rewriter dropped six such names and missed TE, which is the one
name on that list a backend is most likely to send back for an ordinary reason
(content negotiation). h1 has always dropped it -- h1_proxy_hop_by_hop.py
checks exactly this on the h1 path -- and h3 does too, so h2 was the odd one
out and the same backend answer travelled differently depending on which
protocol the client happened to speak.

The check has to decode rather than search: linnea emits forwarded response
fields as literal-name/literal-value pairs with H=0, and a plain substring
search for "te" matches inside "content-length".

usage: h2_proxy_hop_by_hop.py <cafile> <port>
"""
import socket
import ssl
import struct
import sys

ca, port = sys.argv[1], int(sys.argv[2])

# Fields that must never reach the client, and one that must (nothing asked for
# X-Kept to be removed, and a rewriter that dropped everything would "pass" too).
HOP_BY_HOP = ("keep-alive", "te", "trailer", "proxy-connection",
              "proxy-authenticate", "transfer-encoding", "connection", "upgrade")
MUST_REMAIN = "x-kept"


def frame(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def field(n, v):
    return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v


def response_fields(path):
    """The names of the response header fields, in order."""
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5),
                        server_hostname="localhost")
    s.settimeout(5)
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0))
    s.sendall(frame(1, 0x05, 1,
                    field(b":method", b"GET") + field(b":scheme", b"https")
                    + field(b":authority", b"localhost") + field(b":path", path)))
    block = b""
    try:
        for _ in range(12):
            h = b""
            while len(h) < 9:
                d = s.recv(9 - len(h))
                if not d:
                    raise OSError
                h += d
            ln = int.from_bytes(h[:3], "big")
            p = b""
            while len(p) < ln:
                d = s.recv(ln - len(p))
                if not d:
                    break
                p += d
            if h[3] == 1:               # HEADERS
                block = p
                break
    except OSError:
        pass
    s.close()

    def integer(i, prefix_bits):
        """RFC 7541 5.1: an N-bit prefix, then continuation octets when it is
        all ones. Getting this wrong desynchronises the whole walk -- `via` is
        static index 60, which does not fit a 4-bit prefix and so spills into a
        second byte that would otherwise be read as a length."""
        mask = (1 << prefix_bits) - 1
        value = block[i] & mask
        i += 1
        if value < mask:
            return value, i
        shift = 0
        while True:
            octet = block[i]
            i += 1
            value += (octet & 0x7f) << shift
            shift += 7
            if not octet & 0x80:
                return value, i

    def string(i):
        """A length with a 7-bit prefix, the top bit saying Huffman. linnea
        never Huffman-codes what it emits, so a set bit means we have lost our
        place -- say so rather than return plausible nonsense."""
        huff = bool(block[i] & 0x80)
        ln, i = integer(i, 7)
        if huff:
            raise ValueError("Huffman-coded string: the walk has desynchronised")
        return block[i:i + ln], i + ln

    names, i = [], 0
    while i < len(block):
        b0 = block[i]
        if b0 & 0x80:                   # indexed field line: name not spelled out
            _, i = integer(i, 7)
            names.append("<indexed>")
            continue
        if b0 & 0xc0 == 0x40:           # literal, incremental indexing
            idx, i = integer(i, 6)
        elif b0 & 0xe0 == 0x20:         # dynamic table size update: no field
            _, i = integer(i, 5)
            continue
        else:                           # literal, without indexing / never indexed
            idx, i = integer(i, 4)
        if idx == 0:
            name, i = string(i)
            names.append(name.decode("latin1").lower())
        else:
            names.append(f"<static {idx}>")
        _, i = string(i)                # the value, skipped
    return names


names = response_fields(b"/api/hopresp")
fails = 0

leaked = [n for n in HOP_BY_HOP if n in names]
if leaked:
    print(f"FAIL the response relayed {', '.join(leaked)} — those describe the "
          f"backend's connection to us, not ours to the client, and RFC 9113 "
          f"8.2.2 makes a message carrying one malformed")
    fails += 1

if MUST_REMAIN not in names:
    print(f"FAIL the response lost {MUST_REMAIN}, which nothing asked to have "
          f"removed (fields: {names})")
    fails += 1

if not fails:
    print("ok   hop-by-hop response fields are not relayed over h2")
sys.exit(1 if fails else 0)
