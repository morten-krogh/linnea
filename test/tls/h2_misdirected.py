#!/usr/bin/env python3
# Q126: HTTP/2 must only answer for names the certificate it presented
# covers. h2 routes per request by :authority, so it always served whatever
# vhost the request named — over a connection whose certificate may have
# been issued for a different site. HTTP/3 got this right in Q124; this is
# the same rule, and the same 421 Misdirected Request (RFC 9110 7.4), which
# sends the client to a connection where the right certificate is offered.
#
# Two vhosts with SEPARATE certificates (localhost, sni.test) exercise the
# refusal; two sharing ONE certificate exercise the case browsers coalesce,
# which must keep working.
# Usage: h2_misdirected.py <cafile> <sni-port> <coalesce-port>
import socket
import ssl
import struct
import sys

ca, sni_port, coal_port = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])


def fr(t, fl, sid, p=b""):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def h(n, v):
    return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v


def get(port, sni, authority, path=b"/index.html"):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5),
                        server_hostname=sni)
    s.settimeout(5)
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(4, 0, 0))
    s.sendall(fr(1, 0x05, 1, h(b":method", b"GET") + h(b":scheme", b"https")
                  + h(b":authority", authority) + h(b":path", path)))
    status, body = None, b""
    try:
        for _ in range(10):
            hd = b""
            while len(hd) < 9:
                d = s.recv(9 - len(hd))
                if not d:
                    raise OSError
                hd += d
            ln = int.from_bytes(hd[:3], "big")
            p = b""
            while len(p) < ln:
                d = s.recv(ln - len(p))
                if not d:
                    break
                p += d
            if hd[3] == 1:
                for c in (b"200", b"404", b"421"):
                    if c in p:
                        status = c.decode()
            if hd[3] == 0:
                body += p
                if hd[4] & 1:
                    break
    except OSError:
        pass
    s.close()
    return status, body


# separate certificates: each connection answers for its own name only
st, body = get(sni_port, "localhost", b"localhost")
assert st == "200" and b"doctype" in body, f"own vhost not served: {st} {body[:40]}"
st, body = get(sni_port, "sni.test", b"sni.test")
assert st == "200" and b"sub index" in body, f"own vhost not served: {st} {body[:40]}"

st, body = get(sni_port, "localhost", b"sni.test")
assert st == "421", f"cross-certificate request was served: {st} {body[:40]}"
assert b"sub index" not in body, "cross-certificate request leaked the other page"
st, body = get(sni_port, "sni.test", b"localhost")
assert st == "421", f"cross-certificate request was served: {st} {body[:40]}"
assert b"doctype" not in body, "cross-certificate request leaked the other page"

# a name we do not host at all is answered by the connection's own vhost —
# this is how address-based access keeps working
st, body = get(sni_port, "sni.test", b"127.0.0.1:%d" % sni_port)
assert st == "200" and b"sub index" in body, \
    f"unknown authority was not served locally: {st} {body[:40]}"

# one certificate covering both names: coalescing must NOT be refused
st, body = get(coal_port, "localhost", b"localhost")
assert st == "200" and b"doctype" in body, f"coalesce baseline failed: {st}"
st, body = get(coal_port, "localhost", b"alias.test")
assert st == "200" and b"sub index" in body, (
    f"a name the connection's own certificate covers was refused: {st} {body[:40]}")
print("ok")
