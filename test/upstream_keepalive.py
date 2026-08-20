#!/usr/bin/env python3
"""Upstream keep-alive: reuse, and the four things that must veto it.

Reuse is INVISIBLE from the client -- same status, same body, same headers
whether the proxy opened a connection or reused one. So every check here reads
the backend's own accept counter, which is the only direct evidence. A suite
that watched status codes would pass with the feature switched off.

The vetoes matter more than the reuse. "Connection: close" upstream is what
currently makes a close-delimited response terminate, and it also hides a
response length we got wrong -- the close ends the message whatever we believed.
A pooled connection hides nothing: the next request would read the remainder of
this one as its own head. So a connection is kept only when the location opted
in, the method was safe, the backend did not say close, and the body was
delimited and fully consumed.

usage: upstream_keepalive.py <port> <backend-port> [rude-port]
"""
import socket
import sys

port = int(sys.argv[1])
bport = int(sys.argv[2])
rude = int(sys.argv[3]) if len(sys.argv) > 3 else None
fails = 0


def req(path, method="GET", host="localhost", p=None):
    r = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
         f"Connection: close\r\n\r\n").encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(("127.0.0.1", p or port))
    s.sendall(r)
    d = b""
    while True:
        c = s.recv(65536)
        if not c:
            break
        d += c
    s.close()
    head, _, body = d.partition(b"\r\n\r\n")
    return head.split(b"\r\n")[0].decode(), body


_probes = 0


def conns():
    """Connections the backend has accepted, NOT counting the ones this
    question itself opened. Asking costs a connection -- the probe goes
    straight to the backend, and the backend counts it like any other -- so
    every delta measured with it came out one too high until this subtracted
    them back. The instrument was in the reading."""
    global _probes
    raw = int(req("/__stats", p=bport)[1].split(b" ")[0].split(b"=")[1])
    _probes += 1
    return raw - _probes


def check(label, ok):
    global fails
    print(f"{'ok  ' if ok else 'FAIL'} {label}")
    if not ok:
        fails += 1


# --- reuse ------------------------------------------------------------------
req("/ka/warm")                                  # first one must connect
before = conns()
bodies = [req("/ka/x")[1] for _ in range(15)]
opened = conns() - before
check(f"15 GETs over a keep-alive location open no new connections ({opened})",
      opened == 0)
check("...and every one of them is answered correctly",
      bodies == [b"A"] * 15)

# --- veto 1: the location did not ask for it --------------------------------
before = conns()
[req("/noka/x") for _ in range(5)]
opened = conns() - before
check(f"a location without proxy_keepalive still opens one per request "
      f"({opened})", opened == 5)

# --- veto 2: an unsafe method -----------------------------------------------
# A pooled socket can always lose a race with the backend's idle timeout, and
# the only sound answer is to repeat the request -- which a POST may not be.
before = conns()
req("/ka/x", "POST")
opened = conns() - before
check(f"a POST is not sent over a pooled connection ({opened} opened)",
      opened == 1)

# --- HEAD has no body, and the next request must not read one ---------------
ok = True
for _ in range(10):
    st, body = req("/ka/x", "HEAD")
    ok = ok and st == "HTTP/1.1 200 OK" and body == b""
    st, body = req("/ka/x")
    ok = ok and st == "HTTP/1.1 200 OK" and body == b"A"
check("HEAD then GET on the same pooled connection stay in step", ok)

# --- veto 3: a backend that closes without saying so ------------------------
# The stamp on a parked connection says when WE parked it, never what the peer
# did afterwards, so a liveness peek is what stands between a dead socket and a
# request sent into it.
if rude:
    good = sum(1 for _ in range(20) if req("/r/x", p=port) == ("HTTP/1.1 200 OK", b"R"))
    check(f"a backend that closes a kept connection silently is survived "
          f"({good}/20 served)", good == 20)

print("OK" if not fails else f"{fails} failed")
sys.exit(1 if fails else 0)
