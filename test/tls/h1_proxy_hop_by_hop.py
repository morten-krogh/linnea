#!/usr/bin/env python3
"""The proxy must remove the fields the client's Connection names (RFC 9110 7.6.1).

"Intermediaries MUST parse a received Connection header field before a message
is forwarded and, for each connection-option in this field, remove any header
field(s) from the message with the same name as the connection-option, and then
remove the Connection header field itself."

The rewriter dropped exactly two names — Connection and Expect — and copied
everything else through byte for byte. So a client sending

    Connection: X-Auth-Bypass
    X-Auth-Bypass: 1

had X-Auth-Bypass delivered to the backend as an ordinary end-to-end field. That
is the header-smuggling shape the requirement exists to close: the client marks a
field hop-by-hop, the intermediary forwards it regardless, and the backend has no
way to tell it was never meant to arrive. A backend that trusts a header because
"only our proxy sets it" is exactly the deployment this breaks.

The last case is the one that keeps the fix honest. Connection: upgrade names the
Upgrade field, but there the server is a participant rather than a bystander: it
re-emits Connection: upgrade itself and needs the client's Upgrade forwarded, so
that one token must NOT be treated as a removal instruction.

usage: h1_proxy_hop_by_hop.py <port>
"""
import socket
import sys

port = int(sys.argv[1])
HOST = b"one.test"


def backend_saw(extra):
    """Send a proxied request and return what the backend reports receiving."""
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(3)
    s.sendall(b"GET /api/headers HTTP/1.1\r\nHost: " + HOST + b"\r\n" + extra + b"\r\n")
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    s.close()
    head, _, body = out.partition(b"\r\n\r\n")
    return body.decode("latin1", "replace")


fails = 0


def case(label, extra, must_be_gone=(), must_remain=()):
    global fails
    saw = backend_saw(extra)
    lower = saw.lower()
    leaked = [n for n in must_be_gone if (n.lower() + ":") in lower]
    missing = [n for n in must_remain if (n.lower() + ":") not in lower]
    if leaked:
        print(f"FAIL {label}: {', '.join(leaked)} reached the backend, "
              f"but must not cross a hop")
        fails += 1
    elif missing:
        print(f"FAIL {label}: {', '.join(missing)} did not reach the backend, "
              f"but nothing asked for it to be removed")
        fails += 1
    else:
        print(f"ok   {label}")


# the smuggling shape itself
case("a single named field is removed",
     b"Connection: X-Auth-Bypass\r\nX-Auth-Bypass: 1\r\n",
     must_be_gone=["X-Auth-Bypass"])

# several options, mixed spacing, and a field that was NOT named must survive
case("several named fields, one innocent bystander kept",
     b"Connection: X-One,  X-Two ,X-Three\r\n"
     b"X-One: a\r\nX-Two: b\r\nX-Three: c\r\nX-Keep: d\r\n",
     must_be_gone=["X-One", "X-Two", "X-Three"],
     must_remain=["X-Keep"])

# matching is case-insensitive in both directions
case("case-insensitive in both the option and the field name",
     b"Connection: x-MiXeD\r\nX-mIxEd: 1\r\n",
     must_be_gone=["X-mIxEd"])

# a name that merely starts with an option must not be caught by it
case("a longer field name is not matched by a shorter option",
     b"Connection: X-Auth\r\nX-Auth-Extra: keep\r\nX-Auth: drop\r\n",
     must_be_gone=["X-Auth:"],
     must_remain=["X-Auth-Extra"])

# the classic hop-by-hop names, when the client names them
case("Keep-Alive named by the client is removed",
     b"Connection: keep-alive\r\nKeep-Alive: timeout=5\r\n",
     must_be_gone=["Keep-Alive"])

# ...and the exception: upgrade is the server's own business, not a removal
case("Connection: upgrade does not strip the Upgrade field",
     b"Connection: upgrade\r\nUpgrade: websocket\r\n",
     must_remain=["Upgrade"])


# --- fields that are hop-by-hop in THEMSELVES (RFC 9110 7.6.1) -------------
# The Connection-named half above was Q168. These need no Connection entry at
# all: they are connection-specific by definition, and forwarding them hands the
# backend framing and connection instructions meant for a hop it never shared.
case("Keep-Alive is removed even when Connection does not name it",
     b"Keep-Alive: timeout=5, max=100\r\n",
     must_be_gone=["Keep-Alive"])

case("TE is removed even when Connection does not name it",
     b"TE: gzip\r\n",
     must_be_gone=["TE"])

case("Trailer, Proxy-Connection and Proxy-Authorization are removed",
     b"Trailer: X-Late\r\nProxy-Connection: keep-alive\r\n"
     b"Proxy-Authorization: Basic Zm9vOmJhcg==\r\n",
     must_be_gone=["Trailer", "Proxy-Connection", "Proxy-Authorization"])

# ...while an ordinary field alongside them still goes through, so the filter
# is not simply eating everything
case("an ordinary field survives beside them",
     b"Keep-Alive: timeout=5\r\nX-Ordinary: kept\r\n",
     must_be_gone=["Keep-Alive"],
     must_remain=["X-Ordinary"])


# --- and the same on the way back -----------------------------------------
def client_saw(path):
    """Return the response head the CLIENT receives for a proxied request."""
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(3)
    s.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: " + HOST
              + b"\r\nConnection: close\r\n\r\n")
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    s.close()
    head, _, _ = out.partition(b"\r\n\r\n")
    return head.decode("latin1", "replace")


head = client_saw(b"/api/hopresp")
lower = head.lower()
fields = [line.split(":", 1)[0].strip().lower()
          for line in head.split("\r\n")[1:] if ":" in line]
leaked = [n for n in ("Keep-Alive", "TE", "Trailer", "Proxy-Connection",
                      "Proxy-Authenticate") if n.lower() in fields]
if leaked:
    print(f"FAIL the response relayed {', '.join(leaked)} — those describe the "
          f"backend's connection to us, not ours to the client")
    fails += 1
elif "x-kept" not in fields:
    print("FAIL the response lost X-Kept, which nothing asked to have removed")
    fails += 1
else:
    print("ok   hop-by-hop response fields are not relayed to the client")

sys.exit(1 if fails else 0)
