#!/usr/bin/env python3
"""An ALPN mismatch must be fatal, not silently ignored (RFC 7301 3.2).

"In the event that the server supports no protocols that the client advertises,
then the server SHALL respond with a fatal 'no_application_protocol' alert."

The handshake used to complete with no protocol selected, and the server then
spoke HTTP/1 at whatever arrived. So a client offering only h2 to a listener
with HTTP/2 turned off had its connection preface answered with a 400 — which
says nothing about what actually went wrong, and leaves the client to guess.

Two things this must NOT do, both checked below. A client that sends no ALPN
extension at all has stated no requirement, so there is nothing to fail and the
handshake proceeds. And a client offering something we do speak, alongside
things we do not, must still negotiate normally.

usage: alpn_mismatch.py <cafile> <port>
"""
import socket
import ssl
import sys

ca, port = sys.argv[1], int(sys.argv[2])
NO_APPLICATION_PROTOCOL = 120


def handshake(protocols):
    """Returns ('ok', negotiated) or ('alert', description) or ('error', text)."""
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    if protocols is not None:
        ctx.set_alpn_protocols(protocols)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                return "ok", s.selected_alpn_protocol()
    except ssl.SSLError as e:
        text = str(e)
        if "NO_APPLICATION_PROTOCOL" in text.upper().replace(" ", "_"):
            return "alert", NO_APPLICATION_PROTOCOL
        return "error", text
    except OSError as e:
        return "error", str(e)


fails = 0


def case(label, protocols, want_kind, want_detail=None):
    global fails
    kind, detail = handshake(protocols)
    if kind != want_kind or (want_detail is not None and detail != want_detail):
        print(f"FAIL {label}: {kind} {detail!r}, expected {want_kind} "
              f"{want_detail!r}")
        fails += 1
    else:
        print(f"ok   {label}: {kind} {detail!r}")


# nothing we speak: the alert is the whole point
case("only an unknown protocol", ["spdy/3.1"], "alert", NO_APPLICATION_PROTOCOL)
case("several unknown protocols", ["spdy/3.1", "doq", "irc"], "alert",
     NO_APPLICATION_PROTOCOL)

# ...and the two cases that must NOT be broken by it
case("no ALPN extension at all", None, "ok", None)
case("http/1.1 offered", ["http/1.1"], "ok", "http/1.1")
case("something unknown alongside something known",
     ["spdy/3.1", "http/1.1"], "ok", "http/1.1")

sys.exit(1 if fails else 0)
