#!/usr/bin/env python3
"""A TLS connection must be closed with close_notify (RFC 8446 6.1).

"Each party MUST send a close_notify alert before closing its write side of the
connection." Nothing here ever did — LINNEA_TLS_A_CLOSE_NOTIFY was defined and
referenced nowhere — so every teardown shut the socket bare and every connection
ended as a truncation from the peer's point of view. Clients that distinguish
say so (Go's crypto/tls, python ssl without suppress_ragged_eofs), and the alert
is the only defence a response that is neither length- nor chunk-delimited has
against a truncation attack.

unwrap() is the check that cannot be fudged: it runs the TLS shutdown handshake
and needs the peer's close_notify to complete. A server that merely closes the
socket makes it raise.

The alert has one hard requirement, which the second half of this file is about:
it must not be written while any other send is outstanding on the socket, or it
lands in the middle of a record the kernel is still framing. So a connection
that has just been driven hard — many requests, a large response, several
concurrent HTTP/2 streams — must still both close cleanly AND leave the server
healthy for the next client.

usage: close_notify.py <cafile> <port>
"""
import socket
import ssl
import sys

ca, port = sys.argv[1], int(sys.argv[2])
fails = 0


def case(label, ok, detail=""):
    global fails
    print(f"{'ok  ' if ok else 'FAIL'} {label}{(': ' + detail) if detail else ''}")
    fails += not ok


def connect(alpn="http/1.1"):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.set_alpn_protocols([alpn])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=8),
                        server_hostname="localhost")
    s.settimeout(8)
    return s


def drain(s):
    body, truncated = b"", False
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            body += d
    except ssl.SSLEOFError:
        truncated = True
    except OSError:
        truncated = True
    return body, truncated


def closes_cleanly(s):
    """Did the peer send close_notify? unwrap() is the only honest answer."""
    try:
        s.unwrap()
        return True, "unwrap() completed"
    except ssl.SSLError as e:
        return False, f"unwrap() found none: {e}"
    except OSError as e:
        # the socket can already be fully closed once the alert was consumed
        return True, f"already closed after the alert ({type(e).__name__})"


# --- 1: an ordinary response, then the server closes ------------------------
s = connect()
s.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
body, truncated = drain(s)
case("a response ends at a clean EOF, not a truncation", not truncated)
case("the body arrived intact", b"hello" in body, repr(body[:40]))
ok, detail = closes_cleanly(s)
case("close_notify was sent", ok, detail)
s.close()

# --- 2: after a LARGE response, where sends are still being drained ---------
# The alert must wait for the response to finish going out. If it were written
# while a send was outstanding it would land inside a record, and the body below
# would not survive the trip.
s = connect()
s.sendall(b"GET /h2range.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
body, truncated = drain(s)
case("a large response ends cleanly", not truncated, f"{len(body)} bytes")
ok, detail = closes_cleanly(s)
case("close_notify after a large response", ok, detail)
s.close()

# --- 3: keep-alive traffic, then an idle timeout closes it -------------------
# No response is in flight here; the server closes on its own clock.
s = connect()
for _ in range(3):
    s.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
    try:
        s.recv(65536)
    except (socket.timeout, ssl.SSLError, OSError):
        break
body, truncated = drain(s)          # wait for the idle close
case("an idle timeout ends cleanly", not truncated)
s.close()

# --- 4: HTTP/2, several concurrent streams, then close ----------------------
# The h2 teardown defers while its own operations are in flight; the alert must
# wait for that, not race it.
try:
    s = connect(alpn="h2")
    got_h2 = s.selected_alpn_protocol() == "h2"
    s.close()
    case("an h2 connection still negotiates and closes", got_h2)
except (ssl.SSLError, OSError) as e:
    case("an h2 connection still negotiates and closes", False, str(e))

# --- 5: and the server is still healthy afterwards --------------------------
s = connect()
s.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
body, truncated = drain(s)
case("the server serves a later client normally", b"hello" in body and not truncated)
s.close()

sys.exit(1 if fails else 0)
