#!/usr/bin/env python3
"""`close` is a connection option, not a whole field value (RFC 9112 9.1, 9.6).

    Connection = #connection-option

It is a comma-separated list, and `close` may sit anywhere in it. Only a value
that was *entirely* `close` was honoured: the token loop that already walked the
list tested for nothing but `upgrade`. So a client asking to close got

    Connection: keep-alive

back, and the socket held to the idle timeout — the server answering the
opposite of what was asked, and holding a connection the client had finished
with.

Each case checks both halves: what we ANSWER, and whether the socket is actually
closed. A server that says `close` and then holds the socket is no better than
one that says `keep-alive`.

usage: connection_close_token.py <port>
"""
import socket
import sys
import time

port = int(sys.argv[1])
HOST = b"one.test"


def probe(conn_value, budget=2.5):
    """-> (the Connection value we answered, seconds until the peer closed)"""
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(budget)
    s.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: " + HOST + b"\r\n"
              + b"Connection: " + conn_value.encode() + b"\r\n\r\n")
    start = time.time()
    out = b""
    closed = None
    try:
        while True:
            d = s.recv(65536)
            if not d:
                closed = time.time() - start
                break
            out += d
    except socket.timeout:
        pass
    s.close()
    head = out.split(b"\r\n\r\n")[0].decode("latin1", "replace")
    answer = None
    for line in head.split("\r\n")[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "connection":
            answer = value.strip().lower()
    return answer, closed


fails = 0

# every one of these asks to close, and must be answered and acted on as such
for value in ("close", "Close", "keep-alive, close", "close, TE", "TE, close",
              "  close  "):
    answer, closed = probe(value)
    if answer == "close" and closed is not None:
        print(f"ok   {value!r} -> Connection: close, socket closed")
    elif answer != "close":
        print(f"FAIL {value!r} was answered Connection: {answer!r}, want close")
        fails += 1
    else:
        print(f"FAIL {value!r} was answered close but the socket stayed open")
        fails += 1

# ...and one that does not ask to close must still keep the connection, so the
# token match is not simply matching anything containing the letters
for value in ("keep-alive", "TE", "upgrade"):
    answer, closed = probe(value)
    if answer != "close":
        print(f"ok   {value!r} keeps the connection (Connection: {answer})")
    else:
        print(f"FAIL {value!r} was closed, but nothing asked for it")
        fails += 1

# a token that merely starts with "close" is a different token
answer, closed = probe("closely")
if answer != "close":
    print(f"ok   'closely' is not 'close' (Connection: {answer})")
else:
    print("FAIL 'closely' was treated as a close request")
    fails += 1

sys.exit(1 if fails else 0)
