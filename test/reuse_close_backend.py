#!/usr/bin/env python3
"""A backend that keeps a connection alive, then closes it the moment the NEXT
request arrives on it -- without answering that request.

This is the half of the idle-timeout race the liveness peek cannot see. rude_backend
closes right after its first response, so the FIN has arrived by the time linnea
peeks the parked socket and it reconnects fresh. Here the socket is still open and
idle when linnea peeks (it passes), and only closes once linnea sends the reused
request into it -- exactly "the peer may close between the peek and our send".

Reuse is confined to GET/HEAD so that request can simply be sent again; a correct
proxy resends on a fresh connection and the client still gets 200. Before that
retry existed the client got 502, and a healthy backend took a health strike for a
socket it had merely parked and closed.

Per accepted connection: request #1 -> a keep-alive 200 with body "C"; request #2
-> read it and close, no response. Accepts are counted (GET /__stats), which is how
a test sees that each reuse turned into a fresh retried connection.

usage: reuse_close_backend.py <port>
"""
import socket
import sys
import threading

port = int(sys.argv[1])
lock = threading.Lock()
accepts = 0

RESP = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1\r\n\r\nC"


def serve(c):
    global accepts
    with lock:
        accepts += 1
    try:
        c.settimeout(30)
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = c.recv(65536)
            if not d:
                return
            buf += d
        if b"/__stats" in buf.partition(b"\r\n")[0]:
            body = f"accepts={accepts}".encode()
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%b"
                      % (len(body), body))
            return
        c.sendall(RESP)                 # request #1: parked by the proxy after this
        c.recv(65536)                   # request #2 arrives on the reused socket...
    except OSError:
        pass
    finally:
        c.close()                       # ...and it closes with no answer


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(128)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()


main()
