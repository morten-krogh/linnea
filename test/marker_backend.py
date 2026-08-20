#!/usr/bin/env python3
"""A backend that says which one it is, and counts how it was reached.

GET <anything>  -> 200 with this backend's tag as the body
GET /__stats    -> 200 with "conns=<accepted> reqs=<served>"
GET /__head     -> 200 with the request head it received, for asking what an
                   intermediary actually sent (a Connection field the proxy
                   believes it emitted is not evidence that it did)

The two counters are the point. A proxy that reuses upstream connections serves
many requests over few connections, and NOTHING ELSE OBSERVABLE FROM THE CLIENT
distinguishes that from opening one per request -- same status, same body, same
headers. Counting accepts at the backend is the only direct evidence.

Speaks HTTP/1.1 keep-alive: it reads requests from one connection until the
peer closes or asks it to. A request carrying "Connection: close" is answered
and then closed, which is what linnea sends when it does not intend to reuse.

usage: marker_backend.py <port> <tag>
"""
import socket
import sys
import threading

port, tag = int(sys.argv[1]), sys.argv[2]
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(128)

lock = threading.Lock()
conns = 0
reqs = 0


def serve(c):
    global reqs
    try:
        c.settimeout(30)
        buf = b""
        while True:
            while b"\r\n\r\n" not in buf:
                d = c.recv(65536)
                if not d:
                    return
                buf += d
            head, _, buf = buf.partition(b"\r\n\r\n")
            with lock:
                reqs += 1
                if b"/__stats" in head:
                    body = f"conns={conns} reqs={reqs}".encode()
                elif b"/__head" in head:
                    body = head.replace(b"\r\n", b" | ")
                else:
                    body = tag.encode()
            close = b"connection: close" in head.lower()
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                      b"Content-Length: %d\r\n%s\r\n%s"
                      % (len(body),
                         b"Connection: close\r\n" if close else b"",
                         body))
            if close:
                return
    except Exception:
        pass
    finally:
        c.close()


while True:
    conn, _ = srv.accept()
    with lock:
        conns += 1
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
