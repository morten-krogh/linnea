#!/usr/bin/env python3
"""A backend that answers with Content-Length, does NOT say Connection: close,
and then closes anyway. The socket linnea parks is therefore already dead: only
the liveness peek can catch it before a request is sent into it."""
import socket, sys, threading
port = int(sys.argv[1])
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(128)
def serve(c):
    try:
        c.settimeout(10); buf=b""
        while b"\r\n\r\n" not in buf:
            d=c.recv(65536)
            if not d: return
            buf+=d
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nR")
    except Exception: pass
    finally: c.close()           # gone, with no warning in the response
while True:
    c,_=srv.accept(); threading.Thread(target=serve,args=(c,),daemon=True).start()
