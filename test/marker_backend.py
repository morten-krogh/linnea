#!/usr/bin/env python3
"""A backend that says which one it is: GET anything -> 200 with its own tag."""
import socket, sys, threading
port, tag = int(sys.argv[1]), sys.argv[2]
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(64)

def serve(c):
    try:
        c.settimeout(5)
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = c.recv(65536)
            if not d:
                return
            buf += d
        body = tag.encode()
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s"
                  % (len(body), body))
    except Exception:
        pass
    finally:
        c.close()

while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
