#!/usr/bin/env python3
"""Accepts every connection and never answers. The failure mode a connect-only
health check cannot see: the backend is reachable and completely useless."""
import socket, sys, threading, time
port = int(sys.argv[1])
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(128)
def hold(c):
    try:
        time.sleep(120)
    finally:
        c.close()
while True:
    c, _ = srv.accept(); threading.Thread(target=hold, args=(c,), daemon=True).start()
