#!/usr/bin/env python3
"""Hold an idle keep-alive connection open, for the stop-promptness test.

Makes one request, reads the response, then just sits there: exactly the
connection a browser leaves behind, and the one a stop used to wait on for
the whole idle timeout.
Usage: keepalive_holder.py <port> <seconds>
"""
import socket
import sys
import time

port, seconds = int(sys.argv[1]), float(sys.argv[2])
s = socket.create_connection(("127.0.0.1", port))
s.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: one.test\r\n"
          b"Connection: keep-alive\r\n\r\n")
s.recv(4096)
time.sleep(seconds)
s.close()
