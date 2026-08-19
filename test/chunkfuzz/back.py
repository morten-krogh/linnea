"""Serves variant N at /api/f<N>, then closes. One thread per connection."""
import socket, sys, threading
sys.path.insert(0, ".")
from variants import V

PORT = int(sys.argv[1])

def serve(c):
    try:
        c.settimeout(5)
        req = b""
        while b"\r\n\r\n" not in req:
            d = c.recv(4096)
            if not d:
                return
            req += d
        path = req.split(b" ")[1]
        n = int(path.rsplit(b"/f", 1)[1].split(b"?")[0])
        c.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + V[n][1])
    except Exception:
        pass
    finally:
        try:
            c.close()
        except Exception:
            pass

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", PORT))
s.listen(64)
print(f"fuzz backend on {PORT}", flush=True)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
