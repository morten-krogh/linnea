"""Serve variant N split at byte offset K of the RESPONSE (head + body), with a
flush and a pause between the two writes, at /api/s<N>_<K>.

The pause is what makes the split real: two sendalls with nothing between them
arrive as one read on loopback, and a sweep that meant to cross a read boundary
would quietly never cross one. Driven by splitdrive.py."""
import socket, sys, threading, time
sys.path.insert(0, ".")
from variants import V
PORT = int(sys.argv[1])
HEAD = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
def serve(c):
    try:
        c.settimeout(10)
        req = b""
        while b"\r\n\r\n" not in req:
            d = c.recv(4096)
            if not d:
                return
            req += d
        tag = req.split(b" ")[1].rsplit(b"/s", 1)[1].split(b"?")[0]
        n, k = (int(x) for x in tag.split(b"_"))
        whole = HEAD + V[n][1]
        k = min(k, len(whole))
        c.sendall(whole[:k])
        time.sleep(0.12)
        c.sendall(whole[k:])
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT)); srv.listen(64)
while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
