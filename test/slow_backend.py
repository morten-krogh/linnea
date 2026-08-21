import socket, sys, threading, time
port = int(sys.argv[1])
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(128)
def serve(c):
    try:
        c.settimeout(20); buf=b""
        while b"\r\n\r\n" not in buf:
            d=c.recv(65536)
            if not d: return
            buf+=d
        time.sleep(2.0)                      # hold the upstream slot
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nS")
    except Exception: pass
    finally: c.close()
while True:
    c,_=srv.accept(); threading.Thread(target=serve,args=(c,),daemon=True).start()
