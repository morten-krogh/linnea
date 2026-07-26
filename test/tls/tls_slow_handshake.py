#!/usr/bin/env python3
# The request-head deadline must also bound the TLS handshake: a client that
# dribbles ClientHello bytes rearms only the per-op idle timeout and would
# otherwise hold its slot forever (slowloris on 443). The connection must be
# cut near head_timeout, and a normal handshake must still complete.
# Usage: tls_slow_handshake.py <cafile> <port> <head_timeout>. Exits 0 on success.
import ssl, socket, sys, time

ca, port, head = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
HOST = "127.0.0.1"
ok = True

# dribble a partial TLS record, never completing the ClientHello
s = socket.create_connection((HOST, port), timeout=head * 6)
s.settimeout(head * 6)
s.sendall(bytes([0x16, 0x03, 0x01, 0x02, 0x00]))   # handshake record, len=512
t0 = time.time()
held = None
try:
    for _ in range(head * 8):
        time.sleep(head / 3)
        s.sendall(b"\x00")
except OSError:
    held = time.time() - t0
else:
    try:
        s.settimeout(2)
        if s.recv(1) == b"":
            held = time.time() - t0
    except OSError:
        held = time.time() - t0
s.close()

if held is None:
    print("FAIL: dribbling handshake was never cut off"); ok = False
elif held < head * 0.5:
    print("FAIL: cut too early at %.1fs (head_timeout=%d)" % (held, head)); ok = False
elif held > head * 5:
    print("FAIL: held %.1fs — deadline not enforced on the handshake" % held); ok = False

# a normal handshake still completes and serves
try:
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    c = ctx.wrap_socket(socket.create_connection((HOST, port), timeout=5),
                        server_hostname="localhost")
    c.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    d = c.recv(200); c.close()
    if b"200" not in d:
        print("FAIL: normal handshake did not serve"); ok = False
except Exception as e:
    print("FAIL: normal handshake errored:", e); ok = False

sys.exit(0 if ok else 1)
