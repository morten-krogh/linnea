#!/usr/bin/env python3
"""A server whose certificate chain is bigger than the prober can hold.

linnea-probe appended every handshake message the server sent into fixed .bss
buffers with a rep movsb and no bound: tr_buf (16384) over TLS, qtr/qhsc (8192
each) over QUIC. A 22 KB chain walked straight over tr_len, th_buf, every TLS
secret and both key schedules — SIGSEGV, on both transports, from a server that
did nothing stranger than present a long chain. h3buf had the same shape at one
of its two reassembly sites; 875154c had bounded only the other.

The prober's whole purpose is pointing at servers someone else runs, and
`linnea_tls.inc` already anticipates "a post-quantum-scale chain (tens of
KiB)", so this stops being exotic input soon.

What is asserted is the exit code: 2, the "larger than this prober can hold"
diagnostic — never 139 (SIGSEGV), and never 0, which would mean the clamp
silently truncated a transcript and reported a handshake fault that was not the
server's.

Usage: probe_bigchain.py <probe binary> <leaf.crt> <filler.crt> <key>
"""
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

PROBE, LEAF, FILLER, KEY = sys.argv[1:5]
bad = []


def serve_tls(port, chain, stop):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(chain, KEY)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    srv.settimeout(0.5)
    while not stop.is_set():
        try:
            c, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            s = ctx.wrap_socket(c, server_side=True)
            s.recv(4096)
            s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                      b"Connection: close\r\n\r\nhi")
            s.close()
        except Exception:
            try:
                c.close()
            except Exception:
                pass
    srv.close()


def run(port, proto):
    p = subprocess.run([PROBE, "https://localhost:%d/" % port, proto],
                       capture_output=True, timeout=90)
    return p.returncode


with tempfile.TemporaryDirectory() as d:
    chain = os.path.join(d, "big.crt")
    with open(chain, "w") as f:
        f.write(open(LEAF).read() + open(FILLER).read() * 3)
    size = os.path.getsize(chain)

    stop = threading.Event()
    t = threading.Thread(target=serve_tls, args=(47467, chain, stop), daemon=True)
    t.start()
    import time
    time.sleep(1.0)
    rc = run(47467, "h1")
    stop.set()

    ok = rc == 2
    print("%s TLS, %d-byte chain -> exit %d%s"
          % ("PASS" if ok else "FAIL", size, rc,
             "  (SIGSEGV)" if rc == -11 or rc == 139 else ""))
    if not ok:
        bad.append("tls")

    # the QUIC half, if aioquic can serve it
    try:
        import aioquic.asyncio  # noqa: F401
    except ImportError:
        print("PASS QUIC (skipped: aioquic unavailable)")
    else:
        srv = os.path.join(d, "q.py")
        open(srv, "w").write(
            "import asyncio,sys\n"
            "from aioquic.asyncio import serve\n"
            "from aioquic.quic.configuration import QuicConfiguration\n"
            "async def m():\n"
            "    c=QuicConfiguration(is_client=False,alpn_protocols=['h3'])\n"
            "    c.load_cert_chain(sys.argv[2],sys.argv[3])\n"
            "    await serve('127.0.0.1',int(sys.argv[1]),configuration=c)\n"
            "    await asyncio.Future()\n"
            "asyncio.run(m())\n")
        q = subprocess.Popen([sys.executable, srv, "47468", chain, KEY],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2.0)
        try:
            rc = run(47468, "h3")
        finally:
            q.terminate()
            q.wait(timeout=10)
        ok = rc == 2
        print("%s QUIC, %d-byte chain -> exit %d%s"
              % ("PASS" if ok else "FAIL", size, rc,
                 "  (SIGSEGV)" if rc == -11 or rc == 139 else ""))
        if not ok:
            bad.append("quic")

sys.exit(1 if bad else 0)
