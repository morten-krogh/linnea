#!/usr/bin/env python3
# A streaming HTTP/1.1 backend for the incremental-relay checks
# (test/proxy_stream_test.py): the server-sent-events shape of upstream
# protocol v2 -- no Content-Length, "Connection: close", a body that ends only
# when this side closes -- plus the counted and chunked twins of the same slow
# body and an unbounded flood for backpressure.
#
# Every route writes what happened to the event log (argv[2]) as JSON lines,
# so the test can judge the server from the BACKEND's side: when a write
# failed after the client went away, and how far a flood got while nobody read.
#
# Usage: sse_backend.py <unix socket path | port> <event log>
import json, os, socket, sys, threading, time

TARGET, LOG = sys.argv[1], sys.argv[2]
lock = threading.Lock()


def log(**kw):
    kw["t"] = time.time()
    with lock, open(LOG, "a") as f:
        f.write(json.dumps(kw) + "\n")


def read_head(conn):
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = conn.recv(65536)
        if not d:
            return None
        buf += d
    return buf.split(b"\r\n\r\n", 1)[0]


def query(target):
    q = {}
    if b"?" in target:
        for kv in target.split(b"?", 1)[1].split(b"&"):
            k, _, v = kv.partition(b"=")
            q[k.decode()] = v.decode()
    return q


SSE_HEAD = (b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
            b"Cache-Control: no-store\r\nX-Accel-Buffering: no\r\n"
            b"Connection: close\r\n\r\n")


def serve(conn):
    head = read_head(conn)
    if head is None:
        return
    target = head.split(b"\r\n")[0].split(b" ")[1]
    path, q = target.split(b"?")[0], query(target)
    tag = q.get("tag", "")
    n = int(q.get("n", "5"))
    gap = float(q.get("gap", "0.5"))
    if path.endswith(b"/events"):
        # close-delimited: n events, gap seconds apart, then the close ends it
        conn.sendall(SSE_HEAD + b": stream open\n\n")
        log(tag=tag, ev="open")
        for k in range(n):
            time.sleep(gap)
            conn.sendall(b"data: event %d\n\n" % k)
            log(tag=tag, ev="sent", k=k)
        log(tag=tag, ev="done")
    elif path.endswith(b"/counted"):
        # the same slow body with a Content-Length: incremental too
        chunks = [b"data: event %d\n\n" % k for k in range(n)]
        body_len = sum(len(c) for c in chunks)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                     b"Content-Length: %d\r\n\r\n" % body_len)
        log(tag=tag, ev="open")
        for k, c in enumerate(chunks):
            time.sleep(gap)
            conn.sendall(c)
            log(tag=tag, ev="sent", k=k)
        log(tag=tag, ev="done")
    elif path.endswith(b"/chunked"):
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                     b"Transfer-Encoding: chunked\r\n\r\n")
        log(tag=tag, ev="open")
        for k in range(n):
            time.sleep(gap)
            c = b"data: event %d\n\n" % k
            conn.sendall(b"%x\r\n%s\r\n" % (len(c), c))
            log(tag=tag, ev="sent", k=k)
        conn.sendall(b"0\r\n\r\n")
        log(tag=tag, ev="done")
    elif path.endswith(b"/forever"):
        # a stream that never ends by itself: the only way out is linnea
        # closing the upstream connection once its client is gone
        conn.sendall(SSE_HEAD + b": stream open\n\n")
        log(tag=tag, ev="open")
        k = 0
        try:
            while True:
                time.sleep(gap)
                conn.sendall(b"data: event %d\n\n" % k)
                k += 1
        except OSError as e:
            log(tag=tag, ev="closed", k=k, err=type(e).__name__)
    elif path.endswith(b"/flood"):
        # close-delimited, as fast as the socket takes it, `mb` MiB of it. How
        # far it gets while the client is not reading is the backpressure.
        total = int(float(q.get("mb", "64")) * 1048576)
        conn.sendall(SSE_HEAD)
        log(tag=tag, ev="open")
        block = (b"0123456789abcdef" * 4096)
        sent = 0
        last = 0.0
        try:
            while sent < total:
                m = conn.send(block[:min(len(block), total - sent)])
                sent += m
                now = time.time()
                if now - last > 0.1:
                    log(tag=tag, ev="progress", sent=sent)
                    last = now
            log(tag=tag, ev="done", sent=sent)
        except OSError as e:
            log(tag=tag, ev="closed", sent=sent, err=type(e).__name__)
    else:
        conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n"
                     b"Connection: close\r\n\r\n")


def serve_one(conn):
    try:
        serve(conn)
    except OSError:
        pass
    finally:
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        conn.close()


def main():
    if TARGET.startswith("/"):
        try:
            os.unlink(TARGET)
        except FileNotFoundError:
            pass
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(TARGET)
    else:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", int(TARGET)))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=serve_one, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
