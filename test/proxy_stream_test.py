#!/usr/bin/env python3
# Incremental relay of proxied responses on HTTP/1.1, HTTP/2 and HTTP/3
# (upstream protocol v2, the server-sent-events form). The backend is
# test/sse_backend.py on a Unix socket, which is how production reaches its
# application; it logs, from ITS side, when each event went out and when a
# write failed, so every timing below is judged against the backend's clock
# rather than inferred from the client's.
#
# What is checked, per protocol:
#   - a close-delimited body (no Content-Length, Connection: close) arrives as
#     it is written: the first event well before the backend finishes, the
#     whole body intact, and the public stream ending cleanly (curl exit 0 is
#     END_STREAM on h2 and FIN on h3) when the backend closes;
#   - the same for a counted and a chunked body;
#   - proxy_timeout is a NO-PROGRESS timeout: a stream that runs longer than
#     both proxy_timeout and the client idle timeout, making progress, is
#     never cut; one that goes silent for longer than proxy_timeout is;
#   - a client going away (connection close, RST_STREAM, RESET_STREAM +
#     STOP_SENDING) closes the upstream connection promptly;
#   - backpressure: a client that reads slowly holds the backend back instead
#     of linnea buffering the flood;
#   - a large close-delimited body arrives complete and byte-exact.
#
# Prints one "ok <name>" / "not ok <name>" line per check, then OK or FAILED n.
# "quick" runs only the first check per protocol (the fast suite's share).
# Usage: proxy_stream_test.py <port> <backend event log> [h1,h2,h3] [quick]
import hashlib, json, os, socket, ssl, struct, subprocess, sys, time

PORT, ELOG = int(sys.argv[1]), sys.argv[2]
PROTOS = sys.argv[3].split(",") if len(sys.argv) > 3 else ["h1", "h2", "h3"]
QUICK = len(sys.argv) > 4 and sys.argv[4] == "quick"
CURLH3 = os.environ.get("LINNEA_CURL_H3",
                        os.path.expanduser("~/curl-h3/bin/curl"))
FLAG = {"h1": ["--http1.1"], "h2": ["--http2"], "h3": ["--http3-only"]}
failures = 0


def report(ok, name):
    global failures
    print(("ok " if ok else "not ok ") + name, flush=True)
    if not ok:
        failures += 1


def curl_cmd(proto, path, extra=()):
    exe = CURLH3 if proto == "h3" else "curl"
    return ([exe, "-sk", "-N", "--max-time", "40",
             "--resolve", "localhost:%d:127.0.0.1" % PORT] + FLAG[proto]
            + list(extra) + ["https://localhost:%d%s" % (PORT, path)])


def run(proto, path, stop=None, extra=()):
    """Run curl, timestamping every read. stop(body) -> True kills it there.
    Returns (exit code, [(seconds since start, bytes)], start time)."""
    t0 = time.time()
    p = subprocess.Popen(curl_cmd(proto, path, extra), stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL)
    got, body = [], b""
    while True:
        d = os.read(p.stdout.fileno(), 1 << 20)
        if not d:
            break
        got.append((time.time() - t0, d))
        body += d
        if stop and stop(body):
            p.kill()
            break
    rc = p.wait()
    p.stdout.close()
    return rc, got, t0


def first_at(got, needle):
    body = b""
    for t, d in got:
        body += d
        if needle in body:
            return t
    return None


def body_of(got):
    return b"".join(d for _, d in got)


def events(tag):
    out = []
    try:
        with open(ELOG) as f:
            for line in f:
                e = json.loads(line)
                if e.get("tag") == tag:
                    out.append(e)
    except FileNotFoundError:
        pass
    return out


def wait_event(tag, ev, within):
    end = time.time() + within
    while time.time() < end:
        for e in events(tag):
            if e["ev"] == ev:
                return e
        time.sleep(0.05)
    return None


def sse_body(n):
    return b"".join(b"data: event %d\n\n" % k for k in range(n))


# --- incremental relay of the three body framings --------------------------
def check_incremental(proto, route, n, gap, head=b""):
    tag = "%s-%s" % (route, proto)
    rc, got, t0 = run(proto, "/sse/%s?n=%d&gap=%s&tag=%s" % (route, n, gap, tag))
    done = wait_event(tag, "done", 2)
    first = first_at(got, b"data: event 0")
    want = head + sse_body(n)
    body = body_of(got)
    lead = (done["t"] - (t0 + first)) if (done and first is not None) else None
    report(rc == 0 and body == want,
           "%s %s: complete body, clean end (exit %d, %d/%d bytes)"
           % (proto, route, rc, len(body), len(want)))
    # the backend spends n*gap seconds; the first event is written after one
    # gap. It must reach the client long before the last one is written.
    report(lead is not None and lead > (n - 2) * gap,
           "%s %s: first event %s s after the request, %s s before the "
           "backend finished" % (proto, route,
                                 "%.2f" % first if first is not None else "never",
                                 "%.2f" % lead if lead is not None else "-"))


# --- no-progress timeout ------------------------------------------------------
def check_stall(proto):
    # head + ": stream open", then silence for longer than proxy_timeout (2 s)
    tag = "stall-" + proto
    rc, got, t0 = run(proto, "/sse/events?n=1&gap=4&tag=%s" % tag)
    took = time.time() - t0
    body = body_of(got)
    opened = body.startswith(b": stream open\n\n")
    # h1 relays a close-delimited body as one, so a cut there is a close the
    # client cannot tell from the end; h2 and h3 can say it, and must.
    clean_ok = True if proto == "h1" else rc != 0
    report(opened and b"event 0" not in body and 1.5 < took < 3.8 and clean_ok,
           "%s: a stream silent past proxy_timeout is cut after %.1f s "
           "(exit %d, head relayed first: %s)" % (proto, took, rc, opened))


# --- the client going away -----------------------------------------------------
def check_gone_curl(proto):
    # curl is killed: on TCP the kernel closes the connection for it, but a
    # QUIC client that dies sends nothing at all, so HTTP/3 can only notice at
    # the idle timeout (3 s in this fixture) -- the bound says which applies
    tag = "gone-" + proto
    rc, got, t0 = run(proto, "/sse/forever?gap=0.2&tag=" + tag,
                      stop=lambda b: b"data: event 1" in b)
    left = time.time()
    saw = b"data: event 1" in body_of(got)
    closed = wait_event(tag, "closed", 8) if saw else None
    lag = closed["t"] - left if closed else None
    bound = 6.0 if proto == "h3" else 1.5
    what = ("client vanished (no CONNECTION_CLOSE) -> upstream closed at the "
            "idle timeout" if proto == "h3" else "client connection closed -> "
            "upstream closed")
    report(saw and lag is not None and lag < bound,
           "%s: %s, %s s later" % (proto, what,
                                   "%.2f" % lag if lag is not None else "never"))


def h2_rst_client(tag):
    """One h2 stream on a raw TLS connection; RST_STREAM it after the second
    event and keep the connection open. -> time of the reset, or None."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    raw = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    s = ctx.wrap_socket(raw, server_hostname="localhost")
    if s.selected_alpn_protocol() != "h2":
        return None, s

    def frame(ft, fl, sid, pay=b""):
        return (struct.pack(">I", len(pay))[1:] + bytes([ft, fl])
                + struct.pack(">I", sid) + pay)

    def lit(n, v):
        return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v

    block = (lit(b":method", b"GET") + lit(b":scheme", b"https")
             + lit(b":authority", b"localhost")
             + lit(b":path", b"/sse/forever?gap=0.2&tag=" + tag.encode()))
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0)
              + frame(1, 0x05, 1, block))
    buf, data, reset_at = b"", b"", None
    s.settimeout(0.2)
    end = time.time() + 10
    while time.time() < end:
        try:
            d = s.recv(65536)
            if not d:
                break
            buf += d
        except socket.timeout:
            pass
        while len(buf) >= 9:
            ln = int.from_bytes(buf[:3], "big")
            if len(buf) < 9 + ln:
                break
            ft, fl = buf[3], buf[4]
            sid = int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
            pay = buf[9:9 + ln]
            buf = buf[9 + ln:]
            if ft == 4 and not fl & 1:
                s.sendall(frame(4, 1, 0))          # SETTINGS ack
            elif ft == 0 and sid == 1:
                data += pay
        if reset_at is None and b"data: event 1" in data:
            s.sendall(frame(3, 0, 1, struct.pack(">I", 8)))   # CANCEL
            reset_at = time.time()
        if reset_at is not None and time.time() - reset_at > 3:
            break
    return reset_at, s


def check_gone_h2_rst():
    tag = "rst-h2"
    reset_at, s = h2_rst_client(tag)
    closed = wait_event(tag, "closed", 5) if reset_at else None
    s.close()
    lag = closed["t"] - reset_at if closed else None
    report(lag is not None and lag < 1.5,
           "h2: RST_STREAM on an open connection -> upstream closed %s s later"
           % ("%.2f" % lag if lag is not None else "never"))


def h3_client(tag, how):
    """aioquic: one request; after the second event either reset the stream
    (RESET_STREAM + STOP_SENDING, connection kept) or close the connection.
    -> the time of that action, or None."""
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived
    addr = ("127.0.0.1", PORT)
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    conn.connect(addr, now=time.time())
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(0.05)

    def pump():
        for d, _ in conn.datagrams_to_send(now=time.time()):
            u.sendto(d, addr)

    pump()
    end = time.time() + 5
    while not conn._handshake_confirmed and time.time() < end:
        try:
            conn.receive_datagram(u.recvfrom(65536)[0], addr, now=time.time())
        except socket.timeout:
            pass
        pump()
    if not conn._handshake_confirmed:
        return None
    h3 = H3Connection(conn)
    sid = conn.get_next_available_stream_id()
    h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                          (b":authority", b"localhost"),
                          (b":path", b"/sse/forever?gap=0.2&tag=" + tag.encode())],
                    end_stream=True)
    pump()
    data, acted = b"", None
    end = time.time() + 10
    while time.time() < end:
        try:
            conn.receive_datagram(u.recvfrom(65536)[0], addr, now=time.time())
        except socket.timeout:
            pass
        timer = conn.get_timer()
        if timer is not None and timer <= time.time():
            conn.handle_timer(now=time.time())
        while True:
            ev = conn.next_event()
            if ev is None:
                break
            for h in h3.handle_event(ev):
                if isinstance(h, DataReceived) and h.stream_id == sid:
                    data += h.data
        if acted is None and b"data: event 1" in data:
            if how == "reset":
                conn.reset_stream(sid, 0x10c)
                conn.stop_stream(sid, 0x10c)
            else:
                conn.close(error_code=0x100)
            acted = time.time()
        pump()
        if acted is not None and (how == "close" or time.time() - acted > 3):
            break
    u.close()
    return acted


def check_gone_h3(how):
    tag = "%s-h3" % how
    try:
        acted = h3_client(tag, how)
    except ImportError:
        report(True, "h3 %s (skipped: aioquic unavailable)" % how)
        return
    closed = wait_event(tag, "closed", 5) if acted else None
    lag = closed["t"] - acted if closed else None
    what = ("RESET_STREAM + STOP_SENDING, connection kept" if how == "reset"
            else "CONNECTION_CLOSE")
    report(lag is not None and lag < 1.5,
           "h3: %s -> upstream closed %s s later"
           % (what, "%.2f" % lag if lag is not None else "never"))


# --- backpressure ---------------------------------------------------------------
def check_backpressure(proto):
    tag = "bp-" + proto
    # read at 100 KB/s for three seconds, then leave
    rc, got, t0 = run(proto, "/sse/flood?mb=64&tag=" + tag,
                      stop=lambda b: False, extra=["--limit-rate", "100k",
                                                   "--max-time", "3"])
    left = time.time()
    received = len(body_of(got))
    sent = max([e.get("sent", 0) for e in events(tag) if e["t"] <= left] + [0])
    closed = wait_event(tag, "closed", 5)
    report(received >= 100 * 1024 and sent < 16 * 1048576 and closed is not None,
           "%s: a slow reader holds the backend back (%d KiB read, backend "
           "wrote %d KiB of 65536 in 3 s, upstream closed after: %s)"
           % (proto, received // 1024, sent // 1024, closed is not None))


def check_flood(proto, mb=24):
    tag = "full-" + proto
    t0 = time.time()
    p = subprocess.run(curl_cmd(proto, "/sse/flood?mb=%d&tag=%s" % (mb, tag)),
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    took = time.time() - t0
    block = b"0123456789abcdef" * 4096
    want = hashlib.sha256(block * (mb * 1048576 // len(block))).hexdigest()
    got = hashlib.sha256(p.stdout).hexdigest()
    report(p.returncode == 0 and got == want,
           "%s: a %d MiB close-delimited body arrives byte-exact (exit %d, "
           "%d bytes, %.1f MB/s)" % (proto, mb, p.returncode, len(p.stdout),
                                     len(p.stdout) / took / 1e6))


def main():
    for proto in PROTOS:
        if proto == "h3" and not os.access(CURLH3, os.X_OK):
            report(True, "h3 checks (skipped: curl-h3 unavailable)")
            continue
        # six events 0.9 s apart: 5.4 s, longer than both proxy_timeout (2 s)
        # and the client idle timeout (3 s) of this fixture
        check_incremental(proto, "events", 6, 0.9, b": stream open\n\n")
        if QUICK:
            continue
        check_incremental(proto, "counted", 4, 0.8)
        check_incremental(proto, "chunked", 4, 0.8)
        check_stall(proto)
        check_gone_curl(proto)
        if proto == "h2":
            check_gone_h2_rst()
        if proto == "h3":
            check_gone_h3("reset")
            check_gone_h3("close")
        check_backpressure(proto)
        check_flood(proto)
    print("OK" if failures == 0 else "FAILED %d" % failures)


if __name__ == "__main__":
    main()
