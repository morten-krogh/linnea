#!/usr/bin/env python3
# HTTP/3 proxying (stage 3): a request routed to a proxy location is forwarded
# to an HTTP/1.1 upstream and its answer comes back over QUIC.
#
# The upstream leg has no client socket of its own -- the answer is owed to one
# stream of a QUIC connection -- so the response is captured whole and then
# streamed out of a response-stream slot like a file. What that has to get
# right, and what this checks: the status and body survive; the request line,
# query and client headers reach the backend; a chunked upstream is de-chunked
# and described by the length it really has; a close-delimited one ends at the
# close; a body far larger than one packet streams through the pump; hop-by-hop
# fields travel in neither direction; and an unreachable backend is a 502 on
# the stream rather than silence.
#
# Usage: h3_proxy_test.py <port>
import socket, ssl, sys, time
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

PORT = int(sys.argv[1])
ADDR = ("127.0.0.1", PORT)


def request(path, extra_headers=(), body=None, method=b"GET"):
    """One request on a connection of its own -> (status, headers, body)."""
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    vt = [0.0]

    def clk():
        vt[0] += 0.001
        return vt[0]

    conn.connect(ADDR, now=clk())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.1)

    def pump():
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ADDR)

    pump()
    dl = time.time() + 10
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            conn.receive_datagram(s.recvfrom(4096)[0], ADDR, now=clk())
        except socket.timeout:
            pass
        pump()
    if not conn._handshake_confirmed:
        s.close()
        return None, {}, "handshake failed"

    h3 = H3Connection(conn)
    sid = conn.get_next_available_stream_id()
    hdrs = [(b":method", method), (b":scheme", b"https"),
            (b":authority", b"localhost"), (b":path", path.encode())]
    hdrs += list(extra_headers)
    if body is not None:
        hdrs.append((b"content-length", str(len(body)).encode()))
    h3.send_headers(sid, hdrs, end_stream=body is None)
    if body is not None:
        h3.send_data(sid, body, end_stream=True)
    pump()

    status, head, data, done = None, {}, b"", False
    end = time.time() + 20
    while time.time() < end and not done:
        try:
            conn.receive_datagram(s.recvfrom(4096)[0], ADDR, now=clk())
        except socket.timeout:
            pass
        while True:
            ev = conn.next_event()
            if ev is None:
                break
            for e in h3.handle_event(ev):
                if isinstance(e, HeadersReceived):
                    head = {k.decode(): v.decode() for k, v in e.headers}
                    status = head.get(":status")
                    done = done or e.stream_ended
                elif isinstance(e, DataReceived):
                    data += e.data
                    done = done or e.stream_ended
        pump()
    s.close()
    return status, head, data.decode(errors="replace")


bad = []


def want(label, cond, detail=""):
    if not cond:
        bad.append(f"{label}: {detail}")


st, hd, body = request("/api/simple")
want("simple status", st == "200", f"{st} {body[:60]!r}")
want("simple body", body == "backend body", repr(body[:60]))
want("simple content-length", hd.get("content-length") == "12", hd.get("content-length"))
# the proxy names the hop, and the version it names is the one the RESPONSE
# was received on (RFC 9110 7.6.3) -- the request's own Via says 3
want("via", hd.get("via") == "1.1 linnea", hd.get("via"))
want("no keep-alive relayed", "keep-alive" not in hd, str(hd))

# the location prefix is not stripped and the query survives
st, hd, body = request("/api/target?x=1&y=2")
want("target forwarded", body == "/api/target?x=1&y=2", repr(body))

# an arbitrary client header reaches the backend -- the whole point of the
# header rebuild -- while the ones the proxy owns are its own to state
st, hd, body = request("/api/headers", extra_headers=[(b"x-test", b"abc")])
want("client header forwarded", "X-Test: abc" in body or "x-test: abc" in body, repr(body[:200]))
want("host rewritten from :authority", "Host: localhost" in body, repr(body[:200]))
want("connection close upstream", "Connection: close" in body, repr(body[:200]))

# chunked upstream: de-chunked on the way in, so the client is told the length
# the body really has and never sees the framing
st, hd, body = request("/api/chunked")
want("chunked status", st == "200", str(st))
want("chunked body", body == "chunked body", repr(body))
want("chunked re-lengthed", hd.get("content-length") == "12", hd.get("content-length"))
want("no transfer-encoding", "transfer-encoding" not in hd, str(hd))

# close-delimited upstream: the close is the framing
st, hd, body = request("/api/eof")
want("eof body", body == "eof delimited body", repr(body))

# a body far larger than one QUIC packet: it streams out of the mapping through
# the pump, chunk by chunk, exactly as a large static file does
st, hd, body = request("/api/big")
want("big status", st == "200", str(st))
want("big length", len(body) == 40000, str(len(body)))
want("big intact", body == "x" * 40000, f"first bad byte at {next((i for i, c in enumerate(body) if c != 'x'), -1)}")

# response hop-by-hop fields stop here (RFC 9110 7.6.1); the rest goes on
st, hd, body = request("/api/hopresp")
want("hopresp keeps x-kept", hd.get("x-kept") == "yes", str(hd))
for name in ("keep-alive", "te", "trailer", "proxy-connection", "proxy-authenticate"):
    want(f"hopresp drops {name}", name not in hd, str(hd))

# a request body is forwarded whole
st, hd, body = request("/api/echo", body=b"hello over h3", method=b"POST")
want("post echoed", body == "hello over h3", repr(body))

# ...including one far past a single packet. An h3 request used to be bounded
# by the buffer it was reassembled in, so an upload could not exceed 8 KB and a
# larger one simply stalled -- the client was flow-controlled to a window that
# never moved. The stream is consumed as it arrives now and its body captured to
# a file, so what bounds it is the window, not the buffer a request is held in.
# (printable bytes, so the helper's lossy decode round-trips and a difference
# is a difference rather than an artefact of comparing through it)
for n in (20000, 30000, 100000, 199000):
    payload = bytes((i * 37 + 11) % 26 + 97 for i in range(n))
    st, hd, body = request("/api/echo", body=payload, method=b"POST")
    want(f"upload of {n} bytes", st == "200", str(st))
    want(f"upload of {n} bytes intact", body == payload.decode(),
         f"{len(body)} of {n} bytes back")

# ...and max_body still bounds it. The window slides, so size alone no longer
# stops anything; what stops this is the cap, answered on the stream as a 413
# rather than as a reset the client would have to interpret.
st, hd, body = request("/api/echo", method=b"POST",
                       body=b"z" * 250000)      # the fixture's max_body is 200000
want("upload past max_body is 413", st == "413", f"{st} {body[:30]!r}")

# HEAD is deliberately not checked here. A HEAD response states the content
# length the GET would have had and carries no body (RFC 9110 9.3.2), and this
# client cannot accept that: aioquic's H3Connection does not track the request
# method, so it measures the DATA against the stated length and closes the
# connection. It does the same to linnea's STATIC HEAD over h3, which has
# shipped for a long time, so it is the client's limitation and not ours -- the
# h1 and h2 HEAD tests use curl, which knows what it asked for.

# nothing listening on the location's upstream: an answer, not silence
st, hd, body = request("/down/x")
want("unreachable is 502", st == "502", f"{st} {body[:40]!r}")

# a static location on the same vhost is unaffected
st, hd, body = request("/hello.txt")
want("static still served", st == "200", str(st))


def abandon(path):
    """Send a proxied request and close the connection before the backend has
    answered. The leg outlives the client, and its answer must be dropped
    rather than sent to whichever connection holds that slot by then."""
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    vt = [0.0]

    def clk():
        vt[0] += 0.001
        return vt[0]

    conn.connect(ADDR, now=clk())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.1)

    def pump():
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ADDR)

    pump()
    dl = time.time() + 10
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            conn.receive_datagram(s.recvfrom(4096)[0], ADDR, now=clk())
        except socket.timeout:
            pass
        pump()
    h3 = H3Connection(conn)
    sid = conn.get_next_available_stream_id()
    h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                          (b":authority", b"localhost"), (b":path", path.encode())],
                    end_stream=True)
    pump()
    time.sleep(0.2)
    conn.close(error_code=0)          # a CONNECTION_CLOSE, then nothing
    pump()
    s.close()


# The backend takes 1.5s; the client is gone within 0.2s. Two of them, so a
# freed slot could be handed to the second while the first is still in flight.
abandon("/api/linger")
abandon("/api/linger")
time.sleep(2.5)
st, hd, body = request("/api/simple")
want("survives an abandoned exchange", st == "200", f"{st} {body[:40]!r}")

print("OK" if not bad else "; ".join(bad))
sys.exit(0 if not bad else 1)
