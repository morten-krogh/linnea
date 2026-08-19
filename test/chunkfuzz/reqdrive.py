"""Drive every variant as an HTTP/1 REQUEST body, through both request decoders,
and flag any disagreement between them or any malformed body accepted.

drive.py sweeps RESPONSE bodies -- the direction all three protocols share.
A request may be chunked over HTTP/1 alone, and there it is read by
chunked_decode while the body fits in LINNEA_CONN_IN_BUF (17408 bytes) and by
linnea_spill_chunked above it. Two decoders, one grammar, and nothing but the
body SIZE deciding which one answers: pad 0 stays buffered, pad 40000 forces the
capture path. That is what this asks.

It found audit-report-22's second defect -- a size bound that had assembled to
something that could never fire, so a 17-digit size wrapped to zero and the rest
of the body was served as a pipelined request -- while verifying the first.

Needs a linnea whose /api is a proxy location (the request must reach a route
that accepts a body; a static location takes none):

    python3 reqdrive.py <linnea-plain-http-port>
"""
import socket, sys
sys.path.insert(0, ".")
from variants import V

PORT = int(sys.argv[1])


def run(pad, body):
    lead = b"%x\r\n" % pad + b"P" * pad + b"\r\n" if pad else b""
    s = socket.create_connection(("127.0.0.1", PORT), timeout=8)
    try:
        s.sendall(b"POST /api/echo HTTP/1.1\r\nHost: one.test\r\n"
                  b"Transfer-Encoding: chunked\r\n\r\n" + lead + body)
        s.shutdown(socket.SHUT_WR)        # nothing more is coming
        buf = b""
        while b"\r\n" not in buf:
            d = s.recv(65536)
            if not d:
                # a truncated body leaves the decoder mid-state: the server is
                # right to wait, and the close is the answer
                return "EOF" if not buf else buf.split(b"\r\n")[0].decode()
            buf += d
        return buf.split(b"\r\n")[0].decode()[9:]
    except OSError as e:
        return type(e).__name__
    finally:
        s.close()


dis = acc = 0
for name, body, verdict in V:
    a, b = run(0, body), run(40000, body)
    flag = ""
    if a != b:
        flag += "   DISAGREE"
        dis += 1
    if verdict == "bad" and (a.startswith("200") or b.startswith("200")):
        flag += "   ACCEPTED"
        acc += 1
    print(f"  {name:<22} {verdict:<4} buffered={a:<22} captured={b:<22}{flag}")
print(f"\n{dis} disagreements, {acc} malformed accepted, of {len(V)} variants")
sys.exit(1 if dis or acc else 0)
