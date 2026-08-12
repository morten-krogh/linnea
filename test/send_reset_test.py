#!/usr/bin/env python3
# A client that RESETS the connection while a response is still being sent.
#
# "send error" carried no errno at all, and ECONNRESET/EPIPE on the sending side
# are not errors: they are what a client closing a tab, navigating away or
# trimming its pool looks like from the other end. The receive side learned that
# in 911e0b9; the send side kept filing all of it as "send error", 49 times in
# the production log, with nothing to say which write failed or why.
#
# This drives exactly that: request a response far larger than any socket
# buffer, read one byte so the server is definitely mid-send, then close with
# SO_LINGER 0 — which sends a TCP RST rather than a FIN, so the server's
# in-flight send completes with ECONNRESET instead of merely running dry.
#
# The observable is the close reason the server writes for THAT connection,
# matched by its source port so a concurrent connection cannot be mistaken for
# it. Before the fix it reads "send error"; after, "peer reset".
#
# Note both sides can now answer "peer reset" — the recv path has since
# 911e0b9 — so the reason alone does not prove WHICH path produced it. What
# does is the A/B: the pre-fix binary says "send error" for this same scenario,
# and only the send path changed.
#
# Usage: send_reset_test.py <port> <logfile> [expected-reason] [plain]
import re, socket, ssl, struct, sys, time

PORT = int(sys.argv[1])
LOG = sys.argv[2]
WANT = sys.argv[3] if len(sys.argv) > 3 else "peer reset"

PLAIN = len(sys.argv) > 4 and sys.argv[4] == "plain"

sock = socket.create_connection(("127.0.0.1", PORT), timeout=10)
if PLAIN:
    s = sock
else:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    s = ctx.wrap_socket(sock, server_hostname="localhost")
myport = s.getsockname()[1]
s.sendall(b"GET /huge.bin HTTP/1.1\r\nHost: one.test\r\n\r\n" if PLAIN
          else b"GET /huge.bin HTTP/1.1\r\nHost: localhost\r\n\r\n")

# One byte proves the response is under way; stopping there leaves the rest
# queued, so there is a send in flight when the reset lands.
s.settimeout(10)
first = s.recv(1)
if not first:
    print("no response at all; nothing was in flight to fail")
    sys.exit(1)
time.sleep(0.2)                       # let the server queue more behind it

s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
s.close()                             # linger 0 -> RST, not FIN

# The reason is written when the server notices, a moment later. The close
# line carries only the fd — the PEER's port is on the accept line — so the two
# are correlated through it: find the accept for our source port, then the
# first close of that same fd after it. Taking the last close line instead
# would attribute someone else's connection on a busy fixture.
acc = re.compile(r"accepted connection on \S+ from (\S+):(\d+) \(fd (\d+)\)")
clo = re.compile(r"closed connection on \S+ \(fd (\d+)\): (.*)$")
deadline = time.time() + 10
reason = None
while time.time() < deadline and reason is None:
    myfd, seen_at = None, None
    try:
        lines = open(LOG, "r", errors="replace").read().splitlines()
    except FileNotFoundError:
        lines = []
    for i, line in enumerate(lines):
        m = acc.search(line)
        if m and int(m.group(2)) == myport:
            myfd, seen_at = m.group(3), i
    if myfd is not None:
        for line in lines[seen_at + 1:]:
            m = clo.search(line)
            if m and m.group(1) == myfd:
                reason = m.group(2)
                break
    if reason is None:
        time.sleep(0.25)

if reason is None:
    print("no close line correlated to source port %d in %s" % (myport, LOG))
    sys.exit(1)
if reason != WANT:
    print("closed with %r, want %r" % (reason, WANT))
    sys.exit(1)
print("ok (a reset mid-response is reported as %r)" % reason)
