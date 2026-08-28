#!/usr/bin/env python3
"""A transfer coding is not something an HTTP/1.0 request may be answered with.

RFC 9112 7.1: "A server MUST NOT send a response containing Transfer-Encoding
unless the corresponding request indicates HTTP/1.1 (or later minor
revisions)." The version linnea writes on its own response line is 1.1 for
every HTTP/1 answer, which is what made this look conformant -- but the rule is
about the version that was ASKED IN, not the one we answer in.

audit-report-130: the proxy response head appended "Transfer-Encoding: chunked"
whenever the upstream response carried one, with no test of the request's
version, and then relayed the body byte for byte. A 1.0 client got the
prohibited field and the chunk size lines and terminal chunk as content: the
response to /api/chunked was "7\\r\\nchunked\\r\\n5\\r\\n body\\r\\n0\\r\\n\\r\\n"
where "chunked body" was the resource.

The fix de-chunks while relaying instead. The branch is already the
close-delimited one, so the "Connection: close" that delimits the message for a
1.0 client was already being sent and is asserted here too.

Every row is paired, because a blanket build passes half of this on its own:

  * a build that simply stopped sending Transfer-Encoding and relayed the body
    unchanged fails the 1.0 BODY rows -- the client would still get framing;
  * a build that de-chunked EVERYTHING fails the 1.1 control rows, which must
    still receive the upstream's framing verbatim, field and all;
  * a build that dropped the body when de-chunking fails the 1.0 body rows;
  * the two non-chunked rows (counted and close-delimited) are 1.0 responses
    this rule never touched, and must be byte-identical to what they were.

The routes span the two places the decoder runs -- the leftover that arrives
behind the response head, and each later relay read -- and the cases that are
only reachable from one of them:

  /api/chunked        head and whole body in one write: the leftover path
  /api/chunklategood  head, pause, body: the relay-read path
  /api/chunksplitok   head + "4;a=", pause, "bad\\r\\nbody...": the leftover
                      decodes to ZERO bytes, so there is nothing to send behind
                      the head and the relay has to carry on without one
  /api/chunkkeepalive complete body, then the backend holds the socket 3s: the
                      exchange still has to end at the TERMINAL CHUNK
                      (audit-report-26) even though the framing is being
                      stripped, so this row is timed
  /api/chunktrunc     a body that stops mid-chunk: the client gets the decoded
                      prefix and a close, and never a completed message
  /api/chunklatebad   malformed framing after the head is gone: h1 declines to
                      finish (audit-report-24), which de-chunking must not undo

usage: h1_proxy_http10_chunked.py <front port>
"""
import socket
import sys
import time

port = int(sys.argv[1])


def fetch(path, version):
    """One request, then read to the close. Every response here is
    close-delimited, so the close IS the end of the body."""
    s = socket.create_connection(("127.0.0.1", port), timeout=15)
    s.settimeout(15)
    s.sendall(b"GET %s HTTP/%s\r\nHost: one.test\r\n\r\n"
              % (path.encode(), version))
    buf = b""
    started = time.time()
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
    except OSError:
        pass
    s.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    return head.decode("latin1", "replace"), body, time.time() - started


def field(head, name):
    for line in head.split("\r\n")[1:]:
        n, _, v = line.partition(":")
        if n.strip().lower() == name:
            return v.strip()
    return None


DECODED = b"chunked body"          # what /api/chunked's framing encodes
ENCODED = b"7\r\nchunked\r\n5\r\n body\r\n0\r\n\r\n"

# (label, path, version, want Transfer-Encoding, want body)
cases = [
    # the finding: a 1.0 request must get neither the field nor the framing
    ("1.0 chunked", "/api/chunked", b"1.0", None, DECODED),
    ("1.1 chunked (control)", "/api/chunked", b"1.1", "chunked", ENCODED),

    # the same, decoded on a later read rather than behind the head
    ("1.0 chunked late", "/api/chunklategood", b"1.0", None, b"body"),
    ("1.1 chunked late (control)",
     "/api/chunklategood", b"1.1", "chunked", b"4\r\nbody\r\n0\r\n\r\n"),

    # the leftover behind the head is "4;a=" -- all framing, no data
    ("1.0 chunked split ext", "/api/chunksplitok", b"1.0", None, b"body"),
    ("1.1 chunked split ext (control)",
     "/api/chunksplitok", b"1.1", "chunked", b"4;a=bad\r\nbody\r\n0\r\n\r\n"),

    # a body that stops mid-chunk: the decoded prefix, and no more
    ("1.0 chunked truncated", "/api/chunktrunc", b"1.0", None, b"bo"),
    ("1.1 chunked truncated (control)",
     "/api/chunktrunc", b"1.1", "chunked", b"4\r\nbo"),

    # malformed framing arriving after the head: nothing of that read is
    # forwarded and the message is never finished (audit-report-24)
    ("1.0 chunked bad late", "/api/chunklatebad", b"1.0", None, b""),
    ("1.1 chunked bad late (control)",
     "/api/chunklatebad", b"1.1", "chunked", b""),

    # ...and the two 1.0 framings this rule does not touch
    ("1.0 counted (control)", "/api/simple", b"1.0", None, b"backend body"),
    ("1.0 close-delimited (control)",
     "/api/eof", b"1.0", None, b"eof delimited body"),
]

fails = 0
for label, path, version, want_te, want_body in cases:
    head, body, _ = fetch(path, version)
    te = field(head, "transfer-encoding")
    if not head.startswith("HTTP/1.1 200"):
        print("FAIL %-32s status %r" % (label, head.split("\r\n")[0]))
        fails += 1
    elif te != want_te:
        print("FAIL %-32s Transfer-Encoding %r (want %r)"
              % (label, te, want_te))
        fails += 1
    elif body != want_body:
        print("FAIL %-32s body %r (want %r)" % (label, body, want_body))
        fails += 1
    else:
        print("ok   %-32s TE %-8s body %r" % (label, te or "(absent)", body))

# The close is what delimits a de-chunked 1.0 response, so it has to be there.
# Without it the client has no framing at all -- which would be a worse defect
# than the one this test exists for.
head, _, _ = fetch("/api/chunked", b"1.0")
if (field(head, "connection") or "").lower() != "close":
    print("FAIL %-32s Connection %r (want close)"
          % ("1.0 chunked closes", field(head, "connection")))
    fails += 1
else:
    print("ok   %-32s Connection: close" % "1.0 chunked closes")

# A chunked message ends at its terminal chunk, not at the upstream's close
# (audit-report-26). Stripping the framing must not cost that: this backend
# sends a complete body and then holds its socket open for three seconds.
head, body, took = fetch("/api/chunkkeepalive", b"1.0")
if body != b"body" or field(head, "transfer-encoding") is not None:
    print("FAIL %-32s TE %r body %r"
          % ("1.0 ends at the terminal chunk",
             field(head, "transfer-encoding"), body))
    fails += 1
elif took > 1.5:
    print("FAIL %-32s complete but took %.1fs -- it waited for the upstream"
          % ("1.0 ends at the terminal chunk", took))
    fails += 1
else:
    print("ok   %-32s %r in %.2fs"
          % ("1.0 ends at the terminal chunk", body, took))

sys.exit(1 if fails else 0)
