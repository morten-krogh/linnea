#!/usr/bin/env python3
"""Every variant, split at every byte offset of the response, driven through h1.

drive.py asks whether a malformed chunked response is refused. This asks whether
the answer depends on where the upstream happened to flush -- because HTTP/1 is
the protocol that relays as it streams, and its validator has to carry state
from the read that brought the head into every read after it.

The rule is report 24's: a malformed body must never become a clean, COMPLETE
response. Where the split falls decides only WHICH refusal -- 502 while the head
is still unsent, a closed unterminated message once it has gone -- never whether
there is one. A valid body must arrive whole wherever it is cut.

Written for audit-report-25, which read the relay path as unvalidated. It is
not: 4057 splits, 0 wrong. Needs splitback.py on 62950 and a linnea whose /api
proxies to it, on plain HTTP:

    python3 splitback.py 62950 &
    python3 splitdrive.py            # or: splitdrive.py <variant-name> ...
"""
import socket, sys
sys.path.insert(0, ".")
from variants import V
PORT = int(__import__("os").environ.get("LINNEA_SPLIT_PORT", 64180))
HEAD_LEN = len(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")

def fetch(n, k):
    s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    s.sendall(b"GET /api/s%d_%d HTTP/1.1\r\nHost: one.test\r\n\r\n" % (n, k))
    s.settimeout(10)
    buf = b""
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
    return head.split(b"\r\n")[0], body

def dechunk(buf):
    """(decoded, complete). Complete means the terminating chunk AND the empty
    line that closes the trailer section both arrived -- "ends with 0\\r\\n\\r\\n"
    is not that test: a body carrying a trailer, or an extension on the last
    chunk, ends with neither. Getting this wrong made 422 VALID relays look
    like failures."""
    out, i = b"", 0
    while True:
        j = buf.find(b"\r\n", i)
        if j < 0:
            return out, False
        line = buf[i:j]
        size_txt = line.split(b";", 1)[0].strip()
        try:
            n = int(size_txt, 16)
        except ValueError:
            return out, False
        i = j + 2
        if n == 0:
            # the trailer section runs to an empty line
            while True:
                k = buf.find(b"\r\n", i)
                if k < 0:
                    return out, False
                if k == i:
                    return out, True
                i = k + 2
        if len(buf) < i + n + 2:
            return out, False
        out += buf[i:i + n]
        i += n + 2


only = sys.argv[1:] or None
bad = 0
checked = 0
for n, (name, body, verdict) in enumerate(V):
    if only and name not in only:
        continue
    want = b"bodybody!!" if body.startswith((b"a\r\n", b"A\r\n")) else b"body"
    whole = HEAD_LEN + len(body)
    for k in range(0, whole + 1):
        status, got = fetch(n, k)
        checked += 1
        decoded, complete = dechunk(got)
        ok200 = b" 200 " in status
        if verdict == "bad" and ok200 and complete:
            bad += 1
            print(f"  {name} split@{k}: CLEAN COMPLETE 200 -- {got[:60]!r}")
        if verdict == "ok" and not (ok200 and complete and decoded == want):
            bad += 1
            print(f"  {name} split@{k}: VALID body not relayed -- "
                  f"{status!r} decoded={decoded!r} complete={complete} {got[:60]!r}")
print(f"{checked} splits driven, {bad} wrong")
sys.exit(1 if bad else 0)
