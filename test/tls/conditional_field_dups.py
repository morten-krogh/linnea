#!/usr/bin/env python3
"""Repeated field lines: the singleton conditionals, and Accept-Encoding.

Two rules meet here, and both were decided per protocol rather than per field.

SINGLETONS. If-Modified-Since, If-Unmodified-Since, Range and If-Range each
define one date, validator or range -- not a list -- so two of them are a
request that says two different things. HTTP/1 kept the FIRST and HTTP/2 and
HTTP/3 kept the LAST, so one request was 200 on one protocol and 304 on
another, and a doubled Range served byte 0 over HTTP/1 and byte 10 over the
other two (audit-report-32). All three refuse a repeat now, as they have always
refused a repeated Host or Content-Length. On HTTP/1 that is 400; on the binary
protocols a malformed request is a stream error (RFC 9113 8.1.1), which curl
reports as no status at all -- the same treatment a duplicate Content-Length
has had there since it was written.

ACCEPT-ENCODING is the opposite kind of field: a list, where repeated lines
combine and a coding is acceptable if ANY line accepts it. HTTP/1 has recorded
one span per line since h1-14; HTTP/2 and HTTP/3 kept only the last, so
`Accept-Encoding: br` followed by `Accept-Encoding: identity` served the plain
file there and the .br variant here. Found beside report 32 -- on the very
field whose treatment report 30 cited as the precedent for fixing the ETag
lists.

usage: conditional_field_dups.py <port> <cafile> [curl-h3]
"""
import subprocess
import sys

port, ca = sys.argv[1], sys.argv[2]
curl_h3 = sys.argv[3] if len(sys.argv) > 3 else None
RESOLVE = f"localhost:{port}:127.0.0.1"
PAST = "If-Modified-Since: Wed, 01 Jan 2020 00:00:00 GMT"
FUTURE = "If-Modified-Since: Fri, 01 Jan 2100 00:00:00 GMT"
U_PAST = "If-Unmodified-Since: Wed, 01 Jan 2020 00:00:00 GMT"
U_FUTURE = "If-Unmodified-Since: Fri, 01 Jan 2100 00:00:00 GMT"

protos = ["http1.1", "http2"] + (["h3"] if curl_h3 else [])
# a refused request: HTTP/1 answers 400, the binary protocols reset the stream
REFUSED = {"http1.1": "400", "http2": "000", "h3": "000"}


def run(proto, headers, path="/hello.txt", want_header=None):
    cmd = ([curl_h3, "--http3-only"] if proto == "h3" else ["curl", f"--{proto}"])
    cmd += ["-s", "-o", "/dev/null", "-D", "-", "-w", "\n%{http_code}",
            "--max-time", "12", "--cacert", ca, "--resolve", RESOLVE]
    for h in headers:
        cmd += ["-H", h]
    cmd.append(f"https://localhost:{port}{path}")
    p = subprocess.run(cmd, capture_output=True, text=True)
    code = p.stdout.strip().split("\n")[-1].strip()
    if want_header is None:
        return code
    value = "plain"
    for line in p.stdout.replace("\r", "").split("\n"):
        if line.lower().startswith(want_header.lower() + ":"):
            value = line.split(":", 1)[1].strip()
    return f"{code}/{value}"


fails = 0


def case(label, headers, expect, **kw):
    global fails
    got = {p: run(p, headers, **kw) for p in protos}
    want = {p: (expect[p] if isinstance(expect, dict) else expect) for p in protos}
    if got == want:
        print(f"ok   {label}")
    else:
        print(f"FAIL {label}: want {want}, got {got}")
        fails += 1


# --- singletons: a repeat is refused, whichever order it is written in -------
for name, a, b in (("If-Modified-Since", PAST, FUTURE),
                   ("If-Unmodified-Since", U_PAST, U_FUTURE),
                   ("Range", "Range: bytes=0-0", "Range: bytes=10-10"),
                   ("If-Range", 'If-Range: "a"', 'If-Range: "b"')):
    case(f"a repeated {name} is refused", [a, b], REFUSED)
    case(f"a repeated {name}, reversed, is refused too", [b, a], REFUSED)

# ...and one of each still works, or the rule would be "refuse the field"
case("one If-Modified-Since in the past is still 200", [PAST], "200")
case("one If-Modified-Since in the future is still 304", [FUTURE], "304")
case("one If-Unmodified-Since in the future is still 200", [U_FUTURE], "200")
case("one Range is still 206", ["Range: bytes=0-0"], "206")

# --- Accept-Encoding: a list, so every line counts ---------------------------
case("Accept-Encoding: br on its own line is honoured",
     ["Accept-Encoding: br"], "200/br", path="/aetest.txt", want_header="content-encoding")
case("...and still is when a later line does not mention it",
     ["Accept-Encoding: br", "Accept-Encoding: identity"], "200/br",
     path="/aetest.txt", want_header="content-encoding")
case("...or when an earlier line does not",
     ["Accept-Encoding: gzip", "Accept-Encoding: br"], "200/br",
     path="/aetest.txt", want_header="content-encoding")
case("no Accept-Encoding at all serves the plain file",
     [], "200/plain", path="/aetest.txt", want_header="content-encoding")

sys.exit(1 if fails else 0)
