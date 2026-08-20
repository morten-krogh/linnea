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


# --- Cookie: split lines must be JOINED before a hop that is not h2/h3 -------
# RFC 9113 8.2.3 and RFC 9114 4.2.1, in the same words: a client may split
# Cookie across field lines for compression, and an intermediary MUST
# concatenate them with "; " before passing them on. h2 has since Finding 32;
# h3 never did, because the decoder guards the rule on a buffer h3 was not
# given -- a guard added to stop a null write from crashing, which also
# switched the behaviour off. A backend reading Cookie sees the first line
# only, so a session cookie a browser split was silently truncated.
def cookie_case(label, headers, expect):
    global fails
    got = {}
    for p in protos:
        body = fetch_body(p, headers, "/api/headers")
        lines = [l.split(":", 1)[1].strip()
                 for l in body.replace("\r", "").split("\n")
                 if l.lower().startswith("cookie:")]
        got[p] = "|".join(lines)
    want = {p: (expect[p] if isinstance(expect, dict) else expect) for p in protos}
    if got == want:
        print(f"ok   {label}")
    else:
        print(f"FAIL {label}: want {want}, got {got}")
        fails += 1


def fetch_body(proto, headers, path):
    """The response BODY, which is where the echo backend reports what it was
    given. run() discards it (-o /dev/null): the first version of these cases
    asked run() for a body, got the response HEAD, found no cookie lines in it
    and passed -- a check that could not fail. The cookie rows failed loudly
    and gave it away; the Expect row would have passed forever."""
    cmd = ([curl_h3, "--http3-only"] if proto == "h3" else ["curl", f"--{proto}"])
    cmd += ["-s", "--max-time", "12", "--cacert", ca, "--resolve", RESOLVE]
    for h in headers:
        cmd += ["-H", h]
    cmd.append(f"https://localhost:{port}{path}")
    return subprocess.run(cmd, capture_output=True, text=True).stdout


SPLIT = ["Cookie: a=1", "Cookie: b=2", "Cookie: c=3"]
# HTTP/1 relays what it was given: an h1 client does not split Cookie, and
# forwarding the lines as they arrived is what an h1 hop is for.
cookie_case("split cookie lines are joined for the backend",
            SPLIT, {"http1.1": "a=1|b=2|c=3", "http2": "a=1; b=2; c=3",
                    "h3": "a=1; b=2; c=3"})
cookie_case("one cookie line is passed through unchanged",
            ["Cookie: a=1; b=2"], "a=1; b=2")


# --- Expect: 100-continue is ours to answer, not the backend's ---------------
# The same guard switched this off for h3 too, so an h3 client's
# Expect: 100-continue was forwarded upstream and no interim 100 was generated.
def expect_case(label, headers, want_count):
    """want_count is how many Expect lines the backend should see."""
    global fails
    got = {}
    for p in protos:
        body = fetch_body(p, headers, "/api/headers")
        got[p] = sum(1 for l in body.replace("\r", "").split("\n")
                     if l.lower().startswith("expect:"))
    if all(v == want_count for v in got.values()):
        print(f"ok   {label}")
    else:
        print(f"FAIL {label}: want {want_count} everywhere, got {got}")
        fails += 1


expect_case("Expect: 100-continue never reaches the backend",
            ["Expect: 100-continue"], 0)
# ...and an expectation we do NOT know is the backend's to refuse with a 417,
# so it must travel. HTTP/1 dropped every Expect, which made it the only
# protocol that never gave the backend the chance; HTTP/2 and HTTP/3 answered
# 431 to one instead, because the field NAME was destroyed by the comparison
# that decided it was not 100-continue and the rebuilt line ran the header
# block past its end.
expect_case("an unknown expectation is forwarded for the backend to refuse",
            ["Expect: other-expectation"], 1)

# --- ...and where WE are the origin, we refuse it ourselves -------------------
# 100-continue is the only expectation this server can meet. Another one used to
# fall through to ordinary processing: the resource was served, which tells the
# client by omission that its expectation was honoured (audit-report-33). A
# proxy location still forwards it, because there the backend is the one asked
# and may well be able to meet it -- which is the whole distinction.
case("an unknown expectation on a static path is 417",
     ["Expect: feature-x"], "417")
case("...and on a redirect, which is equally our own answer",
     ["Expect: feature-x"], "417", path="/old")
case("...but a proxy location forwards it instead of refusing",
     ["Expect: feature-x"], "200", path="/api/simple")
case("100-continue alone is still met, not refused",
     ["Expect: 100-continue"], "200")
case("a redirect without one still redirects",
     [], "301", path="/old")
# a value we do not understand IN FULL is one we cannot promise to meet, so a
# recognised member cannot conceal an unsupported one -- in a list or on a
# second field line
case("a list carrying an unknown member is 417",
     ["Expect: 100-continue, feature-x"], "417")
case("a second line carrying an unknown member is 417",
     ["Expect: 100-continue", "Expect: feature-x"], "417")

sys.exit(1 if fails else 0)
