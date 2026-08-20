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
lists. Its `*` entry was ignored outright until report 36, which made `*;q=0`
answer 200 and `*` serve the unencoded file past a variant it could have sent.

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
# Three spans is more than any client sends, and a FOURTH line is refused
# rather than dropped. The reasoning that once let it be dropped was mine, in
# report 32: "a fourth line can only narrow what is served, never answer
# wrongly". A list member can be a PROHIBITION -- identity;q=0 says the
# unencoded form is unacceptable -- so dropping one can turn a refusal into
# permission. And even for ordinary preferences the same legal request served a
# different representation depending only on which line carried br
# (audit-report-35).
case("three Accept-Encoding lines are all honoured",
     ["Accept-Encoding: identity", "Accept-Encoding: gzip",
      "Accept-Encoding: br"], "200/br",
     path="/aetest.txt", want_header="content-encoding")
# identity;q=0 forbids the unencoded form (RFC 9110 12.5.3). The negotiation
# only ever asked whether br or gzip was allowed, never whether the form it
# actually falls back to was -- so a client that refused the unencoded
# representation was served it, on all three protocols (audit-report-35).
# Nothing here is available that this client will take, which is a 406.
case("identity;q=0 with nothing else acceptable is 406",
     ["Accept-Encoding: identity;q=0"], "406/plain",
     path="/aetest.txt", want_header="content-encoding")
# ...but refusing identity is not refusing everything: br is offered and we
# have it. Without this row the rule could become "identity;q=0 is always 406".
case("...while identity;q=0 with br still serves br",
     ["Accept-Encoding: identity;q=0, br"], "200/br",
     path="/aetest.txt", want_header="content-encoding")
# only q=0 refuses; any nonzero q still allows the unencoded form
case("identity;q=0.5 still allows the plain file",
     ["Accept-Encoding: identity;q=0.5"], "200/plain",
     path="/aetest.txt", want_header="content-encoding")
case("a fourth is refused, not silently dropped",
     ["Accept-Encoding: identity", "Accept-Encoding: gzip",
      "Accept-Encoding: deflate", "Accept-Encoding: br"], "431/plain",
     path="/aetest.txt", want_header="content-encoding")


# --- the wildcard, which stands for every coding the list does not name -------
# RFC 9110 12.5.3 gives three steps in order: a coding named explicitly is
# governed by its own q; otherwise `*` governs; otherwise the coding is
# unacceptable -- except identity, which is acceptable by default. Only the
# first and last were implemented, so `*` was read as if it were absent: `*;q=0`
# refused nothing and was answered 200, and `*` selected nothing and fell back
# to the unencoded file even where a variant was sitting there (audit-report-36).
#
# The reason I gave for leaving it out, one commit earlier, was that honouring
# `*` "would mean guessing which coding the client meant". That guess only
# exists for `*` used as a POSITIVE selector, and there is none to make here:
# this server holds two variants and prefers br to gzip, and choosing among
# codings the client called equally acceptable is the server's to make. The
# NEGATIVE case, `*;q=0`, never needed a guess at all.
case("Accept-Encoding: * takes the coding this server prefers",
     ["Accept-Encoding: *"], "200/br",
     path="/aetest.txt", want_header="content-encoding")
# br is tried first, so a row where br exists cannot tell "the wildcard chose"
# from "the wildcard was ignored and br happened to be first". This one can.
case("...and reaches gzip where that is the variant there is",
     ["Accept-Encoding: *"], "200/gzip",
     path="/gztest.txt", want_header="content-encoding")
case("...and asks for no coding where there is none",
     ["Accept-Encoding: *"], "200/plain",
     path="/hello.txt", want_header="content-encoding")
# the negative half: identity is acceptable by default, and *;q=0 is one of the
# two ways RFC 9110 names for excluding it
case("*;q=0 refuses every coding not named, identity included",
     ["Accept-Encoding: *;q=0"], "406/plain",
     path="/hello.txt", want_header="content-encoding")
case("...and is not rescued by variants the client did not name",
     ["Accept-Encoding: *;q=0"], "406/plain",
     path="/aetest.txt", want_header="content-encoding")
# "unless a more specific entry for identity exists", in the RFC's words
# a control, not a test: with identity named and allowed and no coding named,
# a build that ignores the wildcard answers plain too. There is no resource on
# which this request distinguishes them -- kept because the rule must not
# over-apply and start refusing it.
case("...unless identity is allowed separately",
     ["Accept-Encoding: *;q=0, identity;q=1"], "200/plain",
     path="/aetest.txt", want_header="content-encoding")
case("...or a coding we hold is",
     ["Accept-Encoding: *;q=0, br;q=1"], "200/br",
     path="/aetest.txt", want_header="content-encoding")
# ...and the row above only shows the half it names. br is this server's first
# preference, so serving br proves nothing about whether *;q=0 excluded gzip and
# identity -- it is the same answer a build that ignores the wildcard gives. On a
# resource holding gzip and no br, the same request has nowhere to go and must be
# 406; that one fails on a pre-fix binary, where it is 200/plain (audit-report-37
# asked for this case, and asking for it is what showed the aetest row was a
# control wearing a test's clothes).
case("...where refusing all but br leaves a gzip-only resource unservable",
     ["Accept-Encoding: *;q=0, br;q=1"], "406/plain",
     path="/gztest.txt", want_header="content-encoding")
# the same precedence read the other way: the wildcard must not override a
# coding the client named, whichever of them appears first
case("a named coding stays authoritative over the wildcard",
     ["Accept-Encoding: br;q=0, *"], "200/gzip",
     path="/aetest.txt", want_header="content-encoding")
# the same with the wildcard's q spelled out, which is how a client is most
# likely to write it
case("...spelled with an explicit q on the wildcard",
     ["Accept-Encoding: br;q=0, *;q=1"], "200/gzip",
     path="/aetest.txt", want_header="content-encoding")
case("...and that holds when the named one is identity",
     ["Accept-Encoding: identity;q=0, *"], "200/br",
     path="/aetest.txt", want_header="content-encoding")
case("...leaving 406 when refusing identity leaves nothing",
     ["Accept-Encoding: identity;q=0, *"], "406/plain",
     path="/hello.txt", want_header="content-encoding")
# and the wildcard is subject to the line-combining rule like any other member:
# a refusal on one line does not decide a coding that a later line allows
case("a wildcard on one line, a coding on another",
     ["Accept-Encoding: *;q=0", "Accept-Encoding: br"], "200/br",
     path="/aetest.txt", want_header="content-encoding")
case("...and the pair is still 406 where that coding is not held",
     ["Accept-Encoding: *;q=0", "Accept-Encoding: br"], "406/plain",
     path="/hello.txt", want_header="content-encoding")
# --- and a negotiated response must say it was negotiated ---------------------
# A response whose selection depended on Accept-Encoding needs Vary, or a shared
# cache stores it under the bare URL and serves it to a client that sent a
# different one. The 200, 206, 304 and the static 404 all carried it; the 406
# did not, because it was added two commits after the rule and nothing
# re-asked the question of the new status (audit-report-37). The 406 needs it
# most of all -- it is the one status that exists ONLY because of this field.
#
# The value's case differs by protocol and legitimately so: h1 and h2 send the
# literal "Accept-Encoding", h3 sends QPACK static entry 59 whose built-in value
# is lowercase. Compared case-insensitively, so a cosmetic difference is not
# frozen into a requirement.
def vary_case(label, headers, path, want_status):
    global fails
    got = {}
    for p_ in protos:
        r = run(p_, headers, path=path, want_header="vary")
        code, _, val = r.partition("/")
        got[p_] = f"{code}/{val.lower()}"
    want = f"{want_status}/accept-encoding"
    if all(v == want for v in got.values()):
        print(f"ok   {label}")
    else:
        print(f"FAIL {label}: want {want} everywhere, got {got}")
        fails += 1


vary_case("a 406 says it varies on Accept-Encoding",
          ["Accept-Encoding: identity;q=0"], "/hello.txt", "406")
vary_case("...as the wildcard spelling of the same refusal does",
          ["Accept-Encoding: *;q=0"], "/hello.txt", "406")
# the responses that already had it, so the rule is asserted for the whole set
# rather than only for the status that was found missing
vary_case("...and a negotiated 200 still does", ["Accept-Encoding: br"],
          "/aetest.txt", "200")
vary_case("...and a 404 on a static path", ["Accept-Encoding: br"],
          "/nope-not-here.txt", "404")

# an empty field value names no coding at all -- so nothing is named, no
# wildcard governs, and only the default survives (RFC 9110 12.5.3). curl sends
# an empty-valued field for "Name;", where "Name:" would delete it.
case("an empty Accept-Encoding asks for no coding at all",
     ["Accept-Encoding;"], "200/plain",
     path="/aetest.txt", want_header="content-encoding")


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
