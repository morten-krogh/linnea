#!/usr/bin/env python3
"""If-Match and If-None-Match are entity-tag LISTS, so repeated field lines are
the comma-joined value (RFC 9110 5.3) and every line may carry the tag.

HTTP/1 kept the FIRST occurrence -- the rule for Host, which is a field that may
not repeat at all -- and HTTP/2 and HTTP/3 kept the LAST. So the same legal
request was answered differently by each protocol, and reversing the client's
two lines swapped which of them was right:

    If-None-Match: <current>        h1 304   h2 200   h3 200
    If-None-Match: "miss"

    If-None-Match: "miss"           h1 200   h2 304   h3 304
    If-None-Match: <current>

A needless 200 costs a cache revalidation; the If-Match direction is worse, a
412 on a request that must pass. Accept-Encoding has been recorded as one span
per line since h1-14 for exactly this reason; these two were not.

usage: etag_list_lines.py <port> <cafile> [curl-h3]
"""
import subprocess
import sys

port, ca = sys.argv[1], sys.argv[2]
curl_h3 = sys.argv[3] if len(sys.argv) > 3 else None
URL = f"https://localhost:{port}/hello.txt"
RESOLVE = f"localhost:{port}:127.0.0.1"


def run(proto, headers):
    cmd = ([curl_h3, "--http3-only"] if proto == "h3" else ["curl", f"--{proto}"])
    cmd += ["-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "12",
            "--cacert", ca, "--resolve", RESOLVE]
    for h in headers:
        cmd += ["-H", h]
    cmd.append(URL)
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.stdout.strip() or f"rc={p.returncode}"


etag = None
p = subprocess.run(["curl", "-sD", "-", "-o", "/dev/null", "--http1.1",
                    "--cacert", ca, "--resolve", RESOLVE, URL],
                   capture_output=True, text=True)
for line in p.stdout.replace("\r", "").split("\n"):
    if line.lower().startswith("etag:"):
        etag = line.split(":", 1)[1].strip()
if not etag:
    print(f"FAIL no ETag on the test file (rc={p.returncode}) {p.stdout[:200]!r}")
    sys.exit(1)

protos = ["http1.1", "http2"] + (["h3"] if curl_h3 else [])
MISS = '"miss"'

# (label, headers, expected status) -- every row is a LIST containing the
# current tag, spelled three ways, plus the negatives that keep the rule honest
CASES = [
    ("INM one line",        [f"If-None-Match: {MISS}, {etag}"],                 "304"),
    ("INM tag on line 1",   [f"If-None-Match: {etag}", f"If-None-Match: {MISS}"], "304"),
    ("INM tag on line 2",   [f"If-None-Match: {MISS}", f"If-None-Match: {etag}"], "304"),
    ("INM tag on line 3",   [f"If-None-Match: \"a\"", f"If-None-Match: \"b\"",
                             f"If-None-Match: {etag}"],                          "304"),
    ("INM no line matches", [f"If-None-Match: {MISS}", 'If-None-Match: "other"'], "200"),
    ("IM one line",         [f"If-Match: {MISS}, {etag}"],                       "200"),
    ("IM tag on line 2",    [f"If-Match: {MISS}", f"If-Match: {etag}"],          "200"),
    ("IM tag on line 1",    [f"If-Match: {etag}", f"If-Match: {MISS}"],          "200"),
    ("IM no line matches",  [f"If-Match: {MISS}", 'If-Match: "other"'],          "412"),
]

fails = 0
for label, headers, want in CASES:
    got = {p: run(p, headers) for p in protos}
    if all(v == want for v in got.values()):
        print(f"ok   {label}: every protocol answers {want}")
    else:
        print(f"FAIL {label}: want {want}, got {got}")
        fails += 1

sys.exit(1 if fails else 0)
