#!/usr/bin/env python3
"""Every field the two request collectors name, sent TWICE, across h1/h2/h3.

NOT part of run_tests.sh: it is a hand-run sweep, like test/chunkfuzz. What it
finds becomes a fixture in test/tls/conditional_field_dups.py; this is the net,
not the catch.

    python3 test/tls/field_repeat_sweep.py <tls-port> <cafile> [curl-h3]

Read the output with two cautions, both of which cost time the first time:

  * curl REFUSES to send connection-specific fields (Connection, Keep-Alive,
    Upgrade, Transfer-Encoding, TE) over h2 and h3. Those rows read as "the
    server accepted it" when the client never sent it. That rule is covered by
    test/quic/h3_field_rules_test.py and the h2 shard instead.
  * a refusal takes each protocol's own shape -- 400 on h1, a stream error
    (curl prints 000) on h2 and h3 -- so a refused-everywhere row is FLAGGED
    here as a disagreement. Read the columns, not the flag.

It found: split cookie lines unjoined on h3, Expect: 100-continue forwarded on
h3, an unknown expectation answered 431 on h2, and h1 dropping every Expect.

The collectors are lists of per-field cases, written twice -- once in the HTTP/1
header parser and once in the HPACK/QPACK collector -- and whether a field is a
list or a singleton was decided independently in each. Reports 28-32 each found
one field where they disagreed. This asks every field at once.

Flags three things:
  * the three protocols answering differently
  * the ORDER of the two lines changing the answer
  * a proxied request reaching the backend with a different value per protocol
"""
import subprocess, sys
PORT, CA = sys.argv[1], sys.argv[2]
CURLH3 = sys.argv[3] if len(sys.argv) > 3 else None
RESOLVE = f"localhost:{PORT}:127.0.0.1"
PROTOS = ["http1.1", "http2"] + (["h3"] if CURLH3 else [])

# field, value A, value B -- the two values differ so that "which one won" shows
FIELDS = [
    ("Accept-Encoding",      "br",                              "identity"),
    ("Expect",               "100-continue",                    "other-expectation"),
    ("If-Match",             '"a"',                             '"b"'),
    ("If-None-Match",        '"a"',                             '"b"'),
    ("If-Modified-Since",    "Wed, 01 Jan 2020 00:00:00 GMT",   "Fri, 01 Jan 2100 00:00:00 GMT"),
    ("If-Unmodified-Since",  "Wed, 01 Jan 2020 00:00:00 GMT",   "Fri, 01 Jan 2100 00:00:00 GMT"),
    ("If-Range",             '"a"',                             '"b"'),
    ("Range",                "bytes=0-0",                       "bytes=2-2"),
    ("Content-Length",       "0",                               "0"),
    ("Host",                 "localhost",                       "elsewhere.test"),
    ("Cookie",               "a=1",                             "b=2"),
    ("TE",                   "trailers",                        "gzip"),
    ("Priority",             "u=1",                             "u=5"),
    ("Upgrade",              "websocket",                       "h2c"),
    ("Trailers",             "X-A",                             "X-B"),
    ("Keep-Alive",           "timeout=5",                       "timeout=9"),
    ("X-Not-Collected",      "one",                             "two"),
]


def run(proto, headers, path):
    cmd = ([CURLH3, "--http3-only"] if proto == "h3" else ["curl", f"--{proto}"])
    cmd += ["-s", "-o", "-", "-w", "\n<<%{http_code}>>", "--max-time", "12",
            "--cacert", CA, "--resolve", RESOLVE]
    for h in headers:
        cmd += ["-H", h]
    cmd.append(f"https://localhost:{PORT}{path}")
    p = subprocess.run(cmd, capture_output=True, text=True)
    body, _, code = p.stdout.rpartition("<<")
    return code.rstrip(">>").strip() or "000", body


def backend_saw(field, body):
    """what the echo backend reports receiving for `field`"""
    seen = [l.split(":", 1)[1].strip()
            for l in body.replace("\r", "").split("\n")
            if l.lower().startswith(field.lower() + ":")]
    return ",".join(seen) if seen else "-"


issues = 0
print(f"{'field':<22} {'order':<6} static: " + " ".join(f"{p:<8}" for p in PROTOS)
      + "   proxied (status/what the backend saw)")
for field, a, b in FIELDS:
    rows = {}
    for order, (v1, v2) in (("A,B", (a, b)), ("B,A", (b, a))):
        hs = [f"{field}: {v1}", f"{field}: {v2}"]
        stat = {}
        prox = {}
        for p in PROTOS:
            c, _ = run(p, hs, "/hello.txt")
            stat[p] = c
            c2, body = run(p, hs, "/api/headers")
            prox[p] = f"{c2}/{backend_saw(field, body)}"
        rows[order] = (stat, prox)
        print(f"  {field:<20} {order:<6} " + " ".join(f"{stat[p]:<8}" for p in PROTOS)
              + "   " + " ".join(prox[p] for p in PROTOS))
        if len(set(stat.values())) > 1:
            print(f"      ^ PROTOCOLS DISAGREE on status")
            issues += 1
        if len(set(prox.values())) > 1:
            print(f"      ^ PROTOCOLS DISAGREE on what reached the backend")
            issues += 1
    if rows["A,B"][0] != rows["B,A"][0]:
        print(f"      ^ ORDER CHANGES the static answer")
        issues += 1
print(f"\n{issues} disagreements")
