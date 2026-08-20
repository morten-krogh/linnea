#!/usr/bin/env python3
"""A precompressed variant older than its source must not be served.

Serving it is worse than not compressing at all. The two forms of one URL then
carry DIFFERENT bodies, and each carries its own self-consistent ETag and
Last-Modified -- taken from whichever file was opened -- so neither client ever
revalidates into agreement, and `Vary: Accept-Encoding` lets a shared cache hold
both quite legally. A client that accepts br keeps yesterday's page; one that
does not gets today's. Demonstrated on this server before the check existed, and
it is the mechanism behind every "regenerate the .br or browsers see the old
page" deploy note.

The gate is per PROTOCOL, because HTTP/1 opens its variants itself while HTTP/2
and HTTP/3 go through linnea_static_open_enc. The first version of the fix went
into open_enc alone and h1 kept serving the stale file -- which is why all three
are driven here.

A variant with NO source beside it is not stale: it is the resource. That row
stops the check from being written as "the source must be newer", which would
have made a .br-only file unservable.

usage: variant_staleness.py <port> <cafile> [curl-h3]
"""
import subprocess
import sys

port, ca = sys.argv[1], sys.argv[2]
curl_h3 = sys.argv[3] if len(sys.argv) > 3 else None
RESOLVE = f"localhost:{port}:127.0.0.1"
protos = ["http1.1", "http2"] + (["h3"] if curl_h3 else [])
fails = 0


def get(proto, path, ae=None):
    cmd = ([curl_h3, "--http3-only"] if proto == "h3" else ["curl", f"--{proto}"])
    cmd += ["-s", "--max-time", "12", "--cacert", ca, "--resolve", RESOLVE]
    if ae:
        cmd += ["-H", f"Accept-Encoding: {ae}"]
    cmd.append(f"https://localhost:{port}{path}")
    return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()


def check(label, ok, got=""):
    global fails
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + (f"  got {got!r}" if not ok else ""))
    if not ok:
        fails += 1


for p in protos:
    got = get(p, "/stale.txt", "br")
    check(f"{p}: a .br older than its source is not served", got == "STALE-SOURCE", got)
    got = get(p, "/fresh.txt", "br")
    check(f"{p}: a .br newer than its source still is", got == "FRESH-VARIANT", got)
    got = get(p, "/bronly.txt", "br")
    check(f"{p}: a .br with no source beside it is the resource",
          got == "BR-ONLY", got)
    got = get(p, "/stale.txt")
    check(f"{p}: and the plain form is unaffected", got == "STALE-SOURCE", got)

print("OK" if not fails else f"{fails} failed")
sys.exit(1 if fails else 0)
