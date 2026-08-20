#!/usr/bin/env python3
"""Max-Forwards (RFC 9110 7.6.2) and TRACE, across h1/h2/h3.

Max-Forwards counts the intermediaries an OPTIONS may cross. At zero the
recipient MUST NOT forward and must answer as the final recipient; above zero it
MUST forward a value one lower. linnea did neither -- the field went upstream
untouched -- so a request whose whole purpose is to stop at a chosen hop would
circulate instead. Only OPTIONS is affected: 7.6.2 leaves every other method
free to ignore the field, so it travels unchanged there.

TRACE reflects the received request back to whoever sent it. At an origin that
is a curiosity; through a proxy it hands the caller whatever the request carried
by the time it arrived -- its own credentials among it, and any header an
intermediary added. A static location has always answered 405; a proxy location
forwarded it to a backend that might implement it. It is refused on both now, so
the answer does not depend on which location matched, which also settles
Max-Forwards for TRACE: there is no hop to count to.

usage: max_forwards_trace.py <port> <cafile> [curl-h3]
"""
import subprocess
import sys

port, ca = sys.argv[1], sys.argv[2]
curl_h3 = sys.argv[3] if len(sys.argv) > 3 else None
RESOLVE = f"localhost:{port}:127.0.0.1"
protos = ["http1.1", "http2"] + (["h3"] if curl_h3 else [])
fails = 0


def run(proto, path, method=None, headers=(), body=False):
    cmd = ([curl_h3, "--http3-only"] if proto == "h3" else ["curl", f"--{proto}"])
    cmd += ["-s", "--max-time", "12", "--cacert", ca, "--resolve", RESOLVE]
    cmd += ["-o", "-", "-w", "\n<<%{http_code}>>"] if body else \
           ["-o", "/dev/null", "-w", "%{http_code}"]
    if method:
        cmd += ["-X", method]
    for h in headers:
        cmd += ["-H", h]
    cmd.append(f"https://localhost:{port}{path}")
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    if not body:
        return out.strip() or "000"
    text, _, code = out.rpartition("<<")
    return code.rstrip(">").strip() or "000", text


def check(label, got, want):
    global fails
    if got == want:
        print(f"ok   {label}")
    else:
        print(f"FAIL {label}: want {want}, got {got}")
        fails += 1


# --- TRACE is refused wherever it lands -------------------------------------
for path, what in (("/hello.txt", "a static path"), ("/api/headers", "a proxy path")):
    check(f"TRACE on {what} is 405",
          {p: run(p, path, "TRACE") for p in protos},
          {p: "405" for p in protos})

# --- Max-Forwards: the hop count ---------------------------------------------
def backend_saw(proto, method, mf):
    _, text = run(proto, "/api/headers", method,
                  [f"Max-Forwards: {mf}"], body=True)
    seen = [l.split(":", 1)[1].strip()
            for l in text.replace("\r", "").split("\n")
            if l.lower().startswith("max-forwards:")]
    return ",".join(seen) if seen else "-"


check("an OPTIONS reaches the backend with one hop taken off",
      {p: backend_saw(p, "OPTIONS", 3) for p in protos},
      {p: "2" for p in protos})
check("...and at one, with none left",
      {p: backend_saw(p, "OPTIONS", 1) for p in protos},
      {p: "0" for p in protos})
# 7.6.2 applies to OPTIONS and TRACE only, so nothing else is touched
check("another method's Max-Forwards travels unchanged",
      {p: backend_saw(p, None, 9) for p in protos},
      {p: "9" for p in protos})

# at zero we are the final recipient: the request must not reach the backend,
# which shows as our own answer rather than the backend's echo of the head
def answered_locally(proto):
    code, text = run(proto, "/api/headers", "OPTIONS",
                     ["Max-Forwards: 0"], body=True)
    reached = "OPTIONS /api/headers" in text
    return f"{code}/{'forwarded' if reached else 'ours'}"


check("an OPTIONS at zero hops is answered by us, not forwarded",
      {p: answered_locally(p) for p in protos},
      {p: "200/ours" for p in protos})

# A hop count we cannot work out is a bad request, not a field to ignore. The
# refusal takes each protocol's own shape -- 400 on HTTP/1, a stream error on
# the binary ones, which curl reports as no status at all -- exactly as a
# duplicate Content-Length or a repeated singleton conditional does there
# (audit-report-32). One refusal, three spellings, by precedent rather than
# accident.
REFUSED = {"http1.1": "400", "http2": "000", "h3": "000"}
check("a Max-Forwards that is not a number is refused",
      {p: run(p, "/hello.txt", None, ["Max-Forwards: soon"]) for p in protos},
      {p: REFUSED[p] for p in protos})
# ...and where we are the origin it changes nothing
check("a static GET carrying one is served normally",
      {p: run(p, "/hello.txt", None, ["Max-Forwards: 5"]) for p in protos},
      {p: "200" for p in protos})

sys.exit(1 if fails else 0)
