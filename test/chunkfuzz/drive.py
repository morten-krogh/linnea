"""Drive every variant through h1, h2 and h3 with curl -- an independent client
-- and flag (a) any h2/h3 disagreement and (b) any malformed body delivered as
a clean complete 200."""
import subprocess, sys
sys.path.insert(0, ".")
from variants import V

PORT, CA, CURLH3 = sys.argv[1], sys.argv[2], sys.argv[3]
BASE = f"https://localhost:{PORT}/api/f"

def run(proto, n):
    cmd = ([CURLH3, "--http3-only"] if proto == "h3" else ["curl", f"--{proto}"])
    cmd += ["-s", "-o", "/dev/null", "-w", "%{http_code} %{size_download}",
            "--max-time", "12", "--cacert", CA,
            "--resolve", f"localhost:{PORT}:127.0.0.1", BASE + str(n)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    code, size = (p.stdout.split() + ["0", "0"])[:2]
    return (code, int(size or 0), p.returncode)

bad_serve, disagree = [], []
for n, (name, body, verdict) in enumerate(V):
    r = {p: run(p, n) for p in ("http1.1", "http2", "h3")}
    h2, h3 = r["http2"], r["h3"]
    # A malformed body must not be delivered as a clean, complete 200 -- on ANY
    # protocol. h1 was excluded here for as long as it relayed the upstream's
    # chunk framing byte for byte: it has already sent its head, so it cannot
    # answer 502 once the body is under way. It now judges what it forwards, so
    # a malformed chunk is a 502 when it arrives with the head and a closed,
    # unterminated message when it arrives later -- either way not a clean 200,
    # which is the rule this line has always been asserting (audit-report-24).
    for proto in ("http1.1", "http2", "h3"):
        code, size, rc = r[proto]
        if verdict == "bad" and code == "200" and rc == 0:
            bad_serve.append((name, proto, code, size, rc))
        want = 10 if body.startswith((b"a\r\n", b"A\r\n")) else 4
        if verdict == "ok" and not (code == "200" and rc == 0 and size == want):
            bad_serve.append((name + " [VALID!]", proto, code, size, rc))
    if (h2[0], h2[2] == 0) != (h3[0], h3[2] == 0):
        disagree.append((name, verdict, h2, h3, r["http1.1"]))

print(f"=== {len(V)} variants driven ===")
print(f"malformed served as a clean 200, or valid rejected: {len(bad_serve)}")
for row in bad_serve:
    print("   ", row)
print(f"h2/h3 disagreements: {len(disagree)}")
for name, verdict, h2, h3, h1 in disagree:
    print(f"    {name:22s} [{verdict}] h2={h2} h3={h3} h1={h1}")
