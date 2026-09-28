#!/usr/bin/env python3
"""HTTP/2 part of the isolated PDF source ingress acceptance probe.

Usage: pdf_source_body_limit_h2.py <tls-port> [host] [ordinary-cap] [source-cap]
The fixture may proxy to an intentionally absent backend (accepted = 502).
"""

import pathlib
import subprocess
import sys
import tempfile


port = int(sys.argv[1])
host = sys.argv[2] if len(sys.argv) > 2 else "vefruna.test"
ordinary_cap = int(sys.argv[3]) if len(sys.argv) > 3 else 12288
source_cap = int(sys.argv[4]) if len(sys.argv) > 4 else 16777216
suffix = sys.argv[5] if len(sys.argv) > 5 else "/source"
project = "project_" + "0" * 25 + "1"
source = f"/projects/{project}{suffix}"


def request(path, body, *, method="POST", no_length=False, authority=host):
    with tempfile.TemporaryDirectory() as directory:
        payload = pathlib.Path(directory) / "payload"
        payload.write_bytes(body)
        args = ["curl", "--noproxy", "*", "--http2", "-k", "-sS",
                "--max-time", "15", "--resolve",
                f"{authority}:{port}:127.0.0.1", "-o", "/dev/null",
                "-w", "%{http_code} %{http_version}", "-X", method]
        if no_length:
            args += ["-H", "Content-Length:"]
        args += ["--data-binary", f"@{payload}",
                 f"https://{authority}:{port}{path}"]
        result = subprocess.run(args, capture_output=True, text=True,
                                timeout=20, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()


def main():
    body = b"A" * (ordinary_cap + 1)
    cases = [
        ("source counted", source, "POST", False, "502 2"),
        ("source DATA without length", source, "POST", True, "502 2"),
        ("source exactly at scoped cap", source, "POST", False, "502 2"),
        ("source one byte above scoped cap", source, "POST", False, "413 2"),
        ("adjacent counted", source.replace(suffix, "/notes"),
         "POST", False, "413 2"),
        ("adjacent DATA without length", source.replace(suffix, "/notes"),
         "POST", True, "413 2"),
        ("wrong method", source, "PUT", False, "413 2"),
        ("query", source + "?other=1", "POST", False, "413 2"),
        ("encoded path", source.replace(suffix,
         f"/%{ord(suffix[1]):02x}{suffix[2:]}"),
         "POST", False, "413 2"),
    ]
    failures = []
    for name, path, method, no_length, expected in cases:
        candidate = (b"A" * source_cap
                     if name == "source exactly at scoped cap" else
                     b"A" * (source_cap + 1)
                     if name == "source one byte above scoped cap" else body)
        got = request(path, candidate, method=method, no_length=no_length)
        if got != expected:
            failures.append(f"{name}: {got}, expected {expected}")
    other = request(source, body, authority="other.test")
    if other != "413 2":
        failures.append(f"other authority: {other}, expected 413 2")
    if failures:
        print("\n".join(failures))
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
