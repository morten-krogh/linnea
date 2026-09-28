#!/usr/bin/env python3
"""HTTP/2 part of the isolated PDF source ingress acceptance probe.

Usage: pdf_source_body_limit_h2.py <tls-port> [host] [ordinary-cap]
The fixture may proxy to an intentionally absent backend (accepted = 502).
"""

import pathlib
import subprocess
import sys
import tempfile


port = int(sys.argv[1])
host = sys.argv[2] if len(sys.argv) > 2 else "vefruna.test"
ordinary_cap = int(sys.argv[3]) if len(sys.argv) > 3 else 12288
project = "project_" + "0" * 25 + "1"
source = f"/projects/{project}/source"


def request(path, body, *, method="POST", no_length=False):
    with tempfile.TemporaryDirectory() as directory:
        payload = pathlib.Path(directory) / "payload"
        payload.write_bytes(body)
        args = ["curl", "--noproxy", "*", "--http2", "-k", "-sS",
                "--max-time", "15", "--resolve",
                f"{host}:{port}:127.0.0.1", "-o", "/dev/null",
                "-w", "%{http_code} %{http_version}", "-X", method]
        if no_length:
            args += ["-H", "Content-Length:"]
        args += ["--data-binary", f"@{payload}",
                 f"https://{host}:{port}{path}"]
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
        ("adjacent counted", source.replace("/source", "/notes"),
         "POST", False, "413 2"),
        ("adjacent DATA without length", source.replace("/source", "/notes"),
         "POST", True, "413 2"),
        ("wrong method", source, "PUT", False, "413 2"),
        ("query", source + "?other=1", "POST", False, "413 2"),
        ("encoded path", source.replace("/source", "/%73ource"),
         "POST", False, "413 2"),
    ]
    failures = []
    for name, path, method, no_length, expected in cases:
        got = request(path, body, method=method, no_length=no_length)
        if got != expected:
            failures.append(f"{name}: {got}, expected {expected}")
    if failures:
        print("\n".join(failures))
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
