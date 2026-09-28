#!/usr/bin/env python3
"""Run exact PDF ingress probes against isolated H1/H2 Linnea instances."""

import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time


root = Path(__file__).resolve().parents[1]
binary = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else root / "bin/linnea"
source_cap = 16384
confirmation_cap = 262144
package_cap = 16384
confirmation_path = "/projects/{project_id}/pdf-candidate-confirmations"


def serve(directory, tls):
    directory.mkdir()
    config = {"log": str(directory / "access.log"),
              "error_log": str(directory / "error.log"),
              "spill_dir": str(directory), "port_file": str(directory / "ports"),
              "workers": 1, "max_body": 12288, "http2": 1, "http3": 0,
              "servers": [{"host": "127.0.0.1", "port": 0,
                           "hostname": "vefruna.test",
                           "body_limits": [{"method": "POST",
                                            "path": "/projects/{project_id}/source",
                                            "max_body": source_cap},
                                           {"method": "POST",
                                            "path": confirmation_path,
                                            "max_body": confirmation_cap},
                                           {"method": "POST",
                                            "path": "/projects/{project_id}/pattern-package",
                                            "max_body": package_cap}],
                           "locations": [{"prefix": "/",
                                          "proxy": "127.0.0.1:1"}]}]}
    if tls:
        server = config["servers"][0]
        server["cert"] = str(root / "test/tls/server.crt")
        server["key"] = str(root / "test/tls/server.key")
    path = directory / "config.json"
    path.write_text(json.dumps(config))
    process = subprocess.Popen([binary, "--config", str(path)],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, start_new_session=True)
    for _ in range(100):
        if (directory / "ports").exists() or process.poll() is not None:
            break
        time.sleep(0.05)
    if not (directory / "ports").exists():
        error = process.stderr.read().decode(errors="replace")
        raise RuntimeError(f"Linnea failed to start: {error}")
    port = int((directory / "ports").read_text().split()[2])
    return process, port


def stop(process):
    os.killpg(process.pid, signal.SIGTERM)
    process.wait(timeout=5)


with tempfile.TemporaryDirectory(prefix="linnea-pdf-ingress-") as raw:
    directory = Path(raw)
    process, port = serve(directory / "h1", False)
    try:
        subprocess.run([sys.executable, str(root / "test/pdf_source_body_limit.py"),
                        str(port), "vefruna.test", "12288", str(source_cap)],
                       check=True, timeout=40)
        subprocess.run([sys.executable, str(root / "test/pdf_source_body_limit.py"),
                        str(port), "vefruna.test", "12288", str(confirmation_cap),
                        "/pdf-candidate-confirmations"], check=True, timeout=40)
        subprocess.run([sys.executable, str(root / "test/pdf_source_body_limit.py"),
                        str(port), "vefruna.test", "12288", str(package_cap),
                        "/pattern-package"], check=True, timeout=40)
    finally:
        stop(process)

    process, port = serve(directory / "h2", True)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind(("127.0.0.1", port))  # no QUIC listener with http3: 0
        subprocess.run([sys.executable,
                        str(root / "test/pdf_source_body_limit_h2.py"),
                        str(port), "vefruna.test", "12288", str(source_cap)],
                       check=True, timeout=40)
        subprocess.run([sys.executable,
                        str(root / "test/pdf_source_body_limit_h2.py"),
                        str(port), "vefruna.test", "12288", str(confirmation_cap),
                        "/pdf-candidate-confirmations"], check=True, timeout=40)
        subprocess.run([sys.executable,
                        str(root / "test/pdf_source_body_limit_h2.py"),
                        str(port), "vefruna.test", "12288", str(package_cap),
                        "/pattern-package"], check=True, timeout=40)
        for protocol in ("--http1.1", "--http2"):
            response = subprocess.run(
                ["curl", "--noproxy", "*", protocol, "-k", "-sS", "-D", "-",
                 "-o", "/dev/null", "--max-time", "15", "--resolve",
                 f"vefruna.test:{port}:127.0.0.1",
                 f"https://vefruna.test:{port}/"],
                capture_output=True, text=True, timeout=20, check=True)
            assert "alt-svc:" not in response.stdout.lower(), protocol
    finally:
        stop(process)
print("PDF ingress H1/H2 exact-route probes and H3 opt-out: passed")
