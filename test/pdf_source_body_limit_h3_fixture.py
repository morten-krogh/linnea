#!/usr/bin/env python3
"""Exercise HTTP/3 exact PDF ingress on isolated loopback vhosts."""

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

with tempfile.TemporaryDirectory(prefix="linnea-h3-pdf-ingress-") as raw:
    directory = Path(raw)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]

    cert = str(root / "test/tls/server.crt")
    key = str(root / "test/tls/server.key")
    shared = {"host": "127.0.0.1", "port": port, "cert": cert, "key": key,
              "locations": [{"prefix": "/", "proxy": "127.0.0.1:1"}]}
    config = {
        "log": str(directory / "access.log"),
        "error_log": str(directory / "error.log"),
        "spill_dir": str(directory),
        "port_file": str(directory / "ports"),
        "workers": 1, "max_body": 256, "http2": 1, "http3": 1,
        "servers": [
            {**shared, "hostname": "vefruna.test", "body_limits": [
                {"method": "POST", "path": "/projects/{project_id}/source",
                 "max_body": 512}]},
            {**shared, "hostname": "other.test"},
        ],
    }
    path = directory / "config.json"
    path.write_text(json.dumps(config))
    subprocess.run([binary, "--config", path, "--test"], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)
    server = subprocess.Popen([binary, "--config", path], start_new_session=True,
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if (directory / "ports").exists() or server.poll() is not None:
                break
            time.sleep(0.05)
        if not (directory / "ports").exists():
            raise RuntimeError(server.stderr.read().decode(errors="replace"))
        worker = None
        children = Path(f"/proc/{server.pid}/task/{server.pid}/children")
        for _ in range(100):
            found = children.read_text().split()
            if found:
                worker = found[0]
                break
            time.sleep(0.05)
        if worker is None:
            raise RuntimeError("Linnea worker did not start")
        environment = {**os.environ,
                       "LINNEA_H3_COALESCED_AUTHORITY": "other.test",
                       "LINNEA_H3_WORKER_PID": worker,
                       "LINNEA_H3_SPILL_MARKER": str(directory)}
        subprocess.run([sys.executable, str(root / "test/pdf_source_body_limit_h3.py"),
                        str(port), "vefruna.test", "256", "512"],
                       env=environment, check=True, timeout=90)
    finally:
        if server.poll() is None:
            os.killpg(server.pid, signal.SIGTERM)
            server.wait(timeout=5)
print("HTTP/3 exact PDF ingress, coalesced authority and capture bound: passed")
