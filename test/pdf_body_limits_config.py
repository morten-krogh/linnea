#!/usr/bin/env python3
"""Strict parser checks for the initial exact PDF source body rule."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile


binary = Path(sys.argv[1] if len(sys.argv) > 1 else "bin/linnea").resolve()
rule = {"method": "POST", "path": "/projects/{project_id}/source",
        "max_body": 16777216}


def run(candidate):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "config.json"
        base = {"log": str(Path(directory) / "log"), "max_body": 12288,
                "http3": 0,
                "servers": [{"host": "127.0.0.1", "port": 0,
                             "hostname": "vefruna.test",
                             "locations": [{"prefix": "/", "proxy":
                                            "127.0.0.1:1"}],
                             "body_limits": [candidate]}]}
        path.write_text(json.dumps(base))
        accepted = subprocess.run([binary, "--config", str(path), "--test"],
                                  capture_output=True, check=False).returncode
        if candidate == rule:
            base["http3"] = 1
            path.write_text(json.dumps(base))
            unsafe = subprocess.run([binary, "--config", str(path), "--test"],
                                    capture_output=True, check=False).returncode
            assert unsafe != 0, "body_limits accepted with HTTP/3 enabled"
            del base["http3"]
            path.write_text(json.dumps(base))
            default_unsafe = subprocess.run(
                [binary, "--config", str(path), "--test"],
                capture_output=True, check=False).returncode
            assert default_unsafe != 0, "body_limits accepted with default H3"
        return accepted


assert run(rule) == 0
for change in ({"method": "PUT"}, {"path": "/projects/"},
               {"max_body": 0}, {"extra": True}):
    assert run(rule | change) != 0, change
for missing in rule:
    assert run({key: value for key, value in rule.items()
                if key != missing}) != 0, missing
print("PDF body-limits config: valid and malformed rules checked")
