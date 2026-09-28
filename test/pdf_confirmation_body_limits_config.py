#!/usr/bin/env python3
"""Check both exact PDF body rules and reject broadened/duplicate variants."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile


binary = Path(sys.argv[1] if len(sys.argv) > 1 else "bin/linnea").resolve()
source = {"method": "POST", "path": "/projects/{project_id}/source",
          "max_body": 16777216}
confirmation = {"method": "POST",
                "path": "/projects/{project_id}/pdf-candidate-confirmations",
                "max_body": 262144}

package = {"method": "POST", "path": "/projects/{project_id}/pattern-package",
           "max_body": 16777216}


def accepted(rules):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "config.json"
        config = {"log": str(Path(directory) / "log"), "spill_dir": directory,
                  "max_body": 12288, "servers": [{"host": "127.0.0.1",
                  "port": 0, "hostname": "vefruna.test", "locations": [
                      {"prefix": "/", "proxy": "127.0.0.1:1"}],
                  "body_limits": rules}]}
        path.write_text(json.dumps(config))
        result = subprocess.run([binary, "--config", str(path), "--test"],
                                capture_output=True, check=False)
        return result.returncode == 0


assert accepted([source])
assert accepted([confirmation])
assert accepted([source, confirmation])
assert accepted([package])
assert accepted([source, confirmation, package])
assert accepted([package, confirmation, source])
assert accepted([confirmation, source])
for candidate in ([source, source], [confirmation, confirmation],
                  [source, confirmation, source], [package, package], []):
    assert not accepted(candidate), candidate
for altered in (confirmation | {"method": "PUT"},
                confirmation | {"path": "/projects/"},
                confirmation | {"max_body": 262145},
                confirmation | {"max_body": 0},
                confirmation | {"extra": True}):
    assert not accepted([source, altered]), altered
for altered in (package | {"method": "PUT"},
                package | {"path": "/projects/"},
                package | {"max_body": 16777217},
                package | {"max_body": 0},
                package | {"extra": True}):
    assert not accepted([source, confirmation, altered]), altered
print("Source, confirmation and package config rules: OK")
