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
assert accepted([confirmation, source])
for candidate in ([source, source], [confirmation, confirmation],
                  [source, confirmation, source], []):
    assert not accepted(candidate), candidate
for altered in (confirmation | {"method": "PUT"},
                confirmation | {"path": "/projects/"},
                confirmation | {"max_body": 262145},
                confirmation | {"max_body": 0},
                confirmation | {"extra": True}):
    assert not accepted([source, altered]), altered
print("PDF source and confirmation config rules: OK")
