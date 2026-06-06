#!/usr/bin/env python3
"""Regenerate the hash lock after an intentional conformance version change."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFORMANCE_ROOT = ROOT / "conformance"


def main() -> int:
    suite = json.loads((CONFORMANCE_ROOT / "suite.json").read_text(encoding="utf-8"))
    files: dict[str, str] = {}
    for vector_set in suite["vector_sets"]:
        vector_root = ROOT / vector_set["path"]
        for path in sorted(vector_root.rglob("*.json")):
            relative_path = path.relative_to(ROOT).as_posix()
            files[relative_path] = hashlib.sha256(path.read_bytes()).hexdigest()

    payload = {
        "schema_version": 1,
        "conformance_version": suite["conformance_version"],
        "algorithm": "sha256",
        "files": files,
    }
    output = CONFORMANCE_ROOT / "vector-lock.json"
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {output.relative_to(ROOT)} with {len(files)} vector files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
