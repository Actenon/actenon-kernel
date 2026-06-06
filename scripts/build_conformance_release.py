#!/usr/bin/env python3
"""Build a deterministic, attestable conformance-vector release archive."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from actenon.conformance.manifest import validate_conformance_manifest  # noqa: E402


FIXED_MTIME = 1_704_067_200


def _release_files() -> list[Path]:
    suite = json.loads((ROOT / "conformance/suite.json").read_text(encoding="utf-8"))
    paths = {
        ROOT / "conformance/VERSION",
        ROOT / "conformance/CHANGELOG.md",
        ROOT / "conformance/README.md",
        ROOT / "conformance/MATRIX.md",
        ROOT / "conformance/suite.json",
        ROOT / "conformance/vector-lock.json",
        ROOT / "CONFORMANCE.md",
        ROOT / "VERSIONING_POLICY.md",
        ROOT / "docs/SECURITY_ASSURANCE.md",
    }
    for vector_set in suite["vector_sets"]:
        paths.update((ROOT / vector_set["path"]).rglob("*"))
    paths.update((ROOT / "schemas").glob("*.json"))
    paths.update((ROOT / "spec").glob("*/SPEC.md"))
    return sorted(path for path in paths if path.is_file())


def _build_archive(output_path: Path, version: str) -> None:
    prefix = f"actenon-conformance-{version}"
    with output_path.open("wb") as raw_output:
        with gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=raw_output,
            mtime=FIXED_MTIME,
        ) as gzip_output:
            with tarfile.open(
                fileobj=gzip_output,
                mode="w",
                format=tarfile.PAX_FORMAT,
            ) as archive:
                for path in _release_files():
                    data = path.read_bytes()
                    relative_path = path.relative_to(ROOT).as_posix()
                    info = tarfile.TarInfo(f"{prefix}/{relative_path}")
                    info.size = len(data)
                    info.mtime = FIXED_MTIME
                    info.mode = 0o644
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    archive.addfile(info, io.BytesIO(data))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist/conformance")
    args = parser.parse_args()

    manifest = validate_conformance_manifest(ROOT)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = args.output_dir / f"actenon-conformance-{manifest.version}.tar.gz"
    _build_archive(archive_path, manifest.version)
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    digest_path = archive_path.with_suffix(archive_path.suffix + ".sha256")
    digest_path.write_text(f"{digest}  {archive_path.name}\n", encoding="ascii")
    print(f"Built {archive_path}")
    print(f"SHA-256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
