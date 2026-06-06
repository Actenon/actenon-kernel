#!/usr/bin/env python3
"""Verify version agreement, required vector families, and locked hashes."""

from __future__ import annotations

from pathlib import Path

from actenon.conformance.manifest import (
    ConformanceManifestError,
    validate_conformance_manifest,
)


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    try:
        manifest = validate_conformance_manifest(ROOT)
    except (ConformanceManifestError, OSError) as exc:
        print(f"FAIL: {exc}")
        return 1

    print(
        f"Conformance {manifest.version} manifest verified: "
        f"{manifest.vector_file_count} locked vectors, "
        f"{len(manifest.vector_sets)} vector sets, "
        f"{len(manifest.sdk_targets)} SDK targets."
    )
    print(f"Mark: {manifest.verified_mark}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
