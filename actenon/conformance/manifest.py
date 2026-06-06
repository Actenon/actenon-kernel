"""Validation helpers for the versioned public conformance vectors."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .version import CONFORMANCE_VERSION, VERIFIED_MARK

SEMVER_PATTERN = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
REQUIRED_VECTOR_SETS = {
    "verifier_sdk_v1",
    "receipt_countersignature_v1",
    "transparency_log_v1",
    "trust_artifacts_v1",
}
REQUIRED_SDKS = {"python", "typescript", "go", "rust"}


class ConformanceManifestError(ValueError):
    """Raised when versioned conformance metadata is incomplete or altered."""


@dataclass(frozen=True)
class ConformanceManifest:
    version: str
    release_tag: str
    verified_mark: str
    vector_file_count: int
    vector_sets: tuple[str, ...]
    sdk_targets: tuple[str, ...]


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConformanceManifestError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ConformanceManifestError(f"{path} must contain a JSON object")
    return value


def _require_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConformanceManifestError(f"{field} must be a non-empty string")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_conformance_manifest(repo_root: Path) -> ConformanceManifest:
    """Validate suite metadata, version agreement, vector coverage, and hashes."""

    conformance_root = repo_root / "conformance"
    version = (conformance_root / "VERSION").read_text(encoding="utf-8").strip()
    if not SEMVER_PATTERN.fullmatch(version):
        raise ConformanceManifestError(
            f"conformance/VERSION must be semantic versioning, got {version!r}"
        )
    if version != CONFORMANCE_VERSION:
        raise ConformanceManifestError(
            "conformance/VERSION and actenon.conformance.CONFORMANCE_VERSION differ"
        )

    suite = _load_json(conformance_root / "suite.json")
    lock = _load_json(conformance_root / "vector-lock.json")
    if suite.get("conformance_version") != version:
        raise ConformanceManifestError("suite.json conformance_version does not match VERSION")
    if lock.get("conformance_version") != version:
        raise ConformanceManifestError(
            "vector-lock.json conformance_version does not match VERSION"
        )

    release_tag = _require_string(suite.get("release_tag"), "suite.json release_tag")
    if release_tag != f"conformance-v{version}":
        raise ConformanceManifestError(
            f"release_tag must be conformance-v{version}, got {release_tag!r}"
        )

    mark = suite.get("verified_mark")
    if not isinstance(mark, Mapping):
        raise ConformanceManifestError("suite.json verified_mark must be an object")
    mark_claim = _require_string(mark.get("claim"), "verified_mark.claim")
    if mark_claim != VERIFIED_MARK or version not in mark_claim:
        raise ConformanceManifestError(
            "Actenon Verified claim must name the exact conformance version"
        )

    raw_sets = suite.get("vector_sets")
    if not isinstance(raw_sets, list) or not raw_sets:
        raise ConformanceManifestError("suite.json vector_sets must be a non-empty array")

    vector_sets: list[str] = []
    expected_files: set[str] = set()
    for item in raw_sets:
        if not isinstance(item, Mapping):
            raise ConformanceManifestError("every vector_sets entry must be an object")
        vector_id = _require_string(item.get("id"), "vector_sets[].id")
        vector_path = _require_string(item.get("path"), f"vector set {vector_id} path")
        vector_sets.append(vector_id)
        root = repo_root / vector_path
        if not root.is_dir():
            raise ConformanceManifestError(
                f"vector set {vector_id} directory does not exist: {vector_path}"
            )
        files = {
            path.relative_to(repo_root).as_posix()
            for path in root.rglob("*.json")
            if path.is_file()
        }
        if not files:
            raise ConformanceManifestError(f"vector set {vector_id} has no JSON vectors")
        expected_files.update(files)

        targets = item.get("sdk_targets")
        if vector_id in REQUIRED_VECTOR_SETS:
            if not isinstance(targets, list) or set(targets) != REQUIRED_SDKS:
                raise ConformanceManifestError(
                    f"vector set {vector_id} must target Python, TypeScript, Go, and Rust"
                )

    missing_sets = REQUIRED_VECTOR_SETS.difference(vector_sets)
    if missing_sets:
        raise ConformanceManifestError(
            f"suite.json is missing required vector sets: {sorted(missing_sets)}"
        )

    sdk_entries = suite.get("sdk_targets")
    if not isinstance(sdk_entries, list):
        raise ConformanceManifestError("suite.json sdk_targets must be an array")
    sdk_targets = tuple(
        _require_string(item.get("id"), "sdk_targets[].id")
        for item in sdk_entries
        if isinstance(item, Mapping)
    )
    if set(sdk_targets) != REQUIRED_SDKS:
        raise ConformanceManifestError(
            "suite.json must declare Python, TypeScript, Go, and Rust SDK targets"
        )

    locked_files = lock.get("files")
    if not isinstance(locked_files, Mapping):
        raise ConformanceManifestError("vector-lock.json files must be an object")
    if set(locked_files) != expected_files:
        missing = sorted(expected_files.difference(locked_files))
        extra = sorted(set(locked_files).difference(expected_files))
        raise ConformanceManifestError(
            f"vector lock file set differs; missing={missing}, extra={extra}"
        )

    for relative_path, expected_hash in locked_files.items():
        if not isinstance(relative_path, str) or not isinstance(expected_hash, str):
            raise ConformanceManifestError("vector lock paths and hashes must be strings")
        actual_hash = _sha256(repo_root / relative_path)
        if actual_hash != expected_hash:
            raise ConformanceManifestError(
                f"vector hash mismatch for {relative_path}: "
                f"expected {expected_hash}, got {actual_hash}"
            )

    return ConformanceManifest(
        version=version,
        release_tag=release_tag,
        verified_mark=mark_claim,
        vector_file_count=len(expected_files),
        vector_sets=tuple(vector_sets),
        sdk_targets=sdk_targets,
    )


__all__ = [
    "ConformanceManifest",
    "ConformanceManifestError",
    "validate_conformance_manifest",
]
