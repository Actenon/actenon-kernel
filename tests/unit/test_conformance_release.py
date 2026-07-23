from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tarfile
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.conformance import CONFORMANCE_VERSION, VERIFIED_MARK
from actenon.conformance.manifest import validate_conformance_manifest


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_conformance_version_manifest_and_required_vectors_are_declared() -> None:
    manifest = validate_conformance_manifest(REPO_ROOT)

    assert manifest.version == CONFORMANCE_VERSION == "1.0.0"
    assert manifest.verified_mark == VERIFIED_MARK
    assert manifest.vector_file_count >= 50
    assert {
        "receipt_countersignature_v1",
        "transparency_log_v1",
        "trust_artifacts_v1",
    }.issubset(manifest.vector_sets)
    assert set(manifest.sdk_targets) == {"python", "typescript", "go", "rust"}


def test_manifest_verification_command_passes() -> None:
    result = subprocess.run(
        [sys.executable, "-I", "scripts/verify_conformance_manifest.py"],
        cwd=REPO_ROOT,
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Conformance 1.0.0 manifest verified" in result.stdout
    assert VERIFIED_MARK in result.stdout


def test_conformance_release_archive_is_deterministic_and_complete() -> None:
    with TemporaryDirectory() as tempdir:
        output_dir = Path(tempdir)
        command = [
            sys.executable,
            "-I",
            "scripts/build_conformance_release.py",
            "--output-dir",
            str(output_dir),
        ]
        subprocess.run(
            command,
            cwd=REPO_ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        archive = output_dir / "actenon-conformance-1.0.0.tar.gz"
        first_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        subprocess.run(
            command,
            cwd=REPO_ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        second_digest = hashlib.sha256(archive.read_bytes()).hexdigest()

        assert first_digest == second_digest
        sidecar = archive.with_suffix(archive.suffix + ".sha256")
        assert sidecar.read_text(encoding="ascii") == (
            f"{first_digest}  {archive.name}\n"
        )

        with tarfile.open(archive) as release:
            names = set(release.getnames())
        prefix = "actenon-conformance-1.0.0"
        assert f"{prefix}/conformance/suite.json" in names
        assert f"{prefix}/conformance/vector-lock.json" in names
        assert (
            f"{prefix}/conformance/vectors/receipt_countersignature_v1/"
            "countersignature.json"
        ) in names
        assert (
            f"{prefix}/conformance/vectors/transparency_log_v1/"
            "consistency_proof.json"
        ) in names
        assert (
            f"{prefix}/conformance/vectors/trust_artifacts_v1/"
            "issuer_status_good.json"
        ) in names


def test_suite_mark_claim_names_exact_version() -> None:
    suite = json.loads(
        (REPO_ROOT / "conformance/suite.json").read_text(encoding="utf-8")
    )

    assert suite["verified_mark"]["claim"] == (
        f"Actenon Verified (Conformance {suite['conformance_version']})"
    )


def test_release_workflow_requires_signed_tag_and_provenance() -> None:
    workflow = (
        REPO_ROOT / ".github/workflows/conformance-release.yml"
    ).read_text(encoding="utf-8")

    assert ".verification.verified" in workflow
    assert 'test "$verified" = "true"' in workflow
    assert "actions/attest-build-provenance@v2" in workflow
    assert 'tags:\n      - "conformance-v*"' in workflow
