from __future__ import annotations

import runpy
import shutil
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "verify_scope_claims.py"
SCRIPT_NAMESPACE = runpy.run_path(str(SCRIPT))
DOCUMENT_REQUIREMENTS = SCRIPT_NAMESPACE["DOCUMENT_REQUIREMENTS"]
validate_scope_claims = SCRIPT_NAMESPACE["validate_scope_claims"]


def _copy_guarded_documents(destination: Path) -> None:
    for relative_path in DOCUMENT_REQUIREMENTS:
        target = destination / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / relative_path, target)


def test_public_scope_claim_guard_passes_for_repository() -> None:
    assert validate_scope_claims(REPO_ROOT) == []


def test_public_scope_claim_guard_detects_removed_scope_statement(
    tmp_path: Path,
) -> None:
    _copy_guarded_documents(tmp_path)
    readme = tmp_path / "README.md"
    text = readme.read_text(encoding="utf-8")
    readme.write_text(
        text.replace("model output", "generated material", 1),
        encoding="utf-8",
    )

    failures = validate_scope_claims(tmp_path)

    assert any("README.md" in failure for failure in failures)


def test_public_scope_claim_guard_detects_removed_edge_precondition(
    tmp_path: Path,
) -> None:
    _copy_guarded_documents(tmp_path)
    scope_doc = tmp_path / "docs" / "SCOPE_AND_GUARANTEES.md"
    text = scope_doc.read_text(encoding="utf-8")
    scope_doc.write_text(
        text.replace("alternate route", "secondary path", 1),
        encoding="utf-8",
    )

    failures = validate_scope_claims(tmp_path)

    assert any("docs/SCOPE_AND_GUARANTEES.md" in failure for failure in failures)
