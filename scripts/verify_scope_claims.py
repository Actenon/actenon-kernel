from __future__ import annotations

import argparse
import re
from pathlib import Path


SCOPE_BOUNDARY_STATEMENT = (
    "Actenon gates explicit execution-edge actions; it does not inspect or "
    "filter prompts, model output, or in-band response content."
)
EXPORT_DISTINCTION_STATEMENT = (
    "It can require proof for an explicit export or transmit action, but it "
    "does not stop data disclosed inside ordinary output unless that "
    "disclosure is itself modeled and routed as a protected action."
)
EDGE_PRECONDITION_STATEMENT = (
    "The edge guarantee applies only when the protected edge is the only path "
    "to the resource, the backend accepts only brokered credentials issued "
    "after verification, and the agent has no standing credential or "
    "alternate route."
)

DOCUMENT_REQUIREMENTS = {
    Path("README.md"): (
        SCOPE_BOUNDARY_STATEMENT,
        EXPORT_DISTINCTION_STATEMENT,
        EDGE_PRECONDITION_STATEMENT,
        "docs/SCOPE_AND_GUARANTEES.md",
    ),
    Path("docs/SCOPE_AND_GUARANTEES.md"): (
        SCOPE_BOUNDARY_STATEMENT,
        EXPORT_DISTINCTION_STATEMENT,
        EDGE_PRECONDITION_STATEMENT,
    ),
    Path("THREAT_MODEL.md"): (
        SCOPE_BOUNDARY_STATEMENT,
        EXPORT_DISTINCTION_STATEMENT,
        EDGE_PRECONDITION_STATEMENT,
        "docs/SCOPE_AND_GUARANTEES.md",
    ),
    Path("KERNEL_GUARANTEES.md"): (
        SCOPE_BOUNDARY_STATEMENT,
        EXPORT_DISTINCTION_STATEMENT,
        EDGE_PRECONDITION_STATEMENT,
        "docs/SCOPE_AND_GUARANTEES.md",
    ),
    Path("docs/guides/FRAMEWORK_ADAPTERS.md"): (
        SCOPE_BOUNDARY_STATEMENT,
        EXPORT_DISTINCTION_STATEMENT,
        EDGE_PRECONDITION_STATEMENT,
        "../SCOPE_AND_GUARANTEES.md",
    ),
    Path("docs/guides/EDGE_DEPLOYMENT.md"): (
        EDGE_PRECONDITION_STATEMENT,
        "../SCOPE_AND_GUARANTEES.md",
    ),
    Path("examples/edge_templates/README.md"): (
        EDGE_PRECONDITION_STATEMENT,
        "../../docs/SCOPE_AND_GUARANTEES.md",
    ),
}


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def validate_scope_claims(root: Path) -> list[str]:
    failures: list[str] = []
    for relative_path, requirements in DOCUMENT_REQUIREMENTS.items():
        path = root / relative_path
        if not path.is_file():
            failures.append(f"{relative_path}: document is missing")
            continue
        normalized = _normalize(path.read_text(encoding="utf-8"))
        for requirement in requirements:
            if _normalize(requirement) not in normalized:
                failures.append(
                    f"{relative_path}: missing required scope or edge statement: "
                    f"{requirement}"
                )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify public scope-boundary and protected-edge claims."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to the parent of scripts/)",
    )
    args = parser.parse_args()

    failures = validate_scope_claims(args.root.resolve())
    if failures:
        print("Public scope-claim verification failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print(
        "Public scope-claim verification passed: explicit-action boundary and "
        "edge precondition are present."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
