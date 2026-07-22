#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="${ACTENON_PORTABLE_DIST_DIR:-$ROOT_DIR/dist/portable_distribution}"
PACKAGE_NAME="actenon-portable"
TARGET_DIR="$BUILD_ROOT/$PACKAGE_NAME"
ARCHIVE_PATH="$BUILD_ROOT/$PACKAGE_NAME.tar.gz"

copy_file() {
  local relative_path="$1"
  install -d "$TARGET_DIR/$(dirname "$relative_path")"
  cp "$ROOT_DIR/$relative_path" "$TARGET_DIR/$relative_path"
}

rm -rf "$BUILD_ROOT"
install -d "$TARGET_DIR"

portable_files=(
  "docs/reference/contracts/ACTION_INTENT_EXTERNAL_SPEC.md"
  "docs/reference/contracts/PCCB_SPEC.md"
  "docs/reference/contracts/RECEIPT_SPEC.md"
  "docs/reference/contracts/REFUSAL_SPEC.md"
  "VERSIONING_POLICY.md"
  "OPEN_SOURCE_BOUNDARY.md"
  "docs/reference/verifier/VERIFIER_SDK_REFERENCE.md"
  "docs/reference/verifier/HELLO_WORLD_PROTECTED_RESOURCE.md"
  "docs/guides/CONFORMANCE_TESTS_GUIDE.md"
  "schemas/action_intent.v1.json"
  "schemas/pccb.v1.json"
  "schemas/receipt.v1.json"
  "schemas/refusal.v1.json"
  "actenon/__init__.py"
  "actenon/api/intake.py"
  "actenon/core/errors.py"
  "actenon/models/contracts.py"
  "actenon/models/runtime.py"
  "actenon/proof/__init__.py"
  "actenon/proof/canonical.py"
  "actenon/proof/local.py"
  "actenon/proof/service.py"
  "actenon/proof/signing.py"
  "actenon/verifier/sdk.py"
  "actenon/demo/portable_local_proof.py"
  "examples/__init__.py"
  "examples/hello_world_protected_resource_python/__init__.py"
  "examples/hello_world_protected_resource_python/protected_resource.py"
  "tests/conformance/__init__.py"
  "tests/conformance/test_verifier_sdk_conformance.py"
)

for relative_path in "${portable_files[@]}"; do
  copy_file "$relative_path"
done

install -d \
  "$TARGET_DIR/actenon/api" \
  "$TARGET_DIR/actenon/core" \
  "$TARGET_DIR/actenon/models" \
  "$TARGET_DIR/actenon/verifier" \
  "$TARGET_DIR/actenon/demo" \
  "$TARGET_DIR/tests"

cat >"$TARGET_DIR/actenon/api/__init__.py" <<'EOF'
"""Portable Action Intent intake helpers."""

from .intake import ActionIntentIntakeService

__all__ = ["ActionIntentIntakeService"]
EOF

cat >"$TARGET_DIR/actenon/core/__init__.py" <<'EOF'
"""Portable verifier-side errors."""

from .errors import ContractValidationError, ProofVerificationError, RefusalException

__all__ = ["ContractValidationError", "ProofVerificationError", "RefusalException"]
EOF

cat >"$TARGET_DIR/actenon/models/__init__.py" <<'EOF'
"""Portable public contract and runtime models."""

from .contracts import (
    ActionHashSpec,
    ActionIntent,
    ActionSpec,
    AudienceRef,
    CorrelationRef,
    EvidenceRef,
    PCCB,
    PartyRef,
    Receipt,
    Refusal,
    ScopeSpec,
    SignatureSpec,
    TargetRef,
    TenantRef,
    Violation,
)
from .runtime import DynamicContextInput, PolicyDecision, PolicyOutcome, ProtectedExecutionRequest, RuleEvaluation

__all__ = [
    "ActionHashSpec",
    "ActionIntent",
    "ActionSpec",
    "AudienceRef",
    "CorrelationRef",
    "DynamicContextInput",
    "EvidenceRef",
    "PCCB",
    "PartyRef",
    "PolicyDecision",
    "PolicyOutcome",
    "ProtectedExecutionRequest",
    "Receipt",
    "Refusal",
    "RuleEvaluation",
    "ScopeSpec",
    "SignatureSpec",
    "TargetRef",
    "TenantRef",
    "Violation",
]
EOF

cat >"$TARGET_DIR/actenon/verifier/__init__.py" <<'EOF'
"""Portable verifier SDK."""

from .sdk import VerifiedPortableRequest, VerifierSDK

__all__ = ["VerifiedPortableRequest", "VerifierSDK"]
EOF

cat >"$TARGET_DIR/actenon/demo/__init__.py" <<'EOF'
"""Portable local proof demo helpers."""
EOF

cat >"$TARGET_DIR/tests/__init__.py" <<'EOF'
"""Portable conformance tests."""
EOF

cat >"$TARGET_DIR/README.md" <<'EOF'
# Actenon Portable Distribution

This distribution contains the portable verifier-side open layer only.

Included:

- verifier SDK
- public versioned schemas
- local proof mode
- hello-world protected resource example
- conformance tests

Excluded:

- full kernel orchestration
- policy engines
- finance wedges
- hosted control-plane services

Quick start:

```bash
PYTHONPATH=. python3 -m actenon.demo.portable_local_proof --artifacts-dir artifacts/portable_local_proof
```

Verifier reference:

- `docs/reference/verifier/VERIFIER_SDK_REFERENCE.md`

Open boundary:

- `OPEN_SOURCE_BOUNDARY.md`
EOF

cat >"$TARGET_DIR/pyproject.toml" <<'EOF'
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "actenon-portable"
version = "0.1.0"
description = "Portable verifier SDK and public contracts for protected endpoint verification."
readme = "README.md"
requires-python = ">=3.9"
dependencies = []

[tool.setuptools.packages.find]
where = ["."]
include = ["actenon*", "examples*", "tests*"]
EOF

tar -czf "$ARCHIVE_PATH" -C "$BUILD_ROOT" "$PACKAGE_NAME"

printf 'Portable distribution built at: %s\n' "$TARGET_DIR"
printf 'Portable distribution archive: %s\n' "$ARCHIVE_PATH"
