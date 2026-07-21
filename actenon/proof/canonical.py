from __future__ import annotations

import json
from hashlib import sha256
from typing import Any

from actenon.core.json import DEFAULT_MAX_JSON_DEPTH, JSONInputTooLargeError, validate_json_depth


DEFAULT_MAX_CANONICAL_OUTPUT_BYTES = 1_048_576

# The canonicalisation profile used for all newly minted proofs, receipts,
# and action hashes. This is a strict subset of RFC 8785 (JCS) that rejects
# floating-point values entirely instead of canonicalising them.
#
# Profile name: ACTENON-JCS-STRICT-1
# Version: 1
# Legacy identifier: RFC8785-JCS (historical proofs — same canonicalisation
# logic, different label)
#
# The canonicalisation profile label is sourced from the pinned
# actenon-protocol package to prevent drift. See
# github.com/Actenon/actenon-protocol and
# canonicalisation/ACTENON-JCS-STRICT-1.md for the authoritative
# specification.
from actenon_protocol import (
    CANONICALISATION_PROFILE as _PROTOCOL_CANONICALISATION_PROFILE,
    LEGACY_CANONICALISATION_PROFILE as _PROTOCOL_LEGACY_CANONICALISATION_PROFILE,
    ACCEPTED_CANONICALISATION_PROFILES as _PROTOCOL_ACCEPTED_CANONICALISATION_PROFILES,
    CANONICALISATION_PROFILE_VERSION as _PROTOCOL_CANONICALISATION_PROFILE_VERSION,
)

# Kernel uses US spelling (canonicalization) for backward compatibility.
# The protocol uses British spelling (canonicalisation). The values are
# identical; only the attribute name differs.
CANONICALIZATION_PROFILE = _PROTOCOL_CANONICALISATION_PROFILE
CANONICALIZATION_PROFILE_VERSION = _PROTOCOL_CANONICALISATION_PROFILE_VERSION

# The legacy identifier used by historical proofs. The canonicalisation
# logic is identical — only the label differs. Historical proofs with
# this identifier continue to verify under the same logic.
LEGACY_CANONICALIZATION_PROFILE = _PROTOCOL_LEGACY_CANONICALISATION_PROFILE

# All canonicalisation identifiers accepted by the verifier.
# New proofs use CANONICALIZATION_PROFILE; historical proofs may use
# LEGACY_CANONICALIZATION_PROFILE. Any other identifier is rejected.
# Sourced from the protocol to prevent drift.
ACCEPTED_CANONICALIZATION_PROFILES = _PROTOCOL_ACCEPTED_CANONICALISATION_PROFILES


def _canonicalize_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _canonicalize_json(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise TypeError("floating-point values are not supported in canonical action hashing")
    if isinstance(value, str):
        return _canonicalize_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_canonicalize_json(item) for item in value) + "]"
    if isinstance(value, tuple):
        return "[" + ",".join(_canonicalize_json(item) for item in value) + "]"
    if isinstance(value, dict):
        pieces = []
        for key in sorted(value.keys()):
            if not isinstance(key, str):
                raise TypeError("canonical JSON object keys must be strings")
            pieces.append(_canonicalize_string(key) + ":" + _canonicalize_json(value[key]))
        return "{" + ",".join(pieces) + "}"
    raise TypeError(f"unsupported value type for canonicalization: {type(value)!r}")


def canonicalize_json(value: Any, *, max_depth: int = DEFAULT_MAX_JSON_DEPTH) -> str:
    validate_json_depth(value, max_depth=max_depth)
    return _canonicalize_json(value)


def canonicalize_bytes(
    value: Any,
    *,
    max_depth: int = DEFAULT_MAX_JSON_DEPTH,
    max_output_bytes: int = DEFAULT_MAX_CANONICAL_OUTPUT_BYTES,
) -> bytes:
    if max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be positive")
    encoded = canonicalize_json(value, max_depth=max_depth).encode("utf-8")
    if len(encoded) > max_output_bytes:
        raise JSONInputTooLargeError(f"canonical JSON output exceeds maximum size {max_output_bytes} bytes")
    return encoded


def sha256_hex(value: Any) -> str:
    return sha256(canonicalize_bytes(value)).hexdigest()
