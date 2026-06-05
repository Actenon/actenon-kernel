from __future__ import annotations

import json as _json
from collections.abc import Iterable, Mapping
from typing import Any


DEFAULT_MAX_JSON_BYTES = 1_048_576
DEFAULT_MAX_JSON_DEPTH = 128


class DuplicateJSONKeyError(ValueError):
    """Raised when a JSON object contains the same key more than once."""


class JSONInputTooLargeError(ValueError):
    """Raised when raw JSON input exceeds the configured byte limit."""


class JSONNestingDepthError(ValueError):
    """Raised when JSON-like data exceeds the configured nesting-depth limit."""


def _input_size(raw: str | bytes | bytearray) -> int:
    if isinstance(raw, str):
        return len(raw.encode("utf-8"))
    return len(raw)


def reject_duplicate_object_pairs(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise DuplicateJSONKeyError(f"duplicate JSON object key {key!r}")
        payload[key] = value
    return payload


def validate_json_depth(value: Any, *, max_depth: int = DEFAULT_MAX_JSON_DEPTH) -> None:
    if max_depth <= 0:
        raise ValueError("max_depth must be positive")
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > max_depth:
            raise JSONNestingDepthError(f"JSON value exceeds maximum nesting depth {max_depth}")
        if isinstance(item, Mapping):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend((child, depth + 1) for child in item)


def loads_no_duplicate_keys(
    raw: str | bytes | bytearray,
    *,
    max_bytes: int = DEFAULT_MAX_JSON_BYTES,
    max_depth: int = DEFAULT_MAX_JSON_DEPTH,
) -> Any:
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if _input_size(raw) > max_bytes:
        raise JSONInputTooLargeError(f"JSON input exceeds maximum size {max_bytes} bytes")
    try:
        payload = _json.loads(raw, object_pairs_hook=reject_duplicate_object_pairs)
    except RecursionError as exc:
        raise JSONNestingDepthError(f"JSON input exceeds maximum nesting depth {max_depth}") from exc
    validate_json_depth(payload, max_depth=max_depth)
    return payload
