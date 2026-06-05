from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from threading import Thread
from typing import Callable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from actenon.models import ExecutionAnchor, build_artifact_digest, sha256_artifact_hex
from actenon.models.contracts import JsonScalar, PCCB, Receipt, Refusal, utc_now


LOGGER = logging.getLogger(__name__)
ExecutionGraphTransport = Callable[[str, bytes, float], None]


class ExecutionGraphClient(Protocol):
    def publish(self, anchor: ExecutionAnchor) -> None:
        """Publish an execution anchor without affecting execution outcome."""


def _normalize_metadata(metadata: Mapping[str, JsonScalar] | None) -> dict[str, JsonScalar]:
    if metadata is None:
        return {}
    normalized = dict(metadata)
    for key, value in normalized.items():
        if not isinstance(key, str) or not key:
            raise ValueError("execution anchor metadata keys must be non-empty strings")
        if value is not None and not isinstance(value, (str, int, float, bool)):
            raise ValueError(f"execution anchor metadata value for {key!r} must be a JSON scalar")
    return normalized


def create_execution_anchor_from_receipt(
    receipt: Receipt,
    pccb: PCCB,
    *,
    published_at=None,
    metadata: Mapping[str, JsonScalar] | None = None,
) -> ExecutionAnchor:
    if receipt.outcome != "executed":
        raise ValueError("only executed receipts can produce a receipt-based execution anchor")
    if receipt.correlation is None or receipt.correlation.pccb_id is None:
        raise ValueError("receipt must include a correlated pccb_id")
    if receipt.correlation.pccb_id != pccb.pccb_id:
        raise ValueError("receipt correlation pccb_id does not match the supplied PCCB")
    if receipt.correlation.action_hash is not None and receipt.correlation.action_hash != pccb.action_hash:
        raise ValueError("receipt correlation action_hash does not match the supplied PCCB")
    return ExecutionAnchor(
        published_at=published_at or utc_now(),
        outcome="executed",
        action_hash=pccb.action_hash,
        pccb_digest=build_artifact_digest(pccb),
        receipt_digest=build_artifact_digest(receipt),
        metadata=_normalize_metadata(metadata),
    )


def create_execution_anchor_from_refusal(
    refusal: Refusal,
    pccb: PCCB,
    *,
    published_at=None,
    metadata: Mapping[str, JsonScalar] | None = None,
) -> ExecutionAnchor:
    if refusal.correlation is None or refusal.correlation.pccb_id is None:
        raise ValueError("refusal must include a correlated pccb_id")
    if refusal.correlation.pccb_id != pccb.pccb_id:
        raise ValueError("refusal correlation pccb_id does not match the supplied PCCB")
    if refusal.correlation.action_hash is not None and refusal.correlation.action_hash != pccb.action_hash:
        raise ValueError("refusal correlation action_hash does not match the supplied PCCB")
    return ExecutionAnchor(
        published_at=published_at or utc_now(),
        outcome="refused",
        action_hash=pccb.action_hash,
        pccb_digest=build_artifact_digest(pccb),
        refusal_digest=build_artifact_digest(refusal),
        metadata=_normalize_metadata(metadata),
    )


def build_execution_anchor_hash(anchor: ExecutionAnchor) -> str:
    return sha256_artifact_hex(anchor)


@dataclass(frozen=True)
class NoOpExecutionGraphClient:
    def publish(self, anchor: ExecutionAnchor) -> None:
        return None


def _default_http_transport(endpoint_url: str, payload: bytes, timeout_seconds: float) -> None:
    request = Request(
        endpoint_url,
        data=payload,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_seconds):
            return None
    except HTTPError as exc:
        raise RuntimeError(f"execution graph publication failed with HTTP {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError("execution graph publication request failed") from exc


@dataclass
class HttpExecutionGraphClient:
    endpoint_url: str
    timeout_seconds: float = 2.0
    transport: ExecutionGraphTransport = _default_http_transport
    logger: logging.Logger = field(default_factory=lambda: LOGGER)

    def publish(self, anchor: ExecutionAnchor) -> None:
        payload = json.dumps(anchor.to_dict(), separators=(",", ":"), sort_keys=True).encode("utf-8")

        def _worker() -> None:
            try:
                self.transport(self.endpoint_url, payload, self.timeout_seconds)
            except Exception as exc:  # pragma: no cover - exercised via logger behavior, not transport details
                self.logger.warning("Execution graph publication failed: %s", exc)

        Thread(target=_worker, daemon=True).start()
