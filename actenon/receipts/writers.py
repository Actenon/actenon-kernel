from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from actenon.evidence.stores import PCCBStore
from actenon.execution_graph import (
    ExecutionGraphClient,
    create_execution_anchor_from_receipt,
    create_execution_anchor_from_refusal,
)
from actenon.models.contracts import Receipt, Refusal
from .store import InMemoryReceiptStore, InMemoryRefusalStore


LOGGER = logging.getLogger(__name__)


class OutcomeWriter(Protocol):
    def write_receipt(self, receipt: Receipt) -> None:
        ...

    def write_refusal(self, refusal: Refusal) -> None:
        ...


class CompositeOutcomeWriter:
    def __init__(self, *writers: OutcomeWriter) -> None:
        self._writers = writers

    def write_receipt(self, receipt: Receipt) -> None:
        for writer in self._writers:
            writer.write_receipt(receipt)

    def write_refusal(self, refusal: Refusal) -> None:
        for writer in self._writers:
            writer.write_refusal(refusal)


@dataclass
class InMemoryOutcomeWriter:
    receipts: list[Receipt] = field(default_factory=list)
    refusals: list[Refusal] = field(default_factory=list)
    receipt_store: InMemoryReceiptStore | None = None
    refusal_store: InMemoryRefusalStore | None = None
    pccb_store: PCCBStore | None = None
    execution_graph_client: ExecutionGraphClient | None = None

    def write_receipt(self, receipt: Receipt) -> None:
        self.receipts.append(receipt)
        if self.receipt_store is not None:
            self.receipt_store.put_receipt(receipt)
        if self.execution_graph_client is not None and self.pccb_store is not None and receipt.outcome == "executed":
            correlation = receipt.correlation
            if correlation is None or correlation.pccb_id is None:
                LOGGER.warning("Skipping execution anchor publication for receipt %s: missing pccb correlation.", receipt.receipt_id)
                return
            pccb = self.pccb_store.get_pccb(correlation.pccb_id)
            if pccb is None:
                LOGGER.warning(
                    "Skipping execution anchor publication for receipt %s: pccb %s not found.",
                    receipt.receipt_id,
                    correlation.pccb_id,
                )
                return
            try:
                anchor = create_execution_anchor_from_receipt(receipt, pccb)
                self.execution_graph_client.publish(anchor)
            except Exception as exc:
                LOGGER.warning("Execution anchor publication failed for receipt %s: %s", receipt.receipt_id, exc)

    def write_refusal(self, refusal: Refusal) -> None:
        self.refusals.append(refusal)
        if self.refusal_store is not None:
            self.refusal_store.put_refusal(refusal)
        if self.execution_graph_client is not None and self.pccb_store is not None:
            correlation = refusal.correlation
            if correlation is None or correlation.pccb_id is None:
                LOGGER.warning("Skipping execution anchor publication for refusal %s: missing pccb correlation.", refusal.refusal_id)
                return
            pccb = self.pccb_store.get_pccb(correlation.pccb_id)
            if pccb is None:
                LOGGER.warning(
                    "Skipping execution anchor publication for refusal %s: pccb %s not found.",
                    refusal.refusal_id,
                    correlation.pccb_id,
                )
                return
            try:
                anchor = create_execution_anchor_from_refusal(refusal, pccb)
                self.execution_graph_client.publish(anchor)
            except Exception as exc:
                LOGGER.warning("Execution anchor publication failed for refusal %s: %s", refusal.refusal_id, exc)


@dataclass
class JsonArtifactOutcomeWriter:
    artifact_root: Path
    pccb_store: PCCBStore | None = None
    execution_graph_client: ExecutionGraphClient | None = None

    def __post_init__(self) -> None:
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        (self.artifact_root / "receipts").mkdir(parents=True, exist_ok=True)
        (self.artifact_root / "refusals").mkdir(parents=True, exist_ok=True)

    def write_receipt(self, receipt: Receipt) -> None:
        target = self.artifact_root / "receipts" / f"{receipt.receipt_id}.json"
        target.write_text(json.dumps(receipt.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if self.execution_graph_client is not None and self.pccb_store is not None and receipt.outcome == "executed":
            correlation = receipt.correlation
            if correlation is None or correlation.pccb_id is None:
                LOGGER.warning("Skipping execution anchor publication for receipt %s: missing pccb correlation.", receipt.receipt_id)
                return
            pccb = self.pccb_store.get_pccb(correlation.pccb_id)
            if pccb is None:
                LOGGER.warning(
                    "Skipping execution anchor publication for receipt %s: pccb %s not found.",
                    receipt.receipt_id,
                    correlation.pccb_id,
                )
                return
            try:
                anchor = create_execution_anchor_from_receipt(receipt, pccb)
                self.execution_graph_client.publish(anchor)
            except Exception as exc:
                LOGGER.warning("Execution anchor publication failed for receipt %s: %s", receipt.receipt_id, exc)

    def write_refusal(self, refusal: Refusal) -> None:
        target = self.artifact_root / "refusals" / f"{refusal.refusal_id}.json"
        target.write_text(json.dumps(refusal.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if self.execution_graph_client is not None and self.pccb_store is not None:
            correlation = refusal.correlation
            if correlation is None or correlation.pccb_id is None:
                LOGGER.warning("Skipping execution anchor publication for refusal %s: missing pccb correlation.", refusal.refusal_id)
                return
            pccb = self.pccb_store.get_pccb(correlation.pccb_id)
            if pccb is None:
                LOGGER.warning(
                    "Skipping execution anchor publication for refusal %s: pccb %s not found.",
                    refusal.refusal_id,
                    correlation.pccb_id,
                )
                return
            try:
                anchor = create_execution_anchor_from_refusal(refusal, pccb)
                self.execution_graph_client.publish(anchor)
            except Exception as exc:
                LOGGER.warning("Execution anchor publication failed for refusal %s: %s", refusal.refusal_id, exc)
