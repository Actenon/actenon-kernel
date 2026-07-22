from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Protocol

from actenon.core.json import loads_no_duplicate_keys
from actenon.models import Receipt, Refusal


class ReceiptStore(Protocol):
    def get_receipt(self, receipt_id: str) -> Receipt | None:
        ...

    def list_receipts(self) -> tuple[Receipt, ...]:
        ...


class RefusalStore(Protocol):
    def get_refusal(self, refusal_id: str) -> Refusal | None:
        ...

    def list_refusals(self) -> tuple[Refusal, ...]:
        ...


@dataclass
class InMemoryReceiptStore:
    receipts: dict[str, Receipt] = field(default_factory=dict)

    @classmethod
    def from_receipts(cls, receipts: Iterable[Receipt]) -> "InMemoryReceiptStore":
        return cls(receipts={receipt.receipt_id: receipt for receipt in receipts})

    def put_receipt(self, receipt: Receipt) -> None:
        self.receipts[receipt.receipt_id] = receipt

    def get_receipt(self, receipt_id: str) -> Receipt | None:
        return self.receipts.get(receipt_id)

    def list_receipts(self) -> tuple[Receipt, ...]:
        return tuple(self.receipts.values())


@dataclass(frozen=True)
class JsonArtifactReceiptStore:
    artifact_root: Path

    def _receipts_dir(self) -> Path:
        return self.artifact_root / "receipts"

    def get_receipt(self, receipt_id: str) -> Receipt | None:
        target = self._receipts_dir() / f"{receipt_id}.json"
        if not target.exists():
            return None
        payload = loads_no_duplicate_keys(target.read_text(encoding="utf-8"))
        return Receipt.from_dict(payload)

    def list_receipts(self) -> tuple[Receipt, ...]:
        root = self._receipts_dir()
        if not root.exists():
            return ()
        receipts: list[Receipt] = []
        for target in sorted(root.glob("*.json")):
            payload = loads_no_duplicate_keys(target.read_text(encoding="utf-8"))
            receipts.append(Receipt.from_dict(payload))
        return tuple(receipts)


@dataclass
class InMemoryRefusalStore:
    refusals: dict[str, Refusal] = field(default_factory=dict)

    @classmethod
    def from_refusals(cls, refusals: Iterable[Refusal]) -> "InMemoryRefusalStore":
        return cls(refusals={refusal.refusal_id: refusal for refusal in refusals})

    def put_refusal(self, refusal: Refusal) -> None:
        self.refusals[refusal.refusal_id] = refusal

    def get_refusal(self, refusal_id: str) -> Refusal | None:
        return self.refusals.get(refusal_id)

    def list_refusals(self) -> tuple[Refusal, ...]:
        return tuple(self.refusals.values())


@dataclass(frozen=True)
class JsonArtifactRefusalStore:
    artifact_root: Path

    def _refusals_dir(self) -> Path:
        return self.artifact_root / "refusals"

    def get_refusal(self, refusal_id: str) -> Refusal | None:
        target = self._refusals_dir() / f"{refusal_id}.json"
        if not target.exists():
            return None
        payload = loads_no_duplicate_keys(target.read_text(encoding="utf-8"))
        return Refusal.from_dict(payload)

    def list_refusals(self) -> tuple[Refusal, ...]:
        root = self._refusals_dir()
        if not root.exists():
            return ()
        refusals: list[Refusal] = []
        for target in sorted(root.glob("*.json")):
            payload = loads_no_duplicate_keys(target.read_text(encoding="utf-8"))
            refusals.append(Refusal.from_dict(payload))
        return tuple(refusals)
