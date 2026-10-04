from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Protocol

from actenon.core.json import loads_no_duplicate_keys
from actenon.models import Receipt, Refusal


def _artifact_file(directory: Path, artifact_id: str) -> Path | None:
    """Return ``directory/<artifact_id>.json`` only if it stays inside ``directory``.

    Artifact ids reach these stores from untrusted input (for example an
    Action Intent's ``evidence_refs[].value``), so an id must be a single
    path segment: no separators, no ``..``, no absolute paths.
    """

    if (
        not isinstance(artifact_id, str)
        or not artifact_id
        or artifact_id in {".", ".."}
        or any(char in artifact_id for char in ("/", "\\", "\x00"))
    ):
        return None
    target = directory / f"{artifact_id}.json"
    try:
        if target.resolve().parent != directory.resolve():
            return None
    except (OSError, RuntimeError):
        return None
    return target


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
        target = _artifact_file(self._receipts_dir(), receipt_id)
        if target is None or not target.is_file():
            return None
        payload = loads_no_duplicate_keys(target.read_text(encoding="utf-8"))
        receipt = Receipt.from_dict(payload)
        if receipt.receipt_id != receipt_id:
            return None
        return receipt

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
        target = _artifact_file(self._refusals_dir(), refusal_id)
        if target is None or not target.is_file():
            return None
        payload = loads_no_duplicate_keys(target.read_text(encoding="utf-8"))
        refusal = Refusal.from_dict(payload)
        if refusal.refusal_id != refusal_id:
            return None
        return refusal

    def list_refusals(self) -> tuple[Refusal, ...]:
        root = self._refusals_dir()
        if not root.exists():
            return ()
        refusals: list[Refusal] = []
        for target in sorted(root.glob("*.json")):
            payload = loads_no_duplicate_keys(target.read_text(encoding="utf-8"))
            refusals.append(Refusal.from_dict(payload))
        return tuple(refusals)
