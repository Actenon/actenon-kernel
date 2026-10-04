"""Receipts for every consequential action Airlock decided.

Stored per run under ``.airlock/runs/<run-id>/receipts.jsonl`` (human and machine readable). For allowed
actions the kernel execution receipt, the proof (PCCB) and the intent are written next to it, so
``actenon-kernel verify-receipt`` can check them offline.
"""

from __future__ import annotations

import json
import secrets
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .manifest import now_iso


@dataclass
class Receipt:
    id: str
    ts: str
    decision: str  # ALLOWED | BLOCKED
    action: str
    target: str
    kind: str  # http | filesystem | process | network
    request: dict[str, Any] = field(default_factory=dict)  # method/url, path, program
    reason: str = ""
    authority: str = ""  # the approved entry used, e.g. "github.issue.create github.com/acme/support"
    authority_source: str = ""  # where the authority came from (discovered at file:line / approved by user)
    provenance: list[dict[str, Any]] = field(default_factory=list)  # code that needs this authority
    proof_id: str = ""
    action_hash: str = ""
    kernel_receipt_id: str = ""
    credential_released: bool = False
    credentials: list[str] = field(default_factory=list)  # names only, never values
    execution_occurred: bool = False
    result: dict[str, Any] = field(default_factory=dict)
    upstream: str = ""  # real | stand-in | none

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def new_receipt_id() -> str:
    return "rcpt_" + secrets.token_hex(8)


class ReceiptStore:
    def __init__(self, run_dir: Path, redact=lambda s: s):
        self.dir = run_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "kernel").mkdir(exist_ok=True)
        self.path = self.dir / "receipts.jsonl"
        self._lock = threading.Lock()
        self._redact = redact
        self.receipts: list[Receipt] = []

    def add(self, r: Receipt) -> Receipt:
        line = self._redact(json.dumps(r.to_dict(), sort_keys=True))
        with self._lock:
            self.receipts.append(r)
            with self.path.open("a") as f:
                f.write(line + "\n")
        return r

    def write_public_key(self, jwk: dict[str, Any]) -> None:
        """The edge's proof-verification key, so kernel receipts verify offline with --public-key-jwk."""
        (self.dir / "kernel" / "proof-public-key.jwk.json").write_text(json.dumps(jwk, indent=2) + "\n")

    def write_kernel_artifacts(self, receipt_id: str, *, intent: Any, pccb: Any, kernel_receipt: Any) -> None:
        d = self.dir / "kernel" / receipt_id
        d.mkdir(exist_ok=True)
        for name, obj in (("intent", intent), ("pccb", pccb), ("receipt", kernel_receipt)):
            data = obj.model_dump(mode="json") if hasattr(obj, "model_dump") else (obj.to_dict() if hasattr(obj, "to_dict") else obj)
            (d / f"{name}.json").write_text(self._redact(json.dumps(data, indent=2, default=str)) + "\n")


def load_receipts(run_dir: Path) -> list[dict[str, Any]]:
    p = run_dir / "receipts.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]


def stamp() -> str:
    return now_iso()
