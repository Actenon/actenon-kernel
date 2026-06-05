from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Iterable, Protocol

from actenon.api import ActionIntentIntakeService
from actenon.core.json import loads_no_duplicate_keys
from actenon.models import ActionIntent, PCCB


class ActionIntentStore(Protocol):
    def get_intent(self, intent_id: str) -> ActionIntent | None:
        ...

    def list_intents(self) -> tuple[ActionIntent, ...]:
        ...


class PCCBStore(Protocol):
    def get_pccb(self, pccb_id: str) -> PCCB | None:
        ...

    def list_pccbs(self) -> tuple[PCCB, ...]:
        ...


@dataclass
class InMemoryActionIntentStore:
    intents: dict[str, ActionIntent] = field(default_factory=dict)

    @classmethod
    def from_intents(cls, intents: Iterable[ActionIntent]) -> "InMemoryActionIntentStore":
        return cls(intents={intent.intent_id: intent for intent in intents})

    def put_intent(self, intent: ActionIntent) -> None:
        self.intents[intent.intent_id] = intent

    def get_intent(self, intent_id: str) -> ActionIntent | None:
        return self.intents.get(intent_id)

    def list_intents(self) -> tuple[ActionIntent, ...]:
        return tuple(self.intents.values())


@dataclass
class InMemoryPCCBStore:
    pccbs: dict[str, PCCB] = field(default_factory=dict)

    @classmethod
    def from_pccbs(cls, pccbs: Iterable[PCCB]) -> "InMemoryPCCBStore":
        return cls(pccbs={pccb.pccb_id: pccb for pccb in pccbs})

    def put_pccb(self, pccb: PCCB) -> None:
        self.pccbs[pccb.pccb_id] = pccb

    def get_pccb(self, pccb_id: str) -> PCCB | None:
        return self.pccbs.get(pccb_id)

    def list_pccbs(self) -> tuple[PCCB, ...]:
        return tuple(self.pccbs.values())


@dataclass(frozen=True)
class JsonArtifactActionIntentStore:
    artifact_root: Path

    @cached_property
    def _intents(self) -> dict[str, ActionIntent]:
        intake = ActionIntentIntakeService()
        intents: dict[str, ActionIntent] = {}
        seen_paths: dict[str, Path] = {}
        for target in sorted(self.artifact_root.rglob("action_intent.json")):
            payload = loads_no_duplicate_keys(target.read_text(encoding="utf-8"))
            intent = intake.parse(payload)
            existing = seen_paths.get(intent.intent_id)
            if existing is not None:
                raise ValueError(
                    f"duplicate Action Intent id {intent.intent_id!r} found in {existing} and {target}"
                )
            seen_paths[intent.intent_id] = target
            intents[intent.intent_id] = intent
        return intents

    def get_intent(self, intent_id: str) -> ActionIntent | None:
        return self._intents.get(intent_id)

    def list_intents(self) -> tuple[ActionIntent, ...]:
        return tuple(self._intents.values())


@dataclass(frozen=True)
class JsonArtifactPCCBStore:
    artifact_root: Path

    @cached_property
    def _pccbs(self) -> dict[str, PCCB]:
        pccbs: dict[str, PCCB] = {}
        seen_paths: dict[str, Path] = {}
        for target in sorted(self.artifact_root.rglob("pccb.json")):
            payload = loads_no_duplicate_keys(target.read_text(encoding="utf-8"))
            pccb = PCCB.from_dict(payload)
            existing = seen_paths.get(pccb.pccb_id)
            if existing is not None:
                raise ValueError(
                    f"duplicate PCCB id {pccb.pccb_id!r} found in {existing} and {target}"
                )
            seen_paths[pccb.pccb_id] = target
            pccbs[pccb.pccb_id] = pccb
        return pccbs

    def get_pccb(self, pccb_id: str) -> PCCB | None:
        return self._pccbs.get(pccb_id)

    def list_pccbs(self) -> tuple[PCCB, ...]:
        return tuple(self._pccbs.values())
