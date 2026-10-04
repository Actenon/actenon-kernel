"""The decision path every consequential action goes through.

1. The approved manifest must contain an entry matching (action, resource) exactly (or a single-segment
   template). Nothing else is authority: an empty manifest, a pending entry, an unresolved item, an
   unknown host or route are all refused.
2. Permit's PDP decides on the run's grant (scopes = the approved actions) and, on ALLOW, mints a kernel
   PCCB bound to the exact action: capability, target resource and parameters (method, URL, body digest /
   path / program).
3. Immediately before execution the edge rebuilds the action from the request it is about to execute and
   verifies the PCCB against it (kernel ``PCCBVerifier``): a changed target, method, URL or body is refused.
   Only then is a credential released and the action executed.
"""

from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .home import grant_key_file, proof_key_file
from .manifest import AuthorityEntry, Manifest
from .receipts import Receipt, ReceiptStore, new_receipt_id, stamp

NO_AUTHORITY_SCOPE = "airlock.no-approved-authority"  # Permit treats an empty allow list as "allow all"


@dataclass(frozen=True)
class ActionFacts:
    kind: str  # http | filesystem | process | network
    action: str
    resource: str | None  # None: the target could not be named (always refused)
    params: dict[str, Any] = field(default_factory=dict)
    display: dict[str, Any] = field(default_factory=dict)  # what to show in receipts (method/url/path/program)


@dataclass
class Authorization:
    allowed: bool
    reason: str
    facts: ActionFacts
    entry: AuthorityEntry | None = None
    intent: Any = None
    pccb: Any = None
    permit_action: Any = None
    receipt_id: str = ""


def body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


class Decider:
    def __init__(self, manifest: Manifest, run_dir: Path, receipts: ReceiptStore, *, agent_id: str):
        os.environ["ACTENON_SIGNING_KEY_FILE"] = str(grant_key_file())
        os.environ["ACTENON_ED25519_KEY_FILE"] = str(proof_key_file())
        from actenon_permit.ledger import Ledger
        from actenon_permit.model import Grant, Scopes
        from actenon_permit.pdp import PDP
        from actenon_permit.state import SQLiteStore

        self.manifest = manifest
        self.receipts = receipts
        self._lock = threading.Lock()
        self.store = SQLiteStore(str(run_dir / "permit-state.db"))
        self.ledger = Ledger(self.store)
        self.pdp = PDP(self.store, self.ledger)
        allow = sorted({e.action for e in manifest.approved()}) or [NO_AUTHORITY_SCOPE]
        self.grant = Grant(agent_id=agent_id, expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
                           scopes=Scopes(allow=allow)).sign()
        self.store.put_grant(self.grant)
        from actenon_permit.ed25519_signer import load_ed25519_keypair

        receipts.write_public_key(load_ed25519_keypair(proof_key_file()).public_key_jwk)

    # --- step 1 + 2 -----------------------------------------------------------------------------------
    def authorize(self, facts: ActionFacts) -> Authorization:
        if facts.resource is None:
            return Authorization(False, "the target of this action could not be determined", facts)
        entry = self.manifest.find(facts.action, facts.resource)
        if entry is None:
            pending = self.manifest.find(facts.action, facts.resource, approved_only=False)
            reason = ("authority is pending approval (run `airlock approve`)" if pending is not None
                      else "authority not present in approved manifest")
            return Authorization(False, reason, facts)
        from actenon_permit.model import Action, DecisionOutcome

        action = Action(grant_id=self.grant.id, type=facts.action, target=facts.resource, params=dict(facts.params))
        with self._lock:
            decision, intent, pccb = self.pdp.decide_and_mint_pccb(self.grant, action)
        if decision.outcome != DecisionOutcome.ALLOW or pccb is None:
            return Authorization(False, f"Permit refused: {decision.reason}", facts, entry)
        return Authorization(True, "approved authority", facts, entry, intent, pccb, action)

    # --- step 3 ---------------------------------------------------------------------------------------
    def verify(self, auth: Authorization, final: ActionFacts) -> None:
        """Raise unless the action about to execute is exactly the one the proof is bound to."""
        from actenon_permit import kernel_bridge as kb

        if final.action != auth.facts.action or final.resource != auth.facts.resource:
            raise PermissionError("the action changed after authorisation")
        executed = auth.permit_action.model_copy(update={"params": dict(final.params), "target": final.resource})
        kb.verify_pccb_at_edge(auth.intent, auth.pccb, self.grant, executed, store=self.store)

    # --- receipts -------------------------------------------------------------------------------------
    def record(self, auth: Authorization, *, executed: bool, result: dict[str, Any] | None = None,
               credentials: list[str] | None = None, upstream: str = "", reason: str | None = None) -> Receipt:
        rid = auth.receipt_id or new_receipt_id()
        allowed = auth.allowed and executed
        entry = auth.entry
        r = Receipt(
            id=rid, ts=stamp(), decision="ALLOWED" if allowed else "BLOCKED", action=auth.facts.action,
            target=auth.facts.resource or "(unknown)", kind=auth.facts.kind, request=dict(auth.facts.display),
            reason=reason or ("approved authority" if allowed else auth.reason),
            authority=f"{entry.action} {entry.resource}" if entry is not None and allowed else "",
            authority_source=_authority_source(entry) if entry is not None and allowed else "",
            provenance=[{"file": e.file, "line": e.line, "function": e.function, "via": e.via} for e in entry.evidence]
            if entry is not None else [],
            proof_id=getattr(auth.pccb, "pccb_id", "") if auth.pccb is not None else "",
            action_hash=getattr(getattr(auth.pccb, "action_hash", None), "value", "") if auth.pccb is not None else "",
            credential_released=bool(allowed and credentials), credentials=list(credentials or []) if allowed else [],
            execution_occurred=allowed, result=dict(result or {}), upstream=upstream if allowed else "none",
        )
        if allowed and auth.pccb is not None:
            from actenon_permit import kernel_bridge as kb

            kernel_receipt = kb.build_execution_receipt(auth.intent, auth.pccb, self.grant, auth.permit_action,
                                                        {"airlock_receipt": rid, **(result or {})})
            r.kernel_receipt_id = getattr(kernel_receipt, "receipt_id", "")
            self.receipts.write_kernel_artifacts(rid, intent=auth.intent, pccb=auth.pccb, kernel_receipt=kernel_receipt)
        return self.receipts.add(r)


def _authority_source(entry: AuthorityEntry) -> str:
    if entry.origin == "user":
        return f"approved by user{(' (' + entry.note + ')') if entry.note else ''}"
    if entry.evidence:
        e = entry.evidence[0]
        more = f" (+{len(entry.evidence) - 1} more)" if len(entry.evidence) > 1 else ""
        return f"discovered at {e.file}:{e.line}{more}, approved {entry.approved_at or ''}".rstrip()
    return "approved manifest"
