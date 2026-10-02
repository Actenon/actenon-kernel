"""Boundary Verifier — high-level Kernel verification for resource boundaries.

Wraps PCCBVerifier with the boundary-protection workflow:
  1. Decode the proof token into a PCCB (strict JSON: no duplicate keys,
     size and depth limits).
  2. Bind it to the exact Action Intent the request is performing, the
     route's declared action and target, and the boundary's audience.
  3. Verify the proof with the configured PCCBVerifier (signature,
     time window, audience, tenant, subject, target, action, action hash).
  4. Enforce single use (in-process by default, or a durable ReplayStore).
  5. Return a structured verification result.
  6. Construct a Kernel receipt on success.

This is the Kernel's contribution to the Actenon Boundary Kit. The
boundary middleware (in actenon-permit) calls this verifier; it does
NOT implement proof verification itself.

The verifier fails closed: without a configured ``PCCBVerifier`` (the
trust root) or without the Action Intent the proof was issued for, no
token is ever reported valid.
"""

from __future__ import annotations

import base64
import binascii
import logging
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import uuid4

from actenon.api import ActionIntentIntakeService
from actenon.core.errors import ProofVerificationError, RefusalException
from actenon.core.json import loads_no_duplicate_keys
from actenon.models import PCCB, ActionIntent, AudienceRef, DynamicContextInput
from actenon.proof.canonical import sha256_hex
from actenon.proof.service import PCCBVerifier
from actenon.replay.base import ReplayStore
from actenon.replay.service import build_action_consumption_claim, permit_process_local_replay

logger = logging.getLogger(__name__)

PROOF_TOKEN_PREFIX = "v1."


@dataclass(frozen=True)
class BoundaryVerificationRequest:
    """Input to BoundaryVerifier.verify_boundary().

    ``proof_token`` is the PCCB as JSON, as unpadded base64url of that
    JSON, or as ``"v1." + base64url(JSON)``. ``intent`` is the exact
    Action Intent (object or dict) the request is performing; a proof can
    only be verified against the action it authorises, so a request
    without one is refused. ``action_type`` and ``target`` are the
    route's declared action name and resource id, and must match the
    intent. ``action_hash``, when non-empty, must equal the proof's
    action hash. ``audience`` (``"type:id"``) identifies this boundary
    and is required. ``now`` overrides the verification time (default:
    the current UTC time).
    """

    proof_token: str
    action_type: str
    action_hash: str
    audience: str = ""
    boundary_id: str = ""
    target: str = ""
    intent: ActionIntent | Mapping[str, Any] | None = None
    now: datetime | None = None


@dataclass(frozen=True)
class BoundaryVerificationResult:
    """Result of boundary verification.

    The `reason` field is safe to surface to the caller; it NEVER
    contains credential values or secrets.
    """

    valid: bool
    reason: str
    refusal_code: str = ""
    proof_id: str | None = None
    receipt_id: str | None = None
    verified_at: str = ""

    @classmethod
    def success(cls, proof_id: str, receipt_id: str) -> BoundaryVerificationResult:
        return cls(
            valid=True,
            reason="verified",
            proof_id=proof_id,
            receipt_id=receipt_id,
            verified_at=datetime.now(timezone.utc).isoformat(),
        )

    @classmethod
    def failure(
        cls, reason: str, refusal_code: str = "PROOF_INVALID"
    ) -> BoundaryVerificationResult:
        return cls(
            valid=False,
            reason=reason,
            refusal_code=refusal_code,
            verified_at=datetime.now(timezone.utc).isoformat(),
        )


def _decode_proof_token(token: str) -> PCCB:
    """Decode a proof token into a PCCB. Raises ValueError on any problem."""

    text = token.strip()
    if not text.startswith("{"):
        text = text.removeprefix(PROOF_TOKEN_PREFIX)
        padding = "=" * (-len(text) % 4)
        try:
            text = base64.b64decode(
                (text + padding).encode("ascii"), altchars=b"-_", validate=True
            ).decode("utf-8")
        except (binascii.Error, UnicodeError) as exc:
            raise ValueError("proof token is neither PCCB JSON nor base64url-encoded PCCB JSON") from exc
    payload = loads_no_duplicate_keys(text)
    if not isinstance(payload, Mapping):
        raise ValueError("proof token must decode to a JSON object")
    return PCCB.from_dict(payload)


def _parse_audience(raw: str) -> AudienceRef:
    audience_type, separator, audience_id = raw.partition(":")
    if not separator:
        return AudienceRef(type="service", id=raw)
    if not audience_type or not audience_id:
        raise ValueError("audience must be 'type:id' or a bare service id")
    return AudienceRef(type=audience_type, id=audience_id)


class BoundaryVerifier:
    """High-level Kernel verifier for resource boundaries.

    Wraps PCCBVerifier with replay protection and receipt construction.
    The boundary middleware calls this verifier; it does NOT implement
    proof verification itself.

    The verifier DOES:
      - Verify the proof's signature, time window, audience, tenant,
        subject, target, action, and action hash against the exact intent
      - Check replay (single-use), keyed on proof identity rather than on
        the token's encoding
      - Return a structured result
      - Construct a receipt on success

    The verifier does NOT:
      - Execute the action (handler's job)
      - Resolve credentials (broker's job)
      - Issue proofs (authority's job)

    Without a ``pccb_verifier`` (the trust root) every token is refused
    with ``ISSUER_UNTRUSTED``. Single use is enforced against a durable
    ``replay_store`` shared by every worker: pass one, or set
    ``ACTENON_REPLAY_DB`` to a shared SQLite path. A process-local in-memory
    set (accepts a proof once per worker and again after a restart) requires
    explicit development intent or ``ACTENON_UNSAFE_ALLOW_PROCESS_LOCAL_REPLAY=1``
    and is listed in ``health()["security_downgrades"]``.
    """

    def __init__(
        self,
        *,
        pccb_verifier: PCCBVerifier | None = None,
        replay_store: ReplayStore | None = None,
    ) -> None:
        self._pccb_verifier = pccb_verifier
        self._security_downgrades: tuple[str, ...] = ()
        if replay_store is None and pccb_verifier is not None:
            # No trust root means every proof is refused, so there is no
            # single-use guarantee to protect; otherwise insist on shared state.
            configured = os.environ.get("ACTENON_REPLAY_DB")
            if configured:
                from actenon.replay.sqlite import SqliteReplayStore

                replay_store = SqliteReplayStore(configured)
            else:
                self._security_downgrades = (permit_process_local_replay("BoundaryVerifier"),)
        self._replay_store = replay_store
        self._replay_lock = threading.Lock()
        self._replay_keys: set[str] = set()
        self._intake = ActionIntentIntakeService()

    def verify_boundary(
        self, request: BoundaryVerificationRequest
    ) -> BoundaryVerificationResult:
        """Verify a boundary protection request.

        Returns a BoundaryVerificationResult. Never raises — all
        failures are captured in the result.
        """
        try:
            return self._verify(request)
        except Exception:  # pragma: no cover - defensive: never fail open
            logger.exception("boundary.verification_error")
            return BoundaryVerificationResult.failure(
                "boundary verification failed unexpectedly", "OUTCOME_UNKNOWN"
            )

    def _verify(self, request: BoundaryVerificationRequest) -> BoundaryVerificationResult:
        # Step 1: Proof presence.
        if not request.proof_token:
            return BoundaryVerificationResult.failure(
                "no proof token provided", "PROOF_MISSING"
            )

        # Step 2: A trust root is mandatory. Structure alone is never proof.
        if self._pccb_verifier is None:
            return BoundaryVerificationResult.failure(
                "no PCCBVerifier trust root is configured; the boundary refuses every proof",
                "ISSUER_UNTRUSTED",
            )

        # Step 3: Decode the token into a PCCB.
        try:
            pccb = _decode_proof_token(request.proof_token)
        except (ValueError, TypeError, RecursionError):
            return BoundaryVerificationResult.failure(
                "proof token is not a well-formed PCCB", "PROOF_INVALID"
            )

        # Step 4: The exact Action Intent this request performs.
        if request.intent is None:
            return BoundaryVerificationResult.failure(
                "no Action Intent supplied; a proof can only be verified against "
                "the exact action it authorises",
                "MALFORMED_REQUEST",
            )
        try:
            intent = (
                request.intent
                if isinstance(request.intent, ActionIntent)
                else self._intake.parse(request.intent)
            )
            audience = _parse_audience(request.audience)
        except (RefusalException, ValueError, TypeError):
            return BoundaryVerificationResult.failure(
                "the Action Intent or boundary audience is malformed", "MALFORMED_REQUEST"
            )

        # Step 5: The route's declared action and target bind the intent.
        if intent.action.name != request.action_type:
            return BoundaryVerificationResult.failure(
                "the intent's action does not match this boundary's action", "ACTION_MISMATCH"
            )
        if request.target and intent.target.resource_id != request.target:
            return BoundaryVerificationResult.failure(
                "the intent's target does not match this request's target", "TARGET_MISMATCH"
            )

        # Step 6: Full PCCB verification against the intent and this audience.
        context = DynamicContextInput(
            request_id=f"req_boundary_{uuid4().hex}",
            audience=audience,
            scope_capabilities=(intent.action.capability,),
            now=request.now or datetime.now(timezone.utc),
        )
        try:
            self._pccb_verifier.verify(intent, pccb, context)
        except ProofVerificationError as e:
            return BoundaryVerificationResult.failure(
                f"proof verification failed: {e.refusal_code}",
                e.refusal_code,
            )
        if request.action_hash and request.action_hash != pccb.action_hash.value:
            return BoundaryVerificationResult.failure(
                "the declared action hash does not match the proof", "ACTION_HASH_MISMATCH"
            )

        # Step 7: Single use. Keyed on proof identity, not on the token's
        # encoding, so re-serialising the same proof is still a replay.
        replay_refusal = self._claim_single_use(intent, pccb, context)
        if replay_refusal is not None:
            return replay_refusal

        # Step 8: Construct receipt ID.
        receipt_id = f"rcpt_{uuid4().hex[:16]}"

        logger.info(
            "boundary.verified",
            extra={
                "boundary_id": request.boundary_id,
                "action_type": request.action_type,
                "proof_id": pccb.pccb_id,
                "receipt_id": receipt_id,
                "audience": request.audience,
            },
        )

        return BoundaryVerificationResult.success(
            proof_id=pccb.pccb_id,
            receipt_id=receipt_id,
        )

    def _claim_single_use(
        self, intent: ActionIntent, pccb: PCCB, context: DynamicContextInput
    ) -> BoundaryVerificationResult | None:
        if self._replay_store is not None:
            claim = build_action_consumption_claim(intent, pccb, context)
            try:
                self._replay_store.claim_once(claim, now=context.now)
                self._replay_store.mark_consumed(claim.replay_key, now=context.now)
            except RefusalException:
                return BoundaryVerificationResult.failure(
                    "replay detected: proof has already been used", "REPLAY_DETECTED"
                )
            except Exception:
                return BoundaryVerificationResult.failure(
                    "replay state could not be established; refusing", "REPLAY_STORE_UNAVAILABLE"
                )
            return None

        replay_key = sha256_hex(
            {
                "pccb_id": pccb.pccb_id,
                "nonce": pccb.nonce,
                "action_hash": pccb.action_hash.to_dict(),
                "audience": pccb.audience.to_dict(),
            }
        )
        with self._replay_lock:
            if replay_key in self._replay_keys:
                return BoundaryVerificationResult.failure(
                    "replay detected: proof has already been used", "REPLAY_DETECTED"
                )
            self._replay_keys.add(replay_key)
        return None

    def construct_receipt(
        self,
        request: BoundaryVerificationRequest,
        result: BoundaryVerificationResult,
        outcome: str = "succeeded",
    ) -> dict[str, Any]:
        """Construct a receipt for a verified boundary execution."""
        if not result.valid:
            raise ValueError("a boundary receipt can only be constructed for a verified result")
        return {
            "receipt_id": result.receipt_id,
            "boundary_id": request.boundary_id,
            "action": request.action_type,
            "action_hash": request.action_hash[:16] + "...",
            "proof_id": result.proof_id,
            "outcome": outcome,
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "execution_mode": "resource_owned",
            "verified_at": result.verified_at,
        }

    def health(self) -> dict[str, Any]:
        """Health check."""
        return {
            "ok": self._pccb_verifier is not None,
            "pccb_verifier_configured": self._pccb_verifier is not None,
            "replay_store": "durable" if self._replay_store is not None else "in_memory_set",
            "replay_keys_tracked": len(self._replay_keys),
            "security_downgrades": list(self._security_downgrades),
        }


__all__ = [
    "BoundaryVerificationRequest",
    "BoundaryVerificationResult",
    "BoundaryVerifier",
]
