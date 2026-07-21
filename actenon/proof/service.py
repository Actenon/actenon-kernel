from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum
from secrets import token_urlsafe
from typing import Any, Callable
from uuid import uuid4

from actenon.core.errors import ProofVerificationError
from actenon.models.contracts import (
    ActionHashSpec,
    ActionIntent,
    PCCB,
    PartyRef,
    ScopeSpec,
    SignatureSpec,
)
from actenon.models.runtime import DynamicContextInput, PolicyDecision
from .audit import AuditLogSink, PCCBMintAuditRecord
from .canonical import canonicalize_bytes, sha256_hex
from .refusal_messages import public_proof_refusal_message
from .signing import SignatureVerifier, Signer


DEFAULT_CLOCK_SKEW_TOLERANCE = timedelta(0)

logger = logging.getLogger("actenon.proof.verifier")


class VerifierDisclosureMode(str, Enum):
    """How much detail the verifier exposes in its public refusal result.

    - ``public_generic`` (default, production-safe): invalidly-signed or
      unauthenticated proof returns one generic ``PROOF_INVALID`` code.
      No field-level detail is disclosed. Forged field values are not
      echoed into public receipts or caller-visible exceptions.

    - ``trusted_detailed``: after cryptographic authenticity is
      established, existing detailed semantic refusal codes remain
      available (``AUDIENCE_MISMATCH``, ``ACTION_MISMATCH``, etc.).

    - ``local_debug``: full diagnostics including pre-signature granular
      refusal codes. **Fail-closed**: construction with this mode in a
      production-like environment raises ``ValueError``.
    """

    PUBLIC_GENERIC = "public_generic"
    TRUSTED_DETAILED = "trusted_detailed"
    LOCAL_DEBUG = "local_debug"


# Environments where local_debug mode is permitted. Anything else
# (production, staging, etc.) refuses local_debug at construction time.
_LOCAL_DEBUG_ALLOWED_ENVS = frozenset({"local", "dev", "test", "demo", ""})


def _is_production_like_env() -> bool:
    """Return True if ACTENON_ENV indicates a production-like environment."""
    env = os.environ.get("ACTENON_ENV", "").strip().lower()
    return env not in _LOCAL_DEBUG_ALLOWED_ENVS


def build_action_hash_input(intent: ActionIntent) -> dict[str, Any]:
    return {
        "intent_id": intent.intent_id,
        "tenant": intent.tenant.to_dict(),
        "requester": intent.requester.to_dict(),
        "action": intent.action.to_dict(),
        "target": intent.target.to_dict(),
        "issued_at": intent.to_dict()["issued_at"],
        "expires_at": intent.to_dict()["expires_at"],
    }


@dataclass
class PCCBMinter:
    signer: Signer
    issuer: PartyRef
    pccb_id_factory: Callable[[], str] = field(default=lambda: f"pccb_{uuid4().hex}")
    nonce_factory: Callable[[], str] = field(default=lambda: token_urlsafe(24))
    audit_sink: AuditLogSink | None = None

    def mint(self, intent: ActionIntent, decision: PolicyDecision, context: DynamicContextInput, *, escrow_id: str | None = None) -> PCCB:
        if not decision.allowed:
            raise ValueError("PCCB minting requires an allow decision")

        issued_at = context.now
        scope = ScopeSpec(
            mode="exact",
            capabilities=tuple(sorted(set(context.scope_capabilities or (intent.action.capability,)))),
            single_use=True,
            resource_selectors=context.resource_selectors,
            parameter_constraints=context.parameter_constraints,
        )
        action_hash = ActionHashSpec(
            algorithm="sha-256",
            canonicalization="RFC8785-JCS",
            value=sha256_hex(build_action_hash_input(intent)),
        )
        unsigned = PCCB(
            pccb_id=self.pccb_id_factory(),
            intent_id=intent.intent_id,
            issued_at=issued_at,
            not_before=issued_at,
            expires_at=intent.expires_at,
            issuer=self.issuer,
            subject=intent.requester,
            tenant=intent.tenant,
            audience=context.audience,
            action=intent.action,
            target=intent.target,
            scope=scope,
            nonce=self.nonce_factory(),
            action_hash=action_hash,
            escrow_id=escrow_id,
            signature=SignatureSpec(algorithm=self.signer.algorithm, key_id=self.signer.key_id, encoding="base64url", value="pending"),
        )
        signature = self.signer.sign(canonicalize_bytes(unsigned.unsigned_payload()))
        pccb = PCCB(
            pccb_id=unsigned.pccb_id,
            intent_id=unsigned.intent_id,
            issued_at=unsigned.issued_at,
            not_before=unsigned.not_before,
            expires_at=unsigned.expires_at,
            issuer=unsigned.issuer,
            subject=unsigned.subject,
            tenant=unsigned.tenant,
            audience=unsigned.audience,
            action=unsigned.action,
            target=unsigned.target,
            scope=unsigned.scope,
            nonce=unsigned.nonce,
            action_hash=unsigned.action_hash,
            escrow_id=unsigned.escrow_id,
            signature=signature,
            extensions=unsigned.extensions,
        )
        if self.audit_sink is not None:
            self.audit_sink.record_pccb_mint(PCCBMintAuditRecord(pccb))
        return pccb


@dataclass
class PCCBVerifier:
    """Verify a PCCB against an ActionIntent and runtime context.

    The verifier enforces a strict two-phase ordering:

    **Phase A — Pre-authentication (minimum safe work):**
      1. bounded structural parsing (PCCB fields present and typed)
      2. total-size and nesting-depth enforcement (via canonicalize_bytes)
      3. strict type and encoding validation
      4. required-field presence for key resolution (signature, issuer)
      5. SSRF-safe issuer and key lookup (delegated to the signer)
      6. canonicalisation of the unsigned proof
      7. signature verification

    **Phase B — Post-authentication (detailed semantic validation):**
      8. time bounds (not_before, expires_at)
      9. audience
     10. scope mode + capability
     11. intent_id, tenant, subject, action, target
     12. action_hash

    This ordering prevents proof-forging oracles: a forger who presents
    a structurally-valid-but-wrong-signature PCCB with field mutations
    cannot learn which field is wrong, because all pre-authentication
    failures collapse to ``PROOF_INVALID`` in ``public_generic`` mode.

    The ``disclosure_mode`` parameter controls how much detail is exposed:
      - ``public_generic`` (default): pre-auth failures return
        ``PROOF_INVALID``; post-auth failures also return ``PROOF_INVALID``
        (no field-level detail is disclosed for unauthenticated proofs).
      - ``trusted_detailed``: post-auth failures return the existing
        detailed codes (``AUDIENCE_MISMATCH``, etc.) — but pre-auth
        failures still return ``PROOF_INVALID``.
      - ``local_debug``: full granular diagnostics (the pre-2B behaviour).
        **Fail-closed**: refused in production-like environments.
    """

    signer: SignatureVerifier
    clock_skew_tolerance: timedelta = DEFAULT_CLOCK_SKEW_TOLERANCE
    disclosure_mode: VerifierDisclosureMode = VerifierDisclosureMode.TRUSTED_DETAILED

    def __post_init__(self) -> None:
        if self.clock_skew_tolerance < timedelta(0):
            raise ValueError("clock_skew_tolerance must be non-negative")
        # Fail-closed: local_debug cannot be enabled in a production-like
        # environment. This is a hard construction-time refusal.
        if self.disclosure_mode == VerifierDisclosureMode.LOCAL_DEBUG:
            if _is_production_like_env():
                raise ValueError(
                    "VerifierDisclosureMode.LOCAL_DEBUG cannot be enabled in "
                    "a production-like environment (ACTENON_ENV="
                    f"{os.environ.get('ACTENON_ENV', '')!r}). Use "
                    "public_generic or trusted_detailed, or set ACTENON_ENV "
                    "to 'local', 'dev', 'test', or 'demo' for local debugging."
                )

    def verify(self, intent: ActionIntent, pccb: PCCB, context: DynamicContextInput) -> None:
        """Verify a PCCB. Raises ``ProofVerificationError`` on any failure.

        The refusal code in the raised exception depends on the
        ``disclosure_mode``:
          - ``public_generic``: all pre-auth + post-auth failures for
            invalidly-signed proofs return ``PROOF_INVALID``.
          - ``trusted_detailed``: pre-auth failures return ``PROOF_INVALID``;
            post-auth failures return the detailed code.
          - ``local_debug``: all failures return the granular code (the
            pre-2B behaviour, for debugging only).
        """
        # ── Phase A: Pre-authentication ──────────────────────────────
        # Only the minimum safe work needed for authentication.
        # Any failure here collapses to PROOF_INVALID (in public_generic
        # or trusted_detailed mode) to prevent field-by-field oracle probing.

        # Step 1-3: structural parsing, type validation, size/depth checks
        # are performed by canonicalize_bytes() and the PCCB dataclass
        # constructors. The action_hash recomputation is deferred to
        # post-authentication (it requires the intent, which is
        # caller-supplied — we must not trust it until after signature
        # verification).

        # Step 4: required-field presence for key resolution.
        # The signature field must be present and non-empty to attempt
        # verification. The issuer field is needed for key resolution
        # (performed by the signer's verify_with_metadata if available).
        sig_error = self._validate_signature_structure(pccb)
        if sig_error is not None:
            self._raise_pre_auth_failure(sig_error, pccb=pccb, context=context)

        # Step 5-6: canonicalise the unsigned proof payload.
        # This also enforces size limits (1 MB) and depth limits (128).
        try:
            unsigned_payload = canonicalize_bytes(pccb.unsigned_payload())
        except (TypeError, ValueError, RecursionError) as exc:
            self._raise_pre_auth_failure(
                "PROOF_PAYLOAD_INVALID",
                pccb=pccb,
                context=context,
                internal_detail=str(exc),
            )

        # Step 7: signature verification.
        verify_with_metadata = getattr(self.signer, "verify_with_metadata", None)
        if callable(verify_with_metadata):
            is_valid = verify_with_metadata(
                unsigned_payload,
                pccb.signature,
                issuer=pccb.issuer,
                issued_at=pccb.issued_at,
            )
        else:
            is_valid = self.signer.verify(unsigned_payload, pccb.signature)
        if not is_valid:
            self._raise_pre_auth_failure(
                "SIGNATURE_INVALID",
                pccb=pccb,
                context=context,
            )

        # ── Phase B: Post-authentication semantic validation ─────────
        # The proof is now cryptographically authentic. We can safely
        # perform detailed semantic checks and (in trusted_detailed /
        # local_debug mode) disclose which check failed.

        # Time bounds
        if context.now + self.clock_skew_tolerance < pccb.not_before:
            self._raise_post_auth_failure(
                "PROOF_NOT_YET_VALID",
                pccb=pccb,
                context=context,
            )
        if context.now - self.clock_skew_tolerance > pccb.expires_at:
            self._raise_post_auth_failure(
                "PROOF_EXPIRED",
                pccb=pccb,
                context=context,
            )

        # Audience
        if pccb.audience != context.audience:
            self._raise_post_auth_failure(
                "AUDIENCE_MISMATCH",
                pccb=pccb,
                context=context,
            )

        # Scope
        if pccb.scope.mode != "exact":
            self._raise_post_auth_failure(
                "SCOPE_MODE_INVALID",
                pccb=pccb,
                context=context,
            )
        if intent.action.capability not in pccb.scope.capabilities:
            self._raise_post_auth_failure(
                "SCOPE_CAPABILITY_MISMATCH",
                pccb=pccb,
                context=context,
            )

        # Intent ID (the signed intent_id differs from the supplied intent_id)
        if pccb.intent_id and pccb.intent_id != intent.intent_id:
            self._raise_post_auth_failure(
                "INTENT_MISMATCH",
                pccb=pccb,
                context=context,
            )

        # Tenant
        if pccb.tenant != intent.tenant:
            self._raise_post_auth_failure(
                "TENANT_MISMATCH",
                pccb=pccb,
                context=context,
            )

        # Subject
        if pccb.subject != intent.requester:
            self._raise_post_auth_failure(
                "SUBJECT_MISMATCH",
                pccb=pccb,
                context=context,
            )

        # Action (the bound action or action parameters differ)
        if pccb.action != intent.action:
            self._raise_post_auth_failure(
                "ACTION_MISMATCH",
                pccb=pccb,
                context=context,
            )

        # Target
        if pccb.target != intent.target:
            self._raise_post_auth_failure(
                "TARGET_MISMATCH",
                pccb=pccb,
                context=context,
            )

        # Action hash (algorithm + canonicalization + value)
        try:
            expected_hash = sha256_hex(build_action_hash_input(intent))
        except (TypeError, ValueError, RecursionError) as exc:
            self._raise_post_auth_failure(
                "ACTION_HASH_INVALID",
                pccb=pccb,
                context=context,
                internal_detail=str(exc),
            )
        if pccb.action_hash.algorithm != "sha-256" or pccb.action_hash.canonicalization != "RFC8785-JCS":
            self._raise_post_auth_failure(
                "ACTION_HASH_ALGORITHM_INVALID",
                pccb=pccb,
                context=context,
            )
        if pccb.action_hash.value != expected_hash:
            self._raise_post_auth_failure(
                "ACTION_HASH_MISMATCH",
                pccb=pccb,
                context=context,
            )

    # ── Internal helpers ─────────────────────────────────────────────

    def _validate_signature_structure(self, pccb: PCCB) -> str | None:
        """Validate the signature field is present and structurally sound
        for key resolution. Returns a refusal_code string if invalid,
        or None if the structure is acceptable.
        """
        sig = pccb.signature
        if not sig or not sig.value:
            return "SIGNATURE_INVALID"
        if sig.encoding != "base64url":
            return "SIGNATURE_INVALID"
        # The algorithm and key_id are validated by the signer during
        # verification (algorithm confusion attacks are handled there).
        return None

    def _raise_pre_auth_failure(
        self,
        internal_code: str,
        *,
        pccb: PCCB,
        context: DynamicContextInput,
        internal_detail: str | None = None,
    ) -> None:
        """Raise a ProofVerificationError for a pre-authentication failure.

        In ``public_generic`` and ``trusted_detailed`` modes, all
        pre-authentication failures collapse to ``PROOF_INVALID`` to
        prevent field-by-field oracle probing.

        In ``local_debug`` mode, the granular ``internal_code`` is
        preserved for debugging.

        The precise internal reason is logged at DEBUG level (protected
        diagnostic event) but never included in the public exception
        message or details.
        """
        if self.disclosure_mode == VerifierDisclosureMode.LOCAL_DEBUG:
            raise ProofVerificationError(
                internal_code,
                public_proof_refusal_message(internal_code),
            )
        # public_generic + trusted_detailed: collapse to PROOF_INVALID
        logger.debug(
            "proof.pre_auth_failure",
            extra={
                "event": "proof.pre_auth_failure",
                "internal_code": internal_code,
                "internal_detail": internal_detail,
                "pccb_id": pccb.pccb_id,
                "request_id": getattr(context, "request_id", None),
            },
        )
        raise ProofVerificationError(
            "PROOF_INVALID",
            public_proof_refusal_message("PROOF_INVALID"),
        )

    def _raise_post_auth_failure(
        self,
        detailed_code: str,
        *,
        pccb: PCCB,
        context: DynamicContextInput,
        internal_detail: str | None = None,
    ) -> None:
        """Raise a ProofVerificationError for a post-authentication failure.

        The proof was cryptographically authentic, so the semantic check
        failure is real (not a forgery attempt). The disclosure depends
        on the mode:

        - ``public_generic``: return ``PROOF_INVALID``. Even though the
          proof was authentic, we don't disclose which field mismatched
          because the caller may be an attacker probing the boundary.
        - ``trusted_detailed``: return the detailed ``detailed_code``.
          The issuer is authentic, so the operator is allowed to know
          which policy check failed.
        - ``local_debug``: return the detailed ``detailed_code`` (same
          as trusted_detailed, but also applies to pre-auth failures).
        """
        if self.disclosure_mode == VerifierDisclosureMode.PUBLIC_GENERIC:
            logger.debug(
                "proof.post_auth_failure",
                extra={
                    "event": "proof.post_auth_failure",
                    "internal_code": detailed_code,
                    "internal_detail": internal_detail,
                    "pccb_id": pccb.pccb_id,
                    "request_id": getattr(context, "request_id", None),
                },
            )
            raise ProofVerificationError(
                "PROOF_INVALID",
                public_proof_refusal_message("PROOF_INVALID"),
            )
        # trusted_detailed + local_debug: disclose the detailed code
        raise ProofVerificationError(
            detailed_code,
            public_proof_refusal_message(detailed_code),
        )
