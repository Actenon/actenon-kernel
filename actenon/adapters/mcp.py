"""FastMCP decorator for proof-gated tools with request-metadata proof."""

from __future__ import annotations

import inspect
from functools import wraps
from typing import Any, Callable, Mapping

from actenon.gate import ActenonGate
from actenon.models import ActionIntent, PCCB
from actenon.preflight import PreflightEvidence

from ._authorization import authorization_from_mapping

try:
    from mcp.server.fastmcp import Context
except ImportError as exc:  # pragma: no cover - exercised without the optional extra
    raise ImportError(
        "Actenon's MCP adapter requires the 'mcp' extra: "
        "python -m pip install 'actenon-kernel[mcp]'"
    ) from exc


ACTENON_MCP_META_KEY = "actenon"
ActionBuilder = Callable[[Mapping[str, Any]], ActionIntent | dict[str, Any]]
EvidenceBuilder = Callable[
    [Mapping[str, Any]],
    Mapping[str, Any] | PreflightEvidence | None,
]


def mcp_authorization_meta(
    proof: Mapping[str, Any] | PCCB | None,
    *,
    evidence: Mapping[str, Any] | PreflightEvidence | None = None,
) -> dict[str, Any]:
    if isinstance(proof, PCCB):
        proof = proof.to_dict()
    if isinstance(evidence, PreflightEvidence):
        evidence = evidence.to_dict()
    return {
        ACTENON_MCP_META_KEY: {
            "proof": proof,
            "evidence": evidence,
        }
    }


def _context_meta(context: Context[Any, Any, Any]) -> Mapping[str, Any]:
    request_context = context.request_context
    meta = getattr(request_context, "meta", None)
    return meta if isinstance(meta, Mapping) else {}


def protected_mcp_tool(
    gate: ActenonGate,
    *,
    action_builder: ActionBuilder,
    audience: str | None = None,
    evidence_builder: EvidenceBuilder | None = None,
    context_parameter: str = "ctx",
) -> Callable[[Callable[..., Any]], Callable[..., dict[str, Any]]]:
    """Decorate an arbitrary sync FastMCP tool using injected request Context."""

    def decorator(domain_function: Callable[..., Any]) -> Callable[..., dict[str, Any]]:
        if inspect.iscoroutinefunction(domain_function):
            raise TypeError(
                "protected_mcp_tool currently requires a synchronous tool function"
            )
        signature = inspect.signature(domain_function)
        context = signature.parameters.get(context_parameter)
        if context is None:
            raise TypeError(
                f"protected MCP tool must declare an injected '{context_parameter}: Context' parameter"
            )

        @wraps(domain_function)
        def protected_call(*args: Any, **kwargs: Any) -> dict[str, Any]:
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            mcp_context = bound.arguments.get(context_parameter)
            if not isinstance(mcp_context, Context):
                raise TypeError(
                    f"'{context_parameter}' must be an mcp.server.fastmcp.Context"
                )
            domain_args = {
                key: value
                for key, value in bound.arguments.items()
                if key != context_parameter
            }
            authorization = authorization_from_mapping(
                _context_meta(mcp_context).get(ACTENON_MCP_META_KEY)
            )
            evidence = (
                evidence_builder(domain_args)
                if evidence_builder is not None
                else authorization.evidence
            )
            action = action_builder(domain_args)
            outcome = gate.protect(
                action,
                authorization.proof,
                lambda: domain_function(*args, **kwargs),
                audience=audience,
                evidence=evidence,
            )
            return outcome.to_dict()

        return protected_call

    return decorator


__all__ = [
    "ACTENON_MCP_META_KEY",
    "mcp_authorization_meta",
    "protected_mcp_tool",
]
