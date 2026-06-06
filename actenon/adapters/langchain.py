"""LangChain StructuredTool adapter with out-of-band proof injection."""

from __future__ import annotations

import inspect
from typing import Any, Callable, Mapping

from actenon.gate import ActenonGate
from actenon.models import ActionIntent, PCCB
from actenon.preflight import PreflightEvidence

from ._authorization import authorization_from_mapping

try:
    from langchain_core.runnables import RunnableConfig
    from langchain_core.tools import StructuredTool, create_schema_from_function
except ImportError as exc:  # pragma: no cover - exercised without the optional extra
    raise ImportError(
        "Actenon's LangChain adapter requires the 'langchain' extra: "
        "python -m pip install 'actenon-kernel[langchain]'"
    ) from exc


ACTENON_CONFIG_KEY = "actenon"
ActionBuilder = Callable[[Mapping[str, Any]], ActionIntent | dict[str, Any]]
EvidenceBuilder = Callable[
    [Mapping[str, Any]],
    Mapping[str, Any] | PreflightEvidence | None,
]


def actenon_runnable_config(
    proof: Mapping[str, Any] | PCCB | None,
    *,
    evidence: Mapping[str, Any] | PreflightEvidence | None = None,
) -> RunnableConfig:
    """Build runtime-only LangChain config; it is excluded from tool schemas."""

    return {
        "configurable": {
            ACTENON_CONFIG_KEY: {
                "proof": proof,
                "evidence": evidence,
            }
        }
    }


def protected_structured_tool(
    gate: ActenonGate,
    domain_function: Callable[..., Any],
    *,
    action_builder: ActionBuilder,
    audience: str | None = None,
    evidence_builder: EvidenceBuilder | None = None,
    name: str | None = None,
    description: str | None = None,
    return_direct: bool = False,
) -> StructuredTool:
    """Wrap a plain sync function without exposing proof fields to the model."""

    if not callable(domain_function):
        raise TypeError("domain_function must be callable")
    if inspect.iscoroutinefunction(domain_function):
        raise TypeError(
            "protected_structured_tool currently requires a synchronous domain function"
        )
    tool_name = name or domain_function.__name__
    tool_description = description or domain_function.__doc__
    if not tool_description:
        raise ValueError("LangChain tools require a description or function docstring")
    args_schema = create_schema_from_function(
        f"{tool_name.title().replace('_', '')}Input",
        domain_function,
    )

    def protected_call(config: RunnableConfig, **domain_args: Any) -> dict[str, Any]:
        authorization = authorization_from_mapping(
            config.get("configurable", {}).get(ACTENON_CONFIG_KEY)
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
            lambda: domain_function(**domain_args),
            audience=audience,
            evidence=evidence,
        )
        return outcome.to_dict()

    protected_call.__name__ = tool_name
    protected_call.__doc__ = tool_description
    return StructuredTool.from_function(
        func=protected_call,
        name=tool_name,
        description=tool_description,
        args_schema=args_schema,
        return_direct=return_direct,
    )


__all__ = [
    "ACTENON_CONFIG_KEY",
    "actenon_runnable_config",
    "protected_structured_tool",
]
