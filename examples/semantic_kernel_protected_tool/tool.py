"""Semantic Kernel protected tool example.

The important property of this example is boundary placement: proof
verification happens inside the Semantic Kernel plugin function before any
protected action runs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Annotated


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from actenon.core import ContractValidationError  # noqa: E402
from actenon.demo.portable_local_proof import FIXED_BASE_TIME  # noqa: E402
from actenon.receipts import RefusalFactory  # noqa: E402
from examples.integration_support import (  # noqa: E402
    DEFAULT_AUDIENCE_ID,
    build_request_id,
    execute_protected_hello,
    parse_optional_json_mapping,
)

try:  # noqa: E402
    from semantic_kernel.functions import kernel_function
    from semantic_kernel.kernel import Kernel
except ImportError as exc:  # pragma: no cover - optional integration dependency
    raise SystemExit("Install Semantic Kernel first: pip install -r requirements.txt") from exc


EXAMPLE_ROOT = Path(__file__).resolve().parent
AUDIENCE_MISMATCH_ID = "semantic-kernel-wrong-audience"


def _build_contract_refusal(*, request_id: str, exc: ContractValidationError) -> dict[str, object]:
    refusal = RefusalFactory(refusal_id_factory=lambda: f"rfsl_{request_id}").create_from_exception(
        exc,
        occurred_at=FIXED_BASE_TIME,
        intent=None,
        context=None,
    )
    return {
        "ok": False,
        "refusal": refusal.to_dict(),
    }


class ProtectedHelloPlugin:
    """Semantic Kernel plugin whose function method is the protected execution edge."""

    @kernel_function(
        name="protected_hello_read",
        description=(
            "Verify an Action Intent and PCCB inside the plugin function before reading the "
            "protected hello-world resource. Returns Actenon receipt or refusal artifacts."
        ),
    )
    def protected_hello_read(
        self,
        intent_json: Annotated[str | None, "Optional Action Intent JSON string. Omit to use the local proof fixture."] = None,
        pccb_json: Annotated[str | None, "Optional PCCB JSON string. Omit to use the local proof fixture."] = None,
        audience_id: Annotated[str, "Protected endpoint audience identity for this function."] = DEFAULT_AUDIENCE_ID,
    ) -> Annotated[str, "JSON string containing Actenon receipt or refusal artifacts."]:
        request_id = build_request_id("semantic_kernel")
        try:
            # Semantic Kernel exposes this method as a plugin function, but the method
            # body is still the execution edge. Verification has to stay here.
            outcome = execute_protected_hello(
                example_root=EXAMPLE_ROOT,
                request_id=request_id,
                intent_payload=parse_optional_json_mapping(intent_json, field_name="intent_json"),
                pccb_payload=parse_optional_json_mapping(pccb_json, field_name="pccb_json"),
                audience_id=audience_id,
            )
            return json.dumps(outcome.to_dict(), sort_keys=True)
        except json.JSONDecodeError as exc:
            return json.dumps(
                _build_contract_refusal(
                    request_id=request_id,
                    exc=ContractValidationError(f"Invalid JSON supplied to the plugin function: {exc.msg}."),
                ),
                sort_keys=True,
            )
        except ContractValidationError as exc:
            return json.dumps(_build_contract_refusal(request_id=request_id, exc=exc), sort_keys=True)


def build_kernel_and_plugin() -> tuple[Kernel, ProtectedHelloPlugin]:
    plugin = ProtectedHelloPlugin()
    kernel = Kernel()
    kernel.add_plugin(plugin, plugin_name="ActenonProtectedHello")
    return kernel, plugin


def run_direct(args: argparse.Namespace) -> None:
    kernel, plugin = build_kernel_and_plugin()
    _ = kernel  # Keep registration explicit so the plugin/function pattern is visible.
    audience_id = DEFAULT_AUDIENCE_ID
    if args.scenario == "audience-mismatch":
        audience_id = AUDIENCE_MISMATCH_ID
    result_json = plugin.protected_hello_read(
        intent_json=args.intent_file.read_text(encoding="utf-8") if args.intent_file else None,
        pccb_json=args.pccb_file.read_text(encoding="utf-8") if args.pccb_file else None,
        audience_id=audience_id,
    )
    print(json.dumps(json.loads(result_json), indent=2, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description="Semantic Kernel protected tool example.")
    parser.add_argument(
        "--scenario",
        choices=("success", "audience-mismatch"),
        default="success",
        help="Choose a deterministic success or refusal demonstration.",
    )
    parser.add_argument(
        "--intent-file",
        type=Path,
        help="Optional path to an Action Intent JSON file. Omit to use the bundled local proof fixture.",
    )
    parser.add_argument(
        "--pccb-file",
        type=Path,
        help="Optional path to a PCCB JSON file. Omit to use the bundled local proof fixture.",
    )
    args = parser.parse_args()

    run_direct(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
