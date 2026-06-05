from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from actenon.core import ContractValidationError  # noqa: E402
from examples.integration_support import build_request_id, execute_protected_hello  # noqa: E402


EXAMPLE_ROOT = Path(__file__).resolve().parent
app = FastAPI(title="Action Control FastAPI Protected Route", version="0.1.0")


class ProtectedRouteRequest(BaseModel):
    intent: dict[str, Any] | None = None
    pccb: dict[str, Any] | None = None


@app.get("/")
def root() -> dict[str, Any]:
    return {"ok": True, "endpoint": "/protected-resource"}


@app.post("/protected-resource")
def protected_resource(body: ProtectedRouteRequest) -> JSONResponse | dict[str, Any]:
    try:
        # Proof verification happens inside execute_protected_hello before the route returns a protected result.
        outcome = execute_protected_hello(
            example_root=EXAMPLE_ROOT,
            request_id=build_request_id("fastapi"),
            intent_payload=body.intent,
            pccb_payload=body.pccb,
        )
    except ContractValidationError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error": exc.refusal_code,
                "message": exc.message,
                "details": exc.details,
            },
        ) from exc

    if outcome.ok:
        return outcome.to_dict()
    return JSONResponse(status_code=403, content=outcome.to_dict())
