#!/usr/bin/env python3
"""
Actenon worked example & evidence: a protected clinical EHR medication-administration service.

A runnable, self-verifying demonstration in a safety-critical domain.
A clinical medication-administration service is protected with Actenon's FastAPI adapter.
The proof travels in the X-Actenon-Proof HTTP header, not in the request body.

This is illustrative evidence only. It is not clinical safety certification,
a production deployment, a third-party audit, or evidence of production key custody.
"""

import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from actenon import ActenonGate
from actenon.adapters.fastapi import ACTENON_PROOF_HEADER, encode_json_header


NOW = datetime.now(timezone.utc)

EMAR = {"administered": []}

gate = ActenonGate.local_dev(
    audience="service:ehr-medication-administration",
    clock=lambda: NOW,
)


class AdministerBody(BaseModel):
    patient_id: str
    drug: str
    dose_mcg: int
    route: str


def build_intent(body: Mapping[str, Any]):
    return {
        "contract": {"name": "action_intent", "version": "v1"},
        "intent_id": f"intent_admin_{body['patient_id']}_{body['drug']}_{body['dose_mcg']}_{body['route']}",
        "issued_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=15)).isoformat(),
        "tenant": {"tenant_id": "ward-3"},
        "requester": {"type": "agent", "id": "med-admin-agent"},
        "action": {
            "name": "medication.administer",
            "capability": "clinical.medication.administer",
            "parameters": {
                "patient_id": body["patient_id"],
                "drug": body["drug"],
                "dose_mcg": int(body["dose_mcg"]),
                "route": body["route"],
            },
        },
        "target": {"resource_type": "patient", "resource_id": body["patient_id"]},
    }


def do_administer(body: Mapping[str, Any]):
    event = {
        "patient_id": body["patient_id"],
        "drug": body["drug"],
        "dose_mcg": int(body["dose_mcg"]),
        "route": body["route"],
    }
    EMAR["administered"].append(event)
    return {"outcome": "executed", "administered": event, "total_events": len(EMAR["administered"])}


app = FastAPI()


@app.post("/ehr/administer")
def administer(
    result: Any = Depends(
        gate.fastapi_dependency(
            action_builder=build_intent,
            side_effect=do_administer,
            body_model=AdministerBody,
            audience="service:ehr-medication-administration",
        )
    )
):
    return result


client = TestClient(app, raise_server_exceptions=False)


def proof_header(patient_id: str, drug: str, dose_mcg: int, route: str):
    intent = build_intent(
        {
            "patient_id": patient_id,
            "drug": drug,
            "dose_mcg": dose_mcg,
            "route": route,
        }
    )
    pccb = gate.mint_proof(intent)
    return {ACTENON_PROOF_HEADER: encode_json_header(pccb.to_dict())}


def refusal_reason(response):
    try:
        body = response.json()
    except Exception:
        return f"HTTP_{response.status_code}"

    if isinstance(body, dict):
        detail = body.get("detail", body)
        if isinstance(detail, dict):
            return detail.get("reason_code") or detail.get("message") or str(detail)
        return str(detail)

    return f"HTTP_{response.status_code}"


def main() -> int:
    print("=" * 74)
    print("Actenon FastAPI/HTTP clinical EHR medication-administration evidence")
    print("=" * 74)

    approved = {
        "patient_id": "P-1001",
        "drug": "morphine",
        "dose_mcg": 4000,
        "route": "IV",
    }

    good_headers = proof_header(**approved)
    results = []

    def run(label, response_fn, expected_status, expected_reason=None):
        response = response_fn()
        reason = refusal_reason(response) if response.status_code != 200 else None
        ok = response.status_code == expected_status and (
            expected_reason is None or reason == expected_reason
        )
        results.append(ok)
        tail = f" / {reason}" if reason else ""
        print(f"  [{'PASS' if ok else 'FAIL'}] {label:<55} -> HTTP {response.status_code}{tail}")

    print("\nHealthcare adversarial battery:")
    print("Proof issued only for: P-1001 morphine 4mg IV\n")

    run(
        "A authorized administration",
        lambda: client.post("/ehr/administer", json=approved, headers=good_headers),
        200,
    )

    run(
        "B wrong patient",
        lambda: client.post(
            "/ehr/administer",
            json={**approved, "patient_id": "P-2002"},
            headers=good_headers,
        ),
        403,
        "TARGET_MISMATCH",
    )

    run(
        "C overdose",
        lambda: client.post(
            "/ehr/administer",
            json={**approved, "dose_mcg": 40000},
            headers=good_headers,
        ),
        403,
        "INTENT_MISMATCH",
    )

    run(
        "D wrong drug",
        lambda: client.post(
            "/ehr/administer",
            json={**approved, "drug": "insulin"},
            headers=good_headers,
        ),
        403,
        "INTENT_MISMATCH",
    )

    run(
        "E wrong route",
        lambda: client.post(
            "/ehr/administer",
            json={**approved, "route": "PO"},
            headers=good_headers,
        ),
        403,
        "INTENT_MISMATCH",
    )

    run(
        "F no proof header",
        lambda: client.post("/ehr/administer", json=approved),
        403,
        "PCCB_REQUIRED",
    )

    run(
        "G replay approved administration",
        lambda: client.post("/ehr/administer", json=approved, headers=good_headers),
        403,
        "DUPLICATE_REPLAY",
    )

    past = datetime.now(timezone.utc) - timedelta(hours=1)
    gate_past = ActenonGate.local_dev(
        audience="service:ehr-medication-administration",
        clock=lambda: past,
    )
    stale_intent = {
        **build_intent(approved),
        "issued_at": past.isoformat(),
        "expires_at": (past + timedelta(minutes=15)).isoformat(),
    }
    stale_headers = {
        ACTENON_PROOF_HEADER: encode_json_header(gate_past.mint_proof(stale_intent).to_dict())
    }

    run(
        "H stale expired proof",
        lambda: client.post("/ehr/administer", json=approved, headers=stale_headers),
        403,
        "PROOF_EXPIRED",
    )

    run(
        "I malformed proof header",
        lambda: client.post(
            "/ehr/administer",
            json=approved,
            headers={ACTENON_PROOF_HEADER: "not-a-real-proof"},
        ),
        403,
    )

    invariants = {
        "exactly_one_administration": len(EMAR["administered"]) == 1,
        "the_one_is_correct": EMAR["administered"]
        == [{"patient_id": "P-1001", "drug": "morphine", "dose_mcg": 4000, "route": "IV"}],
        "no_wrong_patient": all(e["patient_id"] != "P-2002" for e in EMAR["administered"]),
        "no_overdose": all(e["dose_mcg"] <= 4000 for e in EMAR["administered"]),
        "no_wrong_drug": all(e["drug"] == "morphine" for e in EMAR["administered"]),
    }

    print(f"\nFinal eMAR administrations: {EMAR['administered']}")
    print("\nPatient-safety invariants:")
    for name, ok in invariants.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")

    all_ok = all(results) and all(invariants.values())

    print("\n" + "=" * 74)
    print(
        f"RESULT: {'ALL CHECKS PASSED' if all_ok else 'CHECKS FAILED'} "
        f"(battery={sum(results)}/{len(results)}, invariants={sum(invariants.values())}/{len(invariants)})"
    )
    print("No valid proof, no execution.")
    print("=" * 74)

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
