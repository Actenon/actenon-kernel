#!/usr/bin/env python3
"""Client — mints a PCCB and calls the protected endpoint.

This script demonstrates the full mint → verify → execute → receipt cycle.
"""

from __future__ import annotations

import json
import sys
from urllib.request import Request, urlopen

BASE_URL = "http://localhost:8000"


def main() -> int:
    print("Minting PCCB...")
    mint_body = json.dumps({
        "action": "payment.refund",
        "target_id": "pi_ref_001",
        "parameters": {"amount_cents": 2500, "currency": "GBP"},
    }).encode()
    req = Request(f"{BASE_URL}/mint-proof", data=mint_body, headers={"Content-Type": "application/json"})
    resp = json.loads(urlopen(req).read())
    intent = resp["intent"]
    pccb = resp["pccb"]
    print(f"PCCB minted: {pccb['pccb_id']}")

    print("Sending to protected endpoint...")
    refund_body = json.dumps({"intent": intent, "pccb": pccb}).encode()
    req = Request(
        f"{BASE_URL}/refunds",
        data=refund_body,
        headers={"Content-Type": "application/json", "X-Actenon-Proof": pccb["pccb_id"]},
    )
    try:
        resp = json.loads(urlopen(req).read())
        print(f"Response: {json.dumps(resp)}")
        print("Receipt verified.")
        return 0
    except Exception as e:
        print(f"FAILED: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
