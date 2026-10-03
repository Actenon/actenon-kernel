#!/usr/bin/env python3
"""Fail if a pytest JUnit report contains a skip that is not allow-listed.

A skipped test is work CI claims but did not do. Optional integrations are
installed in CI, so the only accepted skips are the ones listed here, each
with the reason it is accepted.

usage: assert_no_unexpected_skips.py [--no-allowlist] REPORT.xml [REPORT.xml ...]
  --no-allowlist  every skip fails (for jobs whose whole point is to run the
                  allow-listed tests, e.g. postgres-replay)
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET

# (classname, test name) -> why the skip is accepted
ALLOWED_SKIPS = {
    ("tests.security.test_operation_idempotency.ReconciliationTests", "test_5_unauthorised_reconciliation_is_denied"):
        "reconciliation module not implemented (Phase 4B); the test documents the gap",
    ("tests.security.test_operation_idempotency.ReconciliationTests", "test_6_reconciliation_cannot_mutate_original_action"):
        "reconciliation module not implemented (Phase 4B); the test documents the gap",
    ("tests.integration.test_postgres_real_server", "test_one_execution_across_independent_store_connections"):
        "needs a PostgreSQL server; executed (no skips allowed) by the postgres-replay CI job",
    ("tests.integration.test_postgres_real_server", "test_unreachable_server_never_executes"):
        "needs a PostgreSQL server; executed (no skips allowed) by the postgres-replay CI job",
    ("tests.integration.test_postgres_real_server", "test_concurrent_cold_start_creates_the_schema_once"):
        "needs a PostgreSQL server; executed (no skips allowed) by the postgres-replay CI job",
}


def main(paths: list[str]) -> int:
    allowed = ALLOWED_SKIPS
    if paths and paths[0] == "--no-allowlist":
        allowed, paths = {}, paths[1:]
    if not paths:
        print(__doc__)
        return 2
    executed = 0
    unexpected: list[str] = []
    for path in paths:
        for case in ET.parse(path).getroot().iter("testcase"):
            key = (case.get("classname", ""), case.get("name", ""))
            skipped = case.find("skipped")
            if skipped is None:
                executed += 1
            elif key not in allowed:
                unexpected.append(f"{key[0]}::{key[1]}: {skipped.get('message', '')}")
    print(f"executed test cases: {executed}; unexpected skips: {len(unexpected)}")
    for line in unexpected:
        print(f"UNEXPECTED SKIP {line}")
    if executed == 0:
        print("FAIL: no test case executed")
        return 1
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
