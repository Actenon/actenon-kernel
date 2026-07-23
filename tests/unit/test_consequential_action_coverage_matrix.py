from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.coverage_matrix import (
    build_consequential_action_matrix,
    render_coverage_matrix_text,
    run_consequential_action_matrix,
)


REQUIRED_DOMAINS = (
    "DevOps",
    "Fintech",
    "IAM / Access Control",
    "Database",
    "Browser / Computer Use",
    "MCP Tools",
    "Data Export",
    "Email / Communications",
    "Code Agent Operations",
)


class ConsequentialActionCoverageMatrixTests(unittest.TestCase):
    def test_matrix_definition_contains_required_domains_and_actions(self) -> None:
        domains = build_consequential_action_matrix()
        names = tuple(domain.name for domain in domains)

        self.assertEqual(REQUIRED_DOMAINS, names)
        for domain in domains:
            self.assertGreaterEqual(len(domain.actions), 6)
            self.assertTrue(all(action.action_name for action in domain.actions))

    def test_matrix_runs_at_least_500_checks_and_writes_public_safe_evidence(self) -> None:
        with TemporaryDirectory() as tempdir:
            evidence_path = Path(tempdir) / "matrix.json"
            result = run_consequential_action_matrix(
                evidence_path=evidence_path,
                generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )

            self.assertEqual("PASS", result.result)
            self.assertGreaterEqual(result.total_scenarios, 500)
            self.assertEqual(set(REQUIRED_DOMAINS), set(result.per_domain_counts))
            self.assertTrue(all(count > 0 for count in result.per_domain_counts.values()))

            counts = result.check_counts
            self.assertEqual(counts["missing_proof_refused"], {"passed": 54, "total": 54})
            self.assertEqual(counts["action_hash_mismatch_refused"], {"passed": 54, "total": 54})
            self.assertEqual(counts["expired_proof_refused"], {"passed": 54, "total": 54})
            self.assertEqual(counts["replay_attempt_refused"], {"passed": 54, "total": 54})
            self.assertEqual(counts["valid_proof_bound_actions_executed_once"], {"passed": 108, "total": 108})

            artifact_counts = result.artifact_counts
            self.assertEqual(artifact_counts["refusal_artifacts_emitted"], {"passed": 432, "total": 432})
            self.assertEqual(artifact_counts["receipt_artifacts_emitted"], {"passed": 108, "total": 108})

            self.assertTrue(evidence_path.exists())
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            self.assertEqual("PASS", evidence["result"])
            self.assertEqual(result.total_scenarios, evidence["total_scenarios"])
            self.assertEqual(set(REQUIRED_DOMAINS), set(evidence["domains"]))
            self.assertIn("artifact_samples", evidence)

            serialized = json.dumps(evidence, sort_keys=True)
            for forbidden in ("sk_live", "akia", "secret_access_key", "private_key", "-----begin"):
                self.assertNotIn(forbidden, serialized.lower())

    def test_refusal_and_execution_modes_have_expected_outcomes(self) -> None:
        with TemporaryDirectory() as tempdir:
            result = run_consequential_action_matrix(evidence_path=Path(tempdir) / "matrix.json")

        by_key = {}
        for record in result.records:
            by_key.setdefault(record.check_key, []).append(record)

        self.assertTrue(all(record.outcome == "refused" for record in by_key["missing_proof_refused"]))
        self.assertTrue(all(record.reason_code == "MISSING_PROOF" for record in by_key["missing_proof_refused"]))
        self.assertTrue(all(record.reason_code == "SIGNATURE_INVALID" for record in by_key["action_hash_mismatch_refused"]))
        self.assertTrue(all(record.reason_code == "PROOF_EXPIRED" for record in by_key["expired_proof_refused"]))
        self.assertTrue(all(record.reason_code == "DUPLICATE_REPLAY" for record in by_key["replay_attempt_refused"]))
        self.assertTrue(all(not record.side_effect_executed for record in by_key["replay_attempt_refused"]))
        self.assertTrue(all(record.outcome == "executed" for record in by_key["valid_proof_bound_actions_executed_once"]))
        self.assertTrue(all(record.side_effect_executed for record in by_key["valid_proof_bound_actions_executed_once"]))

    def test_rendered_output_includes_per_domain_evidence_counts(self) -> None:
        with TemporaryDirectory() as tempdir:
            result = run_consequential_action_matrix(evidence_path=Path(tempdir) / "matrix.json")
        output = render_coverage_matrix_text(result)

        self.assertIn("ACTENON CONSEQUENTIAL ACTION COVERAGE MATRIX", output)
        self.assertIn("Total scenarios: 540", output)
        self.assertIn("Domains covered: 9", output)
        for domain in REQUIRED_DOMAINS:
            self.assertIn(f"- {domain}:", output)
        self.assertIn("Result: PASS", output)
        self.assertIn("No valid proof, no execution.", output)


if __name__ == "__main__":
    unittest.main()
