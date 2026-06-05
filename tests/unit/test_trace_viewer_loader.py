from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from actenon.demo.local_proof import run_all_local_proof_demos
from actenon.demo.portable_local_proof import run_portable_local_proof_demo
from actenon.local_runtime import simulate_local_runtime
from actenon.ui.trace_viewer.trace_loader import load_trace_index, repo_root_from_viewer, resolve_artifact_roots


class TraceViewerLoaderTests(unittest.TestCase):
    def test_load_trace_index_from_local_and_portable_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            local_root = root / "local_proof"
            portable_root = root / "portable_local_proof"
            runtime_root = root / "runtime"
            run_all_local_proof_demos(local_root)
            run_portable_local_proof_demo(portable_root)
            simulate_local_runtime(runtime_root, incident="replit")
            simulations_root = runtime_root / "simulations"

            config = resolve_artifact_roots(repo_root_from_viewer(), (local_root, portable_root, simulations_root))
            index = load_trace_index(config)

            self.assertEqual(len(index["runs"]), 4)
            titles = {run["title"] for run in index["runs"]}
            self.assertEqual(
                titles,
                {
                    "Local Proof: Refund",
                    "Local Proof: Invoice Payment",
                    "Portable Local Proof",
                    "Incident Simulator",
                },
            )

            refund_run = next(run for run in index["runs"] if run["title"] == "Local Proof: Refund")
            allow_scenario = next(scenario for scenario in refund_run["scenarios"] if scenario["name"] == "allow")
            deny_scenario = next(scenario for scenario in refund_run["scenarios"] if scenario["name"] == "deny")

            artifact_kinds = {artifact["kind"] for artifact in allow_scenario["artifacts"]}
            self.assertIn("action_intent", artifact_kinds)
            self.assertIn("pccb", artifact_kinds)
            self.assertIn("execution_receipt", artifact_kinds)
            self.assertIn("replay_entries", artifact_kinds)
            self.assertIn("protected_endpoint_state", artifact_kinds)

            deny_artifact_kinds = {artifact["kind"] for artifact in deny_scenario["artifacts"]}
            self.assertIn("refusal", deny_artifact_kinds)
            self.assertEqual(deny_scenario["final_outcome"], "deny")

            portable_run = next(run for run in index["runs"] if run["title"] == "Portable Local Proof")
            portable_scenario = portable_run["scenarios"][0]
            portable_artifact_kinds = {artifact["kind"] for artifact in portable_scenario["artifacts"]}
            self.assertIn("action_intent", portable_artifact_kinds)
            self.assertIn("pccb", portable_artifact_kinds)
            self.assertIn("verification_result", portable_artifact_kinds)
            self.assertIn("protected_response", portable_artifact_kinds)

            incident_run = next(run for run in index["runs"] if run["title"] == "Incident Simulator")
            incident_scenario = next(scenario for scenario in incident_run["scenarios"] if scenario["name"] == "replit")
            incident_artifact_kinds = {artifact["kind"] for artifact in incident_scenario["artifacts"]}
            self.assertIn("framing", incident_artifact_kinds)
            self.assertIn("intent_record", incident_artifact_kinds)
            self.assertIn("action_intent", incident_artifact_kinds)
            self.assertIn("pccb", incident_artifact_kinds)
            self.assertIn("refusal", incident_artifact_kinds)
            self.assertIn("counterfactual_execution", incident_artifact_kinds)
            self.assertEqual("refused", incident_scenario["final_outcome"])

    def test_resolve_artifact_roots_skips_missing_paths(self) -> None:
        repo_root = repo_root_from_viewer()
        with tempfile.TemporaryDirectory() as temp_dir:
            existing = Path(temp_dir) / "existing"
            existing.mkdir()
            config = resolve_artifact_roots(repo_root, (existing, Path(temp_dir) / "missing"))
            self.assertEqual(config.roots, (existing.resolve(),))


if __name__ == "__main__":
    unittest.main()
