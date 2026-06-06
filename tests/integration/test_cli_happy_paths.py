from __future__ import annotations

import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.cli import main
from actenon.demo.local_proof import run_local_proof_demo
from actenon.demo.portable_local_proof import run_portable_local_proof_demo


class CliHappyPathIntegrationTests(unittest.TestCase):
    def _run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_verify_proof_command_accepts_portable_local_artifacts(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "portable"
            run_portable_local_proof_demo(artifact_root)
            code, stdout, stderr = self._run_cli(
                [
                    "verify-proof",
                    "--intent",
                    str(artifact_root / "action_intent.json"),
                    "--pccb",
                    str(artifact_root / "pccb.json"),
                    "--audience",
                    "service:portable-hello-world-endpoint",
                    "--verification-time",
                    "pccb-issued-at",
                ]
            )
            self.assertEqual(0, code, stderr)
            self.assertIn("Proof verified.", stdout)
            self.assertIn("Audience: service:portable-hello-world-endpoint", stdout)

    def test_verify_proof_command_supports_json_output(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "portable"
            run_portable_local_proof_demo(artifact_root)
            code, stdout, stderr = self._run_cli(
                [
                    "verify-proof",
                    "--intent",
                    str(artifact_root / "action_intent.json"),
                    "--pccb",
                    str(artifact_root / "pccb.json"),
                    "--audience",
                    "service:portable-hello-world-endpoint",
                    "--verification-time",
                    "pccb-issued-at",
                    "--json",
                ]
            )
            self.assertEqual(0, code, stderr)
            payload = json.loads(stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual("portable-hello-world-endpoint", payload["audience"]["id"])

    def test_verify_proof_command_reports_structured_failure_details(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "portable"
            run_portable_local_proof_demo(artifact_root)
            code, stdout, stderr = self._run_cli(
                [
                    "verify-proof",
                    "--intent",
                    str(artifact_root / "action_intent.json"),
                    "--pccb",
                    str(artifact_root / "pccb.json"),
                    "--audience",
                    "service:wrong-endpoint",
                    "--verification-time",
                    "pccb-issued-at",
                    "--json",
                ]
            )
            self.assertEqual(1, code)
            self.assertEqual("", stderr)
            payload = json.loads(stdout)
            self.assertFalse(payload["ok"])
            self.assertEqual("proof", payload["refusal"]["category"])
            self.assertEqual("AUDIENCE_MISMATCH", payload["refusal"]["reason_code"])

    def test_verify_proof_command_reports_schema_failure_for_malformed_json(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "portable"
            run_portable_local_proof_demo(artifact_root)
            bad_intent = artifact_root / "bad_action_intent.json"
            bad_intent.write_text("{not-json", encoding="utf-8")
            code, stdout, stderr = self._run_cli(
                [
                    "verify-proof",
                    "--intent",
                    str(bad_intent),
                    "--pccb",
                    str(artifact_root / "pccb.json"),
                    "--audience",
                    "service:portable-hello-world-endpoint",
                    "--verification-time",
                    "pccb-issued-at",
                    "--json",
                ]
            )
            self.assertEqual(1, code)
            self.assertEqual("", stderr)
            payload = json.loads(stdout)
            self.assertFalse(payload["ok"])
            self.assertEqual("schema", payload["refusal"]["category"])
            self.assertEqual("SCHEMA_INVALID", payload["refusal"]["reason_code"])

    def test_verify_receipt_command_accepts_local_receipt_and_links(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "local"
            run_local_proof_demo(artifact_root)
            scenario_dir = artifact_root / "scenarios" / "allow"
            code, stdout, stderr = self._run_cli(
                [
                    "verify-receipt",
                    "--receipt",
                    str(scenario_dir / "execution_receipt.json"),
                    "--intent",
                    str(scenario_dir / "action_intent.json"),
                    "--pccb",
                    str(scenario_dir / "pccb.json"),
                ]
            )
            self.assertEqual(0, code, stderr)
            self.assertIn("Receipt verified.", stdout)

    def test_verify_refusal_command_accepts_local_refusal_and_links(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "local"
            run_local_proof_demo(artifact_root)
            scenario_dir = artifact_root / "scenarios" / "deny"
            code, stdout, stderr = self._run_cli(
                [
                    "verify-refusal",
                    "--refusal",
                    str(scenario_dir / "refusal.json"),
                    "--intent",
                    str(scenario_dir / "action_intent.json"),
                    "--receipt",
                    str(scenario_dir / "decision_receipt.json"),
                ]
            )
            self.assertEqual(0, code, stderr)
            self.assertIn("Refusal verified.", stdout)

    def test_outcome_attestation_commands_attest_and_verify_receipt_and_refusal(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "local"
            run_local_proof_demo(artifact_root)
            receipt_path = artifact_root / "scenarios" / "allow" / "execution_receipt.json"
            refusal_path = artifact_root / "scenarios" / "deny" / "refusal.json"
            receipt_attestation_path = Path(tempdir) / "receipt_attestation.json"
            refusal_attestation_path = Path(tempdir) / "refusal_attestation.json"

            code, stdout, stderr = self._run_cli(
                [
                    "attest-receipt",
                    "--receipt",
                    str(receipt_path),
                    "--output",
                    str(receipt_attestation_path),
                    "--issuer",
                    "service:local-refund-endpoint",
                    "--issued-at",
                    "2026-04-10T09:02:00Z",
                ]
            )
            self.assertEqual(0, code, stderr)
            self.assertIn("Receipt attested.", stdout)

            code, stdout, stderr = self._run_cli(
                [
                    "verify-receipt-attestation",
                    "--attestation",
                    str(receipt_attestation_path),
                    "--json",
                ]
            )
            self.assertEqual(0, code, stderr)
            receipt_verification = json.loads(stdout)
            self.assertTrue(receipt_verification["ok"])
            self.assertEqual("receipt", receipt_verification["artifact_kind"])

            tampered_payload = json.loads(receipt_attestation_path.read_text(encoding="utf-8"))
            tampered_payload["unsigned_payload"]["outcome_artifact"]["summary"] = "Tampered summary."
            receipt_attestation_path.write_text(json.dumps(tampered_payload), encoding="utf-8")
            code, stdout, stderr = self._run_cli(
                [
                    "verify-receipt-attestation",
                    "--attestation",
                    str(receipt_attestation_path),
                    "--json",
                ]
            )
            self.assertEqual(1, code, stderr)
            tamper_result = json.loads(stdout)
            self.assertFalse(tamper_result["ok"])

            code, stdout, stderr = self._run_cli(
                [
                    "attest-refusal",
                    "--refusal",
                    str(refusal_path),
                    "--output",
                    str(refusal_attestation_path),
                    "--issuer",
                    "service:local-refund-endpoint",
                ]
            )
            self.assertEqual(0, code, stderr)
            self.assertIn("Refusal attested.", stdout)

            code, stdout, stderr = self._run_cli(
                [
                    "verify-refusal-attestation",
                    "--attestation",
                    str(refusal_attestation_path),
                    "--json",
                ]
            )
            self.assertEqual(0, code, stderr)
            refusal_verification = json.loads(stdout)
            self.assertTrue(refusal_verification["ok"])
            self.assertEqual("refusal", refusal_verification["artifact_kind"])

    def test_conformance_run_command_passes(self) -> None:
        code, stdout, stderr = self._run_cli(
            ["conformance", "run", "--require-complete"]
        )
        self.assertEqual(0, code, stderr)
        self.assertIn("Conformance version: 1.0.0", stdout)
        self.assertIn("Conformance tests passed.", stdout)
        self.assertIn(
            "Mark eligibility: Actenon Verified (Conformance 1.0.0)",
            stdout,
        )


if __name__ == "__main__":
    unittest.main()
