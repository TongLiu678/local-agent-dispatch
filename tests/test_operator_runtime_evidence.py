from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_controller():
    spec = importlib.util.spec_from_file_location(
        "operator_runtime_evidence_controller",
        ROOT / "scripts" / "continuity_controller.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


continuity = load_controller()


class OperatorRuntimeEvidenceTests(unittest.TestCase):
    def test_location_error_is_model_scoped_and_message_is_not_persisted(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = pathlib.Path(temporary) / "runtime-state.json"
            evidence = continuity.record_operator_evidence(
                runtime,
                pool_id="antigravity.gemini",
                provider="antigravity",
                model="gemini-3.1-pro-high",
                variant="high",
                error_class="location_restricted",
                source="user_report",
                message="User location is not supported for the API use; SECRET_PROMPT",
                observed_at="2026-08-15T12:00:00+00:00",
            )
            payload = json.loads(runtime.read_text(encoding="utf-8"))
            row = payload["models"]["antigravity"]["gemini-3.1-pro-high"]["variants"]["high"]
            self.assertEqual("rejected", row["runtime_state"])
            self.assertEqual("location_restricted", row["error_class"])
            self.assertEqual("gcp_project_or_supported_region", row["recovery_action"])
            self.assertFalse(row["retryable"])
            self.assertTrue(row["route_change_required"])
            self.assertEqual(False, evidence["message_persisted"])
            self.assertNotIn("SECRET_PROMPT", runtime.read_text(encoding="utf-8"))
            self.assertEqual(1, len(payload["operator_evidence"]))

    def test_location_error_does_not_cooldown_sibling_model_or_pool(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = pathlib.Path(temporary) / "runtime-state.json"
            continuity.record_operator_evidence(
                runtime,
                pool_id="antigravity.gemini",
                provider="antigravity",
                model="gemini-3.1-pro-high",
                error_class="location_restricted",
                source="official_error",
            )
            payload = json.loads(runtime.read_text(encoding="utf-8"))
            self.assertNotIn("health", payload["pools"]["antigravity.gemini"])
            self.assertNotIn("gemini-3.6-flash-high", payload["models"]["antigravity"])

    def test_identical_evidence_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = pathlib.Path(temporary) / "runtime-state.json"
            kwargs = dict(
                pool_id="antigravity.gemini",
                provider="antigravity",
                model="gemini-3.1-pro-high",
                error_class="location_restricted",
                source="user_report",
                message="User location is not supported",
                observed_at="2026-08-15T12:00:00+00:00",
            )
            first = continuity.record_operator_evidence(runtime, **kwargs)
            second = continuity.record_operator_evidence(runtime, **kwargs)
            payload = json.loads(runtime.read_text(encoding="utf-8"))
            self.assertEqual(first["evidence_id"], second["evidence_id"])
            self.assertEqual(1, len(payload["operator_evidence"]))

    def test_invalid_operator_evidence_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = pathlib.Path(temporary) / "runtime-state.json"
            with self.assertRaisesRegex(ValueError, "unsupported operator evidence"):
                continuity.record_operator_evidence(
                    runtime,
                    pool_id="antigravity.gemini",
                    provider="antigravity",
                    model="gemini-3.1-pro-high",
                    error_class="unknown",
                    source="user_report",
                )
            self.assertFalse(runtime.exists())

    def test_cli_returns_redacted_evidence_envelope(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = pathlib.Path(temporary) / "runtime-state.json"
            command = [
                sys.executable,
                str(ROOT / "scripts" / "continuity_controller.py"),
                "record-evidence",
                "--runtime-state", str(runtime),
                "--pool-id", "antigravity.gemini",
                "--provider", "antigravity",
                "--model", "gemini-3.1-pro-high",
                "--error-class", "location_restricted",
                "--source", "user_report",
                "--message", "User location is not supported SECRET_TOKEN",
            ]
            completed = subprocess.run(command, check=False, text=True, capture_output=True)
            self.assertEqual(0, completed.returncode, completed.stderr)
            output = json.loads(completed.stdout)
            self.assertFalse(output["message_persisted"])
            self.assertNotIn("SECRET_TOKEN", completed.stdout)


if __name__ == "__main__":
    unittest.main()
