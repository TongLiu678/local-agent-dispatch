from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "controller_monitor_adapter_under_test",
    ROOT / "scripts" / "controller_monitor_adapter.py",
)
assert SPEC and SPEC.loader
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


class ControllerMonitorAdapterTests(unittest.TestCase):
    def test_running_sqlite_job_becomes_explicit_unknown_without_pid_guess(self):
        snapshot = {
            "schema_version": 1,
            "jobs": [
                {
                    "job_id": "job-1",
                    "status": "running",
                    "payload": {
                        "pool_id": "opencode.go",
                        "provider": "opencode",
                        "model": "opencode-go/deepseek-v4-flash",
                        "variant": "max",
                        "execution_host": "local_system",
                        "workload_host": "remote-a",
                        "required_artifacts": ["out.txt"],
                        "prompt": "must not be copied",
                        "argv": ["secret"],
                    },
                }
            ],
            "attempts": [
                {"job_id": "job-1", "attempt_id": "a-1", "attempt_no": 1, "status": "running", "payload": {}}
            ],
            "leases": [],
        }
        state = adapter.build_monitor_state(snapshot)
        worker = state["workers"][0]
        self.assertEqual("unknown", worker["status"])
        self.assertEqual("controller_state_has_no_pid_telemetry", worker["observation_reason"])
        self.assertIsNone(worker.get("pid"))
        self.assertNotIn("prompt", worker)
        self.assertNotIn("argv", worker)
        self.assertEqual("remote-a", worker["workload_host"])

    def test_terminal_success_preserves_validation_and_hash_evidence(self):
        snapshot = {
            "schema_version": 1,
            "jobs": [
                {
                    "job_id": "job-2",
                    "status": "completed",
                    "payload": {
                        "pool_id": "codex.luna",
                        "model": "gpt-5.6-luna",
                        "required_artifacts": ["out.txt"],
                    },
                }
            ],
            "attempts": [
                {
                    "job_id": "job-2",
                    "attempt_id": "a-2",
                    "attempt_no": 1,
                    "status": "completed",
                    "validation": {"ok": True, "returncode": 0},
                    "artifact_manifest": [{"path": "out.txt", "exists": True, "size": 3, "sha256": "abc"}],
                }
            ],
            "leases": [{"scope": "controller", "status": "active", "owner_id": "c1"}],
        }
        state = adapter.build_monitor_state(snapshot)
        worker = state["workers"][0]
        self.assertEqual("completed", worker["status"])
        self.assertTrue(worker["validation_ok"])
        self.assertTrue(worker["artifact_freshness_verified"])
        self.assertEqual("c1", state["controller_leases"][0]["owner_id"])

    def test_multi_lane_state_exposes_fence_lease_and_heartbeat_evidence(self):
        snapshot = {
            "schema_version": 1,
            "jobs": [
                {
                    "job_id": "lane-a",
                    "status": "running",
                    "claimed_by": "controller-1",
                    "claim_fence": 7,
                    "lease_expires_at_utc": "2099-01-01T00:00:00+00:00",
                    "updated_at_utc": "2026-08-12T00:00:10+00:00",
                    "payload": {"pool_id": "codex.luna", "model": "gpt-5.6-luna"},
                },
                {
                    "job_id": "lane-b",
                    "status": "running",
                    "claimed_by": "controller-1",
                    "claim_fence": 7,
                    "lease_expires_at_utc": "2099-01-01T00:00:00+00:00",
                    "updated_at_utc": "2026-08-12T00:00:10+00:00",
                    "payload": {"pool_id": "opencode.go", "model": "opencode-go/deepseek-v4-flash"},
                },
            ],
            "attempts": [
                {
                    "job_id": "lane-a", "attempt_id": "attempt-a", "attempt_no": 1,
                    "status": "running", "owner_id": "controller-1", "fence_token": 7,
                    "lease_expires_at_utc": "2099-01-01T00:00:00+00:00",
                },
                {
                    "job_id": "lane-b", "attempt_id": "attempt-b", "attempt_no": 1,
                    "status": "running", "owner_id": "controller-1", "fence_token": 7,
                    "lease_expires_at_utc": "2099-01-01T00:00:00+00:00",
                },
            ],
            "leases": [{
                "scope": "controller", "status": "active", "owner_id": "controller-1",
                "fence_token": 7, "lease_expires_at_utc": "2099-01-01T00:00:00+00:00",
                "heartbeat_at_utc": "2026-08-12T00:00:09+00:00",
            }],
        }
        state = adapter.build_monitor_state(snapshot)
        self.assertEqual(2, state["lane_count"])
        self.assertEqual(2, state["active_lane_count"])
        self.assertEqual({"lane-a", "lane-b"}, {row["lane_id"] for row in state["lanes"]})
        worker = state["workers"][0]
        self.assertEqual("active", worker["lease"]["status"])
        self.assertEqual(7, worker["lease"]["fence_token"])
        self.assertEqual("observed", worker["heartbeat"]["status"])
        self.assertEqual("2026-08-12T00:00:09+00:00", worker["heartbeat"]["controller_heartbeat_at_utc"])

    def test_snapshot_can_be_loaded_from_cli_boundary_without_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "snapshot.json"
            path.write_text('{"schema_version": 1, "jobs": [], "attempts": [], "leases": []}\n', encoding="utf-8")
            self.assertEqual(0, adapter.main(["--snapshot", str(path)]))

    def test_terminal_receipt_projection_is_allowlisted_observation_only(self):
        snapshot = {
            "schema_version": 1,
            "jobs": [{"job_id": "job-receipt", "status": "completed", "payload": {}}],
            "attempts": [{
                "job_id": "job-receipt", "attempt_id": "attempt-receipt",
                "attempt_no": 1, "status": "completed",
                "result": {"terminal_receipt": {
                    "schema_version": "0.1.0", "kind": "lad_attempt_receipt",
                    "attempt_id": "attempt-receipt", "state": "completed",
                    "receipt_digest": "sha256:" + "a" * 64,
                    "artifact_digest": "sha256:" + "b" * 64,
                    "settlement_receipt_digest": "sha256:" + "c" * 64,
                    "completed_at": "2026-08-16T00:00:00+00:00",
                    "prompt": "must not enter monitor state",
                }},
            }],
            "leases": [],
        }
        worker = adapter.build_monitor_state(snapshot)["workers"][0]
        self.assertEqual("completed", worker["terminal_receipt"]["state"])
        self.assertNotIn("prompt", worker["terminal_receipt"])


if __name__ == "__main__":
    unittest.main()
