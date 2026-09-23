from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest
import json
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "dispatch_monitor_under_test", ROOT / "scripts" / "dispatch_monitor.py"
)
assert SPEC and SPEC.loader
monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(monitor)


class DispatchMonitorPlacementTests(unittest.TestCase):
    def test_pid_probe_unknown_os_error_is_fail_closed(self):
        with mock.patch.object(monitor.os, "kill", side_effect=OSError("unsupported")):
            self.assertIsNone(monitor.pid_alive(1234))

    def test_local_resource_admission_failure_is_not_provider_failure(self):
        self.assertEqual(
            "resource",
            monitor.classify_error(
                "LocalLaunchAdmissionError: local launch blocked before child creation: "
                "free_bytes_below_floor"
            ),
        )

    def test_resource_feedback_marks_host_not_model_pool(self):
        state = {"pools": {"codex.luna": {"health": "ready"}}, "compute_hosts": {}}
        monitor.apply_feedback(
            state,
            {
                "error_class": "resource",
                "execution_host": "local_mac",
                "pool_id": "codex.luna",
                "observed_at_utc": "2026-08-13T00:00:00+00:00",
            },
        )
        self.assertFalse(state["compute_hosts"]["local_mac"]["local_agent_launch_allowed"])
        self.assertEqual("ready", state["pools"]["codex.luna"]["health"])

    def test_controller_timeout_is_not_classified_as_network(self):
        self.assertEqual(
            "stall",
            monitor.classify_error("continuity controller: attempt timed out after 30s"),
        )
        self.assertEqual("network", monitor.classify_error("connection timed out"))

    def test_observation_preserves_controller_lane_lease_heartbeat_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            worker = {
                "worker_id": "lane-1",
                "job_id": "job-1",
                "lane_id": "lane-1",
                "lane_index": 0,
                "lane_count": 2,
                "lease": {"status": "active", "fence_token": 4},
                "heartbeat": {"status": "observed", "source": "sqlite.leases.heartbeat_at_utc"},
                "pid": 99999999,
            }
            observation = monitor.observe_worker(worker, pathlib.Path(tmp), None)
            self.assertEqual("lane-1", observation["lane_id"])
            self.assertEqual(0, observation["lane_index"])
            self.assertEqual("active", observation["lease"]["status"])
            self.assertEqual("observed", observation["heartbeat"]["status"])

    def test_capability_feedback_updates_exact_runtime_model_variant(self):
        self.assertEqual(
            "location_restricted",
            monitor.classify_error("User location is not supported for the API use."),
        )
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp) / "runtime.json"
            runtime.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "pools": {
                            "opencode.go": {
                                "health": "unknown",
                                "runtime_state": "unknown",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            state = {
                "runtime_state": str(runtime),
                "pools": {"opencode.go": {"health": "ready"}},
            }
            monitor.apply_feedback(
                state,
                {
                    "pool_id": "opencode.go",
                    "provider": "opencode",
                    "model": "opencode-go/deepseek-v4-flash",
                    "variant": "max",
                    "error_class": "capability",
                    "error_message": "unsupported model",
                    "observed_at_utc": "2026-08-12T00:00:00+00:00",
                },
            )
            payload = json.loads(runtime.read_text(encoding="utf-8"))
            row = payload["models"]["opencode"]["opencode-go/deepseek-v4-flash"]
            self.assertEqual("rejected", row["variants"]["max"]["runtime_state"])
            self.assertNotEqual("rejected", payload["pools"]["opencode.go"]["runtime_state"])

            monitor.apply_feedback(
                state,
                {
                    "pool_id": "antigravity.gemini",
                    "provider": "antigravity",
                    "model": "gemini-3.1-pro-high",
                    "error_class": "location_restricted",
                    "error_message": "User location is not supported for the API use.",
                    "observed_at_utc": "2026-08-12T00:00:00+00:00",
                },
            )
            self.assertEqual(
                "gcp_project_or_supported_region",
                state["model_state"]["gemini-3.1-pro-high"]["recovery_action"],
            )

    def test_dead_worker_with_stale_or_unverified_artifact_is_not_completed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            artifact = root / "result.txt"
            artifact.write_text("old result\n", encoding="utf-8")
            worker = {
                "worker_id": "w-stale",
                "job_id": "j-stale",
                "required_paths": [str(artifact)],
                "pid": 99999999,
            }
            with mock.patch.object(monitor, "pid_alive", return_value=False):
                observation = monitor.observe_worker(worker, root, None)
            self.assertEqual("artifact_ready_needs_validation", observation["status"])
            self.assertTrue(observation["artifact_ready"])
            self.assertFalse(observation["completion_verified"])
            self.assertEqual("validation_not_verified", observation["completion_reason"])

    def test_monitor_accepts_only_explicit_validator_and_freshness_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            artifact = root / "result.txt"
            artifact.write_text("new result\n", encoding="utf-8")
            worker = {
                "worker_id": "w-verified",
                "job_id": "j-verified",
                "required_paths": [str(artifact)],
                "pid": 99999999,
                "validation": {"ok": True, "returncode": 0},
                "artifact_freshness_verified": True,
                "controller_status": "completed",
            }
            with mock.patch.object(monitor, "pid_alive", return_value=False):
                observation = monitor.observe_worker(worker, root, None)
            self.assertEqual("completed", observation["status"])
            self.assertTrue(observation["completion_verified"])

    def test_worker_only_completed_evidence_is_not_treated_as_done(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            artifact = root / "result.txt"
            artifact.write_text("new result\n", encoding="utf-8")
            worker = {
                "worker_id": "w-worker-only-complete",
                "job_id": "j-worker-only-complete",
                "required_paths": [str(artifact)],
                "pid": 99999999,
                "validation": {"ok": True, "returncode": 0},
                "artifact_freshness_verified": True,
            }
            with mock.patch.object(monitor, "pid_alive", return_value=False):
                observation = monitor.observe_worker(worker, root, None)
            self.assertEqual("artifact_ready_needs_validation", observation["status"])
            self.assertTrue(observation["completion_verified"])

    def test_compute_alert_uses_workload_host_for_split_placement(self):
        state = {
            "compute_hosts": {
                "local_mac": {"transport": "local", "reachable": True},
                "remote_gpu": {"transport": "ssh", "reachable": False},
            },
            "workers": [{
                "worker_id": "w1", "execution_host": "local_mac",
                "workload_host": "remote_gpu", "status": "healthy",
            }],
        }
        alerts = monitor.compute_alerts(state)
        self.assertEqual("remote_gpu", alerts[0]["host_id"])
        self.assertEqual("active_host_unreachable", alerts[0]["reason"])

    def test_compute_alerts_use_cgroup_and_psi_evidence(self):
        state = {
            "compute_hosts": {
                "remote_cpu": {
                    "transport": "ssh",
                    "reachable": True,
                    "cgroup_required": True,
                    "cgroup_memory_evidence_status": "complete",
                    "cgroup_memory_max_bytes": 10 * 1024**3,
                    "cgroup_memory_current_bytes": 9 * 1024**3,
                    "cgroup_memory_events_oom_kill": 0,
                    "cgroup_memory_events_oom": 0,
                    "psi_some_avg10": 21.0,
                }
            },
            "workers": [],
        }
        alerts = monitor.compute_alerts(state)
        reasons = {row["reason"] for row in alerts}
        self.assertIn("cgroup_memory_current_at_or_above_90_percent", reasons)
        self.assertIn("psi_memory_some_avg10_at_or_above_20_percent", reasons)
        self.assertTrue(all(row["severity"] == "stop" for row in alerts))

    def test_compute_alerts_fail_closed_when_required_cgroup_is_unknown(self):
        alerts = monitor.compute_alerts(
            {
                "compute_hosts": {
                    "remote_cpu": {
                        "transport": "ssh",
                        "reachable": True,
                        "cgroup_required": True,
                        "cgroup_memory_evidence_status": "unknown",
                    }
                },
                "workers": [],
            }
        )
        self.assertEqual(
            [{"host_id": "remote_cpu", "severity": "stop", "reason": "cgroup_memory_evidence_unknown"}],
            alerts,
        )

    def test_compute_alerts_accept_explicit_unbounded_cgroup_v1(self):
        alerts = monitor.compute_alerts(
            {
                "compute_hosts": {
                    "remote_cpu": {
                        "transport": "ssh",
                        "reachable": True,
                        "cgroup_required": True,
                        "cgroup_memory_evidence_status": "unbounded",
                        "cgroup_memory_unbounded": True,
                    }
                },
                "workers": [],
            }
        )
        self.assertEqual([], alerts)

    def test_split_without_workload_telemetry_is_unknown_not_local_healthy(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = {
                "project_root": tmp,
                "compute_hosts": {
                    "local_mac": {"transport": "local", "reachable": True},
                    "remote_gpu": {"transport": "ssh", "reachable": True},
                },
            }
            worker = {
                "worker_id": "w1", "job_id": "j1",
                "execution_host": "local_mac", "workload_host": "remote_gpu",
                "log_path": "agent.log", "required_paths": ["agent.out"],
            }
            observation = monitor.observe_placement(
                worker, state, pathlib.Path(tmp), None, 2.0
            )
            self.assertEqual("unknown", observation["status"])
            self.assertEqual("workload_observation_unavailable", observation["error_origin"])
            self.assertEqual("local_mac", observation["execution_host"])
            self.assertEqual("remote_gpu", observation["workload_host"])

    def test_local_monitor_rejects_traversal_and_absolute_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "project"
            root.mkdir()
            for value in ("../outside.log", "/tmp/outside.log"):
                observation = monitor.observe_worker(
                    {
                        "worker_id": "w-path",
                        "job_id": "j-path",
                        "log_path": value,
                        "pid": 99999999,
                    },
                    root,
                    None,
                )
                self.assertEqual("failed", observation["status"])
                self.assertEqual("path", observation["error_class"])
                self.assertEqual("monitor_security", observation["error_origin"])

    def test_remote_monitor_rejects_traversal_and_root_observation(self):
        with self.assertRaises(ValueError):
            monitor.remote_path("../outside.log", "/srv/project")
        with self.assertRaises(ValueError):
            monitor.remote_path("/etc/passwd", "/srv/project")
        with self.assertRaises(ValueError):
            monitor.remote_path("relative.log", "/")

    def test_local_monitor_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "project"
            root.mkdir()
            outside = pathlib.Path(tmp) / "outside"
            outside.write_text("secret\n", encoding="utf-8")
            link = root / "link.log"
            link.symlink_to(outside)
            observation = monitor.observe_worker(
                {
                    "worker_id": "w-symlink",
                    "job_id": "j-symlink",
                    "log_path": "link.log",
                    "pid": 99999999,
                },
                root,
                None,
            )
            self.assertEqual("failed", observation["status"])
            self.assertEqual("monitor_path_rejected", observation["completion_reason"])


if __name__ == "__main__":
    unittest.main()
