from __future__ import annotations

import json
import copy
import datetime as dt
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import replan_controller as replan  # noqa: E402


def monitor_report(*workers, alerts=None):
    # Keep the original state record intentionally richer than the monitor
    # observation: this catches accidental loss of workload_host/variant.
    original = []
    observations = []
    for worker in workers:
        row = dict(worker)
        original.append(row)
        observation = dict(worker)
        observation.pop("workload_host", None)
        observation.pop("variant", None)
        observations.append(observation)
    return {
        "schema_version": 1,
        "ok": True,
        "decision": "reroute_or_pause",
        "final_workers": observations,
        "compute_alerts": alerts or [],
        "state": {"schema_version": 1, "workers": original},
    }


class MonitorReplanTests(unittest.TestCase):
    def test_quota_watch_is_attached_and_excludes_blocked_pool(self):
        snapshot = {
            "fetched_at_utc": "2026-08-29T16:00:00Z",
            "pools": {
                "codex.spark": {
                    "provider": "codex",
                    "health": "blocked",
                    "effective_remaining_percent": 0,
                    "primary": {"resets_at_utc": "2026-08-29T16:47:03Z"},
                }
            },
        }
        watch = replan.build_quota_window_watch(
            [snapshot], now_utc="2026-08-29T16:00:00Z"
        )
        result = replan.build_replan_decision(
            {"schema_version": 1, "ok": True, "final_workers": [], "compute_alerts": []},
            generated_at_utc="2026-08-29T16:00:00Z",
            quota_watch=watch,
        )
        self.assertIn("codex.spark", result["constraints"]["excluded_pools"])
        self.assertEqual("wait_bounded", result["quota_replan_schedule"]["decision"])
        self.assertEqual("codex.spark", result["quota_replan_schedule"]["quota_reset_pool_id"])
        self.assertEqual([], result["provider_invocations"])

    def test_replan_schedule_bounds_future_quota_reset_wait(self):
        schedule = replan.build_replan_schedule(
            {
                "replan_at_utc": "2026-08-29T16:47:03Z",
                "replan_reason": "blocked_pool_quota_reset",
                "quota_reset_at_utc": "2026-08-29T16:47:03Z",
                "quota_reset_pool_id": "codex.spark",
            },
            now_utc="2026-08-29T14:00:00Z",
            max_wait_seconds=300,
        )
        self.assertTrue(schedule["ok"])
        self.assertFalse(schedule["due"])
        self.assertTrue(schedule["bounded"])
        self.assertEqual(300.0, schedule["sleep_seconds"])
        self.assertEqual("2026-08-29T14:05:00+00:00", schedule["wake_at_utc"])
        self.assertEqual("2026-08-29T16:47:03+00:00", schedule["target_replan_at_utc"])
        self.assertEqual("codex.spark", schedule["quota_reset_pool_id"])

    def test_replan_schedule_due_and_invalid_feedback_fail_closed(self):
        due = replan.build_replan_schedule(
            {"replan_at_utc": "2026-08-29T13:59:59Z"},
            now_utc=dt.datetime(2026, 8, 29, 14, 0, tzinfo=dt.timezone.utc),
        )
        self.assertTrue(due["ok"])
        self.assertTrue(due["due"])
        self.assertEqual(0.0, due["sleep_seconds"])
        self.assertEqual("replan_due", due["reason"])

        invalid = replan.build_replan_schedule(
            {"replan_at_utc": "2026-08-29T16:47:03"},
            now_utc="2026-08-29T14:00:00Z",
        )
        self.assertFalse(invalid["ok"])
        self.assertTrue(invalid["due"])
        self.assertEqual(0.0, invalid["sleep_seconds"])
        self.assertEqual("invalid_replan_at_utc", invalid["reason"])

    def test_replan_decision_carries_replayable_schedule_consumer_result(self):
        worker = {
            "worker_id": "w-provider",
            "job_id": "job-provider",
            "pool_id": "codex.spark",
            "model": "gpt-5.3-codex-spark",
            "variant": "xhigh",
            "execution_host": "remote",
            "workload_host": "remote",
            "status": "failed",
            "error_origin": "worker_log",
            "error_class": "quota",
        }
        planner_feedback = {
            "replan_at_utc": "2026-08-29T16:47:03Z",
            "replan_reason": "blocked_pool_quota_reset",
            "quota_reset_at_utc": "2026-08-29T16:47:03Z",
            "quota_reset_pool_id": "codex.spark",
        }
        result = replan.build_replan_decision(
            monitor_report(worker),
            generated_at_utc="2026-08-29T14:00:00Z",
            plan={"feedback": planner_feedback},
        )
        schedule = result["replan_schedule"]
        self.assertEqual("wait_bounded", schedule["decision"])
        self.assertEqual("codex.spark", schedule["quota_reset_pool_id"])
        self.assertEqual("2026-08-29T14:05:00+00:00", schedule["wake_at_utc"])
        self.assertEqual([], result["provider_invocations"])

    def test_provider_quota_only_cools_shared_pool(self):
        worker = {
            "worker_id": "w-provider",
            "job_id": "job-provider",
            "pool_id": "codex.spark",
            "model": "gpt-5.3-codex-spark",
            "variant": "xhigh",
            "execution_host": "local_mac",
            "workload_host": "remote_gpu",
            "status": "failed",
            "error_origin": "worker_log",
            "error_class": "quota",
        }
        jobs = {"jobs": [{"job_id": "job-provider", "status": "failed"}]}
        result = replan.build_replan_decision(
            monitor_report(worker), jobs, generated_at_utc="2026-08-12T00:00:00Z"
        )
        decision = result["worker_decisions"][0]
        self.assertEqual("provider", decision["failure"]["origin"])
        self.assertEqual("cooldown_pool", decision["action"])
        self.assertEqual(["codex.spark"], result["constraints"]["cooldown_pools"])
        self.assertEqual([], result["constraints"]["excluded_workload_hosts"])
        self.assertEqual(["codex.spark"], result["replan_jobs"][0]["excluded_pools"])
        self.assertEqual("replan", result["decision"])

    def test_capability_rejects_exact_model_variant_and_preserves_pool(self):
        worker = {
            "worker_id": "w-capability",
            "job_id": "job-capability",
            "pool_id": "cursor.other",
            "model": "gpt-5.3-codex-high",
            "variant": "high",
            "execution_host": "local_mac",
            "workload_host": "local_mac",
            "status": "failed",
            "error_origin": "provider",
            "error_class": "capability",
        }
        result = replan.build_replan_decision(monitor_report(worker))
        self.assertEqual("reject_exact_model", result["worker_decisions"][0]["action"])
        self.assertEqual([], result["constraints"]["excluded_pools"])
        self.assertEqual(["gpt-5.3-codex-high"], result["constraints"]["excluded_models"])
        self.assertEqual(
            {"gpt-5.3-codex-high": ["high"]},
            result["constraints"]["rejected_model_variants"],
        )

        location_worker = {
            **worker,
            "worker_id": "w-location",
            "job_id": "job-location",
            "model": "gemini-3.1-pro-high",
            "variant": None,
            "error_class": "location_restricted",
            "error_message": "User location is not supported for the API use.",
        }
        location_result = replan.build_replan_decision(monitor_report(location_worker))
        location_decision = location_result["worker_decisions"][0]
        self.assertEqual("block_location_restricted_model", location_decision["action"])
        self.assertEqual(
            ["provider_location_restriction_requires_gcp_or_supported_region"],
            location_decision["reason_codes"],
        )
        self.assertEqual(["gemini-3.1-pro-high"], location_result["constraints"]["excluded_models"])

    def test_workload_compute_failure_does_not_exclude_desktop_execution_host(self):
        worker = {
            "worker_id": "w-workload",
            "job_id": "job-workload",
            "pool_id": "codex.luna",
            "model": "gpt-5.6-luna",
            "execution_host": "local_mac",
            "workload_host": "remote_gpu",
            "failed_host": "remote_gpu",
            "status": "failed",
            "error_origin": "compute_host",
            "error_class": "host_unreachable",
        }
        jobs = [{"job_id": "job-workload", "status": "stalled"}]
        result = replan.build_replan_decision(monitor_report(worker), jobs)
        row = result["worker_decisions"][0]
        self.assertEqual("compute", row["failure"]["origin"])
        self.assertEqual("workload", row["failure"]["host_role"])
        self.assertEqual("reroute_workload_host", row["action"])
        self.assertEqual([], result["constraints"]["excluded_execution_hosts"])
        self.assertEqual(["remote_gpu"], result["constraints"]["excluded_workload_hosts"])
        self.assertEqual(["remote_gpu"], result["replan_jobs"][0]["excluded_hosts"])
        self.assertEqual(["remote_gpu"], result["replan_jobs"][0]["excluded_workload_hosts"])

    def test_coupled_compute_failure_excludes_both_roles(self):
        worker = {
            "worker_id": "w-both",
            "job_id": "job-both",
            "pool_id": "server_local.qwen",
            "model": "qwen-local",
            "execution_host": "remote_gpu",
            "workload_host": "remote_gpu",
            "failed_host": "remote_gpu",
            "status": "failed",
            "error_origin": "compute_host",
            "error_class": "resource_pressure",
        }
        result = replan.build_replan_decision(monitor_report(worker))
        self.assertEqual(
            "reroute_execution_and_workload_host", result["worker_decisions"][0]["action"]
        )
        self.assertEqual(["remote_gpu"], result["constraints"]["excluded_execution_hosts"])
        self.assertEqual(["remote_gpu"], result["constraints"]["excluded_workload_hosts"])

    def test_stop_alert_is_hard_and_reduce_alert_is_soft(self):
        healthy = {
            "worker_id": "w-healthy",
            "job_id": "job-healthy",
            "pool_id": "opencode.go",
            "model": "opencode-go/mimo-v2.5",
            "execution_host": "local_mac",
            "workload_host": "remote_cpu",
            "status": "healthy",
        }
        alerts = [
            {"host_id": "remote_gpu", "severity": "stop", "reason": "active_host_unreachable"},
            {"host_id": "remote_cpu", "severity": "reduce", "reason": "memory_pressure"},
        ]
        result = replan.build_replan_decision(monitor_report(healthy, alerts=alerts))
        self.assertEqual("reroute", result["decision"])
        self.assertIn("remote_gpu", result["constraints"]["excluded_workload_hosts"])
        self.assertIn("remote_gpu", result["constraints"]["excluded_execution_hosts"])
        self.assertIn("remote_cpu", result["constraints"]["avoid_hosts"])
        self.assertEqual("reduce_host_concurrency", result["host_alerts"][1]["action"])

    def test_unknown_failure_pauses_and_requests_review(self):
        worker = {
            "worker_id": "w-unknown",
            "job_id": "job-unknown",
            "pool_id": "codex.spark",
            "execution_host": "local_mac",
            "workload_host": "local_mac",
            "status": "stalled",
        }
        result = replan.build_replan_decision(monitor_report(worker))
        self.assertEqual("pause", result["decision"])
        self.assertEqual("human_review_required", result["mode"])
        self.assertEqual("pause_and_inspect", result["worker_decisions"][0]["action"])
        self.assertEqual(1, result["summary"]["unknown_failures"])

    def test_healthy_report_is_read_only_and_digest_is_replayable(self):
        worker = {
            "worker_id": "w-ok",
            "job_id": "job-ok",
            "pool_id": "codex.spark",
            "model": "gpt-5.3-codex-spark",
            "execution_host": "local_mac",
            "workload_host": "local_mac",
            "status": "completed",
        }
        report = monitor_report(worker)
        result = replan.build_replan_decision(report, generated_at_utc="fixed")
        result_again = replan.build_replan_decision(report, generated_at_utc="fixed")
        self.assertEqual("keep", result["decision"])
        self.assertTrue(result["read_only"])
        self.assertEqual([], result["provider_invocations"])
        self.assertEqual(result["decision_digest"], result_again["decision_digest"])
        self.assertEqual(report["state"]["workers"][0]["status"], "completed")

    def test_cli_emits_json_without_starting_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            report_path = root / "monitor.json"
            output_path = root / "decision.json"
            report_path.write_text(json.dumps(monitor_report()), encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "replan_controller.py"),
                    "--monitor-report",
                    str(report_path),
                    "--output",
                    str(output_path),
                    "--generated-at-utc",
                    "fixed",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            result = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertTrue(result["read_only"])
            self.assertEqual("keep", result["decision"])
            self.assertEqual([], result["provider_invocations"])

    def test_replan_patch_changes_next_workload_host_without_touching_execution_host(self):
        worker = {
            "worker_id": "w-remote",
            "job_id": "job-remote",
            "pool_id": "cursor.composer_grok",
            "model": "composer-2.5-fast",
            "execution_host": "local_mac",
            "workload_host": "remote_a",
            "failed_host": "remote_a",
            "status": "failed",
            "error_origin": "compute_host",
            "error_class": "host_unreachable",
        }
        job = {
            "job_id": "job-remote",
            "task_type": "code",
            "difficulty": 2,
            "allowed_pools": ["cursor.composer_grok"],
            "allowed_hosts": ["remote_a", "remote_b"],
            "write_scope": "src/job-remote",
            "resource_estimate": {
                "input_gib": 0, "download_gib": 0, "environment_gib": 0,
                "temporary_gib": 0, "cache_gib": 0, "output_gib": 0,
                "ram_gib": 1, "cpu_cores": 2, "gpu_count": 0,
                "vram_gib": 0, "compute_minutes": 20,
            },
        }
        original_job = copy.deepcopy(job)
        decision = replan.build_replan_decision(monitor_report(worker), {"jobs": [job]})
        patched = decision["replan_jobs"][0]
        self.assertEqual(["remote_a"], patched["excluded_workload_hosts"])
        self.assertNotIn("local_mac", patched.get("excluded_execution_hosts", []))

        def host(host_id, transport, cpu=32):
            return {
                "host_id": host_id, "transport": transport, "reachable": True,
                "project_path_exists": True, "project_path_writable": True,
                "project_path": "/srv/project", "logical_cpu_cores": cpu,
                "estimated_idle_cpu_cores": cpu, "memory_total_gib": 64,
                "memory_available_gib": 48, "disk_total_gib": 500,
                "disk_free_gib": 300, "gpu_count": 0, "gpus": [], "commands": {},
            }

        state = {
            "pools": {"cursor.composer_grok": {
                "provider": "cursor", "health": "ready",
                "effective_remaining_percent": 90, "reserve_percent": 10,
                "default_model": "composer-2.5-fast", "max_concurrency": 2, "inflight": 0,
            }},
            "compute_hosts": {
                "local_mac": host("local_mac", "local", 10),
                "remote_a": host("remote_a", "ssh"),
                "remote_b": host("remote_b", "ssh"),
            },
        }
        merged = replan.merge_replan_constraints(decision, {"jobs": [job]}, state)
        self.assertEqual(original_job, job)
        self.assertEqual(["remote_a"], merged["jobs"]["jobs"][0]["excluded_hosts"])
        self.assertTrue(merged["read_only"])
        self.assertFalse(merged["enqueue_performed"])
        replanned_result = replan.plan_after_replan(
            decision, {"jobs": [job]}, state, max_lanes=1, horizon=1
        )
        self.assertTrue(replanned_result["read_only"])
        self.assertFalse(replanned_result["enqueue_performed"])
        replanned = replanned_result["next_plan"]
        self.assertEqual(1, len(replanned["assignments"]))
        self.assertEqual("local_mac", replanned["assignments"][0]["execution_host"])
        self.assertEqual("remote_b", replanned["assignments"][0]["workload_host"])


if __name__ == "__main__":
    unittest.main()
