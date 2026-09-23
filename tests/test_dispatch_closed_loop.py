from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import dispatch_closed_loop  # noqa: E402


def _packet(workspace: pathlib.Path, *, job_id: str = "fake-wave") -> dict[str, object]:
    prompt = workspace / f"{job_id}.md"
    artifact = workspace / f"{job_id}.txt"
    prompt.write_text("provider-free fake wave\n", encoding="utf-8")
    worker = (
        "import pathlib; "
        f"pathlib.Path({str(artifact)!r}).write_text('fake result\\n', encoding='utf-8')"
    )
    validation = (
        "import pathlib,sys; "
        f"sys.exit(0 if pathlib.Path({str(artifact)!r}).read_text(encoding='utf-8') == 'fake result\\n' else 7)"
    )
    return {
        "schema_version": 1,
        "packet_id": f"packet-{job_id}",
        "job_id": job_id,
        "pool_id": "fake.pool",
        "provider": "fake",
        "model": "fake-model",
        "variant": "max",
        "workspace": str(workspace),
        "write_scope": f"artifacts/{job_id}",
        "required_artifacts": [str(artifact)],
        "validation_argv": [sys.executable, "-c", validation],
        "validation_required": True,
        "execution_host": "local_fake",
        "workload_host": "local_fake",
        "execution_transport": "local",
        "workload_transport": "local",
        "attempts": [
            {
                "attempt_id": f"attempt-{job_id}",
                "adapter": "command",
                "transport": "local",
                "host_id": "local_fake",
                "provider": "fake",
                "pool_id": "fake.pool",
                "model": "fake-model",
                "variant": "max",
                "workspace": str(workspace),
                "prompt_file": str(prompt),
                "result_source_path": str(artifact),
                "argv": [sys.executable, "-c", worker],
                "validation_argv": [sys.executable, "-c", validation],
                "timeout_seconds": 60,
            }
        ],
    }


class DispatchClosedLoopTests(unittest.TestCase):
    def test_dry_run_requires_approval_and_does_not_initialize_sqlite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            packet = _packet(workspace)
            bundle = {
                "schema_version": 1,
                "mode": "enqueue-ready",
                "ok": True,
                "packets": [packet],
            }
            with self.assertRaises(dispatch_closed_loop.ClosedLoopError):
                dispatch_closed_loop.run_closed_loop(
                    bundle,
                    workspace=workspace,
                    db_path=root / "dispatch.sqlite3",
                )

            report = dispatch_closed_loop.run_closed_loop(
                bundle,
                workspace=workspace,
                db_path=root / "dispatch.sqlite3",
                approved=True,
            )
            self.assertTrue(report["ok"])
            self.assertTrue(report["read_only"])
            self.assertFalse(report["enqueue_performed"])
            self.assertFalse((root / "dispatch.sqlite3").exists())
            self.assertFalse(report["intent_inferred"])
            self.assertEqual([], report["provider_invocations"])

    def test_fake_closed_loop_runs_sqlite_monitor_replan_without_requeue(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            packet = _packet(workspace)
            bundle = {
                "schema_version": 1,
                "mode": "enqueue-ready",
                "ok": True,
                "approved": True,
                "packets": [packet],
            }
            # The next wave is supplied explicitly as planner input.  The
            # controller must not infer it from the completed packet, but it
            # should be able to produce a read-only plan for this known queue.
            planner_state = {
                "schema_version": 1,
                "ok": True,
                "compute_hosts": {
                    "local_fake": {
                        "host_id": "local_fake",
                        "transport": "local",
                        "reachable": True,
                        "project_path_exists": True,
                        "project_path_writable": True,
                        "logical_cpu_cores": 8,
                        "estimated_idle_cpu_cores": 7,
                        "memory_total_gib": 16,
                        "memory_available_gib": 12,
                        "disk_total_gib": 100,
                        "disk_free_gib": 50,
                        "gpu_count": 0,
                        "gpus": [],
                        "commands": {"python3": sys.executable},
                        "python": {"version": "3.14"},
                    }
                },
                "pools": {
                    "codex.spark": {
                        "provider": "codex",
                        "health": "ready",
                        "effective_remaining_percent": 80,
                        "reserve_percent": 10,
                        "default_model": "gpt-5.3-codex-spark",
                        "default_variant": "xhigh",
                        "catalog_models": ["gpt-5.3-codex-spark"],
                        "role_models": {"hard": "gpt-5.3-codex-spark"},
                        "role_model_candidates": {"hard": ["gpt-5.3-codex-spark"]},
                        "max_concurrency": 2,
                        "inflight": 0,
                    }
                },
            }
            jobs_payload = {
                "jobs": [
                    {
                        "job_id": "future-wave",
                        "task_type": "audit",
                        "difficulty": 1,
                        "allowed_pools": ["codex.spark"],
                        "resources": {
                            "input_gib": 0,
                            "download_gib": 0,
                            "environment_gib": 0,
                            "temporary_gib": 0,
                            "cache_gib": 0,
                            "output_gib": 0,
                            "cpu_cores": 1,
                            "ram_gib": 1,
                            "gpu_count": 0,
                            "vram_gib": 0,
                            "compute_minutes": 1,
                        },
                        "workspace": str(workspace),
                        "write_scope": "artifacts/future-wave",
                    }
                ]
            }
            report = dispatch_closed_loop.run_closed_loop(
                bundle,
                workspace=workspace,
                db_path=root / "dispatch.sqlite3",
                mode="fake-execute",
                max_lanes=1,
                monitor_duration_seconds=0,
                planner_state=planner_state,
                jobs_payload=jobs_payload,
            )
            self.assertTrue(report["ok"], json.dumps(report, indent=2))
            self.assertTrue(report["enqueue_performed"])
            self.assertTrue(report["execution_performed"])
            self.assertFalse(report["intent_inferred"])
            self.assertEqual([], report["provider_invocations"])
            self.assertEqual(["completed"], report["execution"]["statuses"])
            self.assertEqual("replan_unblocked_jobs", report["monitor"]["decision"])
            self.assertEqual("keep", report["replan"]["decision"])
            self.assertTrue(report["next_plan_read_only"])
            self.assertIsNotNone(report["next_plan"])
            self.assertEqual("dispatch", report["next_plan"]["decision"])
            self.assertEqual("future-wave", report["next_plan"]["assignments"][0]["job_id"])
            self.assertEqual(1, report["enqueue"]["count"])
            serialized = json.dumps(report)
            self.assertNotIn('"argv"', serialized)
            self.assertNotIn('"payload"', serialized)
            self.assertTrue((root / "dispatch.sqlite3").is_file())
            artifact = workspace / "fake-wave.txt"
            self.assertEqual("fake result\n", artifact.read_text(encoding="utf-8"))

    def test_quota_snapshot_is_carried_into_read_only_next_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            packet = _packet(workspace, job_id="quota-wave")
            bundle = {
                "schema_version": 1,
                "mode": "enqueue-ready",
                "ok": True,
                "approved": True,
                "packets": [packet],
            }
            planner_state = {
                "schema_version": 1,
                "ok": True,
                "compute_hosts": {
                    "local_fake": {
                        "host_id": "local_fake",
                        "transport": "local",
                        "reachable": True,
                        "project_path_exists": True,
                        "project_path_writable": True,
                        "logical_cpu_cores": 8,
                        "estimated_idle_cpu_cores": 7,
                        "memory_total_gib": 16,
                        "memory_available_gib": 12,
                        "disk_total_gib": 100,
                        "disk_free_gib": 50,
                        "gpu_count": 0,
                        "gpus": [],
                        "commands": {"python3": sys.executable},
                        "python": {"version": "3.14"},
                    }
                },
                "pools": {
                    "codex.spark": {
                        "provider": "codex",
                        "health": "ready",
                        "effective_remaining_percent": 80,
                        "reserve_percent": 10,
                        "default_model": "gpt-5.3-codex-spark",
                        "default_variant": "xhigh",
                        "catalog_models": ["gpt-5.3-codex-spark"],
                        "role_models": {"hard": "gpt-5.3-codex-spark"},
                        "role_model_candidates": {"hard": ["gpt-5.3-codex-spark"]},
                        "max_concurrency": 2,
                        "inflight": 0,
                    }
                },
            }
            jobs_payload = {
                "jobs": [
                    {
                        "job_id": "future-quota-wave",
                        "task_type": "audit",
                        "difficulty": 1,
                        "allowed_pools": ["codex.spark"],
                        "resources": {
                            "input_gib": 0,
                            "download_gib": 0,
                            "environment_gib": 0,
                            "temporary_gib": 0,
                            "cache_gib": 0,
                            "output_gib": 0,
                            "cpu_cores": 1,
                            "ram_gib": 1,
                            "gpu_count": 0,
                            "vram_gib": 0,
                            "compute_minutes": 1,
                        },
                        "workspace": str(workspace),
                        "write_scope": "artifacts/future-quota-wave",
                    }
                ]
            }
            report = dispatch_closed_loop.run_closed_loop(
                bundle,
                workspace=workspace,
                db_path=root / "dispatch.sqlite3",
                mode="fake-execute",
                max_lanes=1,
                planner_state=planner_state,
                jobs_payload=jobs_payload,
                quota_snapshots=[
                    {
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
                ],
                quota_now_utc="2026-08-29T16:00:00Z",
            )
            self.assertTrue(report["ok"], json.dumps(report, indent=2))
            self.assertIn("codex.spark", report["replan"]["constraints"]["excluded_pools"])
            self.assertEqual("wait_bounded", report["replan"]["quota_replan_schedule"]["decision"])
            self.assertEqual([], report["next_plan"]["assignments"])
            self.assertEqual([], report["provider_invocations"])


if __name__ == "__main__":
    unittest.main()
