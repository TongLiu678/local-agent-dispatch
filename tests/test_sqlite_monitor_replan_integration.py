from __future__ import annotations

import copy
import pathlib
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import dispatch_monitor  # noqa: E402
import dispatch_workflow  # noqa: E402
import plan_packet_bridge  # noqa: E402
import replan_controller  # noqa: E402
from controller_monitor_adapter import build_monitor_state  # noqa: E402
from sqlite_controller import SQLiteController  # noqa: E402


class SQLiteMonitorReplanIntegrationTests(unittest.TestCase):
    """Exercise the production SQLite snapshot -> monitor -> replan seam.

    Both lanes use shell-free fake command adapters.  The test deliberately
    does not construct a monitor worker by hand: the worker records come from
    the planner bridge, SQLite claim/complete rows, and the read-only snapshot
    adapter that production monitoring consumes.
    """

    def test_planner_assignments_claim_to_lanes_and_replan_from_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            task_a = workspace / "task-a.md"
            task_b = workspace / "task-b.md"
            task_a.write_text("quota lane\n", encoding="utf-8")
            task_b.write_text("successful lane\n", encoding="utf-8")
            artifact_a = workspace / "a.txt"
            artifact_b = workspace / "b.txt"

            def host() -> dict[str, object]:
                return {
                    "host_id": "local_system",
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

            def pool(provider: str, model: str) -> dict[str, object]:
                return {
                    "provider": provider,
                    "health": "ready",
                    "effective_remaining_percent": 80,
                    "reserve_percent": 10,
                    "default_model": model,
                    "default_variant": "max",
                    "catalog_models": [model],
                    "role_models": {"hard": model},
                    "role_model_candidates": {"hard": [model]},
                    "max_concurrency": 1,
                    "inflight": 0,
                }

            local_system = {
                "ok": True,
                "schema_version": 1,
                "os": {"name": "Linux"},
                "arch": "x86_64",
                "cpu": {"logical_cores": 8, "physical_cores": 8},
                "ram": {"total_gib": 16, "available_gib": 12},
                "disks": {
                    "workspace": {
                        "exists": True,
                        "writable": True,
                        "total_bytes": 100 * 1024**3,
                        "free_bytes": 50 * 1024**3,
                    }
                },
                "accelerators": [],
                "python": {"executable": sys.executable, "version": "3.14"},
                "clis": {},
            }
            preflight = {
                "ok": True,
                "schema_version": 1,
                "compute_hosts": {"local_system": host()},
                "pools": {
                    "codex.luna": pool("codex", "gpt-5.6-luna"),
                    "opencode.go": pool("opencode", "opencode-go/deepseek-v4-flash"),
                },
            }
            resources = {
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
            }
            jobs = [
                {
                    "job_id": "lane-quota",
                    "task_type": "audit",
                    "difficulty": 1,
                    "allowed_pools": ["codex.luna"],
                    "resources": resources,
                    "workspace": str(workspace),
                    "prompt_file": str(task_a),
                    "result_source_path": str(artifact_a),
                    "output_path": str(artifact_a),
                    "required_artifacts": [str(artifact_a)],
                    "write_scope": "artifacts/lane-quota",
                    "validation_argv": [sys.executable, "-c", "import sys; sys.exit(0)"],
                },
                {
                    "job_id": "lane-success",
                    "task_type": "audit",
                    "difficulty": 1,
                    "allowed_pools": ["opencode.go"],
                    # The shared Go pool may only spend an exact task-level
                    # approval; this fixture intentionally approves the
                    # DeepSeek member used by the fake adapter.
                    "model_by_pool": {
                        "opencode.go": {"model": "opencode-go/deepseek-v4-flash"}
                    },
                    "resources": resources,
                    "workspace": str(workspace),
                    "prompt_file": str(task_b),
                    "result_source_path": str(artifact_b),
                    "output_path": str(artifact_b),
                    "required_artifacts": [str(artifact_b)],
                    "write_scope": "artifacts/lane-success",
                    "validation_argv": [
                        sys.executable,
                        "-c",
                        "import pathlib,sys; sys.exit(0 if pathlib.Path('b.txt').read_text() == 'ok\\n' else 1)",
                    ],
                },
            ]

            workflow = dispatch_workflow.build_report(
                local_system,
                preflight,
                jobs,
                workspace,
                max_lanes=2,
                horizon=2,
            )
            self.assertTrue(workflow["ok"])
            self.assertEqual(
                {"codex.luna", "opencode.go"},
                {row["pool_id"] for row in workflow["assignments"]},
            )

            adapters = {
                "codex.luna": {
                    "provider": "codex",
                    "adapter": "command",
                    "transport": "local",
                    "argv": [sys.executable, "-c", "print('rate limit'); raise SystemExit(7)"],
                },
                "opencode.go": {
                    "provider": "opencode",
                    "adapter": "command",
                    "transport": "local",
                    "argv": [
                        sys.executable,
                        "-c",
                        "import pathlib; pathlib.Path('{workspace}/b.txt').write_text('ok\\n')",
                    ],
                },
            }
            bridge = plan_packet_bridge.bridge_plan(
                {**workflow["planner"], "schema_version": 1},
                jobs,
                {"workspace": str(workspace), "hosts": preflight["compute_hosts"]},
                adapters,
            )
            self.assertTrue(bridge["ok"])
            self.assertEqual(2, len(bridge["packets"]))

            controller = SQLiteController(root / "dispatch.sqlite3", workspace=workspace)
            for packet in bridge["packets"]:
                controller.enqueue(packet)
            healthy_ram = {
                "total_bytes": 16 * 1024**3,
                "available_bytes": 12 * 1024**3,
                "swap_total_bytes": 0,
                "swap_used_bytes": 0,
                "pressure_state": "normal",
            }
            # Resource admission is intentionally live in production.  This
            # fake-only integration supplies explicit healthy evidence so the
            # result tests are independent of the developer machine's current
            # memory pressure and external processes.
            with mock.patch(
                "sqlite_controller.governor.observe_local",
                return_value=(healthy_ram, []),
            ):
                execution = controller.run(once=True, max_lanes=2)
            self.assertEqual(2, len(execution["results"]))
            self.assertEqual(
                {"failed", "completed"},
                {row["status"] for row in execution["results"]},
            )
            claimed_events = [
                event
                for event in execution["snapshot"]["events"]
                if event.get("event_type") == "job_claimed"
            ]
            self.assertEqual(2, len(claimed_events))
            self.assertEqual(
                {"lane-quota", "lane-success"},
                {event.get("job_id") for event in claimed_events},
            )

            # This is the production worker-record path: no hand-written
            # monitor worker is allowed to bypass the durable snapshot.
            monitor_state = build_monitor_state(execution["snapshot"])
            monitor_state["project_root"] = str(workspace)
            self.assertEqual(2, monitor_state["lane_count"])
            self.assertEqual(0, monitor_state["active_lane_count"])
            self.assertEqual(
                {"lane-quota", "lane-success"},
                {worker["job_id"] for worker in monitor_state["workers"]},
            )

            report = dispatch_monitor.monitor(
                monitor_state,
                duration_seconds=0,
                interval_seconds=0.1,
                stall_seconds=1,
                refresh_codex=False,
                usage_timeout=2,
                refresh_compute=False,
                compute_timeout=2,
                stream=False,
            )
            final = {row["job_id"]: row for row in report["final_workers"]}
            self.assertEqual("failed", final["lane-quota"]["status"])
            self.assertEqual("quota", final["lane-quota"]["error_class"])
            self.assertEqual("completed", final["lane-success"]["status"])
            self.assertEqual("controller_state", final["lane-quota"]["error_origin"])
            self.assertEqual("terminal", final["lane-quota"]["lease"]["status"])

            decision = replan_controller.build_replan_decision(
                report,
                {"jobs": copy.deepcopy(jobs)},
                workflow["planner"],
            )
            self.assertEqual("replan", decision["decision"])
            self.assertIn("codex.luna", decision["constraints"]["cooldown_pools"])
            self.assertEqual([], decision["provider_invocations"])


if __name__ == "__main__":
    unittest.main()
