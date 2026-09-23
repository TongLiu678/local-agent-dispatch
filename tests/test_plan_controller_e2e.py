from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
BRIDGE = SCRIPTS / "plan_packet_bridge.py"
CONTROLLER = SCRIPTS / "continuity_controller.py"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import dispatch_monitor  # noqa: E402
import dispatch_workflow  # noqa: E402
import plan_packet_bridge  # noqa: E402
import replan_controller  # noqa: E402
from sqlite_controller import SQLiteController  # noqa: E402


class PlanControllerFakeE2ETests(unittest.TestCase):
    """Exercise the offline plan -> packet -> controller boundary.

    The command adapter is deliberately a fake local worker.  No provider,
    network, model, or remote host is contacted; this is a contract test for
    the durable hand-off and completion gates only.
    """

    def test_plan_bridge_enqueue_execute_and_validate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "task.md").write_text("write the bounded artifact\n", encoding="utf-8")
            run_dir = root / "run"
            inventory = root / "hosts.json"
            inventory.write_text(json.dumps({"hosts": []}) + "\n", encoding="utf-8")
            runtime_state = root / "runtime-state.json"
            preflight_state = root / "bridge-state.json"
            jobs_path = root / "jobs.json"
            plan_path = root / "plan.json"
            adapters_path = root / "adapters.json"
            report_path = root / "bridge-report.json"
            job_path = root / "packet.json"

            result = workspace / "result.txt"
            worker_code = (
                "import pathlib; "
                "pathlib.Path('result.txt').write_text('fake worker result\\n', encoding='utf-8')"
            )
            validation_code = (
                "import pathlib,sys; "
                "p=pathlib.Path('result.txt'); "
                "sys.exit(0 if p.is_file() and p.read_text(encoding='utf-8') == 'fake worker result\\n' else 7)"
            )
            job = {
                "job_id": "e2e-job",
                "workspace": str(workspace),
                "prompt_file": str(workspace / "task.md"),
                "result_source_path": str(result),
                "output_path": str(result),
                "required_artifacts": [str(result)],
                "write_scope": "artifacts/e2e-job",
                "validation_argv": [sys.executable, "-c", validation_code],
                "timeout_seconds": 60,
            }
            assignment = {
                "job_id": "e2e-job",
                "pool_id": "codex.spark",
                "model": "gpt-5.3-codex-spark",
                "variant": "xhigh",
                "execution_host": "local_mac",
                "execution_transport": "local",
                "workload_host": "local_mac",
                "workload_transport": "local",
                "write_scope": job["write_scope"],
                "resource_request": {"cpu_cores": 1, "ram_gib": 0.1},
            }
            preflight_state.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "workspace": str(workspace),
                        "hosts": {
                            "local_mac": {
                                "host_id": "local_mac",
                                "transport": "local",
                                "reachable": True,
                            }
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            jobs_path.write_text(json.dumps([job]) + "\n", encoding="utf-8")
            plan_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "ok": True,
                        "decision": "dispatch",
                        "assignments": [assignment],
                        "deferred": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            adapters_path.write_text(
                json.dumps(
                    {
                        "codex.spark": {
                            "provider": "codex",
                            "adapter": "command",
                            "transport": "local",
                            "argv": [sys.executable, "-c", worker_code],
                        }
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            bridge = subprocess.run(
                [
                    sys.executable,
                    str(BRIDGE),
                    "--plan",
                    str(plan_path),
                    "--jobs",
                    str(jobs_path),
                    "--state",
                    str(preflight_state),
                    "--adapters",
                    str(adapters_path),
                    "--output",
                    str(report_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, bridge.returncode, bridge.stdout + bridge.stderr)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertTrue(report["ok"])
            self.assertTrue(report["read_only"])
            packet = report["packets"][0]
            self.assertEqual("gpt-5.3-codex-spark", packet["model"])
            self.assertEqual("xhigh", packet["variant"])
            self.assertTrue(packet["validation_required"])
            self.assertNotIn("write the bounded artifact", json.dumps(packet))
            job_path.write_text(json.dumps(packet) + "\n", encoding="utf-8")

            init = subprocess.run(
                [
                    sys.executable,
                    str(CONTROLLER),
                    "init",
                    "--run-dir",
                    str(run_dir),
                    "--workspace",
                    str(workspace),
                    "--inventory",
                    str(inventory),
                    "--runtime-state",
                    str(runtime_state),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, init.returncode, init.stdout + init.stderr)
            enqueue = subprocess.run(
                [
                    sys.executable,
                    str(CONTROLLER),
                    "enqueue",
                    "--run-dir",
                    str(run_dir),
                    "--job-file",
                    str(job_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, enqueue.returncode, enqueue.stdout + enqueue.stderr)
            run = subprocess.run(
                [sys.executable, str(CONTROLLER), "run", "--run-dir", str(run_dir), "--once"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, run.returncode, run.stdout + run.stderr)

            state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
            self.assertEqual("completed", state["jobs"][0]["status"])
            self.assertTrue(state["jobs"][0]["validation"]["ok"])
            self.assertTrue(state["jobs"][0]["artifact_freshness_verified"])
            self.assertEqual("fake worker result\n", result.read_text(encoding="utf-8"))
            events = [
                json.loads(line)
                for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertTrue(events)
            self.assertTrue(all(row.get("schema_version") == 1 for row in events))
            self.assertIn("job_completed", {row["event"] for row in events})

    def test_workflow_bridge_sqlite_monitor_and_replan_are_one_provider_free_cycle(self):
        """Exercise the real hand-off across all control-plane boundaries.

        The first plan is deliberately restricted to a fake Codex pool while
        the OpenCode pool is blocked.  The fake command emits a rate-limit
        marker and leaves a PID/log breadcrumb; SQLite records the failed
        attempt, the monitor reads those breadcrumbs, and replan converts the
        observation into a shared-pool exclusion.  A second planning wave then
        selects the now-ready OpenCode pool.  No provider binary, network, or
        SSH endpoint is contacted at any point.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            task_file = workspace / "task.md"
            task_file.write_text("provider-free control-plane test\n", encoding="utf-8")
            artifact = workspace / "artifact.txt"
            log_path = workspace / "worker.log"
            pid_path = workspace / "worker.pid"

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
            local_host = {
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

            def pool(provider: str, health: str) -> dict[str, object]:
                is_codex = provider == "codex"
                model = "gpt-5.3-codex-spark" if is_codex else "opencode-go/deepseek-v4-flash"
                return {
                    "provider": provider,
                    "health": health,
                    "effective_remaining_percent": 80 if health == "ready" else 0,
                    "reserve_percent": 10,
                    "default_model": model,
                    "default_variant": "xhigh" if is_codex else "max",
                    "catalog_models": [model],
                    "role_models": {"hard": model},
                    "role_model_candidates": {"hard": [model]},
                    "max_concurrency": 1,
                    "inflight": 0,
                }

            preflight = {
                "ok": True,
                "schema_version": 1,
                "compute_hosts": {"local_system": local_host},
                # OpenCode is initially unavailable, so the first wave is
                # deterministic even though both pools are allowed by the job.
                "pools": {
                    "codex.spark": pool("codex", "ready"),
                    "opencode.go": pool("opencode", "blocked"),
                },
            }
            job = {
                "job_id": "sqlite-cycle",
                "task_type": "audit",
                "difficulty": 2,
                "allowed_pools": ["codex.spark", "opencode.go"],
                # Keep the OpenCode fallback exact without removing the
                # healthy Codex lane from the first wave.
                "approved_models": {
                    "opencode.go": ["opencode-go/deepseek-v4-flash"]
                },
                "resources": resources,
                "workspace": str(workspace),
                "prompt_file": str(task_file),
                "result_source_path": str(artifact),
                "output_path": str(artifact),
                "required_artifacts": [str(artifact)],
                "write_scope": "artifacts/sqlite-cycle",
                "validation_argv": [sys.executable, "-c", "import sys; sys.exit(0)"],
            }

            workflow_report = dispatch_workflow.build_report(
                local_system,
                preflight,
                [job],
                workspace,
                max_lanes=1,
                horizon=2,
            )
            self.assertTrue(workflow_report["ok"])
            self.assertEqual("codex.spark", workflow_report["assignments"][0]["pool_id"])
            assignment = workflow_report["assignments"][0]

            # The bridge is intentionally read-only; SQLite enqueue is the
            # explicit mutation boundary between planning and execution.
            bridge_report = plan_packet_bridge.bridge_plan(
                {**workflow_report["planner"], "schema_version": 1},
                [job],
                {"workspace": str(workspace), "hosts": preflight["compute_hosts"]},
                {
                    "codex.spark": {
                        "provider": "codex",
                        "adapter": "command",
                        "transport": "local",
                        "argv": [
                            sys.executable,
                            "-c",
                            (
                                "import os,pathlib; "
                                f"pathlib.Path({str(log_path)!r}).write_text('rate limit\\n', encoding='utf-8'); "
                                f"pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid()), encoding='utf-8'); "
                                "print('rate limit'); raise SystemExit(7)"
                            ),
                        ],
                    }
                },
            )
            self.assertTrue(bridge_report["ok"])
            packet = bridge_report["packets"][0]
            self.assertEqual(assignment["model"], packet["model"])
            self.assertTrue(bridge_report["read_only"])

            sqlite = SQLiteController(root / "dispatch.sqlite3", workspace=workspace)
            sqlite.enqueue(packet)
            # Keep this provider-free contract test deterministic.  The real
            # governor must continue to observe the host and fail closed; the
            # fixture supplies its own healthy host evidence so a busy
            # developer workstation cannot turn a queue/monitor assertion
            # into an unrelated empty-result failure.
            healthy_ram = {
                "total_bytes": 16 * 1024**3,
                "available_bytes": 12 * 1024**3,
                "swap_total_bytes": 0,
                "swap_used_bytes": 0,
                "pressure_state": "normal",
            }
            with mock.patch(
                "sqlite_controller.governor.observe_local",
                return_value=(healthy_ram, []),
            ):
                execution = sqlite.run(once=True, max_lanes=1)
            self.assertEqual("failed", execution["results"][0]["status"])
            self.assertEqual("quota", execution["results"][0]["error_class"])

            # Feed the actual fake worker breadcrumbs through the monitor
            # observer, then pass its normalized report to the replan API.
            worker = {
                "worker_id": "sqlite-cycle",
                "job_id": "sqlite-cycle",
                "pool_id": packet["pool_id"],
                "model": packet["model"],
                "variant": packet.get("variant"),
                "execution_host": "local_system",
                "workload_host": "local_system",
                "log_path": str(log_path),
                "pid_path": str(pid_path),
                "required_artifact": str(artifact),
            }
            observation = dispatch_monitor.observe_worker(worker, workspace, None)
            self.assertEqual("failed", observation["status"])
            self.assertEqual("quota", observation["error_class"])
            monitor_report = {
                "schema_version": 1,
                "ok": True,
                "decision": "reroute_or_pause",
                "final_workers": [observation],
                "state": {"workers": [worker]},
            }
            decision = replan_controller.build_replan_decision(
                monitor_report,
                {"jobs": [job]},
                workflow_report["planner"],
            )
            self.assertEqual("replan", decision["decision"])
            self.assertEqual(["codex.spark"], decision["constraints"]["cooldown_pools"])

            # Simulate a fresh provider-free preflight where the fallback pool
            # has recovered.  The copy-on-write replan must preserve the job
            # and select that pool, without enqueueing or invoking a provider.
            next_state = json.loads(json.dumps(preflight))
            next_state["pools"]["opencode.go"] = pool("opencode", "ready")
            next_wave = replan_controller.plan_after_replan(
                decision,
                {"jobs": [job]},
                next_state,
                max_lanes=1,
                horizon=2,
            )
            self.assertTrue(next_wave["ok"])
            self.assertTrue(next_wave["read_only"])
            self.assertFalse(next_wave["enqueue_performed"])
            self.assertEqual("opencode.go", next_wave["next_plan"]["assignments"][0]["pool_id"])


if __name__ == "__main__":
    unittest.main()
