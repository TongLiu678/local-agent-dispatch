"""Smoke tests for the `lad` CLI scaffold."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class LadCliScaffoldTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_root = Path(__file__).resolve().parents[1]
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = str(self.repo_root / "src")

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "local_agent_dispatch.cli", *args],
            cwd=self.repo_root,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_version_command(self) -> None:
        result = self.run_cli("--version")
        self.assertEqual(0, result.returncode)
        self.assertEqual("0.1.0a6\n", result.stdout)

    def test_doctor_offline_is_local_only(self) -> None:
        result = self.run_cli("doctor", "--offline")
        self.assertEqual(0, result.returncode)
        payload = json.loads(result.stdout)
        self.assertEqual("doctor", payload["command"])
        self.assertEqual("offline", payload["mode"])
        self.assertEqual("local-only", payload["evidence_level"])
        self.assertFalse(payload["evidence"]["model_prompt_sent"])

    def test_demo_offline_is_local_only(self) -> None:
        result = self.run_cli("demo", "--offline")
        self.assertEqual(0, result.returncode)
        payload = json.loads(result.stdout)
        self.assertEqual("demo", payload["command"])
        self.assertEqual("offline", payload["mode"])
        self.assertIn("No provider contact", payload["message"])

    def test_scan_workspace_uses_local_system_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            workspace.mkdir()
            (workspace / "agent.md").write_text("local-system-scan-check", encoding="utf-8")
            result = self.run_cli("scan", "--workspace", str(workspace))
            self.assertEqual(0, result.returncode)
            payload = json.loads(result.stdout)
            self.assertEqual("scan", payload["command"])
            self.assertEqual(str(workspace.resolve()), payload["workspace"])
            self.assertIsInstance(payload["scan"]["ok"], bool)
            self.assertTrue(payload["scan"]["ok"])

    def test_storage_pressure_is_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = self.run_cli("storage-pressure", "--root", str(root), "--max-entries", "10")
            self.assertEqual(0, result.returncode, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual("storage-pressure", payload["command"])
            self.assertTrue(payload["read_only"])
            self.assertFalse(payload["provider_execution"])
            self.assertFalse(payload["policy"]["automatic_delete"])

    def test_governor_is_read_only_and_exposes_lane_admission(self) -> None:
        from local_agent_dispatch import cli

        args = cli.build_parser().parse_args(
            [
                "governor",
                "--requested-lanes", "5",
                "--per-lane-peak-mib", "1024",
                "--max-local-lanes", "5",
                "--owned-pid", "123",
            ]
        )
        self.assertEqual("governor", args.command)
        with mock.patch.object(
            cli,
            "_run_json_script",
            return_value=(0, {
                "schema_version": 1,
                "read_only": True,
                "provider_execution": False,
                "admission": {"decision": "throttle", "max_new_local_lanes": 0},
            }),
        ):
            from io import StringIO

            with mock.patch("sys.stdout", new_callable=StringIO) as stdout:
                self.assertEqual(0, cli._command_governor(args))
            payload = json.loads(stdout.getvalue())
        self.assertEqual("governor", payload["command"])
        self.assertTrue(payload["read_only"])
        self.assertFalse(payload["provider_execution"])
        self.assertEqual(0, payload["admission"]["max_new_local_lanes"])

    def test_capture_builds_provider_free_task_packet(self) -> None:
        result = self.run_cli("capture", "--task", "run tests then build report")
        self.assertEqual(0, result.returncode, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual("capture", payload["command"])
        self.assertEqual("inferred_sequence", payload["dag"]["source"])
        self.assertFalse(payload["provider_prompts_sent"])
        self.assertFalse(payload["project_executed"])

    def test_legacy_import_cli_uses_review_only_batch_seam(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "legacy"
            run = root / "run-cli"
            run.mkdir(parents=True)
            (run / "state.json").write_text(
                json.dumps(
                    {
                        "run_id": "run-cli",
                        "jobs": [
                            {
                                "job_id": "job-cli",
                                "status": "running",
                                "model": "spark",
                                "prompt": "must never be persisted",
                                "credentials": {"token": "synthetic-secret"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            db = root / "import.sqlite3"
            result = self.run_cli(
                "legacy-import", "--root", str(root), "--output-db", str(db)
            )
            self.assertEqual(0, result.returncode, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual("legacy-import", payload["command"])
            self.assertFalse(payload["read_only"])
            self.assertFalse(payload["provider_execution"])
            self.assertEqual(1, payload["migration"]["imported_jobs"])
            self.assertEqual(1, payload["migration"]["reviewed_jobs"])
            self.assertNotIn("must never be persisted", result.stdout)
            self.assertNotIn("synthetic-secret", result.stdout)
            self.assertTrue(db.is_file())

    def test_evidence_builds_search_plan_without_network(self) -> None:
        result = self.run_cli(
            "evidence",
            "--provider", "opencode",
            "--capability", "usage_endpoint",
            "--version", "1.18.15",
            "--model", "opencode-go/deepseek-v4-flash",
            "--official-domain", "opencode.ai",
        )
        self.assertEqual(0, result.returncode, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual("evidence", payload["command"])
        self.assertTrue(payload["read_only"])
        self.assertFalse(payload["network_contacted"])
        self.assertTrue(payload["search_plan"]["probe_requires_explicit_opt_in"])
        self.assertEqual("official_docs", payload["search_plan"]["queries"][0]["source_kind"])

    def test_fit_reports_saved_hardware_and_server_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            preflight = root / "preflight.json"
            jobs = root / "jobs.json"
            preflight.write_text(
                json.dumps(
                    {
                        "local_system": {},
                        "compute_hosts": {
                            "remote": {
                                "transport": "ssh",
                                "reachable": True,
                                "project_path_exists": True,
                                "project_path_writable": True,
                                "logical_cpu_cores": 32,
                                "estimated_idle_cpu_cores": 30,
                                "memory_total_gib": 64,
                                "memory_available_gib": 48,
                                "disk_total_gib": 300,
                                "disk_free_gib": 200,
                                "gpu_count": 1,
                                "gpus": [{"vram_free_gib": 24, "utilization_percent": 0}],
                                "commands": {"python3": "/usr/bin/python3", "nvidia-smi": "/usr/bin/nvidia-smi"},
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            jobs.write_text(
                json.dumps(
                    {
                        "jobs": [
                            {
                                "job_id": "gpu-job",
                                "resources": {
                                    "download_gib": 2,
                                    "ram_gib": 12,
                                    "cpu_cores": 8,
                                    "gpu_count": 1,
                                    "vram_gib": 16,
                                    "compute_minutes": 20,
                                },
                                "required_commands": ["python3", "nvidia-smi"],
                                "data_source": "public",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            result = self.run_cli(
                "fit", "--preflight", str(preflight), "--jobs", str(jobs), "--workspace", str(root)
            )
            self.assertEqual(0, result.returncode, result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue(payload["read_only"])
            self.assertEqual("run_server", payload["jobs"][0]["decision"]["action"])
            self.assertEqual(8, payload["jobs"][0]["required_server_config"]["min_cpu_cores"])

    def test_preflight_command_keeps_local_first_order_and_is_explicit(self) -> None:
        from local_agent_dispatch import cli

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            inventory = root / "hosts.json"
            inventory.write_text('{"hosts": []}\n', encoding="utf-8")

            class Completed:
                returncode = 0
                stdout = json.dumps({"ok": True, "scan_sequence": [{"stage": 1, "name": "local_system"}]})
                stderr = ""

            with mock.patch.object(cli.subprocess, "run", return_value=Completed()) as run:
                code, payload = cli._run_preflight(
                    workspace, inventory, None, None, None, 5.0, True
                )
            self.assertEqual(0, code)
            self.assertEqual("local_system", payload["scan_sequence"][0]["name"])
            argv = run.call_args.args[0]
            self.assertIn("dispatch_preflight_scan.py", argv[1])
            self.assertIn("--skip-antigravity-usage", argv)
            self.assertFalse(payload["model_prompt_sent"])

    def test_preflight_forwards_opencode_usage_controls(self) -> None:
        from local_agent_dispatch import cli

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            inventory = root / "hosts.json"
            inventory.write_text('{"hosts": []}\n', encoding="utf-8")

            class Completed:
                returncode = 0
                stdout = json.dumps({"ok": True})
                stderr = ""

            with mock.patch.object(cli.subprocess, "run", return_value=Completed()) as run:
                code, payload = cli._run_preflight(
                    workspace,
                    inventory,
                    None,
                    None,
                    None,
                    5.0,
                    True,
                    "https://opencode.ai/zen/go/v1/usage",
                    True,
                )
            self.assertEqual(0, code)
            self.assertTrue(payload["ok"])
            argv = run.call_args.args[0]
            self.assertIn("--opencode-go-usage-endpoint", argv)
            self.assertIn("https://opencode.ai/zen/go/v1/usage", argv)
            self.assertIn("--skip-opencode-go-usage", argv)

    def test_bridge_is_dry_run_and_emits_packet(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "task.md").write_text("bounded", encoding="utf-8")
            plan = root / "plan.json"
            jobs = root / "jobs.json"
            state = root / "state.json"
            adapters = root / "adapters.json"
            assignment = {
                "job_id": "job-1",
                "pool_id": "codex.spark",
                "model": "gpt-5.3-codex-spark",
                "variant": "xhigh",
                "execution_host": "local",
                "execution_transport": "local",
                "workload_host": "local",
                "workload_transport": "local",
                "write_scope": "src",
            }
            plan.write_text(json.dumps({"schema_version": 1, "ok": True, "decision": "dispatch", "assignments": [assignment]}), encoding="utf-8")
            jobs.write_text(json.dumps({"jobs": [{
                "job_id": "job-1", "workspace": str(workspace), "prompt_file": str(workspace / "task.md"),
                "result_source_path": str(workspace / "result.txt"), "output_path": str(workspace / "result.txt"),
                "required_artifacts": [str(workspace / "result.txt")], "write_scope": "src",
                "validation_argv": [sys.executable, "-c", "import sys; sys.exit(0)"],
            }]}), encoding="utf-8")
            state.write_text(json.dumps({"schema_version": 1, "workspace": str(workspace), "hosts": {
                "local": {"host_id": "local", "transport": "local", "reachable": True}
            }}), encoding="utf-8")
            adapters.write_text(json.dumps({"codex.spark": {
                "provider": "codex", "adapter": "command", "transport": "local",
                "argv": [sys.executable, "-c", "print('{model}')"],
            }}), encoding="utf-8")
            result = self.run_cli(
                "bridge", "--plan", str(plan), "--jobs", str(jobs), "--state", str(state),
                "--adapters", str(adapters),
            )
            self.assertEqual(0, result.returncode, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual("bridge", payload["command"])
            self.assertTrue(payload["read_only"])
            self.assertEqual("gpt-5.3-codex-spark", payload["packets"][0]["model"])
            db = root / "dispatch.sqlite3"
            enqueue = self.run_cli(
                "bridge",
                "--plan",
                str(plan),
                "--jobs",
                str(jobs),
                "--state",
                str(state),
                "--adapters",
                str(adapters),
                "--enqueue",
                "--db",
                str(db),
            )
            self.assertEqual(0, enqueue.returncode, enqueue.stderr)
            enqueue_payload = json.loads(enqueue.stdout)
            self.assertFalse(enqueue_payload["read_only"])
            self.assertTrue(enqueue_payload["enqueue_performed"])
            self.assertTrue(db.is_file())

    def test_dispatch_enqueue_option_is_explicit_and_provider_free(self) -> None:
        from local_agent_dispatch import cli

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            prompt = workspace / "task.md"
            prompt.write_text("bounded", encoding="utf-8")
            result_path = workspace / "result.txt"
            jobs = root / "jobs.json"
            adapters = root / "adapters.json"
            db = root / "dispatch.sqlite3"
            assignment = {
                "job_id": "dispatch-enqueue",
                "pool_id": "codex.spark",
                "model": "gpt-5.3-codex-spark",
                "variant": "xhigh",
                "execution_host": "local",
                "execution_transport": "local",
                "workload_host": "local",
                "workload_transport": "local",
                "write_scope": "src",
            }
            job = {
                "job_id": "dispatch-enqueue",
                "workspace": str(workspace),
                "prompt_file": str(prompt),
                "result_source_path": str(result_path),
                "output_path": str(result_path),
                "required_artifacts": [str(result_path)],
                "write_scope": "src",
                "validation_argv": [sys.executable, "-c", "import sys; sys.exit(0)"],
            }
            jobs.write_text(json.dumps([job]), encoding="utf-8")
            adapters.write_text(
                json.dumps(
                    {
                        "codex.spark": {
                            "provider": "codex",
                            "adapter": "command",
                            "transport": "local",
                            "argv": [sys.executable, "-c", "print('{model}')"],
                        }
                    }
                ),
                encoding="utf-8",
            )
            report = {
                "schema_version": 1,
                "ok": True,
                "planner": {
                    "schema_version": 1,
                    "ok": True,
                    "decision": "dispatch",
                    "assignments": [assignment],
                    "deferred": [],
                },
                "assignments": [assignment],
                "hosts": {"local": {"host_id": "local", "transport": "local", "reachable": True}},
                "pools": {"codex.spark": {"provider": "codex", "health": "ready"}},
            }
            enqueue = cli._enqueue_dispatch_report(
                report,
                jobs=jobs,
                workspace=workspace,
                preflight=None,
                adapters=adapters,
                db=db,
            )
            self.assertTrue(enqueue["ok"])
            self.assertTrue(enqueue["enqueue_performed"])
            self.assertFalse(enqueue["provider_execution"])
            self.assertTrue(db.is_file())

            parsed = cli.build_parser().parse_args(
                [
                    "dispatch",
                    "--jobs",
                    str(jobs),
                    "--adapters",
                    str(adapters),
                    "--db",
                    str(db),
                    "--enqueue",
                ]
            )
            self.assertTrue(parsed.enqueue)

    def test_plan_command_exposes_rolling_horizon_planner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state.json"
            jobs = root / "jobs.json"
            state.write_text(
                json.dumps(
                    {
                        "pools": {
                            "codex.spark": {
                                "provider": "codex",
                                "health": "ready",
                                "effective_remaining_percent": 90,
                                "reserve_percent": 10,
                                "default_model": "gpt-5.3-codex-spark/xhigh",
                                "max_concurrency": 1,
                                "inflight": 0,
                            }
                        },
                        "compute_hosts": {
                            "local_mac": {
                                "host_id": "local_mac", "transport": "local", "reachable": True,
                                "project_path_exists": True, "project_path_writable": True,
                                "logical_cpu_cores": 8, "estimated_idle_cpu_cores": 8,
                                "memory_total_gib": 16, "memory_available_gib": 12,
                                "disk_total_gib": 100, "disk_free_gib": 50,
                                "gpu_count": 0, "gpus": [], "commands": {},
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            jobs.write_text(
                json.dumps({"jobs": [{
                    "job_id": "plan-job", "task_type": "code", "difficulty": 1,
                    "priority": "normal", "allowed_pools": ["codex.spark"],
                    "write_scope": "src/plan-job",
                    "resource_estimate": {"input_gib": 0, "download_gib": 0,
                        "environment_gib": 0, "temporary_gib": 0, "cache_gib": 0,
                        "output_gib": 0, "ram_gib": 0.5, "cpu_cores": 1,
                        "gpu_count": 0, "vram_gib": 0, "compute_minutes": 1},
                }]}),
                encoding="utf-8",
            )
            result = self.run_cli("plan", "--state", str(state), "--jobs", str(jobs), "--max-lanes", "1")
            self.assertEqual(0, result.returncode, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual("plan", payload["command"])
            self.assertTrue(payload["ok"])
            self.assertEqual("gpt-5.3-codex-spark/xhigh", payload["assignments"][0]["model"])

    def test_monitor_command_is_offline_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "monitor-state.json"
            state.write_text(json.dumps({"project_root": tmp, "workers": []}), encoding="utf-8")
            result = self.run_cli(
                "monitor", "--state", str(state), "--duration-seconds", "0",
                "--interval-seconds", "0.1",
            )
            self.assertEqual(0, result.returncode, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual("monitor", payload["command"])
            self.assertFalse(payload["codex_usage_before"]["ok"])
            self.assertFalse(payload["compute_snapshot_before"]["ok"])

    def test_monitor_state_projects_saved_snapshot_without_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = Path(tmp) / "sqlite-snapshot.json"
            snapshot.write_text(
                json.dumps({"schema_version": 1, "jobs": [], "attempts": [], "leases": []}),
                encoding="utf-8",
            )
            result = self.run_cli("monitor-state", "--snapshot", str(snapshot))
            self.assertEqual(0, result.returncode, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual("monitor-state", payload["command"])
            self.assertEqual("local-agent-dispatch.monitor_state", payload["state_type"])
            self.assertFalse(payload["source"]["prompt_persisted"])

    def test_monitor_timeout_scales_with_requested_window(self) -> None:
        from local_agent_dispatch import cli

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "monitor.json"
            state.write_text(json.dumps({"workers": []}), encoding="utf-8")
            captured: dict[str, float] = {}

            def fake_run(*args, **kwargs):
                captured["timeout_seconds"] = float(kwargs["timeout_seconds"])
                return 0, {"ok": True}

            with mock.patch.object(cli, "_run_json_script", side_effect=fake_run):
                cli._run_monitor(state, 25.0, 1.0, 10.0, False, False)
            self.assertGreaterEqual(captured["timeout_seconds"], 55.0)

    def test_replan_command_is_provider_free_and_reviewable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "monitor.json"
            report.write_text(
                json.dumps({
                    "schema_version": 1,
                    "ok": True,
                    "final_workers": [],
                    "state": {"schema_version": 1, "workers": []},
                    "compute_alerts": [],
                }),
                encoding="utf-8",
            )
            result = self.run_cli("replan", "--monitor-report", str(report))
            self.assertEqual(0, result.returncode, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual("replan", payload["command"])
            self.assertTrue(payload["read_only"])
            self.assertEqual([], payload["provider_invocations"])

    def test_sqlite_backend_is_available_through_lad_surface(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            artifact = workspace / "out.txt"
            packet = root / "packet.json"
            db = root / "dispatch.sqlite3"
            packet.write_text(
                json.dumps({
                    "schema_version": 1,
                    "packet_id": "packet-cli-sqlite",
                    "job_id": "cli-sqlite",
                    "workspace": str(workspace),
                    "write_scope": "artifacts/cli-sqlite",
                    "required_artifacts": [str(artifact)],
                    "validation_required": True,
                    "validation_argv": [sys.executable, "-c", "import pathlib,sys; sys.exit(0 if pathlib.Path('out.txt').exists() else 2)"],
                    "attempts": [{
                        "attempt_id": "attempt-cli-sqlite",
                        "adapter": "command", "transport": "local",
                        "argv": [sys.executable, "-c", "import pathlib; pathlib.Path('out.txt').write_text('ok\\n')"],
                        "result_source_path": str(artifact), "output_path": str(artifact),
                        "model": "gpt-5.3-codex-spark", "pool_id": "codex.spark", "provider": "codex",
                    }],
                }),
                encoding="utf-8",
            )
            enqueue = self.run_cli("enqueue", "--backend", "sqlite", "--db", str(db), "--job-file", str(packet))
            self.assertEqual(0, enqueue.returncode, enqueue.stderr)
            run = self.run_cli("run", "--backend", "sqlite", "--db", str(db), "--workspace", str(workspace), "--once")
            self.assertEqual(0, run.returncode, run.stderr)
            self.assertEqual("completed", json.loads(run.stdout)["results"][0]["status"])
            status = self.run_cli("status", "--backend", "sqlite", "--db", str(db))
            self.assertEqual(0, status.returncode, status.stderr)
            self.assertEqual("completed", json.loads(status.stdout)["snapshot"]["jobs"][0]["status"])

    def test_auto_backend_defaults_to_workspace_sqlite_for_new_queue(self) -> None:
        """A new queue is durable without requiring users to spell out SQLite."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            artifact = workspace / "auto.txt"
            packet = root / "packet.json"
            packet.write_text(
                json.dumps({
                    "schema_version": 1,
                    "packet_id": "packet-cli-auto",
                    "job_id": "cli-auto",
                    "workspace": str(workspace),
                    "write_scope": "artifacts/cli-auto",
                    "required_artifacts": [str(artifact)],
                    "validation_required": True,
                    "validation_argv": [
                        sys.executable, "-c",
                        "import pathlib,sys; sys.exit(0 if pathlib.Path('auto.txt').is_file() else 2)",
                    ],
                    "attempts": [{
                        "attempt_id": "attempt-cli-auto",
                        "adapter": "command", "transport": "local",
                        "argv": [sys.executable, "-c", "import pathlib; pathlib.Path('auto.txt').write_text('ok\\n')"],
                        "result_source_path": str(artifact), "output_path": str(artifact),
                        "model": "gpt-5.6-luna", "pool_id": "codex.luna", "provider": "codex",
                    }],
                }),
                encoding="utf-8",
            )
            enqueue = self.run_cli("enqueue", "--job-file", str(packet))
            self.assertEqual(0, enqueue.returncode, enqueue.stderr)
            enqueue_payload = json.loads(enqueue.stdout)
            self.assertEqual("sqlite", enqueue_payload["backend_resolution"]["selected"])
            db = workspace / ".lad" / "dispatch.sqlite3"
            self.assertTrue(db.is_file())

            run = self.run_cli("run", "--workspace", str(workspace), "--once")
            self.assertEqual(0, run.returncode, run.stderr)
            run_payload = json.loads(run.stdout)
            self.assertEqual("sqlite", run_payload["backend_resolution"]["selected"])
            self.assertEqual("completed", run_payload["results"][0]["status"])

            status = self.run_cli("status", "--workspace", str(workspace))
            self.assertEqual(0, status.returncode, status.stderr)
            status_payload = json.loads(status.stdout)
            self.assertEqual("sqlite", status_payload["backend_resolution"]["selected"])
            self.assertEqual("completed", status_payload["snapshot"]["jobs"][0]["status"])

    def test_auto_backend_preserves_existing_json_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "legacy-run"
            run_dir.mkdir()
            (run_dir / "state.json").write_text(
                json.dumps({
                    "schema_version": 1,
                    "run_id": "legacy",
                    "workspace": str(run_dir),
                    "status": "prepared",
                    "jobs": [],
                }),
                encoding="utf-8",
            )
            result = self.run_cli("status", "--run-dir", str(run_dir))
            self.assertEqual(0, result.returncode, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual("json", payload["backend_resolution"]["selected"])
            self.assertEqual("existing_json_state", payload["backend_resolution"]["reason"])
            self.assertFalse((run_dir / "dispatch.sqlite3").exists())

    def test_auto_status_and_resume_are_read_only_before_initialization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "uninitialized"
            workspace.mkdir()
            db = workspace / ".lad" / "dispatch.sqlite3"
            status = self.run_cli("status", "--workspace", str(workspace))
            self.assertEqual(0, status.returncode, status.stderr)
            status_payload = json.loads(status.stdout)
            self.assertEqual("not_initialized", status_payload["status"])
            self.assertFalse(status_payload["initialized"])
            self.assertFalse(db.exists())

            resume = self.run_cli("resume", "--workspace", str(workspace))
            self.assertEqual(0, resume.returncode, resume.stderr)
            resume_payload = json.loads(resume.stdout)
            self.assertEqual("not_initialized", resume_payload["status"])
            self.assertFalse(resume_payload["initialized"])
            self.assertFalse(db.exists())

    def test_detached_run_persists_pid_and_log_metadata(self) -> None:
        from local_agent_dispatch import cli

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "dispatch.sqlite3"
            log = root / "controller.log"
            pid_file = root / "controller.pid.json"
            args = cli.build_parser().parse_args([
                "run", "--backend", "sqlite", "--db", str(db),
                "--workspace", str(root), "--detach", "--log", str(log),
                "--pid-file", str(pid_file), "--max-idle-rounds", "0",
            ])
            fake_process = type("FakeProcess", (), {"pid": 43210})()
            with mock.patch.object(cli.subprocess, "Popen", return_value=fake_process) as launch:
                payload = cli._start_detached_controller(args)
            self.assertTrue(payload["chat_independent"])
            self.assertEqual(43210, payload["pid"])
            self.assertTrue(pid_file.is_file())
            self.assertTrue(log.is_file())
            command = launch.call_args.args[0]
            self.assertIn("--max-idle-rounds", command)
            self.assertEqual("0", command[command.index("--max-idle-rounds") + 1])

    def test_sqlite_run_forwards_rolling_replan_feedback_options(self) -> None:
        from local_agent_dispatch import cli

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "dispatch.sqlite3"
            feedback = root / "replan.json"
            feedback.write_text(
                json.dumps({"replan_at_utc": "2099-01-01T00:00:00Z"}),
                encoding="utf-8",
            )
            args = cli.build_parser().parse_args([
                "run", "--backend", "sqlite", "--db", str(db),
                "--workspace", str(root), "--once",
                "--idle-backoff-seconds", "7",
                "--replan-feedback", str(feedback),
                "--replan-max-wait-seconds", "42",
            ])
            with (
                mock.patch.object(cli, "_admit_controller_command"),
                mock.patch.object(
                    cli,
                    "_run_sqlite_command",
                    return_value=(0, json.dumps({"ok": True, "results": [], "snapshot": {}}), ""),
                ) as run_controller,
            ):
                self.assertEqual(0, cli._command_run(args))
            command = run_controller.call_args.args[2]
            self.assertEqual(str(feedback.resolve()), command[command.index("--replan-feedback") + 1])
            self.assertEqual("7.0", command[command.index("--idle-backoff-seconds") + 1])
            self.assertEqual("42.0", command[command.index("--replan-max-wait-seconds") + 1])

    def test_run_is_blocked_before_controller_subprocess_when_local_disk_is_unsafe(self) -> None:
        from local_agent_dispatch import cli

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = cli.build_parser().parse_args([
                "run", "--backend", "sqlite", "--db", str(root / "dispatch.sqlite3"),
                "--workspace", str(root), "--once",
            ])
            blocked = {
                "allowed": False,
                "reasons": ["local_controller:free_bytes_below_floor"],
            }
            with mock.patch.object(cli, "_local_launch_admission", return_value=blocked), mock.patch.object(
                cli, "_run_sqlite_command"
            ) as run_controller:
                self.assertEqual(2, cli._command_run(args))
            run_controller.assert_not_called()

    def test_closed_loop_defaults_dry_run_and_fake_alias_executes(self) -> None:
        """The packaged loop consumes only approved packets and never providers."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            prompt = workspace / "task.md"
            artifact = workspace / "artifact.txt"
            prompt.write_text("fake closed loop\n", encoding="utf-8")
            packet = {
                "schema_version": 1,
                "packet_id": "packet-cli-loop",
                "job_id": "cli-loop",
                "pool_id": "fake.pool",
                "model": "fake-model",
                "variant": "max",
                "workspace": str(workspace),
                "write_scope": "artifacts/cli-loop",
                "required_artifacts": [str(artifact)],
                "validation_required": True,
                "validation_argv": [
                    sys.executable,
                    "-c",
                    f"import pathlib,sys; sys.exit(0 if pathlib.Path({str(artifact)!r}).read_text() == 'ok\\n' else 7)",
                ],
                "attempts": [{
                    "attempt_id": "attempt-cli-loop",
                    "adapter": "command",
                    "transport": "local",
                    "provider": "fake",
                    "pool_id": "fake.pool",
                    "model": "fake-model",
                    "variant": "max",
                    "workspace": str(workspace),
                    "prompt_file": str(prompt),
                    "result_source_path": str(artifact),
                    "argv": [
                        sys.executable,
                        "-c",
                        f"import pathlib; pathlib.Path({str(artifact)!r}).write_text('ok\\n')",
                    ],
                    "validation_argv": [
                        sys.executable,
                        "-c",
                        f"import pathlib,sys; sys.exit(0 if pathlib.Path({str(artifact)!r}).read_text() == 'ok\\n' else 7)",
                    ],
                }],
            }
            bundle = root / "approved.json"
            bundle.write_text(
                json.dumps({"schema_version": 1, "mode": "enqueue-ready", "ok": True, "approved": True, "packets": [packet]}),
                encoding="utf-8",
            )

            dry_run = self.run_cli(
                "closed-loop",
                "--approved-packets", str(bundle),
                "--workspace", str(workspace),
            )
            self.assertEqual(0, dry_run.returncode, dry_run.stderr)
            dry_payload = json.loads(dry_run.stdout)
            self.assertEqual("closed-loop", dry_payload["command"])
            self.assertEqual("dry-run", dry_payload["mode"])
            self.assertTrue(dry_payload["read_only"])
            self.assertFalse((root / "dry.sqlite3").exists())

            db = root / "dispatch.sqlite3"
            fake_run = self.run_cli(
                "loop",
                "--approved-packets", str(bundle),
                "--approved",
                "--fake-execute",
                "--db", str(db),
                "--workspace", str(workspace),
            )
            self.assertEqual(0, fake_run.returncode, fake_run.stderr)
            fake_payload = json.loads(fake_run.stdout)
            self.assertEqual("closed-loop", fake_payload["command"])
            self.assertEqual("fake-execute", fake_payload["mode"])
            self.assertEqual(["completed"], fake_payload["execution"]["statuses"])
            self.assertEqual([], fake_payload["provider_invocations"])
            self.assertTrue(db.is_file())
            self.assertEqual("ok\n", artifact.read_text(encoding="utf-8"))
