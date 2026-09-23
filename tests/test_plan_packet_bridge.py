from __future__ import annotations

import pathlib
import json
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import plan_packet_bridge as bridge  # noqa: E402
import continuity_controller as continuity  # noqa: E402
import remote_cli_placement  # noqa: E402


def base_inputs(root: pathlib.Path):
    workspace = root / "workspace"
    workspace.mkdir()
    (workspace / "task.md").write_text("bounded task", encoding="utf-8")
    state = {
        "schema_version": 1,
        "workspace": str(workspace),
        "hosts": {
            "local_mac": {
                "host_id": "local_mac",
                "transport": "local",
                "reachable": True,
            },
            "remote_gpu": {
                "host_id": "remote_gpu",
                "transport": "ssh",
                "reachable": True,
                "project_path": "/srv/project",
            },
        },
    }
    job = {
        "job_id": "job-1",
        "workspace": str(workspace),
        "prompt_file": str(workspace / "task.md"),
        "result_source_path": str(workspace / "result.txt"),
        "output_path": str(workspace / "result.txt"),
        "required_artifacts": [str(workspace / "result.txt")],
        "write_scope": "src",
        "validation_argv": [sys.executable, "-c", "import sys; sys.exit(0)"],
    }
    assignment = {
        "job_id": "job-1",
        "pool_id": "codex.spark",
        "model": "gpt-5.3-codex-spark",
        "variant": "xhigh",
        "execution_host": "local_mac",
        "execution_transport": "local",
        "workload_host": "local_mac",
        "workload_transport": "local",
        "write_scope": "src",
        "resource_request": {"cpu_cores": 1},
    }
    registry = {
        "codex.spark": {
            "provider": "codex",
            "adapter": "command",
            "transport": "local",
            "argv": ["python3", "-c", "print('{model}')"],
        }
    }
    return state, job, assignment, registry


class PlanPacketBridgeTests(unittest.TestCase):
    @staticmethod
    def _foundry_packet(job_id: str, plan_digest: str) -> dict:
        def digest(value):
            return "sha256:" + bridge._canonical_digest(value)

        resource_body = {
            "schema_version": "0.1.0",
            "kind": "resource_request",
            "request_id": "request:repair-001",
            "project_id": "project-alpha",
            "task_profile_digest": digest("task"),
            "cpu_cores": 2,
            "memory_bytes": 1024,
            "disk_bytes": 4096,
            "gpu_count": 0,
            "minimum_gpu_memory_bytes": 0,
            "maximum_wall_seconds": 120,
            "output_path_digest": digest("output"),
        }
        resource_request = {
            **resource_body,
            "request_digest": digest(resource_body),
        }
        quota_body = {
            "schema_version": "0.1.0",
            "kind": "quota_snapshot_receipt",
            "snapshot_id": "quota:repair-001",
            "project_id": "project-alpha",
            "provider": "fixture-provider",
            "exact_model": "gpt-5.3-codex-spark",
            "quota_kind": "not_applicable_zero_model",
            "pool_id": "pool:fixture",
            "remaining_units": 10,
            "reserved_units": 0,
            "reset_at": "2026-08-17T00:00:00Z",
            "observed_at": "2026-08-16T00:00:00Z",
            "maximum_age_seconds": 3600,
            "source_reference": "source:fixture-001",
            "source_receipt_digest": digest("source:fixture-001"),
        }
        quota_snapshot = {
            **quota_body,
            "snapshot_digest": digest(quota_body),
        }
        binding_body = {
            "schema_version": "cpslab_lad_binding/0.1.0",
            "kind": "lad_packet_binding",
            "task_profile_digest": digest("task"),
            "agent_instance_digest": digest("agent"),
            "cps_recipe_digest": digest("recipe"),
            "route_manifest_digest": digest("route"),
            "lane_profile_digest": digest("lane"),
            "resource_request_digest": resource_request["request_digest"],
            "quota_snapshot_digest": quota_snapshot["snapshot_digest"],
            "builder_backend_evidence_digest": digest("builder"),
            "worktree_lease_digest": digest("lease"),
            "worktree_fence": 1,
            "plan_digest": plan_digest,
            "assignment_digest": digest("assignment"),
            "adapter_digest": digest("adapter"),
        }
        binding = {**binding_body, "binding_digest": digest(binding_body)}
        body = {
            "schema_version": "lad_task_packet/2.0.0",
            "kind": "foundry_task_packet",
            "job_id": job_id,
            "exact_model": "gpt-5.3-codex-spark",
            "exact_effort": "xhigh",
            "execution_host_digest": digest("exec-host"),
            "workload_host_digest": digest("work-host"),
            "resource_request": resource_request,
            "quota_snapshot": quota_snapshot,
            "write_scope": ["src/"],
            "validation_command": ["python3", "-m", "unittest"],
            "artifact_path": "artifacts/result.json",
            "result_path": "artifacts/result.json",
            "plan_digest": plan_digest,
            "assignment_digest": digest("assignment"),
            "foundry_binding": binding,
        }
        return {**body, "packet_digest": digest(body)}

    @staticmethod
    def _resign_foundry_packet(packet: dict) -> dict:
        body = {key: value for key, value in packet.items() if key != "packet_digest"}
        packet["packet_digest"] = "sha256:" + bridge._canonical_digest(body)
        return packet

    def test_foundry_binding_passes_through_and_rederives_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            state, job, assignment, registry = base_inputs(root)
            plan_digest = "sha256:" + bridge._canonical_digest({
                "schema_version": 1,
                "ok": True,
                "decision": "dispatch",
                "assignments": [],
            })
            foundry = self._foundry_packet("job-1", plan_digest)
            assignment["foundry_packet"] = foundry
            packet = bridge.assignment_to_packet(
                assignment, job, state, registry, plan_digest=plan_digest
            )
            self.assertEqual(foundry, packet)
            self.assertEqual(foundry["foundry_binding"], packet["foundry_binding"])
            self.assertEqual(foundry["packet_digest"], packet["packet_digest"])

    def test_foundry_packet_tamper_or_plan_transplant_fails_before_enqueue(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            state, job, assignment, registry = base_inputs(root)
            plan_digest = "sha256:" + "a" * 64
            foundry = self._foundry_packet("job-1", plan_digest)
            foundry["exact_model"] = "other-model"
            assignment["foundry_packet"] = foundry
            with self.assertRaisesRegex(bridge.BridgeError, "self-digest"):
                bridge.assignment_to_packet(
                    assignment, job, state, registry, plan_digest=plan_digest
                )
            foundry = self._foundry_packet("job-1", plan_digest)
            assignment["foundry_packet"] = foundry
            with self.assertRaisesRegex(bridge.BridgeError, "plan digest"):
                bridge.assignment_to_packet(
                    assignment, job, state, registry, plan_digest="sha256:" + "b" * 64
                )

    def test_foundry_packet_rejects_resource_digest_transplant(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            state, job, assignment, registry = base_inputs(root)
            foundry = self._foundry_packet("job-1", "sha256:" + "a" * 64)
            foundry["resource_request"]["request_digest"] = "sha256:" + "b" * 64
            assignment["foundry_packet"] = self._resign_foundry_packet(foundry)
            with self.assertRaisesRegex(bridge.BridgeError, "resource request"):
                bridge.assignment_to_packet(
                    assignment, job, state, registry, plan_digest="sha256:" + "a" * 64
                )

    def test_foundry_packet_rejects_quota_model_or_digest_transplant(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            state, job, assignment, registry = base_inputs(root)
            foundry = self._foundry_packet("job-1", "sha256:" + "a" * 64)
            foundry["quota_snapshot"]["exact_model"] = "other-model"
            assignment["foundry_packet"] = self._resign_foundry_packet(foundry)
            with self.assertRaisesRegex(bridge.BridgeError, "quota"):
                bridge.assignment_to_packet(
                    assignment, job, state, registry, plan_digest="sha256:" + "a" * 64
                )

    def test_foundry_packet_rejects_nested_resource_or_quota_extra_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            state, job, assignment, registry = base_inputs(root)
            foundry = self._foundry_packet("job-1", "sha256:" + "a" * 64)
            foundry["quota_snapshot"]["unexpected"] = "must-not-cross-boundary"
            assignment["foundry_packet"] = self._resign_foundry_packet(foundry)
            with self.assertRaisesRegex(bridge.BridgeError, "quota snapshot"):
                bridge.assignment_to_packet(
                    assignment, job, state, registry, plan_digest="sha256:" + "a" * 64
                )

    def test_valid_assignment_keeps_exact_model_and_safe_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            state, job, assignment, registry = base_inputs(pathlib.Path(tmp))
            packet = bridge.assignment_to_packet(
                assignment, job, state, registry, plan_digest="a" * 64
            )
            self.assertEqual("gpt-5.3-codex-spark", packet["model"])
            self.assertEqual("xhigh", packet["variant"])
            self.assertTrue(packet["validation_required"])
            self.assertNotIn("bounded task", repr(packet["attempts"][0]["argv"]))
            self.assertEqual(packet["model"], packet["attempts"][0]["model"])

    def test_remote_cli_marker_requires_attached_placement_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            state, job, assignment, registry = base_inputs(pathlib.Path(tmp))
            registry["codex.spark"]["adapter"] = "remote_cli"
            with self.assertRaisesRegex(bridge.BridgeError, "placement contract is required"):
                bridge.assignment_to_packet(
                    assignment, job, state, registry, plan_digest="a" * 64
                )

    def test_exact_remote_cli_routes_pass_through_plan_bridge(self):
        """The plan bridge admits only an already compiled remote CLI contract."""
        for gemini in (False, True):
            with self.subTest(route="gemini" if gemini else "spark"):
                with tempfile.TemporaryDirectory() as tmp:
                    root = pathlib.Path(tmp)
                    workspace = root / "controller-workspace"
                    workspace.mkdir()
                    (workspace / "task.md").write_text("bounded remote task", encoding="utf-8")
                    suffix = "gemini" if gemini else "spark"
                    pool_id = "antigravity.gemini" if gemini else "codex.spark"
                    provider = "antigravity" if gemini else "codex"
                    model = "gemini-3.6-flash-high" if gemini else "gpt-5.3-codex-spark"
                    variant = None if gemini else "xhigh"
                    cli_name = "agy" if gemini else "codex"
                    remote_workspace = f"/srv/lad/{suffix}-job"
                    write_scope = f"src/{suffix}"
                    assignment = {
                        "job_id": f"{suffix}-job",
                        "attempt_id": f"{suffix}-attempt",
                        "pool_id": pool_id,
                        "provider": provider,
                        "model": model,
                        "variant": variant,
                        "execution_host": "remote-gpu",
                        "execution_transport": "ssh",
                        "workload_host": "remote-gpu",
                        "workload_transport": "ssh",
                        "remote_workspace": remote_workspace,
                        "write_scope": write_scope,
                        "remote_cli_wrapper": {
                            "name": f"{suffix}-remote-cli-wrapper",
                            "version": "0.1.0",
                            "sha256": "a" * 64,
                            "mode": "dry-run",
                        },
                        "receipt_path": f"{remote_workspace}/.lad/receipts/{suffix}.json",
                    }
                    host = {
                        "host_id": "remote-gpu",
                        "transport": "ssh",
                        "project_path": "/srv/lad",
                        "remote_cli": {
                            "name": cli_name,
                            "path": "/opt/agy/bin/agy" if gemini else "/usr/local/bin/codex",
                            "version": "1.0.0",
                            "install_state": "installed",
                            "auth": {
                                "state": "authenticated",
                                "scope": "remote_host",
                                "host_id": "remote-gpu",
                                "observed_at_utc": "2026-08-15T08:00:00+00:00",
                                "ttl_seconds": 600,
                                "source": "authenticated status",
                            },
                        },
                    }
                    route = {
                        "provider": "racknerd",
                        "kind": "execution",
                        "status": "verified",
                        "verified": True,
                        "target_host_id": "remote-gpu",
                        "egress_ip": "192.0.2.44",
                        "observed_at_utc": "2026-08-15T08:00:00+00:00",
                        "ttl_seconds": 300,
                        "source": "codex-racknerd-route verify",
                        "project_path": "/srv/lad",
                    }
                    contract = remote_cli_placement.build_remote_cli_contract(
                        assignment, host, route, now_utc="2026-08-15T08:00:00+00:00"
                    )
                    self.assertTrue(contract["valid"], contract)
                    job = {
                        "job_id": assignment["job_id"],
                        "workspace": str(workspace),
                        "remote_required_artifacts": ["out/result.json"],
                        "remote_result_source_path": "out/result.json",
                        "remote_prompt_file": "TASK.md",
                        "write_scope": write_scope,
                        "validation_argv": ["python3", "-m", "unittest"],
                    }
                    state = {
                        "schema_version": 1,
                        "workspace": str(workspace),
                        "hosts": {"remote-gpu": {**host, "reachable": True}},
                    }
                    registry = {
                        pool_id: {
                            "provider": provider,
                            "adapter": "remote_cli",
                            "transport": "ssh",
                        }
                    }
                    # Exercise the job-side contract handoff for Gemini and
                    # assignment-side handoff for Spark.
                    if gemini:
                        job["remote_cli_placement"] = contract
                    else:
                        assignment["remote_cli_placement"] = contract
                    packet = bridge.assignment_to_packet(
                        assignment, job, state, registry, plan_digest="a" * 64
                    )
                    self.assertEqual("remote_cli", packet["attempts"][0]["adapter"])
                    self.assertEqual("ssh", packet["execution_transport"])
                    self.assertEqual(remote_workspace, packet["workspace"])
                    self.assertEqual(write_scope, packet["write_scope"])
                    self.assertEqual(model, packet["model"])
                    self.assertEqual(variant, packet["variant"])
                    self.assertFalse(packet["provider_execution"])
                    self.assertFalse(packet["model_prompts_sent"])
                    self.assertFalse(packet["ssh_prompt_sent"])
                    self.assertEqual(
                        contract["contract"]["contract_digest"],
                        packet["remote_cli_placement"]["contract_digest"],
                    )
                    self.assertEqual("strict", continuity.validate_task_packet(packet)["mode"])

    def test_bridge_enqueue_rejects_tampered_remote_cli_contract_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            packet = {
                "schema_version": 1,
                "job_id": "tampered-remote",
                "attempts": [{"adapter": "remote_cli"}],
                "remote_cli_placement": {"contract_digest": "0" * 64},
            }
            result = bridge.enqueue_packets(
                {"mode": "enqueue-ready", "ok": True, "packets": [packet]},
                root / "dispatch.sqlite3",
            )
            self.assertFalse(result["ok"])
            self.assertIn("contract digest mismatch", result["errors"][0]["error"])
            self.assertFalse((root / "dispatch.sqlite3").exists())

    def test_codex_luna_policy_is_carried_into_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            state, job, assignment, registry = base_inputs(pathlib.Path(tmp))
            assignment.update(
                pool_id="codex.luna",
                model="gpt-5.6-luna",
                variant="max",
            )
            registry["codex.luna"] = {
                "provider": "codex",
                "adapter": "command",
                "transport": "local",
                "argv": ["python3", "-c", "print('{model}')"],
            }
            packet = bridge.assignment_to_packet(
                assignment,
                job,
                state,
                registry,
                plan_digest="a" * 64,
                model_policy="codex-luna-max",
            )
            self.assertEqual("codex-luna-max", packet["model_policy"])

    def test_spark_gemini_policy_is_carried_into_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            state, job, assignment, registry = base_inputs(pathlib.Path(tmp))
            packet = bridge.assignment_to_packet(
                assignment,
                job,
                state,
                registry,
                plan_digest="a" * 64,
                model_policy="codex-spark-antigravity-gemini",
            )
            self.assertEqual(
                "codex-spark-antigravity-gemini", packet["model_policy"]
            )

    def test_split_desktop_workload_fails_closed_without_wrapper(self):
        with tempfile.TemporaryDirectory() as tmp:
            state, job, assignment, registry = base_inputs(pathlib.Path(tmp))
            assignment["workload_host"] = "remote_gpu"
            assignment["workload_transport"] = "ssh"
            with self.assertRaisesRegex(bridge.BridgeError, "split_placement_requires_remote_wrapper"):
                bridge.assignment_to_packet(
                    assignment, job, state, registry, plan_digest="b" * 64
                )

    def test_path_escape_and_missing_adapter_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            state, job, assignment, registry = base_inputs(pathlib.Path(tmp))
            job["prompt_file"] = str(pathlib.Path(job["workspace"]) / ".." / "outside.md")
            with self.assertRaisesRegex(bridge.BridgeError, "prompt_file: path escapes workspace"):
                bridge.assignment_to_packet(
                    assignment, job, state, registry, plan_digest="c" * 64
                )
            job["prompt_file"] = str(pathlib.Path(job["workspace"]) / "task.md")
            with self.assertRaisesRegex(bridge.BridgeError, "missing adapter contract"):
                bridge.assignment_to_packet(
                    assignment, job, state, {}, plan_digest="c" * 64
                )

    def test_bridge_report_is_dry_run_and_preserves_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            state, job, assignment, registry = base_inputs(pathlib.Path(tmp))
            plan = {
                "schema_version": 1,
                "ok": True,
                "decision": "dispatch",
                "assignments": [assignment, {"job_id": "unknown", "model": "x", "pool_id": "codex.spark"}],
            }
            report = bridge.bridge_plan(plan, [job], state, registry)
            self.assertFalse(report["ok"])
            self.assertTrue(report["read_only"])
            self.assertEqual(1, len(report["packets"]))
            self.assertEqual("unknown", report["errors"][0]["job_id"])

    def test_explicit_sqlite_enqueue_is_separate_from_dry_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            state, job, assignment, registry = base_inputs(root)
            plan = {
                "schema_version": 1,
                "ok": True,
                "decision": "dispatch",
                "assignments": [assignment],
            }
            db = root / "dispatch.sqlite3"
            dry_run = bridge.bridge_plan(plan, [job], state, registry)
            self.assertTrue(dry_run["ok"])
            self.assertTrue(dry_run["read_only"])
            self.assertFalse(db.exists())

            ready = bridge.bridge_plan(plan, [job], state, registry, mode="enqueue-ready")
            self.assertTrue(ready["ok"])
            self.assertTrue(ready["read_only"])
            self.assertFalse(db.exists())

            result = bridge.enqueue_packets(ready, db)
            self.assertTrue(result["ok"])
            self.assertTrue(result["enqueue_performed"])
            self.assertFalse(result["provider_execution"])
            self.assertEqual(["job-1"], [row["job_id"] for row in result["jobs"]])
            self.assertTrue(db.is_file())

            # The audit response is intentionally a summary, not a copy of
            # packet attempts, prompt paths, or command argv.
            self.assertNotIn("argv", repr(result))
            self.assertNotIn("bounded task", repr(result))

    def test_server_local_ssh_packet_uses_remote_workspace_and_host_validator(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "controller-workspace"
            workspace.mkdir()
            state = {
                "schema_version": 1,
                "workspace": str(workspace),
                "hosts": {
                    "remote-a": {
                        "host_id": "remote-a",
                        "transport": "ssh",
                        "reachable": True,
                        "project_path": "/srv/local-agent-dispatch",
                    }
                },
            }
            job = {
                "job_id": "remote-job",
                "workspace": str(workspace),
                "remote_workspace": "/srv/local-agent-dispatch/remote-job",
                "remote_prompt_file": "TASK.md",
                "remote_required_artifacts": ["out/result.txt"],
                "remote_result_source_path": "out/result.txt",
                "write_scope": "src",
                "validation_argv": ["python3", "-m", "unittest"],
            }
            assignment = {
                "job_id": "remote-job",
                "pool_id": "server_local.remote-a",
                "model": "qwen2.5-coder-14b-awq",
                "variant": "max",
                "execution_host": "remote-a",
                "execution_transport": "ssh",
                "workload_host": "remote-a",
                "workload_transport": "ssh",
                "write_scope": "src",
            }
            registry = {
                "server_local.remote-a": {
                    "provider": "server_local",
                    "adapter": "server_local",
                    "transport": "ssh",
                    "argv": [
                        "/opt/venvs/aider/bin/aider",
                        "--model", "openai/{model}",
                        "--message-file", "{workspace}/TASK.md",
                    ],
                }
            }
            packet = bridge.assignment_to_packet(
                assignment, job, state, registry, plan_digest="d" * 64
            )
            self.assertEqual("/srv/local-agent-dispatch/remote-job", packet["workspace"])
            self.assertEqual(["/srv/local-agent-dispatch/remote-job/out/result.txt"], packet["required_artifacts"])
            self.assertEqual("python3", packet["validation_argv"][0])
            attempt = packet["attempts"][0]
            self.assertEqual("ssh", attempt["transport"])
            self.assertEqual("/srv/local-agent-dispatch/remote-job", attempt["workspace"])
            self.assertIn("/srv/local-agent-dispatch/remote-job/TASK.md", attempt["argv"])
            self.assertIsNone(attempt["output_path"])
            result = bridge.enqueue_packets(
                {"mode": "enqueue-ready", "ok": True, "packets": [packet]},
                root / "dispatch.sqlite3",
            )
            self.assertTrue(result["ok"])
            self.assertTrue(result["jobs"][0]["transport_outbox"])
            from sqlite_store import SQLiteStore
            with SQLiteStore(root / "dispatch.sqlite3") as store:
                outbox = store.list_transport_outbox(statuses=("pending",))
                self.assertEqual(1, len(outbox))
                self.assertEqual("max", outbox[0]["envelope"]["payload_summary"]["variant"])

    def test_remote_resource_evidence_is_projected_and_secret_fields_are_dropped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            state, job, assignment, registry = base_inputs(root)
            state["hosts"] = {
                "remote": {
                    "host_id": "remote",
                    "transport": "ssh",
                    "reachable": True,
                    "project_path": "/srv/project",
                }
            }
            job.update(
                remote_workspace="/srv/project/job",
                remote_prompt_file="TASK.md",
                remote_required_artifacts=["out/result.txt"],
                remote_result_source_path="out/result.txt",
                write_scope="out/job",
                validation_argv=["python3", "-m", "unittest"],
            )
            assignment.update(
                pool_id="server_local.remote",
                model="server/local",
                variant="bounded",
                execution_host="remote",
                workload_host="remote",
                execution_transport="ssh",
                workload_transport="ssh",
                write_scope="out/job",
                remote_resource_evidence={
                    "schema_version": 1,
                    "host_id": "remote",
                    "observed_at_utc": "2026-08-14T01:00:00+00:00",
                    "ttl_seconds": 1800,
                    "cgroup": {
                        "status": "complete",
                        "max_bytes": 16 * 1024**3,
                        "current_bytes": 4 * 1024**3,
                        "available_bytes": 12 * 1024**3,
                        "command": "must-not-persist",
                    },
                    "psi": {"some_avg10": 1.0},
                    "storage": {
                        "mount_path": "/srv",
                        "workspace_path": "/srv/project/job",
                        "writable": True,
                        "total_bytes": 100 * 1024**3,
                        "free_bytes": 20 * 1024**3,
                    },
                    "route": {
                        "kind": "workload",
                        "status": "direct",
                        "verified": True,
                        "target_host_id": "remote",
                    },
                    "capacity": {
                        "cpu_cores": 8,
                        "ram_gib": 12,
                        "gpu_count": 0,
                        "vram_gib_per_gpu": 0,
                        "new_disk_gib": 20,
                    },
                    "write_scope_path": "/srv/project/job/out/job",
                    "secret_token": "must-not-persist",
                },
            )
            registry["server_local.remote"] = {
                "provider": "server_local",
                "adapter": "server_local",
                "transport": "ssh",
                "argv": ["aider", "--model", "{model}"],
            }
            packet = bridge.assignment_to_packet(
                assignment, job, state, registry, plan_digest="r" * 64
            )
            evidence = packet["remote_resource_evidence"]
            self.assertEqual("remote", evidence["host_id"])
            self.assertNotIn("secret_token", repr(packet))
            self.assertNotIn("command", repr(packet))
            self.assertEqual("/srv/project/job/out/job", evidence["write_scope_path"])

    def test_malformed_allowlisted_children_cannot_smuggle_raw_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            state, job, assignment, registry = base_inputs(root)
            state["hosts"] = {
                "remote": {
                    "host_id": "remote",
                    "transport": "ssh",
                    "reachable": True,
                    "project_path": "/srv/project",
                }
            }
            job.update(
                remote_workspace="/srv/project/job",
                remote_prompt_file="TASK.md",
                remote_required_artifacts=["out/result.txt"],
                remote_result_source_path="out/result.txt",
                write_scope="out/job",
                validation_argv=["python3", "-m", "unittest"],
            )
            assignment.update(
                pool_id="server_local.remote",
                model="server/local",
                variant="bounded",
                execution_host="remote",
                workload_host="remote",
                execution_transport="ssh",
                workload_transport="ssh",
                write_scope="out/job",
                remote_resource_evidence={
                    "schema_version": 1,
                    "host_id": "remote",
                    "observed_at_utc": "2026-08-14T01:00:00+00:00",
                    "ttl_seconds": 1800,
                    "cgroup": [{"command": "secret-command", "argv": ["token"]}],
                    "psi": {"some_avg10": "secret-token"},
                    "storage": {
                        "mount_path": "/srv",
                        "workspace_path": "/srv/project/job",
                        "writable": True,
                        "total_bytes": 100 * 1024**3,
                        "free_bytes": 20 * 1024**3,
                    },
                    "route": {
                        "kind": "workload",
                        "status": "direct",
                        "verified": True,
                        "target_host_id": "remote",
                    },
                    "capacity": {
                        "cpu_cores": 8,
                        "ram_gib": 12,
                        "gpu_count": 0,
                        "vram_gib_per_gpu": 0,
                        "new_disk_gib": 20,
                    },
                    "write_scope_path": "/srv/project/job/out/job",
                },
            )
            registry["server_local.remote"] = {
                "provider": "server_local",
                "adapter": "server_local",
                "transport": "ssh",
                "argv": ["aider", "--model", "{model}"],
            }
            packet = bridge.assignment_to_packet(
                assignment, job, state, registry, plan_digest="m" * 64
            )
            evidence = packet["remote_resource_evidence"]
            self.assertEqual({}, evidence["cgroup"])
            self.assertEqual({}, evidence["psi"])
            self.assertNotIn("secret-command", repr(packet))
            self.assertNotIn("secret-token", repr(packet))
            self.assertNotIn("must-not-persist", repr(evidence))

    def test_capacity_aliases_are_canonicalized_before_remote_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            state, job, assignment, registry = base_inputs(root)
            state["hosts"] = {
                "remote": {
                    "host_id": "remote",
                    "transport": "ssh",
                    "reachable": True,
                    "project_path": "/srv/project",
                }
            }
            job.update(
                remote_workspace="/srv/project/job",
                remote_prompt_file="TASK.md",
                remote_required_artifacts=["out/result.txt"],
                remote_result_source_path="out/result.txt",
                write_scope="out/job",
                validation_argv=["python3", "-m", "unittest"],
            )
            assignment.update(
                pool_id="server_local.remote",
                model="server/local",
                variant="bounded",
                execution_host="remote",
                workload_host="remote",
                execution_transport="ssh",
                workload_transport="ssh",
                write_scope="out/job",
                resource_request={"cpu_cores": 1, "ram_gib": 2, "disk_gib": 1},
                remote_resource_evidence={
                    "schema_version": 1,
                    "host_id": "remote",
                    "observed_at_utc": "2026-08-14T01:00:00+00:00",
                    "ttl_seconds": 1800,
                    "cgroup": {
                        "status": "complete",
                        "max_bytes": 16 * 1024**3,
                        "current_bytes": 4 * 1024**3,
                        "available_bytes": 12 * 1024**3,
                    },
                    "psi": {"some_avg10": 1.0},
                    "storage": {
                        "mount_path": "/srv",
                        "workspace_path": "/srv/project/job",
                        "writable": True,
                        "total_bytes": 100 * 1024**3,
                        "free_bytes": 20 * 1024**3,
                    },
                    "route": {
                        "kind": "workload",
                        "status": "direct",
                        "verified": True,
                        "target_host_id": "remote",
                    },
                    "capacity": {
                        "cpu_cores": 8,
                        "ram_gib": 12,
                        "gpu_count": 0,
                        "vram_gib": 0,
                        "disk_gib": 20,
                    },
                    "write_scope_path": "/srv/project/job/out/job",
                },
            )
            registry["server_local.remote"] = {
                "provider": "server_local",
                "adapter": "server_local",
                "transport": "ssh",
                "argv": ["aider", "--model", "{model}"],
            }
            packet = bridge.assignment_to_packet(
                assignment, job, state, registry, plan_digest="a" * 64
            )
            capacity = packet["remote_resource_evidence"]["capacity"]
            self.assertEqual(0, capacity["vram_gib_per_gpu"])
            self.assertEqual(20, capacity["new_disk_gib"])
            self.assertNotIn("vram_gib", capacity)
            self.assertNotIn("disk_gib", capacity)

    def test_capacity_receipt_and_verification_marker_are_allowlisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            state, job, assignment, registry = base_inputs(root)
            state["hosts"] = {
                "remote": {
                    "host_id": "remote",
                    "transport": "ssh",
                    "reachable": True,
                    "project_path": "/srv/project",
                }
            }
            job.update(
                remote_workspace="/srv/project/job",
                remote_prompt_file="TASK.md",
                remote_required_artifacts=["out/result.txt"],
                remote_result_source_path="out/result.txt",
                write_scope="out/job",
                validation_argv=["python3", "-m", "unittest"],
            )
            assignment.update(
                pool_id="server_local.remote",
                model="server/local",
                variant="bounded",
                execution_host="remote",
                workload_host="remote",
                execution_transport="ssh",
                workload_transport="ssh",
                write_scope="out/job",
                remote_resource_evidence={
                    "schema_version": 1,
                    "host_id": "remote",
                    "observed_at_utc": "2026-08-14T01:00:00+00:00",
                    "ttl_seconds": 1800,
                },
                remote_resource_evidence_verified=True,
                resource_request_digest="sha256:" + "e" * 64,
            )
            receipt_body = {
                "schema_version": "0.1.0",
                "kind": "server_capacity_receipt",
                "host_identity_digest": "sha256:" + "a" * 64,
                "project_path_digest": "sha256:" + "b" * 64,
                "output_path_digest": "sha256:" + "c" * 64,
                "runtime_digest": "sha256:" + "d" * 64,
                "resource_request_digest": "sha256:" + "e" * 64,
                "available_disk_bytes": 100,
                "required_disk_bytes": 1,
                "available_memory_bytes": 100,
                "required_memory_bytes": 1,
                "gpu_inventory_digest": "sha256:" + "f" * 64,
                "writable_probe_digest": "sha256:" + "1" * 64,
                "observed_at": "2026-08-14T01:00:00Z",
                "maximum_age_seconds": 300,
            }
            assignment["capacity_receipt"] = {
                **receipt_body,
                "receipt_digest": "sha256:" + "2" * 64,
                "argv": "must-not-persist",
                "credential": "must-not-persist",
            }
            registry["server_local.remote"] = {
                "provider": "server_local",
                "adapter": "server_local",
                "transport": "ssh",
                "argv": ["aider", "--model", "{model}"],
            }
            packet = bridge.assignment_to_packet(
                assignment, job, state, registry, plan_digest="n" * 64
            )
            self.assertEqual(set(receipt_body) | {"receipt_digest"}, set(packet["capacity_receipt"]))
            self.assertTrue(packet["remote_resource_evidence_verified"])
            self.assertNotIn("must-not-persist", repr(packet))

    def test_remote_resource_evidence_is_derived_only_from_verified_host_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            state, job, assignment, registry = base_inputs(root)
            state["hosts"] = {
                "remote": {
                    "host_id": "remote",
                    "transport": "ssh",
                    "reachable": True,
                    "project_path": "/srv/project",
                    "last_probed_at_utc": "2026-08-14T01:00:00+00:00",
                    "cgroup_memory_evidence_status": "complete",
                    "cgroup_memory_max_bytes": 16 * 1024**3,
                    "cgroup_memory_current_bytes": 4 * 1024**3,
                    "cgroup_memory_available_bytes": 12 * 1024**3,
                    "psi_some_avg10": 1.0,
                    "logical_cpu_cores": 8,
                    "estimated_idle_cpu_cores": 6,
                    "gpu_count": 0,
                    "storage_paths": [{
                        "path": "/srv",
                        "mount_path": "/srv",
                        "writable": True,
                        "disk_total_gib": 100,
                        "disk_free_gib": 20,
                    }],
                    "route_evidence": {
                        "provider": "racknerd",
                        "kind": "workload",
                        "status": "verified",
                        "verified": True,
                        "target_host_id": "remote",
                    },
                }
            }
            job.update(
                remote_workspace="/srv/project/job",
                remote_prompt_file="TASK.md",
                remote_required_artifacts=["out/result.txt"],
                remote_result_source_path="out/result.txt",
                write_scope="out/job",
                validation_argv=["python3", "-m", "unittest"],
            )
            assignment.update(
                pool_id="server_local.remote",
                model="server/local",
                variant="bounded",
                execution_host="remote",
                workload_host="remote",
                execution_transport="ssh",
                workload_transport="ssh",
                write_scope="out/job",
                resource_request={"cpu_cores": 1, "ram_gib": 2, "new_disk_gib": 1},
            )
            registry["server_local.remote"] = {
                "provider": "server_local",
                "adapter": "server_local",
                "transport": "ssh",
                "argv": ["aider", "--model", "{model}"],
            }
            packet = bridge.assignment_to_packet(
                assignment, job, state, registry, plan_digest="r" * 64
            )
            self.assertEqual("remote", packet["remote_resource_evidence"]["host_id"])
            self.assertEqual("direct", packet["remote_resource_evidence"]["route"]["status"])
            self.assertEqual("/srv/project/job/out/job", packet["remote_resource_evidence"]["write_scope_path"])

            state["hosts"]["remote"].pop("route_evidence")
            packet_without_route = bridge.assignment_to_packet(
                assignment, job, state, registry, plan_digest="s" * 64
            )
            self.assertNotIn("remote_resource_evidence", packet_without_route)

    def test_server_local_ssh_rejects_local_absolute_validator(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            state, job, assignment, _ = base_inputs(pathlib.Path(tmp))
            state["hosts"] = {
                "remote": {
                    "host_id": "remote", "transport": "ssh", "reachable": True,
                    "project_path": "/srv/project",
                }
            }
            job.update(
                remote_workspace="/srv/project/job",
                remote_prompt_file="TASK.md",
                remote_required_artifacts=["out/result.txt"],
                remote_result_source_path="out/result.txt",
                validation_argv=[sys.executable, "-m", "unittest"],
            )
            assignment.update(
                pool_id="server_local.remote", model="qwen2.5-coder-14b-awq",
                execution_host="remote", workload_host="remote",
                execution_transport="ssh", workload_transport="ssh",
            )
            registry = {
                "server_local.remote": {
                    "provider": "server_local", "adapter": "server_local", "transport": "ssh",
                    "argv": ["aider", "--model", "{model}"],
                }
            }
            with self.assertRaisesRegex(bridge.BridgeError, "remote validation"):
                bridge.assignment_to_packet(
                    assignment, job, state, registry, plan_digest="e" * 64
                )

    def test_server_openai_ssh_keeps_local_prompt_and_fences_remote_artifacts(self):
        """The controller prompt stays local while the result lives on SSH host."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "controller-workspace"
            workspace.mkdir()
            prompt = workspace / "task.md"
            prompt.write_text("remote loopback task", encoding="utf-8")
            state = {
                "schema_version": 1,
                "workspace": str(workspace),
                "hosts": {
                    "remote-a": {
                        "host_id": "remote-a",
                        "transport": "ssh",
                        "reachable": True,
                        "project_path": "/srv/project",
                        "hostname": "remote-a.example.test",
                        "port": 22,
                        "user": "runner",
                    }
                },
            }
            job = {
                "job_id": "remote-openai-job",
                "workspace": str(workspace),
                "prompt_file": str(prompt),
                "remote_workspace": "/srv/project/job",
                "remote_required_artifacts": ["out/result.txt"],
                "remote_result_source_path": "out/result.txt",
                "write_scope": "out/remote-openai-job",
                "validation_argv": ["python3", "-c", "print('validate')"],
            }
            assignment = {
                "job_id": "remote-openai-job",
                "pool_id": "server_openai.remote-a",
                "model": "qwen2.5-coder-14b-awq",
                "variant": None,
                "execution_host": "remote-a",
                "execution_transport": "ssh",
                "workload_host": "remote-a",
                "workload_transport": "ssh",
                "write_scope": "out/remote-openai-job",
            }
            registry = {
                "server_openai.remote-a": {
                    "provider": "server_openai",
                    "adapter": "server_openai",
                    "transport": "ssh",
                    "base_url": "http://127.0.0.1:8000/v1",
                }
            }
            packet = bridge.assignment_to_packet(
                assignment, job, state, registry, plan_digest="f" * 64
            )
            self.assertEqual("strict", continuity.validate_task_packet(packet)["mode"])
            self.assertTrue(packet["workspace"].startswith(str(workspace.resolve())))
            self.assertEqual("/srv/project/job", packet["remote_workspace"])
            self.assertEqual(["/srv/project/job/out/result.txt"], packet["required_artifacts"])
            attempt = packet["attempts"][0]
            self.assertEqual(str(prompt.resolve()), attempt["prompt_file"])
            self.assertEqual("/srv/project/job", attempt["remote_workspace"])
            self.assertEqual("/srv/project/job/out/result.txt", attempt["remote_result_source_path"])
            self.assertIsNone(attempt["output_path"])
            argv, cwd, output_path, stdin_payload = continuity.build_attempt(
                job, attempt, state, state["hosts"]
            )
            self.assertTrue(argv[-1] == "python3 -")
            self.assertIsNone(cwd)
            self.assertIsNone(output_path)
            self.assertIn("/srv/project/job/out/result.txt", stdin_payload or "")


if __name__ == "__main__":
    unittest.main()
