from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone


DISPATCH_ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


continuity = load_module(
    "dispatch_gate_d0_continuity",
    DISPATCH_ROOT / "scripts" / "continuity_controller.py",
)
planner = load_module(
    "dispatch_gate_d0_planner",
    DISPATCH_ROOT / "scripts" / "dynamic_dispatch_planner.py",
)
preflight = load_module(
    "dispatch_gate_d0_preflight",
    DISPATCH_ROOT / "scripts" / "dispatch_preflight_scan.py",
)


def host(
    host_id: str,
    transport: str,
    *,
    gpu_count: int = 0,
    load1: float = 0.0,
    logical_cpu_cores: int = 10,
) -> dict:
    gpus = (
        [{"index": 0, "name": "Apple GPU", "unified_memory": True}]
        if gpu_count
        else []
    )
    return {
        "host_id": host_id,
        "transport": transport,
        "reachable": True,
        "project_path_exists": True,
        "project_path_writable": True,
        "project_path": "/tmp/agent-swarm",
        "logical_cpu_cores": logical_cpu_cores,
        "estimated_idle_cpu_cores": logical_cpu_cores,
        "memory_total_gib": 64,
        "memory_available_gib": 48,
        "disk_total_gib": 512,
        "disk_free_gib": 256,
        "gpu_count": gpu_count,
        "gpus": gpus,
        "load1": load1,
        "commands": {},
        "tags": ["local", "apple"] if transport == "local" else ["remote", "direct-link"],
    }


def ready_pool(pool_id: str) -> dict:
    models = {
        "codex.luna": "gpt-5.6-luna/max",
        "codex.spark": "gpt-5.3-codex-spark/xhigh",
        "cursor.composer_grok": "composer-2.5-fast",
        "antigravity.gemini": "gemini-3.6-flash-high",
        "opencode.go": "opencode-go/mimo-v2.5",
    }
    provider = pool_id.split(".", 1)[0]
    return {
        "provider": provider,
        "health": "ready",
        "effective_remaining_percent": 90,
        "reserve_percent": 10,
        "default_model": models[pool_id],
        "max_concurrency": 1,
        "inflight": 0,
    }


def tiny_job(job_id: str, pool_id: str) -> dict:
    return {
        "job_id": job_id,
        "task_type": "text",
        "difficulty": 1,
        "priority": "normal",
        "allowed_pools": [pool_id],
        "write_scope": f"isolated/{job_id}",
        "resource_estimate": {
            "input_gib": 0,
            "download_gib": 0,
            "environment_gib": 0,
            "temporary_gib": 0,
            "cache_gib": 0,
            "output_gib": 0,
            "ram_gib": 0.5,
            "cpu_cores": 1,
            "gpu_count": 0,
            "vram_gib": 0,
            "compute_minutes": 0,
        },
    }


class LocalSystemMergeTests(unittest.TestCase):
    def _snapshot(self, *, load_1m: float | None, memory: bool = True) -> dict:
        return {
            "ok": True,
            "os": {"name": "Darwin"},
            "arch": "arm64",
            "cpu": {
                "logical_cores": 10,
                "physical_cores": 10,
                "load_1m": load_1m,
                "load_source": "test",
            },
            "ram": {
                "total_gib": 32 if memory else None,
                "available_gib": 8 if memory else None,
            },
            "disks": {
                "workspace": {
                    "exists": True,
                    "writable": True,
                    "total_bytes": 100 * 1024**3 if memory else None,
                    "free_bytes": 5 * 1024**3 if memory else None,
                }
            },
            "accelerators": [],
            "clis": {},
            "python": {},
        }

    def test_local_system_host_uses_load_average_for_idle_capacity(self):
        with tempfile.TemporaryDirectory() as tmp:
            row = preflight.local_system_host(
                self._snapshot(load_1m=2.5), pathlib.Path(tmp)
            )
        self.assertEqual(7.5, row["estimated_idle_cpu_cores"])
        self.assertEqual(2.5, row["load1"])

    def test_unknown_live_capacity_does_not_reuse_inventory_capacity(self):
        stale = {
            "stale-local": {
                "host_id": "stale-local",
                "transport": "local",
                "logical_cpu_cores": 64,
                "estimated_idle_cpu_cores": 64,
                "memory_available_gib": 512,
                "disk_free_gib": 1000,
                "commands": {"codex": "/old/codex"},
                "tags": ["private-inventory"],
                "probe_failure_code": "compute_probe_timeout",
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            merged = preflight.merge_local_system_compute_host(
                stale, self._snapshot(load_1m=None, memory=False), pathlib.Path(tmp)
            )
        row = merged["stale-local"]
        self.assertIsNone(row["estimated_idle_cpu_cores"])
        self.assertIsNone(row["memory_available_gib"])
        self.assertEqual({}, row["commands"])
        self.assertEqual(["private-inventory"], row["tags"])
        self.assertNotIn("probe_failure_code", row)


class FinalOutputCaptureTests(unittest.TestCase):
    def _run_job(self, script: str, *, result_source_name: str = "final.txt"):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        workspace = root / "workspace"
        workspace.mkdir()
        run_dir = root / "run"
        run_dir.mkdir()
        inventory = root / "hosts.json"
        inventory.write_text('{"hosts": []}\n', encoding="utf-8")
        destination = workspace / "required.md"
        result_source = workspace / result_source_name
        runtime_state = root / "runtime-state.json"
        job = {
            "job_id": "clean-output",
            "workspace": str(workspace),
            "required_artifacts": [str(destination)],
            "attempts": [
                {
                    "attempt_id": "command-1",
                    "adapter": "command",
                    "transport": "local",
                    "argv": [sys.executable, "-c", script],
                    "result_source_path": str(result_source),
                    "output_path": str(destination),
                    "pool_id": "codex.spark",
                    "provider": "codex",
                    "model": "gpt-5.3-codex-spark",
                    "runtime_state_path": str(runtime_state),
                }
            ],
        }
        state = {
            "workspace": str(workspace),
            "inventory": str(inventory),
            "runtime_state": str(runtime_state),
            "jobs": [job],
        }
        continuity.atomic_write(run_dir / "state.json", state)
        continuity.run_job(run_dir, job, state, {})
        return job, destination, run_dir / "logs" / "clean-output.command-1.log"

    def test_result_source_keeps_raw_trace_out_of_required_artifact(self):
        script = (
            "import pathlib; "
            "print('MCP TRACE ' * 100); "
            "pathlib.Path('final.txt').write_text('FINAL ANSWER\\n', encoding='utf-8')"
        )
        job, destination, log_path = self._run_job(script)
        self.assertEqual("completed", job["status"])
        self.assertEqual("FINAL ANSWER\n", destination.read_text(encoding="utf-8"))
        self.assertIn("MCP TRACE", log_path.read_text(encoding="utf-8"))
        self.assertNotIn("MCP TRACE", destination.read_text(encoding="utf-8"))

    def test_missing_result_source_fails_closed(self):
        job, destination, _ = self._run_job("print('wrapper trace only')", result_source_name="missing.txt")
        self.assertEqual("failed", job["status"])
        self.assertFalse(destination.exists())


class RuntimeHealthTests(unittest.TestCase):
    def test_runtime_state_lock_serializes_writers(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime_path = pathlib.Path(temporary) / "runtime-state.json"
            acquired = threading.Event()

            def contender():
                with continuity.runtime_state_lock(runtime_path):
                    acquired.set()

            with continuity.runtime_state_lock(runtime_path):
                thread = threading.Thread(target=contender)
                thread.start()
                time.sleep(0.05)
                self.assertFalse(acquired.is_set())
            thread.join(timeout=1)
            self.assertTrue(acquired.is_set())

    def test_real_quota_failure_persists_and_overrides_ready_catalog(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            run_dir = root / "run"
            run_dir.mkdir()
            inventory = root / "hosts.json"
            inventory.write_text('{"hosts": []}\n', encoding="utf-8")
            runtime_path = root / "runtime-state.json"
            job = {
                "job_id": "quota-failure",
                "workspace": str(workspace),
                "attempts": [
                    {
                        "attempt_id": "cursor-other",
                        "adapter": "command",
                        "transport": "local",
                        "argv": [
                            sys.executable,
                            "-c",
                            "import sys; print('monthly shared usage limit reached'); sys.exit(1)",
                        ],
                        "pool_id": "cursor.other",
                        "provider": "cursor",
                        "model": "gpt-5.3-codex",
                        "runtime_state_path": str(runtime_path),
                    }
                ],
            }
            state = {
                "workspace": str(workspace),
                "inventory": str(inventory),
                "runtime_state": str(runtime_path),
                "jobs": [job],
            }
            continuity.atomic_write(run_dir / "state.json", state)
            continuity.run_job(run_dir, job, state, {})
            runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
            pools = {"cursor.other": {"health": "ready", "default_model": "gpt-5.3-codex"}}
            applied = preflight.apply_runtime_overrides(
                pools,
                runtime,
                checked_at="2026-08-09T00:00:00+00:00",
            )
            self.assertEqual("cooldown", pools["cursor.other"]["health"])
            self.assertIn("monthly shared usage limit", pools["cursor.other"]["runtime_reason"])
            self.assertEqual(["cursor.other"], [row["pool_id"] for row in applied])

    def test_expired_cooldown_does_not_override_fresh_health(self):
        pools = {"cursor.other": {"health": "ready"}}
        runtime = {
            "pools": {
                "cursor.other": {
                    "health": "cooldown",
                    "cooldown_until_utc": "2026-08-08T00:00:00+00:00",
                    "runtime_reason": "old limit",
                }
            }
        }
        applied = preflight.apply_runtime_overrides(
            pools,
            runtime,
            checked_at="2026-08-09T00:00:00+00:00",
        )
        self.assertEqual("ready", pools["cursor.other"]["health"])
        self.assertEqual([], applied)

    def test_stale_runtime_success_cannot_revive_live_block(self):
        pools = {"cursor.other": {"health": "blocked"}}
        runtime = {
            "pools": {
                "cursor.other": {
                    "health": "ready",
                    "runtime_state": "accepted",
                    "last_runtime_success": "2026-08-01T00:00:00+00:00",
                    "last_checked_at": "2026-08-01T00:00:00+00:00",
                }
            }
        }
        applied = preflight.apply_runtime_overrides(
            pools, runtime, checked_at="2026-08-11T00:00:00+00:00"
        )
        self.assertEqual("blocked", pools["cursor.other"]["health"])
        self.assertEqual([], applied)

    def test_stale_runtime_failure_cannot_override_unknown_without_evidence(self):
        pools = {"opencode.go": {"health": "unknown"}}
        runtime = {
            "pools": {
                "opencode.go": {
                    "health": "cooldown",
                    "runtime_reason": "old limit",
                    "last_checked_at": "2026-08-01T00:00:00+00:00",
                }
            }
        }
        applied = preflight.apply_runtime_overrides(
            pools, runtime, checked_at="2026-08-11T00:00:00+00:00"
        )
        self.assertEqual("unknown", pools["opencode.go"]["health"])
        self.assertEqual([], applied)


class CursorAdapterSecurityTests(unittest.TestCase):
    def test_cursor_prompt_argv_requires_explicit_authorization(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = pathlib.Path(temporary)
            prompt = workspace / "task.md"
            prompt.write_text("short secret task", encoding="utf-8")
            attempt = {
                "adapter": "cursor",
                "transport": "local",
                "prompt_file": str(prompt),
                "model": "cursor-grok-4.6-xhigh",
            }
            with self.assertRaisesRegex(ValueError, "cursor_prompt_argv_authorized"):
                continuity.build_attempt(
                    {}, attempt, {"workspace": str(workspace)}, {}
                )

    def test_cursor_defaults_keep_privilege_flags_off_and_redact_short_prompt(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = pathlib.Path(temporary)
            prompt = workspace / "task.md"
            prompt.write_text("short secret task", encoding="utf-8")
            attempt = {
                "adapter": "cursor",
                "transport": "local",
                "prompt_file": str(prompt),
                "model": "cursor-grok-4.6-xhigh",
                "cursor_prompt_argv_authorized": True,
                "cursor_mode": "plan",
            }
            argv, _, _, _ = continuity.build_attempt(
                {}, attempt, {"workspace": str(workspace)}, {}
            )
            self.assertIn("--sandbox", argv)
            self.assertIn("enabled", argv)
            self.assertNotIn("--trust", argv)
            self.assertNotIn("--force", argv)
            self.assertEqual(["--", "short secret task"], argv[-2:])
            logged = continuity._redact_argv_for_log(argv)
            self.assertNotIn("short secret task", logged)
            self.assertIn("<redacted cursor prompt 17 chars>", logged)

    def test_cursor_force_is_explicit_and_incompatible_with_read_only_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = pathlib.Path(temporary)
            prompt = workspace / "task.md"
            prompt.write_text("bounded edit", encoding="utf-8")
            base = {
                "adapter": "cursor",
                "transport": "local",
                "prompt_file": str(prompt),
                "model": "cursor-grok-4.6-xhigh",
                "cursor_prompt_argv_authorized": True,
                "cursor_trust_workspace": True,
                "cursor_force_commands": True,
            }
            argv, _, _, _ = continuity.build_attempt(
                {}, base, {"workspace": str(workspace)}, {}
            )
            self.assertIn("--trust", argv)
            self.assertIn("--force", argv)
            with self.assertRaisesRegex(ValueError, "read-only"):
                continuity.build_attempt(
                    {}, {**base, "cursor_mode": "plan"},
                    {"workspace": str(workspace)}, {},
                )

    def test_cursor_built_argv_is_counted_in_its_shared_pool(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = pathlib.Path(temporary)
            prompt = workspace / "task.md"
            prompt.write_text("bounded review", encoding="utf-8")
            attempt = {
                "adapter": "cursor",
                "transport": "local",
                "prompt_file": str(prompt),
                "model": "cursor-grok-4.6-xhigh",
                "cursor_prompt_argv_authorized": True,
                "cursor_mode": "plan",
            }
            argv, _, _, _ = continuity.build_attempt(
                {}, attempt, {"workspace": str(workspace)}, {}
            )
        self.assertIn("--print", argv)
        self.assertEqual(
            ("cursor.composer_grok", "cursor-grok-4.6-xhigh"),
            preflight.pool_for_process(" ".join(argv)),
        )


class CursorCatalogTests(unittest.TestCase):
    def test_non_composer_model_does_not_make_composer_grok_pool_ready(self):
        pools = preflight.build_pools(
            codex_usage={},
            cursor_status={"isAuthenticated": True, "auth_state": "authenticated"},
            cursor_catalog=["gpt-5.3-codex"],
            antigravity_usage={},
            antigravity_catalog=[],
            opencode_go={},
            local_models={},
            blocked_rows=[],
        )
        self.assertEqual("blocked", pools["cursor.composer_grok"]["health"])
        self.assertIsNone(pools["cursor.composer_grok"]["default_model"])
        self.assertEqual("ready", pools["cursor.other"]["health"])
        self.assertEqual("gpt-5.3-codex", pools["cursor.other"]["default_model"])
        self.assertEqual([], pools["cursor.composer_grok"]["catalog_models"])
        self.assertEqual(["gpt-5.3-codex"], pools["cursor.other"]["catalog_models"])

    def test_hard_role_uses_newest_strongest_live_grok_slug(self):
        catalog = [
            "cursor-grok-4.5-high-fast",
            "cursor-grok-4.6-high-fast",
            "cursor-grok-4.6-xhigh",
            "composer-2.5-fast",
        ]
        pools = preflight.build_pools(
            codex_usage={},
            cursor_status={"isAuthenticated": True, "auth_state": "authenticated"},
            cursor_catalog=catalog,
            antigravity_usage={},
            antigravity_catalog=[],
            opencode_go={},
            local_models={},
            blocked_rows=[],
        )
        pool = pools["cursor.composer_grok"]
        self.assertEqual("ready", pool["health"])
        self.assertEqual("composer-2.5-fast", pool["role_models"]["efficient"])
        self.assertEqual("cursor-grok-4.6-xhigh", pool["role_models"]["hard"])
        self.assertEqual(
            [
                "cursor-grok-4.6-xhigh",
                "cursor-grok-4.6-high-fast",
                "cursor-grok-4.5-high-fast",
                "composer-2.5-fast",
            ],
            pool["role_model_candidates"]["hard"],
        )

    def test_grok_only_catalog_is_schedulable_when_authenticated(self):
        pools = preflight.build_pools(
            codex_usage={},
            cursor_status={"isAuthenticated": True, "auth_state": "authenticated"},
            cursor_catalog=["cursor-grok-4.6-xhigh"],
            antigravity_usage={},
            antigravity_catalog=[],
            opencode_go={},
            local_models={},
            blocked_rows=[],
        )
        pool = pools["cursor.composer_grok"]
        self.assertEqual("ready", pool["health"])
        self.assertEqual("cursor-grok-4.6-xhigh", pool["default_model"])

    def test_cursor_family_partition_uses_same_case_insensitive_classifier(self):
        slug = "Cursor-Grok-4.6-XHIGH"
        pools = preflight.build_pools(
            codex_usage={},
            cursor_status={"isAuthenticated": True, "auth_state": "authenticated"},
            cursor_catalog=[slug],
            antigravity_usage={},
            antigravity_catalog=[],
            opencode_go={},
            local_models={},
            blocked_rows=[],
        )
        self.assertEqual("ready", pools["cursor.composer_grok"]["health"])
        self.assertEqual(slug, pools["cursor.composer_grok"]["default_model"])
        self.assertEqual([slug], pools["cursor.composer_grok"]["catalog_models"])
        self.assertEqual([], pools["cursor.other"]["catalog_models"])
        self.assertEqual("blocked", pools["cursor.other"]["health"])

    def test_blocked_grok_slug_is_not_reintroduced_by_ranking(self):
        ranked = preflight.rank_cursor_models(
            ["cursor-grok-4.6-xhigh", "cursor-grok-4.6-high-fast"],
            "grok",
            "hard",
            {"cursor-grok-4.6-xhigh"},
        )
        self.assertEqual(["cursor-grok-4.6-high-fast"], ranked)

    def test_locked_keychain_is_a_specific_sanitized_auth_block(self):
        status = preflight.annotate_cursor_status(
            {"ok": False, "isAuthenticated": False, "error": "raw diagnostic"},
            {
                "ok": False,
                "stderr": "The login keychain is locked and could not be unlocked",
            },
        )
        self.assertEqual("unavailable", status["auth_state"])
        self.assertEqual("keychain_locked", status["auth_error_class"])
        self.assertNotIn("error", status)

        pools = preflight.build_pools(
            codex_usage={},
            cursor_status=status,
            cursor_catalog=["cursor-grok-4.6-xhigh"],
            antigravity_usage={},
            antigravity_catalog=[],
            opencode_go={},
            local_models={},
            blocked_rows=[],
        )
        pool = pools["cursor.composer_grok"]
        self.assertEqual("blocked", pool["health"])
        self.assertEqual("keychain_locked", pool["auth_error_class"])
        self.assertIn("keychain is locked", pool["blocked_reason"])


class AntigravityCatalogTests(unittest.TestCase):
    def test_exact_slug_is_parsed_from_table_catalog(self):
        text = (
            "gemini-3.6-flash-high\tGemini 3.6 Flash (High)\n"
            "gemini-3.1-pro-high    Gemini 3.1 Pro (High)\n"
        )
        self.assertEqual(
            {"gemini-3.6-flash-high", "gemini-3.1-pro-high"},
            set(preflight.antigravity_models(text)),
        )

    def test_exact_match_does_not_accept_slug_prefix(self):
        ids = preflight.antigravity_models(
            "gemini-3.6-flash-highest\tImpostor\n"
        )
        self.assertNotIn("gemini-3.6-flash-high", ids)

    def test_shared_pool_exposes_flash_and_pro_role_candidates(self):
        pools = preflight.build_pools(
            codex_usage={}, cursor_status={}, cursor_catalog=[],
            antigravity_usage={},
            antigravity_catalog=["gemini-3.6-flash-high", "gemini-3.1-pro-high"],
            opencode_go={}, local_models={}, blocked_rows=[],
        )
        pool = pools["antigravity.gemini"]
        self.assertEqual(
            ["gemini-3.1-pro-high", "gemini-3.6-flash-high"],
            pool["catalog_models"],
        )
        self.assertEqual("gemini-3.6-flash-high", pool["role_models"]["efficient"])
        self.assertEqual("gemini-3.1-pro-high", pool["role_models"]["hard"])
        self.assertEqual("pilot", pool["unknown_quota_policy"])

    def test_antigravity_zero_weekly_balance_is_a_shared_pool_block(self):
        pools = preflight.build_pools(
            codex_usage={}, cursor_status={}, cursor_catalog=[],
            antigravity_usage={
                "pools": {
                    "antigravity.claude_gpt": {
                        "health": "unknown",
                        "weekly_percent_displayed": 0.0,
                        "five_hour_percent_displayed": None,
                        "effective_percent_displayed": None,
                    }
                }
            },
            antigravity_catalog=["claude-opus-4-6-thinking", "claude-sonnet-4-6"],
            opencode_go={}, local_models={}, blocked_rows=[],
        )
        pool = pools["antigravity.claude_gpt"]
        self.assertEqual("blocked", pool["health"])
        self.assertEqual(0.0, pool["effective_remaining_percent"])
        self.assertIn("weekly quota exhausted", pool["blocked_reason"])

    def test_capability_rejection_blocks_only_exact_antigravity_model(self):
        pools = preflight.build_pools(
            codex_usage={}, cursor_status={}, cursor_catalog=[],
            antigravity_usage={},
            antigravity_catalog=["gemini-3.6-flash-high", "gemini-3.1-pro-high"],
            opencode_go={}, local_models={},
            blocked_rows=[
                {
                    "provider": "antigravity",
                    "model": "gemini-3.1-pro-high",
                    "runtime_state": "rejected",
                    "error_class": "capability",
                }
            ],
        )
        pool = pools["antigravity.gemini"]
        self.assertEqual("gemini-3.6-flash-high", pool["default_model"])
        self.assertEqual(["gemini-3.1-pro-high"], pool["rejected_models"])
        self.assertNotEqual("blocked", pool["health"])

    def test_location_rejection_from_runtime_state_blocks_exact_gemini_model(self):
        runtime = {
            "models": {
                "antigravity": {
                    "gemini-3.1-pro-high": {
                        "runtime_state": "rejected",
                        "error_class": "location_restricted",
                        "runtime_reason": "location restriction from provider",
                    }
                }
            }
        }
        blocked = preflight.runtime_rejection_rows(runtime)
        self.assertEqual(
            [{
                "provider": "antigravity",
                "model": "gemini-3.1-pro-high",
                "runtime_state": "rejected",
                "error_class": "location_restricted",
                "runtime_reason": "location restriction from provider",
            }],
            blocked,
        )
        pools = preflight.build_pools(
            codex_usage={}, cursor_status={}, cursor_catalog=[],
            antigravity_usage={},
            antigravity_catalog=["gemini-3.6-flash-high", "gemini-3.1-pro-high"],
            opencode_go={}, local_models={}, blocked_rows=blocked,
        )
        pool = pools["antigravity.gemini"]
        self.assertEqual("gemini-3.6-flash-high", pool["default_model"])
        self.assertEqual(["gemini-3.1-pro-high"], pool["rejected_models"])

    def test_failed_precondition_location_rejection_is_exact_and_not_quota(self):
        runtime = {
            "models": {
                "antigravity-cli": {
                    "gemini-3.1-pro-high": {
                        "runtime_state": "rejected",
                        "error_class": "execution",
                        "error_message": (
                            "FAILED_PRECONDITION: User location is not supported "
                            "for the API use"
                        ),
                        "variants": {
                            "high": {
                                "runtime_state": "rejected",
                                "error_message": (
                                    "FAILED_PRECONDITION: User location is not supported"
                                ),
                            }
                        },
                    },
                    "gemini-3.6-flash-high": {
                        "runtime_state": "rejected",
                        "error_class": "quota",
                        "error_message": "FAILED_PRECONDITION: quota exhausted",
                    },
                },
                "codex": {
                    "gpt-5.6-luna": {
                        "runtime_state": "rejected",
                        "error_message": "FAILED_PRECONDITION: User location is not supported",
                    }
                },
            }
        }
        blocked = preflight.runtime_rejection_rows(runtime)
        self.assertEqual(
            {
                (row["provider"], row["model"], row.get("variant"), row["error_class"])
                for row in blocked
            },
            {
                ("antigravity-cli", "gemini-3.1-pro-high", None, "location_restricted"),
                ("antigravity-cli", "gemini-3.1-pro-high", "high", "location_restricted"),
            },
        )

    def test_encoded_antigravity_variant_rejection_blocks_exact_slug(self):
        runtime = {
            "models": {
                "antigravity": {
                    "gemini-3.1-pro-high": {
                        "variants": {
                            "high": {
                                "runtime_state": "rejected",
                                "error_class": "location_restricted",
                                "runtime_reason": "unsupported user location",
                            }
                        }
                    }
                }
            }
        }
        blocked = preflight.runtime_rejection_rows(runtime)
        pools = preflight.build_pools(
            codex_usage={},
            cursor_status={},
            cursor_catalog=[],
            antigravity_usage={
                "pools": {
                    "antigravity.gemini": {
                        "health": "ready",
                        "effective_percent_displayed": 100,
                    }
                }
            },
            antigravity_catalog=["gemini-3.1-pro-high", "gemini-3.6-flash-high"],
            opencode_go={},
            local_models={},
            blocked_rows=blocked,
        )
        pool = pools["antigravity.gemini"]
        self.assertIn("gemini-3.1-pro-high", pool["rejected_models"])
        self.assertEqual("gemini-3.6-flash-high", pool["default_model"])


class PlannerPlacementTests(unittest.TestCase):
    def test_desktop_authenticated_cli_is_bound_to_local_host(self):
        state = {
            "pools": {"cursor.composer_grok": ready_pool("cursor.composer_grok")},
            "compute_hosts": {
                "local_mac": host("local_mac", "local", load1=1),
                "remote_gpu": host("remote_gpu", "ssh", logical_cpu_cores=64),
            },
        }
        result = planner.plan(
            state,
            {"jobs": [tiny_job("cursor-locality", "cursor.composer_grok")]},
            max_lanes=1,
            horizon=1,
        )
        self.assertEqual("local_mac", result["assignments"][0]["execution_host"])
        self.assertEqual("local_mac", result["assignments"][0]["workload_host"])

    def test_critical_local_load_is_a_hard_gate_even_for_small_work(self):
        state = {
            "pools": {"cursor.composer_grok": ready_pool("cursor.composer_grok")},
            "compute_hosts": {"local_mac": host("local_mac", "local", load1=20)},
        }
        result = planner.plan(
            state,
            {"jobs": [tiny_job("overloaded-local", "cursor.composer_grok")]},
            max_lanes=1,
            horizon=1,
        )
        self.assertEqual([], result["assignments"])
        self.assertEqual("no_eligible_compute_host", result["deferred"][0]["reason"])
        self.assertIn(
            "local_load_critical",
            result["deferred"][0]["host_failures"]["local_mac"],
        )

    def test_local_memory_pressure_blocks_new_lane_even_when_ram_ratio_looks_safe(self):
        state = {
            "pools": {"cursor.composer_grok": ready_pool("cursor.composer_grok")},
            "compute_hosts": {
                "local_mac": {
                    **host("local_mac", "local", load1=2),
                    "memory_total_gib": 32,
                    "memory_available_gib": 8,
                    "memory_pressure_state": "critical",
                    "local_agent_launch_allowed": False,
                }
            },
        }
        result = planner.plan(
            state,
            {"jobs": [tiny_job("memory-pressure-local", "cursor.composer_grok")]},
            max_lanes=1,
            horizon=1,
        )
        self.assertEqual([], result["assignments"])
        self.assertEqual("no_eligible_compute_host", result["deferred"][0]["reason"])
        failures = result["deferred"][0]["host_failures"]["local_mac"]
        self.assertIn("local_memory_pressure_critical", failures)
        self.assertIn("local_agent_launch_blocked", failures)

    def test_server_first_workload_separates_agent_host_from_compute_host(self):
        state = {
            "pools": {"cursor.composer_grok": ready_pool("cursor.composer_grok")},
            "compute_hosts": {
                "local_mac": host("local_mac", "local"),
                "remote_cpu": host("remote_cpu", "ssh", logical_cpu_cores=64),
            },
        }
        job = tiny_job("remote-workload", "cursor.composer_grok")
        job["resource_estimate"]["compute_minutes"] = 20
        job["allowed_hosts"] = ["remote_cpu"]
        result = planner.plan(state, {"jobs": [job]}, max_lanes=1, horizon=1)
        assignment = result["assignments"][0]
        self.assertEqual("local_mac", assignment["execution_host"])
        self.assertEqual("remote_cpu", assignment["workload_host"])

    def test_remote_nonroot_writable_mount_is_used_for_disk_fit(self):
        remote = host("remote_cpu", "ssh", logical_cpu_cores=64)
        remote.update(
            project_path="/var/project-on-root",
            project_path_writable=False,
            disk_total_gib=30,
            disk_free_gib=1,
            best_writable_storage_path="/workspace/project",
            storage_paths=[
                {
                    "path": "/var/project-on-root",
                    "exists": True,
                    "writable": False,
                    "disk_total_gib": 30,
                    "disk_free_gib": 1,
                },
                {
                    "path": "/workspace/project",
                    "exists": True,
                    "writable": True,
                    "disk_total_gib": 550,
                    "disk_free_gib": 120,
                },
            ],
            # A remote mount row without a probe timestamp is not safe for
            # claim-time placement.  This fixture represents a fresh probe.
            last_probed_at_utc=datetime.now(timezone.utc).isoformat(),
            storage_probe_ttl_seconds=1800,
        )
        state = {
            "pools": {"cursor.composer_grok": ready_pool("cursor.composer_grok")},
            "compute_hosts": {
                "local_mac": host("local_mac", "local"),
                "remote_cpu": remote,
            },
        }
        job = tiny_job("remote-nonroot-disk", "cursor.composer_grok")
        job["resource_estimate"].update({"compute_minutes": 20, "temporary_gib": 4})
        job["allowed_hosts"] = ["remote_cpu"]
        result = planner.plan(state, {"jobs": [job]}, max_lanes=1, horizon=1)
        self.assertEqual(1, len(result["assignments"]))
        assignment = result["assignments"][0]
        self.assertEqual("/workspace/project", assignment["workload_storage_path"])
        self.assertEqual("/workspace/project", assignment["workload_project_path"])
        self.assertNotIn("insufficient_free_disk", assignment["host_reasons"])

    def test_apple_gpu_does_not_reduce_cpu_only_cli_host_to_one_lane(self):
        pool_ids = [
            "codex.luna",
            "codex.spark",
            "cursor.composer_grok",
            "antigravity.gemini",
        ]
        state = {
            "pools": {pool_id: ready_pool(pool_id) for pool_id in pool_ids},
            "compute_hosts": {"local_mac": host("local_mac", "local", gpu_count=1)},
        }
        jobs = [tiny_job(f"lane-{index}", pool_id) for index, pool_id in enumerate(pool_ids)]
        result = planner.plan(state, {"jobs": jobs}, max_lanes=4, horizon=4)
        self.assertEqual(4, len(result["assignments"]))
        self.assertTrue(all(row["resource_request"]["gpu_count"] == 0 for row in result["assignments"]))

    def test_unknown_quota_uses_explicit_pilot_cap_not_fake_remaining_balance(self):
        pool = ready_pool("cursor.composer_grok")
        pool["effective_remaining_percent"] = None
        pool["unknown_quota_policy"] = "pilot"
        state = {
            "pools": {"cursor.composer_grok": pool},
            "compute_hosts": {"local_mac": host("local_mac", "local")},
        }
        result = planner.plan(
            state,
            {"jobs": [tiny_job("unknown-quota", "cursor.composer_grok")]},
            max_lanes=1,
            horizon=1,
        )
        self.assertEqual(1, len(result["assignments"]))
        assignment = result["assignments"][0]
        self.assertEqual("unknown_pilot_cap", assignment["quota_evidence"])
        self.assertIsNone(assignment["projected_remaining_percent"])
        self.assertEqual("pilot_cap", result["quota_uncertainty"]["cursor.composer_grok"]["policy"])
        self.assertIn(
            "quota_remaining_unknown:no_numeric_score",
            assignment["model_reasons"],
        )

    def test_unknown_quota_can_be_fail_closed_by_policy(self):
        pool = ready_pool("cursor.composer_grok")
        pool["effective_remaining_percent"] = None
        pool["unknown_quota_policy"] = "block"
        state = {
            "pools": {"cursor.composer_grok": pool},
            "compute_hosts": {"local_mac": host("local_mac", "local")},
        }
        result = planner.plan(
            state,
            {"jobs": [tiny_job("blocked-unknown-quota", "cursor.composer_grok")]},
            max_lanes=1,
            horizon=1,
        )
        self.assertEqual([], result["assignments"])
        self.assertEqual("pause", result["decision"])

    def test_cursor_shared_pool_selects_role_model_without_splitting_quota(self):
        pool = ready_pool("cursor.composer_grok")
        pool.update(
            catalog_models=["composer-2.5-fast", "cursor-grok-4.5-high-fast"],
            role_models={
                "efficient": "composer-2.5-fast",
                "code": "composer-2.5-fast",
                "hard": "cursor-grok-4.5-high-fast",
            },
            role_model_candidates={
                "efficient": ["composer-2.5-fast", "cursor-grok-4.5-high-fast"],
                "code": ["composer-2.5-fast", "cursor-grok-4.5-high-fast"],
                "hard": ["cursor-grok-4.5-high-fast", "composer-2.5-fast"],
            },
        )
        state = {
            "pools": {"cursor.composer_grok": pool},
            "compute_hosts": {"local_mac": host("local_mac", "local")},
        }
        efficient = tiny_job("cursor-efficient", "cursor.composer_grok")
        hard = tiny_job("cursor-hard", "cursor.composer_grok")
        hard.update(difficulty=4, task_type="research")
        efficient_result = planner.plan(state, {"jobs": [efficient]}, max_lanes=1, horizon=1)
        hard_result = planner.plan(state, {"jobs": [hard]}, max_lanes=1, horizon=1)
        self.assertEqual("composer-2.5-fast", efficient_result["assignments"][0]["model"])
        self.assertEqual("cursor-grok-4.5-high-fast", hard_result["assignments"][0]["model"])
        self.assertEqual("cursor.composer_grok", hard_result["assignments"][0]["pool_id"])


class ExternalConsumerTests(unittest.TestCase):
    def test_remote_external_consumers_are_aggregated_into_shared_pool(self):
        merged = preflight.aggregate_external_consumers(
            {
                "scan_ok": True,
                "processes": [],
                "inflight_by_pool": {"codex.luna": 1},
            },
            {
                "bjb2": {
                    "transport": "ssh",
                    "external_consumers": {
                        "scan_ok": True,
                        "processes": [
                            {
                                "pid": 410,
                                "pool_id": "opencode.go",
                                "command_name": "opencode",
                                "model": "opencode-go/deepseek-v4-flash",
                                "arguments_collected": False,
                            }
                        ],
                        "inflight_by_pool": {"opencode.go": 1},
                    },
                }
            },
        )
        self.assertEqual({"codex.luna": 1, "opencode.go": 1}, merged["inflight_by_pool"])
        self.assertTrue(merged["scan_ok"])
        self.assertEqual(1, merged["remote_hosts"]["bjb2"]["inflight_by_pool"]["opencode.go"])

    def test_remote_external_scan_failure_is_fail_closed(self):
        merged = preflight.aggregate_external_consumers(
            {"scan_ok": True, "inflight_by_pool": {}},
            {"bjb2": {"transport": "ssh", "external_consumers": {"scan_ok": False}}},
        )
        self.assertFalse(merged["scan_ok"])
        self.assertTrue(merged["unknown"])

    def test_process_snapshot_maps_only_active_agent_invocations(self):
        ps_text = "\n".join(
            [
                "101 1 /opt/bin/codex exec -m gpt-5.6-luna -c model_reasoning_effort=max",
                "102 1 cursor-agent -p bounded --model composer-2.5-fast",
                "103 1 antigravity -p bounded --model gemini-3.6-flash-high",
                "104 1 /opt/bin/codex app-server",
                "105 1 python dispatch_preflight_scan.py",
                "106 1 cursor-agent status --format json",
                "107 1 cursor-agent about --format json",
                "108 1 antigravity models",
                "109 1 opencode run --model opencode-go/mimo-v2.5",
            ]
        )
        snapshot = preflight.local_agent_process_snapshot(ps_text, current_pid=999)
        self.assertEqual(
            {
                "codex.luna": 1,
                "cursor.composer_grok": 1,
                "antigravity.gemini": 1,
                "opencode.go": 1,
            },
            snapshot["inflight_by_pool"],
        )
        self.assertFalse(snapshot["exclusive_pool_observation"])
        self.assertEqual(4, len(snapshot["processes"]))
        self.assertNotIn("bounded", json.dumps(snapshot))

    def test_process_classifier_drops_untrusted_model_token(self):
        snapshot = preflight.local_agent_process_snapshot(
            "101 1 /opt/bin/opencode run --model PRIVATE_PROMPT --prompt SECRET_TOKEN\n",
            current_pid=999,
        )
        self.assertEqual({}, snapshot["inflight_by_pool"])
        self.assertNotIn("PRIVATE_PROMPT", json.dumps(snapshot))
        self.assertNotIn("SECRET_TOKEN", json.dumps(snapshot))

    def test_observed_external_inflight_reduces_pool_capacity(self):
        pools = preflight.build_pools(
            codex_usage={"pools": {"codex.luna": {"health": "ready"}}},
            cursor_status={},
            cursor_catalog=[],
            antigravity_usage={},
            antigravity_catalog=[],
            opencode_go={},
            local_models={},
            blocked_rows=[],
            external_inflight={"codex.luna": 1},
        )
        self.assertEqual(1, pools["codex.luna"]["inflight"])

    def test_codex_preflight_preserves_exact_default_models(self):
        pools = preflight.build_pools(
            codex_usage={
                "pools": {
                    "codex.luna": {"health": "ready", "default_model": None},
                    "codex.spark": {"health": "blocked", "default_model": None},
                }
            },
            cursor_status={}, cursor_catalog=[], antigravity_usage={},
            antigravity_catalog=[], opencode_go={}, local_models={}, blocked_rows=[],
            codex_capabilities={
                "codex.luna": [{"ok": True, "model": "gpt-5.6-luna", "effort": "max"}],
                "codex.spark": [{"ok": True, "model": "gpt-5.3-codex-spark", "effort": "xhigh"}],
            },
        )
        self.assertEqual("gpt-5.6-luna/max", pools["codex.luna"]["default_model"])
        self.assertEqual("gpt-5.3-codex-spark/xhigh", pools["codex.spark"]["default_model"])
        self.assertEqual(["gpt-5.6-luna"], pools["codex.luna"]["catalog_models"])
        self.assertEqual(
            {"gpt-5.3-codex-spark": ["xhigh"]},
            pools["codex.spark"]["available_model_variants"],
        )


class OpenCodeGoIntegrationTests(unittest.TestCase):
    @staticmethod
    def snapshot() -> dict:
        return {
            "ok": True,
            "auth": {"state": "configured"},
            "catalog": {
                "state": "visible",
                "models": [
                    {
                        "model_id": "opencode-go/gpt-5.6-luna",
                        "metadata": {
                            "name": "GPT-5.6 Luna (2x usage)",
                            "variants": {"max": {"reasoningEffort": "max"}},
                        },
                    },
                    {"model_id": "opencode-go/mimo-v2.5", "metadata": {"name": "MiMo V2.5"}},
                    {"model_id": "opencode-go/kimi-k2.7-code", "metadata": {"name": "Kimi K2.7 Code"}},
                    {"model_id": "opencode-go/deepseek-v4-flash", "metadata": {"name": "DeepSeek"}},
                ],
            },
            "pools": {"opencode.go": {"health": "unknown", "runtime_state": "unknown"}},
        }

    def pools(self, blocked_rows=None) -> dict:
        return preflight.build_pools(
            codex_usage={},
            cursor_status={},
            cursor_catalog=[],
            antigravity_usage={},
            antigravity_catalog=[],
            opencode_go=self.snapshot(),
            local_models={},
            blocked_rows=blocked_rows or [],
        )

    def test_go_catalog_is_one_shared_pool_with_policy_exclusion(self):
        pool = self.pools()["opencode.go"]
        self.assertEqual("opencode-go", pool["provider_id"])
        self.assertEqual("unknown", pool["overage_fallback_state"])
        self.assertIn("opencode-go/deepseek-v4-flash", pool["shared_members"])
        self.assertNotIn("opencode-go/deepseek-v4-flash", pool["catalog_models"])
        self.assertEqual(["opencode-go/deepseek-v4-flash"], pool["policy_excluded_models"])
        self.assertTrue(pool["model_approval_required"])
        self.assertEqual("task_exact_model", pool["model_approval_policy"])
        self.assertEqual(2.0, pool["model_usage_multipliers"]["opencode-go/gpt-5.6-luna"])

    def test_explicit_deepseek_opt_in_is_exact_and_stays_in_shared_pool(self):
        pool = self.pools()["opencode.go"]
        pool.update(health="ready", effective_remaining_percent=90)
        state = {
            "pools": {"opencode.go": pool},
            "compute_hosts": {"local_mac": host("local_mac", "local")},
        }
        job = tiny_job("deepseek-parallel-review", "opencode.go")
        job["model_by_pool"] = {
            "opencode.go": {"model": "opencode-go/deepseek-v4-flash"}
        }
        job["allow_policy_excluded_models"] = ["opencode-go/deepseek-v4-flash"]
        result = planner.plan(state, {"jobs": [job]}, max_lanes=1, horizon=1)
        assignment = result["assignments"][0]
        self.assertEqual("opencode-go/deepseek-v4-flash", assignment["model"])
        self.assertEqual("explicit_policy_override", assignment["model_role"])
        self.assertEqual("opencode.go", assignment["pool_id"])

    def test_exact_model_pool_does_not_fallback_to_another_provider(self):
        go_pool = self.pools()["opencode.go"]
        go_pool.update(health="blocked", effective_remaining_percent=0)
        codex_pool = ready_pool("codex.luna")
        state = {
            "pools": {"opencode.go": go_pool, "codex.luna": codex_pool},
            "compute_hosts": {"local_mac": host("local_mac", "local")},
        }
        job = tiny_job("strict-deepseek", "opencode.go")
        job["model_by_pool"] = {
            "opencode.go": {"model": "opencode-go/deepseek-v4-flash"}
        }
        job["allow_policy_excluded_models"] = ["opencode-go/deepseek-v4-flash"]
        result = planner.plan(state, {"jobs": [job]}, max_lanes=1, horizon=1)
        self.assertEqual([], result["assignments"])
        self.assertEqual("pause", result["decision"])

    def test_gemini_pro_and_explicit_deepseek_can_fill_parallel_lanes(self):
        go_pool = self.pools()["opencode.go"]
        go_pool.update(health="ready", effective_remaining_percent=90)
        gemini_pool = ready_pool("antigravity.gemini")
        gemini_pool.update(
            catalog_models=["gemini-3.6-flash-high", "gemini-3.1-pro-high"],
            role_models={"efficient": "gemini-3.6-flash-high", "hard": "gemini-3.1-pro-high"},
            role_model_candidates={
                "efficient": ["gemini-3.6-flash-high"],
                "hard": ["gemini-3.1-pro-high", "gemini-3.6-flash-high"],
            },
        )
        hard_review = tiny_job("gemini-review", "antigravity.gemini")
        hard_review.update(difficulty=4, task_type="audit")
        deepseek_review = tiny_job("deepseek-review", "opencode.go")
        deepseek_review["model_by_pool"] = {
            "opencode.go": {"model": "opencode-go/deepseek-v4-flash"}
        }
        deepseek_review["allow_policy_excluded_models"] = ["opencode-go/deepseek-v4-flash"]
        result = planner.plan(
            {"pools": {"antigravity.gemini": gemini_pool, "opencode.go": go_pool},
             "compute_hosts": {"local_mac": host("local_mac", "local")}},
            {"jobs": [hard_review, deepseek_review]}, max_lanes=2, horizon=2,
        )
        assignments = {row["job_id"]: row for row in result["assignments"]}
        self.assertEqual("gemini-3.1-pro-high", assignments["gemini-review"]["model"])
        self.assertEqual("opencode-go/deepseek-v4-flash", assignments["deepseek-review"]["model"])
        self.assertEqual(2, len(assignments))

    def test_open_code_only_inventory_does_not_fabricate_codex_readiness(self):
        pools = preflight.build_pools(
            codex_usage={"ok": False, "skipped": True, "pools": {}},
            cursor_status={},
            cursor_catalog=[],
            antigravity_usage={},
            antigravity_catalog=[],
            opencode_go=self.snapshot(),
            local_models={},
            blocked_rows=[],
        )
        self.assertEqual("blocked", pools["codex.luna"]["health"])
        self.assertEqual("blocked", pools["codex.spark"]["health"])
        self.assertEqual("unknown", pools["opencode.go"]["health"])
        self.assertIsNotNone(pools["opencode.go"]["default_model"])

    def test_planner_uses_efficient_and_hard_roles_with_exact_variant(self):
        pool = self.pools()["opencode.go"]
        pool.update(health="ready", effective_remaining_percent=90)
        state = {
            "pools": {"opencode.go": pool},
            "compute_hosts": {"local_mac": host("local_mac", "local")},
        }
        small = tiny_job("go-small", "opencode.go")
        # OpenCode Go role candidates are not spend-authorized by the
        # catalogue alone; this test explicitly approves the exact members it
        # wants to exercise.
        small["allowed_models"] = ["opencode-go/mimo-v2.5"]
        small_result = planner.plan(state, {"jobs": [small]}, max_lanes=1, horizon=1)
        self.assertEqual("opencode-go/mimo-v2.5", small_result["assignments"][0]["model"])
        self.assertEqual("efficient", small_result["assignments"][0]["model_role"])

        hard = tiny_job("go-hard", "opencode.go")
        hard.update(difficulty=4, task_type="research")
        hard["allowed_models"] = ["opencode-go/gpt-5.6-luna"]
        hard_result = planner.plan(state, {"jobs": [hard]}, max_lanes=1, horizon=1)
        assignment = hard_result["assignments"][0]
        self.assertEqual("opencode-go/gpt-5.6-luna", assignment["model"])
        self.assertEqual("max", assignment["variant"])
        self.assertEqual("hard", assignment["model_role"])

    def test_unapproved_go_role_candidate_is_blocked_for_task_approval(self):
        pool = self.pools()["opencode.go"]
        pool.update(health="ready", effective_remaining_percent=90)
        state = {
            "pools": {"opencode.go": pool},
            "compute_hosts": {"local_mac": host("local_mac", "local")},
        }
        job = tiny_job("go-needs-approval", "opencode.go")
        result = planner.plan(state, {"jobs": [job]}, max_lanes=1, horizon=1)

        self.assertEqual([], result["assignments"])
        self.assertEqual("pause", result["decision"])
        self.assertEqual("needs_approval", result["model_approval"]["state"])
        self.assertEqual("blocked", result["model_approval"]["blocked"][0]["status"])
        deferred = next(row for row in result["deferred"] if row["job_id"] == job["job_id"])
        self.assertEqual("needs_approval", deferred["reason"])
        self.assertIn("opencode-go/gpt-5.6-luna", deferred["candidate_models"])

    def test_exact_allowed_model_approval_limits_shared_pool_selection(self):
        pool = self.pools()["opencode.go"]
        pool.update(health="ready", effective_remaining_percent=90)
        state = {
            "pools": {"opencode.go": pool},
            "compute_hosts": {"local_mac": host("local_mac", "local")},
        }
        job = tiny_job("go-approved-kimi", "opencode.go")
        job["allowed_models"] = ["opencode-go/kimi-k2.7-code"]
        result = planner.plan(state, {"jobs": [job]}, max_lanes=1, horizon=1)

        self.assertEqual(1, len(result["assignments"]))
        self.assertEqual(
            "opencode-go/kimi-k2.7-code",
            result["assignments"][0]["model"],
        )
        self.assertEqual("approved", result["model_approval"]["state"])

    def test_rejected_variant_falls_back_without_rejecting_shared_pool(self):
        pool = self.pools(
            [
                {
                    "provider": "opencode",
                    "model": "opencode-go/gpt-5.6-luna",
                    "variant": "max",
                    "runtime_state": "rejected",
                }
            ]
        )["opencode.go"]
        pool.update(health="ready", effective_remaining_percent=90)
        state = {
            "pools": {"opencode.go": pool},
            "compute_hosts": {"local_mac": host("local_mac", "local")},
        }
        hard = tiny_job("go-fallback", "opencode.go")
        hard.update(difficulty=4, task_type="research")
        hard["allowed_models"] = [
            "opencode-go/gpt-5.6-luna",
            "opencode-go/kimi-k2.7-code",
        ]
        result = planner.plan(state, {"jobs": [hard]}, max_lanes=1, horizon=1)
        assignment = result["assignments"][0]
        self.assertNotEqual(
            ("opencode-go/gpt-5.6-luna", "max"),
            (assignment["model"], assignment["variant"]),
        )
        self.assertIn("fallback", assignment["model_role"])

    def test_planner_exposes_model_price_when_token_bounds_are_known(self):
        pool = self.pools()["opencode.go"]
        pool.update(
            health="ready",
            effective_remaining_percent=90,
            catalog_models=["opencode-go/deepseek-v4-flash"],
            available_model_variants={"opencode-go/deepseek-v4-flash": ["max"]},
            model_costs_per_million_tokens={
                "opencode-go/deepseek-v4-flash": {"input": 0.07, "output": 0.14}
            },
        )
        state = {
            "pools": {"opencode.go": pool},
            "compute_hosts": {"local_mac": host("local_mac", "local")},
        }
        job = tiny_job("priced-deepseek", "opencode.go")
        job["model_by_pool"] = {
            "opencode.go": {
                "model": "opencode-go/deepseek-v4-flash",
                "variant": "max",
            }
        }
        job["allow_policy_excluded_models"] = ["opencode-go/deepseek-v4-flash"]
        job["resource_estimate"].update({"estimated_input_tokens": 10000, "estimated_output_tokens": 2000})
        result = planner.plan(state, {"jobs": [job]}, max_lanes=1, horizon=1)
        self.assertEqual(1, len(result["assignments"]))
        assignment = result["assignments"][0]
        self.assertEqual(0.00098, assignment["estimated_usd_cost"])
        self.assertEqual(10000, assignment["estimated_input_tokens"])
        self.assertEqual(2000, assignment["estimated_output_tokens"])
        self.assertEqual("model_price_and_token_hints", assignment["cost_evidence"])

    def test_unknown_open_code_quota_caps_pilot_pool_to_one_lane(self):
        pool = self.pools()["opencode.go"]
        pool.update(
            health="unknown",
            effective_remaining_percent=None,
            unknown_quota_policy="pilot",
            unknown_quota_pilot_percent=5,
            max_concurrency=4,
            inflight=0,
            available_model_variants={
                "opencode-go/deepseek-v4-flash": ["max"],
                "opencode-go/mimo-v2.5": [],
            },
        )
        state = {
            "pools": {"opencode.go": pool},
            "compute_hosts": {"local_mac": host("local_mac", "local")},
        }
        first = tiny_job("pilot-deepseek", "opencode.go")
        first["model_by_pool"] = {
            "opencode.go": {
                "model": "opencode-go/deepseek-v4-flash",
                "variant": "max",
            }
        }
        first["allow_policy_excluded_models"] = ["opencode-go/deepseek-v4-flash"]
        second = tiny_job("pilot-mimo", "opencode.go")
        second["model_by_pool"] = {"opencode.go": {"model": "opencode-go/mimo-v2.5"}}
        result = planner.plan(state, {"jobs": [first, second]}, max_lanes=2, horizon=2)
        self.assertEqual(1, len(result["assignments"]))
        self.assertEqual(1, result["quota_uncertainty"]["opencode.go"]["max_concurrency"])

    def test_capability_failure_is_model_variant_scoped(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime_path = pathlib.Path(temporary) / "runtime-state.json"
            state = {"runtime_state": str(runtime_path)}
            job = {"pool_id": "opencode.go"}
            attempt = {
                "pool_id": "opencode.go",
                "provider": "opencode",
                "model": "opencode-go/gpt-5.6-luna",
                "variant": "max",
            }
            continuity.record_runtime_feedback(
                state,
                job,
                attempt,
                success=False,
                error_class="capability",
                output="unsupported model variant",
            )
            runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
            self.assertNotIn("health", runtime["pools"]["opencode.go"])
            variant = runtime["models"]["opencode"]["opencode-go/gpt-5.6-luna"]["variants"]["max"]
            self.assertEqual("rejected", variant["runtime_state"])
            pools = {"opencode.go": {"health": "ready"}}
            self.assertEqual([], preflight.apply_runtime_overrides(pools, runtime, preflight.now()))
            self.assertEqual("ready", pools["opencode.go"]["health"])

    def test_quota_failure_cools_pool_without_rejecting_exact_model(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime_path = pathlib.Path(temporary) / "runtime-state.json"
            state = {"runtime_state": str(runtime_path)}
            continuity.record_runtime_feedback(
                state,
                {"pool_id": "opencode.go"},
                {
                    "pool_id": "opencode.go",
                    "provider": "opencode",
                    "model": "opencode-go/mimo-v2.5",
                },
                success=False,
                error_class="quota",
                output="usage limit reached",
            )
            runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
            self.assertEqual("cooldown", runtime["pools"]["opencode.go"]["health"])
            model = runtime["models"]["opencode"]["opencode-go/mimo-v2.5"]
            self.assertNotEqual("rejected", model.get("runtime_state"))
            self.assertEqual("quota", model["last_failure_class"])

    def test_opencode_attempt_requires_persisted_model_and_keeps_prompt_out_of_argv(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = pathlib.Path(temporary)
            prompt = workspace / "task.md"
            prompt.write_text("SECRET TASK BODY", encoding="utf-8")
            attempt = {
                "adapter": "opencode",
                "transport": "local",
                "prompt_file": str(prompt),
                "result_source_path": str(workspace / "result.txt"),
                "model": "opencode-go/mimo-v2.5",
            }
            argv, _, _, _ = continuity.build_attempt(
                {}, attempt, {"workspace": str(workspace)}, {}
            )
            self.assertIn("opencode-go/mimo-v2.5", argv)
            self.assertNotIn("SECRET TASK BODY", " ".join(argv))
            self.assertNotIn("--auto-approve", argv)
            attempt.pop("model")
            with self.assertRaisesRegex(ValueError, "exact model"):
                continuity.build_attempt({}, attempt, {"workspace": str(workspace)}, {})

    def test_missing_compute_inventory_is_fail_closed(self):
        self.assertEqual({}, planner.normalize_hosts({}))

    def test_unknown_host_capacity_is_not_treated_as_one_core_minimum(self):
        state = {
            "pools": {"codex.spark": ready_pool("codex.spark")},
            "compute_hosts": {
                "unmeasured": {
                    "host_id": "unmeasured", "transport": "local", "reachable": True,
                    "project_path_exists": True, "project_path_writable": True,
                }
            },
        }
        result = planner.plan(
            state,
            {"jobs": [tiny_job("unknown-capacity", "codex.spark")]},
            max_lanes=1,
            horizon=1,
        )
        self.assertEqual([], result["assignments"])
        self.assertEqual("pause", result["decision"])

    def test_unadvertised_explicit_variant_is_not_planned(self):
        pool = self.pools()["opencode.go"]
        pool.update(health="ready", effective_remaining_percent=90)
        state = {
            "pools": {"opencode.go": pool},
            "compute_hosts": {"local_mac": host("local_mac", "local")},
        }
        job = tiny_job("bad-variant", "opencode.go")
        job["model_by_pool"] = {
            "opencode.go": {
                "model": "opencode-go/gpt-5.6-luna",
                "variant": "ultra",
            }
        }
        result = planner.plan(state, {"jobs": [job]}, max_lanes=1, horizon=1)
        self.assertEqual([], result["assignments"])

    def test_opencode_balance_endpoint_defaults_to_official_usage_route(self):
        args = preflight.parse_args([])
        self.assertEqual(
            "https://opencode.ai/zen/go/v1/usage",
            args.opencode_go_usage_endpoint,
        )
        self.assertFalse(args.skip_opencode_go_usage)
        explicit = preflight.parse_args(
            ["--opencode-go-usage-endpoint", "https://usage.example.test/v1/usage"]
        )
        self.assertEqual(
            "https://usage.example.test/v1/usage",
            explicit.opencode_go_usage_endpoint,
        )
        with self.assertRaises(SystemExit):
            preflight.parse_args(["--opencode-go-usage-endpoint", "http://insecure.test"])


if __name__ == "__main__":
    unittest.main()
