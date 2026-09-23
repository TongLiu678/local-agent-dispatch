from __future__ import annotations

import pathlib
import sys
import unittest
from datetime import datetime, timedelta, timezone


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import dynamic_dispatch_planner as planner  # noqa: E402


class DynamicStorageEvidenceTests(unittest.TestCase):
    @staticmethod
    def _fresh_remote_host() -> dict:
        fresh_probe = (
            datetime.now(timezone.utc) - timedelta(seconds=60)
        ).isoformat()
        return {
            "host_id": "remote",
            "transport": "ssh",
            "reachable": True,
            "project_path_exists": True,
            "project_path_writable": True,
            "logical_cpu_cores": 8,
            "estimated_idle_cpu_cores": 8,
            "memory_available_gib": 32,
            "storage_paths": [
                {
                    "path": "/workspace/project",
                    "exists": True,
                    "writable": True,
                    "disk_total_gib": 550,
                    "disk_free_gib": 100,
                }
            ],
            "best_writable_storage_path": "/workspace/project",
            "last_probed_at_utc": fresh_probe,
            "storage_probe_ttl_seconds": 1800,
            "commands": {"python3": "/usr/bin/python3"},
        }

    @staticmethod
    def _network_evidence(status: str = "verified", age_seconds: int = 60) -> dict:
        observed = datetime.now(timezone.utc) - timedelta(seconds=age_seconds)
        ok = status == "verified"
        return {
            "status": status,
            "target_host_id": "remote",
            "observed_at_utc": observed.isoformat(),
            "ttl_seconds": planner.EXTERNAL_NETWORK_EVIDENCE_TTL_SECONDS,
            "targets": {
                "github.com": {"dns_resolved": ok, "https_reachable": ok},
                "opencode.ai": {"dns_resolved": ok, "https_reachable": ok},
            },
        }

    def test_stale_remote_mount_probe_is_rejected(self) -> None:
        host = {
            "host_id": "remote",
            "transport": "ssh",
            "reachable": True,
            "project_path_exists": True,
            "project_path_writable": True,
            "logical_cpu_cores": 8,
            "estimated_idle_cpu_cores": 8,
            "memory_available_gib": 32,
            "storage_paths": [
                {
                    "path": "/workspace/project",
                    "exists": True,
                    "writable": True,
                    "disk_total_gib": 550,
                    "disk_free_gib": 100,
                }
            ],
            "best_writable_storage_path": "/workspace/project",
            "last_probed_at_utc": "2026-08-12T00:00:00+00:00",
            "storage_probe_ttl_seconds": 1800,
            "commands": {"python3": "/usr/bin/python3"},
        }
        job = {"job_id": "j", "task_type": "code", "resources": {"ram_gib": 1}}
        estimate = planner.resource_estimate(job)
        fit, _score, _reasons, _route, errors = planner.host_fit(
            job, estimate, "remote", host
        )
        self.assertFalse(fit)
        self.assertIn("storage_evidence_stale", errors)

    def test_fresh_remote_mount_probe_is_accepted(self) -> None:
        fresh_probe = (
            datetime.now(timezone.utc) - timedelta(seconds=60)
        ).isoformat()
        host = {
            "host_id": "remote",
            "transport": "ssh",
            "reachable": True,
            "project_path_exists": True,
            "project_path_writable": True,
            "logical_cpu_cores": 8,
            "estimated_idle_cpu_cores": 8,
            "memory_available_gib": 32,
            "storage_paths": [
                {
                    "path": "/workspace/project",
                    "exists": True,
                    "writable": True,
                    "disk_total_gib": 550,
                    "disk_free_gib": 100,
                }
            ],
            "best_writable_storage_path": "/workspace/project",
            "last_probed_at_utc": fresh_probe,
            "storage_probe_ttl_seconds": 1800,
            "commands": {"python3": "/usr/bin/python3"},
        }
        job = {"job_id": "j", "task_type": "code", "resources": {"ram_gib": 1}}
        estimate = planner.resource_estimate(job)
        fit, _score, _reasons, _route, errors = planner.host_fit(
            job, estimate, "remote", host
        )
        self.assertTrue(fit, errors)

    def test_external_network_requirement_fails_closed_without_evidence(self) -> None:
        host = self._fresh_remote_host()
        job = {
            "job_id": "needs-network",
            "task_type": "code",
            "requires_external_network": True,
            "resources": {"ram_gib": 1},
        }
        fit, _score, _reasons, route, errors = planner.host_fit(
            job, planner.resource_estimate(job), "remote", host
        )
        self.assertFalse(fit)
        self.assertIn("external_network_unverified", errors)
        self.assertIn("verify_external_network_evidence", route["gates"])

    def test_fresh_verified_external_network_satisfies_requirement(self) -> None:
        host = self._fresh_remote_host()
        host["external_network_evidence"] = self._network_evidence()
        job = {
            "job_id": "needs-network",
            "task_type": "code",
            "requires_external_network": True,
            "resources": {"ram_gib": 1},
        }
        fit, _score, _reasons, _route, errors = planner.host_fit(
            job, planner.resource_estimate(job), "remote", host
        )
        self.assertTrue(fit, errors)

    def test_temporal_remote_job_blocks_material_clock_skew(self) -> None:
        host = self._fresh_remote_host()
        host["clock_evidence"] = {
            "status": "blocked",
            "offset_seconds": 8 * 3600,
            "max_allowed_seconds": planner.MAX_CLOCK_SKEW_SECONDS,
            "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "ttl_seconds": planner.EXTERNAL_NETWORK_EVIDENCE_TTL_SECONDS,
        }
        job = {
            "job_id": "skewed-temporal-job",
            "task_type": "monitor",
            "requires_clock_sync": True,
            "resources": {"ram_gib": 1},
        }
        fit, _score, _reasons, _route, errors = planner.host_fit(
            job, planner.resource_estimate(job), "remote", host
        )
        self.assertFalse(fit)
        self.assertIn("clock_skew_exceeds_limit", errors)

    def test_temporal_remote_job_blocks_fresh_unsynchronized_ntp(self) -> None:
        host = self._fresh_remote_host()
        observed = datetime.now(timezone.utc).isoformat()
        host["clock_evidence"] = {
            "status": "verified",
            "offset_seconds": 0,
            "max_allowed_seconds": planner.MAX_CLOCK_SKEW_SECONDS,
            "observed_at_utc": observed,
            "ttl_seconds": planner.EXTERNAL_NETWORK_EVIDENCE_TTL_SECONDS,
        }
        host["time_sync_evidence"] = {
            "status": "unsynchronized",
            "observed_at_utc": observed,
            "ttl_seconds": planner.EXTERNAL_NETWORK_EVIDENCE_TTL_SECONDS,
        }
        job = {
            "job_id": "ntp-unsynchronized-temporal-job",
            "task_type": "monitor",
            "requires_clock_sync": True,
            "resources": {"ram_gib": 1},
        }
        fit, _score, _reasons, _route, errors = planner.host_fit(
            job, planner.resource_estimate(job), "remote", host
        )
        self.assertFalse(fit)
        self.assertIn("clock_sync_service_unsynchronized", errors)

    def test_unsynchronized_ntp_without_clock_sample_is_not_verified(self) -> None:
        host = self._fresh_remote_host()
        observed = datetime.now(timezone.utc).isoformat()
        host["time_sync_evidence"] = {
            "status": "unsynchronized",
            "observed_at_utc": observed,
            "ttl_seconds": planner.EXTERNAL_NETWORK_EVIDENCE_TTL_SECONDS,
        }
        self.assertEqual("unsynchronized", planner.time_sync_evidence_status(host, now=observed))
        self.assertEqual("unsynchronized", planner.clock_evidence_status(host, now=observed))

    def test_mismatched_ntp_evidence_is_unknown(self) -> None:
        host = self._fresh_remote_host()
        observed = datetime.now(timezone.utc).isoformat()
        host["time_sync_evidence"] = {
            "status": "unsynchronized",
            "target_host_id": "other-host",
            "observed_at_utc": observed,
            "ttl_seconds": planner.EXTERNAL_NETWORK_EVIDENCE_TTL_SECONDS,
        }
        self.assertEqual("unknown", planner.time_sync_evidence_status(host, now=observed))

    def test_runtime_kernel_requirement_blocks_legacy_central_node(self) -> None:
        host = self._fresh_remote_host()
        host["kernel_release"] = "2.6.32-642.el6.x86_64"
        job = {
            "job_id": "opencode-runtime",
            "task_type": "code",
            "runtime_requirements": {"min_linux_kernel": "5.1"},
            "resources": {"ram_gib": 1},
        }
        estimate = planner.resource_estimate(job)
        fit, _score, _reasons, route, errors = planner.host_fit(
            job, estimate, "remote", host
        )
        self.assertFalse(fit)
        self.assertIn("linux_kernel_below_minimum", errors)
        self.assertIn("verify_linux_kernel_compatibility", route["gates"])

    def test_runtime_kernel_requirement_accepts_newer_remote_node(self) -> None:
        host = self._fresh_remote_host()
        host["kernel_release"] = "5.15.0-25-generic"
        job = {
            "job_id": "opencode-runtime",
            "task_type": "code",
            "min_linux_kernel": "5.1",
            "resources": {"ram_gib": 1},
        }
        fit, _score, _reasons, _route, errors = planner.host_fit(
            job, planner.resource_estimate(job), "remote", host
        )
        self.assertTrue(fit, errors)

    def test_runtime_kernel_requirement_fails_closed_without_host_evidence(self) -> None:
        host = self._fresh_remote_host()
        job = {
            "job_id": "opencode-runtime",
            "task_type": "code",
            "min_linux_kernel": "5.1",
            "resources": {"ram_gib": 1},
        }
        fit, _score, _reasons, _route, errors = planner.host_fit(
            job, planner.resource_estimate(job), "remote", host
        )
        self.assertFalse(fit)
        self.assertIn("linux_kernel_evidence_unknown", errors)

    def test_non_temporal_remote_job_keeps_legacy_host_compatibility(self) -> None:
        host = self._fresh_remote_host()
        job = {
            "job_id": "ordinary-remote-job",
            "task_type": "code",
            "resources": {"ram_gib": 1},
        }
        fit, _score, _reasons, _route, errors = planner.host_fit(
            job, planner.resource_estimate(job), "remote", host
        )
        self.assertTrue(fit, errors)

    def test_stale_external_network_evidence_is_rejected(self) -> None:
        host = self._fresh_remote_host()
        host["external_network_evidence"] = self._network_evidence(age_seconds=901)
        job = {
            "job_id": "needs-network",
            "task_type": "code",
            "requires_external_network": True,
            "resources": {"ram_gib": 1},
        }
        fit, _score, _reasons, _route, errors = planner.host_fit(
            job, planner.resource_estimate(job), "remote", host
        )
        self.assertFalse(fit)
        self.assertIn("external_network_evidence_stale", errors)

    def test_blocked_pool_reset_becomes_next_replan_when_no_lane_can_run(self) -> None:
        state = {
            "pools": {
                "codex.spark": {
                    "provider": "codex",
                    "health": "blocked",
                    "effective_remaining_percent": 0,
                    "primary": {"resets_at_utc": "2099-01-02T03:04:05Z"},
                    "default_model": "gpt-5.3-codex-spark",
                    "max_concurrency": 1,
                    "inflight": 0,
                }
            },
            "compute_hosts": {},
        }
        result = planner.plan(
            state,
            {
                "jobs": [
                    {
                        "job_id": "spark-code",
                        "task_type": "code",
                        "allowed_pools": ["codex.spark"],
                        "resources": {"ram_gib": 1},
                    }
                ]
            },
            1,
            8,
        )

        feedback = result["feedback"]
        self.assertEqual("blocked_pool_quota_reset", feedback["replan_reason"])
        self.assertEqual("codex.spark", feedback["quota_reset_pool_id"])
        self.assertEqual("2099-01-02T03:04:05+00:00", feedback["replan_at_utc"])
        self.assertEqual("2099-01-02T03:04:05+00:00", feedback["quota_reset_at_utc"])
        self.assertEqual([], result["assignments"])

    def test_past_or_malformed_reset_does_not_delay_normal_monitor_replan(self) -> None:
        now = datetime.now(timezone.utc)
        self.assertIsNone(
            planner._next_blocked_pool_reset(
                {
                    "codex.spark": {
                        "health": "blocked",
                        "effective_remaining_percent": 0,
                        "primary": {"resets_at_utc": (now - timedelta(seconds=1)).isoformat()},
                    },
                    "cursor.other": {
                        "health": "blocked",
                        "effective_remaining_percent": 0,
                        "primary": {"resets_at_utc": "not-a-timestamp"},
                    },
                },
                now,
            )
        )

    def test_next_reset_uses_the_earliest_future_window(self) -> None:
        now = datetime(2026, 8, 29, 14, 0, tzinfo=timezone.utc)
        reset = planner._next_blocked_pool_reset(
            {
                "codex.spark": {
                    "health": "blocked",
                    "effective_remaining_percent": 0,
                    "primary": {"resets_at_utc": "2026-08-29T16:47:03Z"},
                    "secondary": {"resets_at_utc": "2026-09-05T11:47:03Z"},
                },
                "antigravity.gemini": {
                    "health": "blocked",
                    "effective_remaining_percent": 0,
                    "primary": {"resets_at_utc": "2026-08-29T15:15:00Z"},
                },
            },
            now,
        )
        self.assertIsNotNone(reset)
        assert reset is not None
        self.assertEqual("antigravity.gemini", reset[0])
        self.assertEqual("2026-08-29T15:15:00+00:00", reset[1].isoformat())

    def test_non_quota_block_does_not_delay_replan_when_other_lane_runs(self) -> None:
        now = datetime(2026, 8, 29, 14, 0, tzinfo=timezone.utc)
        self.assertIsNone(
            planner._next_blocked_pool_reset(
                {
                    "codex.spark": {
                        "health": "blocked",
                        "effective_remaining_percent": 80,
                        "blocked_reason": "exact Codex model/effort rejected by runtime",
                        "primary": {"resets_at_utc": "2099-01-02T03:04:05Z"},
                    }
                },
                now,
            )
        )

    def test_assignment_keeps_monitor_replan_and_exposes_other_pool_reset(self) -> None:
        host = self._fresh_remote_host()
        host.update(
            {
                "host_id": "local",
                "transport": "local",
                "local_agent_launch_allowed": True,
            }
        )
        state = {
            "pools": {
                "codex.luna": {
                    "provider": "codex",
                    "health": "ready",
                    "effective_remaining_percent": 80,
                    "default_model": "gpt-5.6-luna",
                    "max_concurrency": 1,
                    "inflight": 0,
                },
                "codex.spark": {
                    "provider": "codex",
                    "health": "blocked",
                    "effective_remaining_percent": 0,
                    "primary": {"resets_at_utc": "2099-01-02T03:04:05Z"},
                    "default_model": "gpt-5.3-codex-spark",
                    "max_concurrency": 1,
                    "inflight": 0,
                },
            },
            "compute_hosts": {"local": host},
        }
        result = planner.plan(
            state,
            {
                "jobs": [
                    {
                        "job_id": "luna-code",
                        "task_type": "code",
                        "allowed_pools": ["codex.luna"],
                        "resources": {"ram_gib": 1},
                    }
                ]
            },
            1,
            8,
        )

        feedback = result["feedback"]
        self.assertEqual(1, len(result["assignments"]))
        self.assertEqual("monitor_interval", feedback["replan_reason"])
        self.assertNotEqual("2099-01-02T03:04:05+00:00", feedback["replan_at_utc"])
        self.assertEqual("codex.spark", feedback["quota_reset_pool_id"])

    def test_invalid_reserve_metadata_blocks_only_that_pool(self) -> None:
        host = self._fresh_remote_host()
        host.update(
            {
                "host_id": "local",
                "transport": "local",
                "local_agent_launch_allowed": True,
            }
        )
        state = {
            "pools": {
                "codex.luna": {
                    "provider": "codex",
                    "health": "ready",
                    "effective_remaining_percent": 80,
                    "reserve_percent": "not-a-number",
                    "default_model": "gpt-5.6-luna",
                    "max_concurrency": 1,
                    "inflight": 0,
                },
                "codex.spark": {
                    "provider": "codex",
                    "health": "ready",
                    "effective_remaining_percent": 80,
                    "reserve_percent": 10,
                    "default_model": "gpt-5.3-codex-spark",
                    "max_concurrency": 1,
                    "inflight": 0,
                },
            },
            "compute_hosts": {"local": host},
        }
        result = planner.plan(
            state,
            {
                "jobs": [
                    {
                        "job_id": "spark-code",
                        "task_type": "code",
                        "allowed_pools": ["codex.spark"],
                        "resources": {"ram_gib": 1},
                    }
                ]
            },
            1,
            8,
        )

        self.assertEqual("codex.spark", result["assignments"][0]["pool_id"])
        self.assertEqual(
            "invalid", result["quota_uncertainty"]["codex.luna"]["state"]
        )


if __name__ == "__main__":
    unittest.main()
