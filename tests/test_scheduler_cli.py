"""Provider-free CLI tests for strict scheduler policy replay."""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from local_agent_dispatch import cli  # noqa: E402
from local_agent_dispatch.api import (  # noqa: E402
    CgroupResources,
    CpuResources,
    MemoryResources,
    MountResources,
    ResourceSnapshot,
    ResourceUsage,
    WorkerHeartbeat,
)
from local_agent_dispatch.scheduler import (  # noqa: E402
    AdaptiveConcurrencyState,
    ConcurrencyDecision,
    OrganizationPolicy,
    ProviderSignals,
    SafetyInvariants,
    SchedulerDecisionInput,
    SchedulingPolicyBundle,
    TaskPreferences,
    TaskResourceEstimate,
)


GIB = 1024**3
NOW = "2026-09-22T12:00:00+00:00"
RECENT = "2026-09-22T11:59:30+00:00"
STALE = "2026-09-22T10:00:00+00:00"


def bundle(*, task_minimum: int | None = None) -> SchedulingPolicyBundle:
    return SchedulingPolicyBundle(
        safety=SafetyInvariants(
            hard_max_concurrency=6,
            min_memory_reserve_bytes=2 * GIB,
            min_disk_reserve_bytes=5 * GIB,
            min_quota_reserve_ratio=0.2,
            max_error_rate=0.1,
        ),
        organization=OrganizationPolicy(
            policy_id="default",
            revision=1,
            min_concurrency=1,
            max_concurrency=6,
            memory_reserve_bytes=GIB,
            disk_reserve_bytes=2 * GIB,
            quota_reserve_ratio=0.1,
            max_error_rate=0.2,
            target_latency_seconds=10,
            additive_increase=1,
            decrease_factor=0.5,
            scale_up_windows=2,
            cooldown_seconds=30,
        ),
        task=(
            TaskPreferences(
                task_id="task-a",
                preferred_min_concurrency=task_minimum,
            )
            if task_minimum is not None
            else None
        ),
    )


def resource_snapshot(
    *,
    observed_at: str = RECENT,
    ttl_seconds: int | None = 120,
) -> ResourceSnapshot:
    return ResourceSnapshot(
        snapshot_id="resource-1",
        host_id="host-a",
        worker_id="worker-a",
        cpu=CpuResources(
            capacity_cores=16,
            allocatable_cores=15,
            available_cores=12,
            utilization_percent=20,
        ),
        ram=MemoryResources(
            capacity_bytes=16 * GIB,
            allocatable_bytes=15 * GIB,
            available_bytes=12 * GIB,
            used_bytes=4 * GIB,
        ),
        swap=MemoryResources(
            capacity_bytes=4 * GIB,
            allocatable_bytes=4 * GIB,
            available_bytes=4 * GIB,
            used_bytes=0,
        ),
        cgroup=CgroupResources(),
        mounts=(
            MountResources(
                mount_path="/work",
                writable=True,
                capacity_bytes=100 * GIB,
                available_bytes=50 * GIB,
                total_inodes=1_000_000,
                free_inodes=900_000,
            ),
        ),
        gpus=(),
        owned_processes=(),
        observed_at=observed_at,
        ttl_seconds=ttl_seconds,
        source="fixture",
        confidence=1.0,
        sequence=1,
        idempotency_key="resource:1",
        fence_token=1,
    )


def heartbeat() -> WorkerHeartbeat:
    return WorkerHeartbeat(
        heartbeat_id="heartbeat-1",
        host_id="host-a",
        worker_id="worker-a",
        state="ready",
        observed_at=RECENT,
        ttl_seconds=120,
        source="fixture",
        confidence=1.0,
        sequence=1,
        idempotency_key="heartbeat:1",
        fence_token=1,
        capability_sequence=None,
        resource_sequence=1,
        reserved_usage=ResourceUsage(
            cpu_cores=4,
            ram_bytes=4 * GIB,
            swap_bytes=0,
            gpu_memory_bytes=0,
            disk_bytes=4 * GIB,
            inodes=1_000,
            owned_process_rss_bytes=0,
        ),
        actual_usage=ResourceUsage(
            cpu_cores=2,
            ram_bytes=2 * GIB,
            swap_bytes=0,
            gpu_memory_bytes=0,
            disk_bytes=2 * GIB,
            inodes=500,
            owned_process_rss_bytes=0,
        ),
        active_execution_handles=(),
    )


def provider(*, timed_out: bool | None = False) -> ProviderSignals:
    return ProviderSignals(
        provider_id="fixture-provider",
        max_concurrency=6,
        quota_remaining_ratio=0.8,
        error_rate=0.01,
        latency_seconds=2,
        timed_out=timed_out,
        observed_at=RECENT,
        ttl_seconds=120,
        confidence=1.0,
        sequence=1,
    )


def task_resources() -> TaskResourceEstimate:
    return TaskResourceEstimate(
        cpu_cores_per_slot=1,
        memory_bytes_per_slot=GIB,
        swap_bytes_per_slot=0,
        gpu_memory_bytes_per_slot=0,
        disk_bytes_per_slot=GIB,
        inodes_per_slot=100,
        owned_process_rss_bytes_per_slot=512 * 1024**2,
        mount_path="/work",
    )


def decision_input(
    *,
    resource: ResourceSnapshot | None = None,
    provider_signals: ProviderSignals | None = None,
) -> SchedulerDecisionInput:
    return SchedulerDecisionInput(
        bundle=bundle(),
        state=AdaptiveConcurrencyState(current_limit=1),
        resource_snapshot=resource or resource_snapshot(),
        heartbeat=heartbeat(),
        provider=provider_signals or provider(),
        task_resources=task_resources(),
        now=NOW,
    )


class SchedulerCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_json(self, name: str, payload: object) -> pathlib.Path:
        path = self.root / name
        path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        return path

    def run_cli(self, *args: str) -> tuple[int, dict[str, object], str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
            mock.patch.object(
                cli.subprocess,
                "run",
                side_effect=AssertionError("scheduler CLI must not run subprocesses"),
            ),
        ):
            code = cli.main(list(args))
        return code, json.loads(stdout.getvalue()), stderr.getvalue()

    def test_resolve_reports_effective_policy_and_task_escalation(self) -> None:
        path = self.write_json("policy.json", bundle(task_minimum=5).to_dict())

        code, payload, stderr = self.run_cli(
            "scheduler", "resolve", "--input", str(path)
        )

        self.assertEqual(0, code)
        self.assertTrue(payload["ok"])
        self.assertEqual("scheduler.resolve", payload["command"])
        self.assertEqual(1, payload["resolution"]["effective"]["min_concurrency"])
        self.assertIn(
            "inherited_minimum_applied",
            [item["code"] for item in payload["resolution"]["diagnostics"]],
        )
        self.assertTrue(payload["read_only"])
        self.assertFalse(payload["network_accessed"])
        self.assertFalse(payload["provider_contacted"])
        self.assertEqual("", stderr)

    def test_decide_returns_typed_decision_and_next_state(self) -> None:
        envelope = decision_input()
        self.assertEqual(
            envelope,
            SchedulerDecisionInput.from_dict(envelope.to_dict()),
        )
        path = self.write_json("decision.json", envelope.to_dict())

        code, payload, stderr = self.run_cli(
            "scheduler", "decide", "--input", str(path)
        )

        self.assertEqual(0, code)
        self.assertEqual("scheduler.decide", payload["command"])
        self.assertEqual("hold", payload["decision"]["status"])
        self.assertEqual(1, payload["decision"]["target_concurrency"])
        self.assertEqual(1, payload["decision"]["next_state"]["healthy_windows"])
        restored = ConcurrencyDecision.from_dict(payload["decision"])
        self.assertEqual(payload["decision"], restored.to_dict())
        self.assertEqual(
            "evaluated-only-from-supplied-timestamps-and-now",
            payload["evidence_boundary"]["freshness"],
        )
        self.assertFalse(payload["live_probe_performed"])
        self.assertFalse(payload["provider_prompt_sent"])
        self.assertEqual("", stderr)

    def test_stale_and_unknown_evidence_return_zero(self) -> None:
        cases = (
            ("stale", resource_snapshot(observed_at=STALE, ttl_seconds=60)),
            ("unknown", resource_snapshot(ttl_seconds=None)),
        )
        for label, resource in cases:
            with self.subTest(label=label):
                path = self.write_json(
                    f"{label}.json",
                    decision_input(resource=resource).to_dict(),
                )
                code, payload, _ = self.run_cli(
                    "scheduler", "decide", "--input", str(path)
                )
                self.assertEqual(0, code)
                self.assertEqual("blocked", payload["decision"]["status"])
                self.assertEqual(0, payload["decision"]["target_concurrency"])
                self.assertIn(label, " ".join(payload["decision"]["reasons"]))

    def test_explicit_provider_timeout_returns_zero(self) -> None:
        path = self.write_json(
            "timeout.json",
            decision_input(provider_signals=provider(timed_out=True)).to_dict(),
        )

        code, payload, _ = self.run_cli(
            "scheduler", "decide", "--input", str(path)
        )

        self.assertEqual(0, code)
        self.assertEqual("blocked", payload["decision"]["status"])
        self.assertEqual(0, payload["decision"]["target_concurrency"])
        self.assertIn("explicit timeout", " ".join(payload["decision"]["reasons"]))

    def test_duplicate_and_unknown_fields_are_rejected(self) -> None:
        duplicate = self.root / "duplicate.json"
        valid_text = json.dumps(decision_input().to_dict(), sort_keys=True)
        duplicate.write_text(
            valid_text.replace(
                '"provider_id": "fixture-provider"',
                (
                    '"provider_id": "fixture-provider", '
                    '"provider_id": "shadowed"'
                ),
                1,
            ),
            encoding="utf-8",
        )
        duplicate_code, duplicate_payload, _ = self.run_cli(
            "scheduler", "decide", "--input", str(duplicate)
        )
        self.assertEqual(2, duplicate_code)
        self.assertFalse(duplicate_payload["ok"])
        self.assertIn("duplicate JSON key", duplicate_payload["error"]["message"])

        unknown_payload = decision_input().to_dict()
        unknown_payload["surprise"] = True
        unknown = self.write_json("unknown-field.json", unknown_payload)
        unknown_code, unknown_result, _ = self.run_cli(
            "scheduler", "decide", "--input", str(unknown)
        )
        self.assertEqual(2, unknown_code)
        self.assertFalse(unknown_result["ok"])
        self.assertIn("unknown field", unknown_result["error"]["message"])

        nested_payload = decision_input().to_dict()
        nested_payload["provider"]["surprise"] = True
        nested = self.write_json("nested-unknown-field.json", nested_payload)
        nested_code, nested_result, _ = self.run_cli(
            "scheduler", "decide", "--input", str(nested)
        )
        self.assertEqual(2, nested_code)
        self.assertFalse(nested_result["ok"])
        self.assertIn("ProviderSignals", nested_result["error"]["message"])
        self.assertIn("unknown field", nested_result["error"]["message"])

    def test_decision_input_schema_is_versioned_and_closed(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "scheduler_decision_input.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(1, schema["properties"]["schema_version"]["const"])
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            {
                "schema_version",
                "bundle",
                "state",
                "resource_snapshot",
                "heartbeat",
                "provider",
                "task_resources",
                "now",
            },
            set(schema["required"]),
        )


if __name__ == "__main__":
    unittest.main()
