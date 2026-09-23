"""Provider-free tests for layered policy and adaptive concurrency."""

from __future__ import annotations

import json
import pathlib
import sys
import unittest
from dataclasses import replace

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from local_agent_dispatch.api import (  # noqa: E402
    CgroupResources,
    CpuResources,
    GpuResources,
    MemoryResources,
    MountResources,
    OwnedProcessResources,
    ResourceSnapshot,
    ResourceUsage,
    WorkerHeartbeat,
)
from local_agent_dispatch.scheduler.policy import (  # noqa: E402
    AdaptiveConcurrencyState,
    OrganizationPolicy,
    ProviderSignals,
    SafetyInvariants,
    SchedulingPolicyBundle,
    SchedulingPolicyError,
    TaskPreferences,
    TaskResourceEstimate,
    adapt_concurrency,
    resolve_policy,
)


GIB = 1024**3
NOW = "2026-09-22T12:00:00+00:00"
RECENT = "2026-09-22T11:59:30+00:00"
STALE = "2026-09-22T10:00:00+00:00"


def safety(*, maximum: int = 6) -> SafetyInvariants:
    return SafetyInvariants(
        hard_max_concurrency=maximum,
        min_memory_reserve_bytes=2 * GIB,
        min_disk_reserve_bytes=5 * GIB,
        min_quota_reserve_ratio=0.20,
        max_error_rate=0.10,
    )


def organization(
    *,
    minimum: int = 1,
    maximum: int = 8,
    revision: int = 1,
    scale_up_windows: int = 2,
    cooldown_seconds: int = 60,
) -> OrganizationPolicy:
    return OrganizationPolicy(
        policy_id="default",
        revision=revision,
        min_concurrency=minimum,
        max_concurrency=maximum,
        memory_reserve_bytes=GIB,
        disk_reserve_bytes=2 * GIB,
        quota_reserve_ratio=0.10,
        max_error_rate=0.20,
        target_latency_seconds=10,
        additive_increase=1,
        decrease_factor=0.5,
        scale_up_windows=scale_up_windows,
        cooldown_seconds=cooldown_seconds,
    )


def resolution(
    *,
    minimum: int = 1,
    maximum: int = 8,
    task: TaskPreferences | None = None,
) -> object:
    return resolve_policy(
        SchedulingPolicyBundle(
            safety=safety(),
            organization=organization(minimum=minimum, maximum=maximum),
            task=task,
        )
    )


def resources(
    *,
    sequence: int = 1,
    observed_at: str = RECENT,
    ttl_seconds: int | None = 120,
    cpu_available: float | None = 12,
    memory_available: int | None = 12 * GIB,
    swap_available: int | None = 4 * GIB,
    disk_available: int | None = 50 * GIB,
    free_inodes: int | None = 900_000,
    writable: bool | None = True,
    gpus: tuple[GpuResources, ...] = (),
    owned_processes: tuple[OwnedProcessResources, ...] = (),
) -> ResourceSnapshot:
    return ResourceSnapshot(
        snapshot_id=f"resource-{sequence}",
        host_id="host-a",
        worker_id="worker-a",
        cpu=CpuResources(
            capacity_cores=16,
            allocatable_cores=15,
            available_cores=cpu_available,
            utilization_percent=20,
        ),
        ram=MemoryResources(
            capacity_bytes=16 * GIB,
            allocatable_bytes=15 * GIB,
            available_bytes=memory_available,
            used_bytes=4 * GIB,
        ),
        swap=MemoryResources(
            capacity_bytes=4 * GIB,
            allocatable_bytes=4 * GIB,
            available_bytes=swap_available,
            used_bytes=0,
        ),
        cgroup=CgroupResources(),
        mounts=(
            MountResources(
                mount_path="/work",
                device="fixture",
                fs_type="fixturefs",
                writable=writable,
                capacity_bytes=100 * GIB,
                available_bytes=disk_available,
                total_inodes=1_000_000,
                free_inodes=free_inodes,
            ),
        ),
        gpus=gpus,
        owned_processes=owned_processes,
        observed_at=observed_at,
        ttl_seconds=ttl_seconds,
        source="fixture",
        confidence=1.0,
        sequence=sequence,
        idempotency_key=f"resource:{sequence}",
        fence_token=1,
    )


def heartbeat(
    *,
    sequence: int = 1,
    resource_sequence: int | None = None,
    observed_at: str = RECENT,
    ttl_seconds: int | None = 120,
    state: str = "ready",
    reserved: ResourceUsage | None = None,
    actual: ResourceUsage | None = None,
    active: tuple[str, ...] = (),
) -> WorkerHeartbeat:
    return WorkerHeartbeat(
        heartbeat_id=f"heartbeat-{sequence}",
        host_id="host-a",
        worker_id="worker-a",
        state=state,
        observed_at=observed_at,
        ttl_seconds=ttl_seconds,
        source="fixture",
        confidence=1.0,
        sequence=sequence,
        idempotency_key=f"heartbeat:{sequence}",
        fence_token=1,
        capability_sequence=None,
        resource_sequence=resource_sequence or sequence,
        reserved_usage=reserved
        or ResourceUsage(
            cpu_cores=4,
            ram_bytes=4 * GIB,
            swap_bytes=0,
            gpu_memory_bytes=0,
            disk_bytes=4 * GIB,
            inodes=1_000,
            owned_process_rss_bytes=0,
        ),
        actual_usage=actual
        or ResourceUsage(
            cpu_cores=2,
            ram_bytes=2 * GIB,
            swap_bytes=0,
            gpu_memory_bytes=0,
            disk_bytes=2 * GIB,
            inodes=500,
            owned_process_rss_bytes=0,
        ),
        active_execution_handles=active,
    )


def provider(
    *,
    sequence: int = 1,
    maximum: int | None = 6,
    quota: float | None = 0.80,
    error_rate: float | None = 0.01,
    latency: float | None = 2.0,
    timed_out: bool | None = False,
    observed_at: str = RECENT,
    ttl_seconds: int | None = 120,
) -> ProviderSignals:
    return ProviderSignals(
        provider_id="fixture-provider",
        max_concurrency=maximum,
        quota_remaining_ratio=quota,
        error_rate=error_rate,
        latency_seconds=latency,
        timed_out=timed_out,
        observed_at=observed_at,
        ttl_seconds=ttl_seconds,
        confidence=1.0,
        sequence=sequence,
    )


def estimate(
    *,
    cpu_cores: float | None = 1.0,
    memory_bytes: int = GIB,
    swap_bytes: int | None = 0,
    gpu_memory_bytes: int | None = 0,
    disk_bytes: int = GIB,
    inodes: int | None = 100,
    owned_process_rss_bytes: int | None = 512 * 1024**2,
    mount_path: str = "/work",
) -> TaskResourceEstimate:
    return TaskResourceEstimate(
        cpu_cores_per_slot=cpu_cores,
        memory_bytes_per_slot=memory_bytes,
        swap_bytes_per_slot=swap_bytes,
        gpu_memory_bytes_per_slot=gpu_memory_bytes,
        disk_bytes_per_slot=disk_bytes,
        inodes_per_slot=inodes,
        owned_process_rss_bytes_per_slot=owned_process_rss_bytes,
        mount_path=mount_path,
    )


def decide(
    state: AdaptiveConcurrencyState,
    *,
    policy: object | None = None,
    resource: ResourceSnapshot | None = None,
    worker_heartbeat: WorkerHeartbeat | None = None,
    provider_signals: ProviderSignals | None = None,
):
    return adapt_concurrency(
        state=state,
        policy=policy or resolution(),
        resource_snapshot=resource or resources(),
        heartbeat=worker_heartbeat or heartbeat(),
        provider=provider_signals or provider(),
        task_resources=estimate(),
        now=NOW,
    )


class LayeredPolicyTests(unittest.TestCase):
    def test_soft_layers_cannot_weaken_safety(self) -> None:
        task = TaskPreferences(
            task_id="task-a",
            preferred_max_concurrency=20,
            memory_reserve_bytes=0,
            disk_reserve_bytes=0,
            quota_reserve_ratio=0,
            max_error_rate=1,
        )

        result = resolution(task=task)

        self.assertTrue(result.valid)
        self.assertEqual(6, result.effective.max_concurrency)
        self.assertEqual(2 * GIB, result.effective.memory_reserve_bytes)
        self.assertEqual(5 * GIB, result.effective.disk_reserve_bytes)
        self.assertEqual(0.20, result.effective.quota_reserve_ratio)
        self.assertEqual(0.10, result.effective.max_error_rate)
        self.assertEqual(
            [
                (item.layer, item.field)
                for item in result.diagnostics
                if item.layer == "task"
            ],
            [
                ("task", "preferred_max_concurrency"),
                ("task", "memory_reserve_bytes"),
                ("task", "disk_reserve_bytes"),
                ("task", "quota_reserve_ratio"),
                ("task", "max_error_rate"),
            ],
        )

    def test_task_minimum_can_reduce_but_not_raise_organization_minimum(self) -> None:
        raised = resolution(
            minimum=2,
            task=TaskPreferences(
                task_id="task-a",
                preferred_min_concurrency=5,
            ),
        )
        self.assertEqual(2, raised.effective.min_concurrency)
        diagnostic = next(
            item
            for item in raised.diagnostics
            if item.code == "inherited_minimum_applied"
        )
        self.assertEqual(5, diagnostic.requested)
        self.assertEqual(2, diagnostic.applied)

        reduced = resolution(
            minimum=2,
            task=TaskPreferences(
                task_id="task-a",
                preferred_min_concurrency=0,
            ),
        )
        self.assertEqual(0, reduced.effective.min_concurrency)

    def test_impossible_organization_policy_is_diagnosed_and_blocks(self) -> None:
        bundle = SchedulingPolicyBundle(
            safety=safety(maximum=2),
            organization=organization(minimum=3, maximum=4),
        )
        policy = resolve_policy(bundle)

        self.assertFalse(policy.valid)
        self.assertEqual("impossible_concurrency_range", policy.diagnostics[-1].code)
        decision = decide(AdaptiveConcurrencyState(current_limit=2), policy=policy)
        self.assertEqual("blocked", decision.status)
        self.assertEqual(0, decision.target_concurrency)

    def test_hot_reload_requires_same_id_and_monotonic_revision(self) -> None:
        bundle = SchedulingPolicyBundle(
            safety=safety(), organization=organization(revision=1)
        )
        reloaded = bundle.with_organization(organization(revision=2, maximum=4))
        self.assertEqual(2, reloaded.organization.revision)
        self.assertEqual(4, reloaded.organization.max_concurrency)
        with self.assertRaisesRegex(SchedulingPolicyError, "revision"):
            reloaded.with_organization(organization(revision=2))

    def test_policy_round_trip_is_strict_and_schema_is_closed(self) -> None:
        bundle = SchedulingPolicyBundle(
            safety=safety(), organization=organization(), task=None
        )
        self.assertEqual(bundle, SchedulingPolicyBundle.from_json(bundle.to_json()))
        malformed = bundle.to_dict()
        malformed["surprise"] = True
        with self.assertRaisesRegex(SchedulingPolicyError, "unknown field"):
            SchedulingPolicyBundle.from_dict(malformed)

        schema = json.loads(
            (ROOT / "schemas" / "scheduling_policy.schema.json").read_text()
        )
        self.assertEqual(1, schema["properties"]["schema_version"]["const"])
        self.assertFalse(schema["additionalProperties"])
        self.assertTrue(
            schema["$defs"]["safety"]["properties"][
                "require_fresh_telemetry"
            ]["const"]
        )


class AdaptiveConcurrencyTests(unittest.TestCase):
    def test_healthy_windows_scale_up_additively(self) -> None:
        first = decide(AdaptiveConcurrencyState(current_limit=1))
        self.assertEqual("hold", first.status)
        self.assertEqual(1, first.next_state.healthy_windows)

        second = decide(
            first.next_state,
            resource=resources(sequence=2),
            worker_heartbeat=heartbeat(sequence=2),
            provider_signals=provider(sequence=2),
        )
        self.assertEqual("increase", second.status)
        self.assertEqual(2, second.target_concurrency)
        self.assertEqual(0, second.next_state.healthy_windows)

    def test_error_and_latency_pressure_scale_down_multiplicatively(self) -> None:
        high_error = decide(
            AdaptiveConcurrencyState(current_limit=4),
            provider_signals=provider(error_rate=0.5),
        )
        self.assertEqual("decrease", high_error.status)
        self.assertEqual(2, high_error.target_concurrency)
        self.assertIn("error rate", " ".join(high_error.reasons))

        high_latency = decide(
            AdaptiveConcurrencyState(current_limit=4),
            provider_signals=provider(latency=20),
        )
        self.assertEqual(2, high_latency.target_concurrency)
        self.assertIn("latency", " ".join(high_latency.reasons))

    def test_total_provider_errors_and_explicit_timeout_open_circuit(self) -> None:
        total_errors = decide(
            AdaptiveConcurrencyState(current_limit=4),
            provider_signals=provider(error_rate=1.0),
        )
        self.assertEqual("blocked", total_errors.status)
        self.assertEqual(0, total_errors.target_concurrency)
        self.assertIn("total error window", " ".join(total_errors.reasons))

        timeout = decide(
            AdaptiveConcurrencyState(current_limit=1),
            provider_signals=provider(timed_out=True),
        )
        self.assertEqual("blocked", timeout.status)
        self.assertEqual(0, timeout.target_concurrency)
        self.assertIn("explicit timeout", " ".join(timeout.reasons))

        unknown_timeout = decide(
            AdaptiveConcurrencyState(current_limit=1),
            provider_signals=provider(timed_out=None),
        )
        self.assertEqual("blocked", unknown_timeout.status)
        self.assertEqual(0, unknown_timeout.target_concurrency)
        self.assertIn("incomplete", " ".join(unknown_timeout.reasons))

    def test_stale_or_unknown_telemetry_fails_closed(self) -> None:
        stale = decide(
            AdaptiveConcurrencyState(current_limit=3),
            resource=resources(observed_at=STALE, ttl_seconds=60),
        )
        self.assertEqual("blocked", stale.status)
        self.assertEqual(0, stale.target_concurrency)
        self.assertIn("stale", " ".join(stale.reasons))

        unknown = decide(
            AdaptiveConcurrencyState(current_limit=3),
            provider_signals=provider(ttl_seconds=None),
        )
        self.assertEqual(0, unknown.target_concurrency)
        self.assertIn("unknown", " ".join(unknown.reasons))

    def test_provider_cap_is_a_hard_ceiling(self) -> None:
        decision = decide(
            AdaptiveConcurrencyState(current_limit=4),
            provider_signals=provider(maximum=2),
        )
        self.assertEqual("decrease", decision.status)
        self.assertEqual(2, decision.target_concurrency)
        self.assertEqual(2, decision.hard_cap)

    def test_memory_and_exact_mount_disk_reserves_gate_concurrency(self) -> None:
        memory = decide(
            AdaptiveConcurrencyState(current_limit=2),
            resource=resources(memory_available=GIB),
        )
        self.assertEqual(0, memory.target_concurrency)
        self.assertIn("RAM reserve gate", " ".join(memory.reasons))

        disk = decide(
            AdaptiveConcurrencyState(current_limit=2),
            resource=resources(disk_available=4 * GIB),
        )
        self.assertEqual(0, disk.target_concurrency)
        self.assertIn("disk reserve gate", " ".join(disk.reasons))

        wrong_mount = adapt_concurrency(
            state=AdaptiveConcurrencyState(current_limit=2),
            policy=resolution(),
            resource_snapshot=resources(),
            heartbeat=heartbeat(),
            provider=provider(),
            task_resources=replace(estimate(), mount_path="/other"),
            now=NOW,
        )
        self.assertEqual(0, wrong_mount.target_concurrency)
        self.assertIn("exact task mount", " ".join(wrong_mount.reasons))

    def test_windows_mount_spelling_is_canonicalized_for_exact_evidence(self) -> None:
        base = resources()
        windows_mount = MountResources(
            mount_path=r"c:\\WORK\\",
            device="fixture",
            fs_type="ntfs",
            writable=True,
            capacity_bytes=100 * GIB,
            available_bytes=50 * GIB,
            total_inodes=1_000_000,
            free_inodes=900_000,
        )
        snapshot = replace(base, mounts=(windows_mount,))
        task = replace(estimate(), mount_path="C:/work")
        decision = adapt_concurrency(
            state=AdaptiveConcurrencyState(current_limit=2),
            policy=resolution(),
            resource_snapshot=snapshot,
            heartbeat=heartbeat(),
            provider=provider(),
            task_resources=task,
            now=NOW,
        )
        self.assertNotIn("exact task mount evidence is missing", decision.reasons)
        self.assertEqual("C:/work", task.mount_path)
        self.assertEqual("C:/WORK", windows_mount.mount_path)

    def test_cpu_gpu_inode_and_owned_rss_cap_concurrency(self) -> None:
        cpu_limited = decide(
            AdaptiveConcurrencyState(current_limit=4),
            resource=resources(cpu_available=2),
        )
        self.assertEqual(2, cpu_limited.resource_cap)
        self.assertEqual(2, cpu_limited.target_concurrency)

        gpu_limited = adapt_concurrency(
            state=AdaptiveConcurrencyState(current_limit=4),
            policy=resolution(),
            resource_snapshot=resources(
                gpus=(
                    GpuResources(
                        gpu_id="gpu-0",
                        memory_capacity_bytes=8 * GIB,
                        memory_available_bytes=8 * GIB,
                    ),
                )
            ),
            heartbeat=heartbeat(),
            provider=provider(),
            task_resources=estimate(gpu_memory_bytes=4 * GIB),
            now=NOW,
        )
        self.assertEqual(2, gpu_limited.resource_cap)
        self.assertEqual(2, gpu_limited.target_concurrency)

        fragmented_gpu = adapt_concurrency(
            state=AdaptiveConcurrencyState(current_limit=2),
            policy=resolution(),
            resource_snapshot=resources(
                gpus=(
                    GpuResources(
                        gpu_id="gpu-0",
                        memory_capacity_bytes=3 * GIB,
                        memory_available_bytes=3 * GIB,
                    ),
                    GpuResources(
                        gpu_id="gpu-1",
                        memory_capacity_bytes=3 * GIB,
                        memory_available_bytes=3 * GIB,
                    ),
                )
            ),
            heartbeat=heartbeat(),
            provider=provider(),
            task_resources=estimate(gpu_memory_bytes=4 * GIB),
            now=NOW,
        )
        self.assertEqual(0, fragmented_gpu.resource_cap)
        self.assertEqual(0, fragmented_gpu.target_concurrency)

        inode_limited = adapt_concurrency(
            state=AdaptiveConcurrencyState(current_limit=4),
            policy=resolution(),
            resource_snapshot=resources(free_inodes=150),
            heartbeat=heartbeat(),
            provider=provider(),
            task_resources=estimate(inodes=100),
            now=NOW,
        )
        self.assertEqual(1, inode_limited.resource_cap)
        self.assertEqual(1, inode_limited.target_concurrency)

        rss_limited = adapt_concurrency(
            state=AdaptiveConcurrencyState(current_limit=4),
            policy=resolution(),
            resource_snapshot=resources(),
            heartbeat=heartbeat(),
            provider=provider(),
            task_resources=estimate(owned_process_rss_bytes=4 * GIB),
            now=NOW,
        )
        self.assertEqual(2, rss_limited.resource_cap)
        self.assertEqual(2, rss_limited.target_concurrency)

    def test_unknown_extended_resource_evidence_fails_closed(self) -> None:
        unknown_cpu = decide(
            AdaptiveConcurrencyState(current_limit=2),
            resource=resources(cpu_available=None),
        )
        self.assertEqual(0, unknown_cpu.target_concurrency)
        self.assertIn("CPU available_cores is unknown", " ".join(unknown_cpu.reasons))

        unknown_gpu = adapt_concurrency(
            state=AdaptiveConcurrencyState(current_limit=2),
            policy=resolution(),
            resource_snapshot=resources(
                gpus=(
                    GpuResources(
                        gpu_id="gpu-0",
                        memory_capacity_bytes=8 * GIB,
                        memory_available_bytes=None,
                    ),
                )
            ),
            heartbeat=heartbeat(),
            provider=provider(),
            task_resources=estimate(gpu_memory_bytes=GIB),
            now=NOW,
        )
        self.assertEqual(0, unknown_gpu.target_concurrency)
        self.assertIn("GPU available memory is unknown", " ".join(unknown_gpu.reasons))

        unknown_inode = adapt_concurrency(
            state=AdaptiveConcurrencyState(current_limit=2),
            policy=resolution(),
            resource_snapshot=resources(free_inodes=None),
            heartbeat=heartbeat(),
            provider=provider(),
            task_resources=estimate(inodes=100),
            now=NOW,
        )
        self.assertEqual(0, unknown_inode.target_concurrency)
        self.assertIn("free_inodes is unknown", " ".join(unknown_inode.reasons))

        unknown_rss = adapt_concurrency(
            state=AdaptiveConcurrencyState(current_limit=2),
            policy=resolution(),
            resource_snapshot=resources(
                owned_processes=(
                    OwnedProcessResources(
                        process_id="process-a",
                        attempt_id="attempt-a",
                        pid=123,
                        started_at=RECENT,
                        fence_token=1,
                        rss_bytes=None,
                    ),
                )
            ),
            heartbeat=heartbeat(),
            provider=provider(),
            task_resources=estimate(owned_process_rss_bytes=GIB),
            now=NOW,
        )
        self.assertEqual(0, unknown_rss.target_concurrency)
        self.assertIn("owned-process RSS evidence is unknown", " ".join(unknown_rss.reasons))

        unknown_estimate = adapt_concurrency(
            state=AdaptiveConcurrencyState(current_limit=2),
            policy=resolution(),
            resource_snapshot=resources(),
            heartbeat=heartbeat(),
            provider=provider(),
            task_resources=estimate(cpu_cores=None),
            now=NOW,
        )
        self.assertEqual(0, unknown_estimate.target_concurrency)
        self.assertIn("per-slot cpu_cores estimate is unknown", " ".join(unknown_estimate.reasons))

    def test_quota_reserve_is_a_hard_gate(self) -> None:
        decision = decide(
            AdaptiveConcurrencyState(current_limit=3),
            provider_signals=provider(quota=0.20),
        )
        self.assertEqual("blocked", decision.status)
        self.assertEqual(0, decision.target_concurrency)
        self.assertIn("quota reserve gate", " ".join(decision.reasons))

    def test_hysteresis_cooldown_and_duplicate_evidence_prevent_flapping(self) -> None:
        state = AdaptiveConcurrencyState(
            current_limit=1,
            healthy_windows=1,
            last_adjusted_at="2026-09-22T11:59:30+00:00",
            last_resource_sequence=1,
            last_heartbeat_sequence=1,
            last_provider_sequence=1,
        )
        cooling = decide(
            state,
            resource=resources(sequence=2),
            worker_heartbeat=heartbeat(sequence=2),
            provider_signals=provider(sequence=2),
        )
        self.assertEqual("hold", cooling.status)
        self.assertEqual(1, cooling.target_concurrency)
        self.assertIn("cooldown", " ".join(cooling.reasons))

        duplicate = decide(
            cooling.next_state,
            resource=resources(sequence=2),
            worker_heartbeat=heartbeat(sequence=2),
            provider_signals=provider(sequence=2),
        )
        self.assertEqual("hold", duplicate.status)
        self.assertIn("duplicate evidence", " ".join(duplicate.reasons))

    def test_unknown_usage_and_sequence_regression_fail_closed(self) -> None:
        unknown_usage = decide(
            AdaptiveConcurrencyState(current_limit=2),
            worker_heartbeat=heartbeat(
                reserved=ResourceUsage(ram_bytes=4 * GIB),
                actual=ResourceUsage(),
            ),
        )
        self.assertEqual(0, unknown_usage.target_concurrency)
        self.assertIn("reconciliation is unknown", " ".join(unknown_usage.reasons))

        regression = decide(
            AdaptiveConcurrencyState(
                current_limit=2,
                last_resource_sequence=2,
                last_heartbeat_sequence=2,
                last_provider_sequence=2,
            )
        )
        self.assertEqual(0, regression.target_concurrency)
        self.assertIn("regressed", " ".join(regression.reasons))
        self.assertEqual(2, regression.next_state.last_resource_sequence)
        self.assertEqual(2, regression.next_state.last_heartbeat_sequence)
        self.assertEqual(2, regression.next_state.last_provider_sequence)

        repeated = decide(regression.next_state)
        self.assertEqual(0, repeated.target_concurrency)
        self.assertIn("regressed", " ".join(repeated.reasons))


if __name__ == "__main__":
    unittest.main()
