"""Provider-free conformance tests for controller/worker v1 contracts."""

from __future__ import annotations

import json
import pathlib
import sys
import threading
import unittest
from dataclasses import replace

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from local_agent_dispatch.api import (  # noqa: E402
    Capability,
    CapabilitySnapshot,
    CgroupResources,
    ContractValidationError,
    CpuResources,
    ExecutionHandle,
    GpuResources,
    HostRegistration,
    MemoryResources,
    MountResources,
    OwnedProcessResources,
    ResourceSnapshot,
    ResourceUsage,
    WorkerHeartbeat,
)
from local_agent_dispatch.worker import (  # noqa: E402
    WorkerFenceError,
    WorkerIdentityError,
    WorkerIdempotencyError,
    WorkerSequenceError,
    WorkerState,
    reconcile_usage,
)

NOW = "2026-09-22T12:00:00+00:00"
EARLIER = "2026-09-22T11:59:30+00:00"
LATER = "2026-09-22T12:02:00+00:00"


def registration(*, fence: int = 1, key: str | None = None) -> HostRegistration:
    return HostRegistration(
        registration_id=f"registration-{fence}",
        host_id="host-a",
        worker_id="worker-a",
        roles=("execution", "workload"),
        registered_at=EARLIER,
        idempotency_key=key or f"registration:{fence}",
        fence_token=fence,
        labels=("fixture",),
    )


def capabilities(
    *, sequence: int = 1, fence: int = 1, confidence: float | None = 1.0
) -> CapabilitySnapshot:
    return CapabilitySnapshot(
        snapshot_id=f"capability-{sequence}",
        host_id="host-a",
        worker_id="worker-a",
        capabilities=(
            Capability(
                capability_id="python",
                kind="runtime",
                status="available",
                version="3.11",
            ),
            Capability(
                capability_id="provider-state",
                kind="other",
                status="unknown",
            ),
        ),
        observed_at=EARLIER,
        ttl_seconds=120,
        source="fixture",
        confidence=confidence,
        sequence=sequence,
        idempotency_key=f"capability:{sequence}:f{fence}",
        fence_token=fence,
    )


def resources(
    *, sequence: int = 1, fence: int = 1, confidence: float | None = 1.0
) -> ResourceSnapshot:
    return ResourceSnapshot(
        snapshot_id=f"resource-{sequence}",
        host_id="host-a",
        worker_id="worker-a",
        cpu=CpuResources(
            capacity_cores=8,
            allocatable_cores=7,
            available_cores=5,
            utilization_percent=25,
        ),
        ram=MemoryResources(
            capacity_bytes=16_000,
            allocatable_bytes=15_000,
            available_bytes=10_000,
            used_bytes=5_000,
        ),
        swap=MemoryResources(
            capacity_bytes=4_000,
            allocatable_bytes=4_000,
            available_bytes=3_000,
            used_bytes=1_000,
        ),
        cgroup=CgroupResources(
            cpu_quota_cores=4,
            memory_limit_bytes=8_000,
            memory_current_bytes=2_000,
            swap_limit_bytes=None,
            swap_current_bytes=None,
        ),
        mounts=(
            MountResources(
                mount_path="/data",
                device="/dev/fake1",
                fs_type="xfs",
                writable=True,
                capacity_bytes=100_000,
                available_bytes=75_000,
                total_inodes=10_000,
                free_inodes=9_000,
            ),
        ),
        gpus=(
            GpuResources(
                gpu_id="gpu-0",
                model="fixture-gpu",
                memory_capacity_bytes=24_000,
                memory_available_bytes=20_000,
                utilization_percent=10,
            ),
        ),
        owned_processes=(
            OwnedProcessResources(
                process_id="process-1",
                attempt_id="attempt-1",
                pid=1234,
                started_at=EARLIER,
                fence_token=fence,
                rss_bytes=512,
                gpu_memory_bytes=256,
            ),
        ),
        observed_at=EARLIER,
        ttl_seconds=120,
        source="fixture",
        confidence=confidence,
        sequence=sequence,
        idempotency_key=f"resource:{sequence}:f{fence}",
        fence_token=fence,
    )


def heartbeat(
    *,
    sequence: int = 1,
    fence: int = 1,
    observed_at: str = EARLIER,
    ttl_seconds: int | None = 120,
    confidence: float | None = 1.0,
    state: str = "ready",
    reserved: ResourceUsage | None = None,
    actual: ResourceUsage | None = None,
    key: str | None = None,
) -> WorkerHeartbeat:
    return WorkerHeartbeat(
        heartbeat_id=f"heartbeat-{sequence}-f{fence}",
        host_id="host-a",
        worker_id="worker-a",
        state=state,
        observed_at=observed_at,
        ttl_seconds=ttl_seconds,
        source="fixture",
        confidence=confidence,
        sequence=sequence,
        idempotency_key=key or f"heartbeat:{sequence}:f{fence}",
        fence_token=fence,
        capability_sequence=1,
        resource_sequence=1,
        reserved_usage=reserved or ResourceUsage(cpu_cores=2, ram_bytes=2_000),
        actual_usage=actual or ResourceUsage(cpu_cores=1, ram_bytes=1_000),
        active_execution_handles=(),
    )


def execution_handle(*, sequence: int = 1, state: str = "running") -> ExecutionHandle:
    return ExecutionHandle(
        handle_id="handle-1",
        job_id="job-1",
        attempt_id="attempt-1",
        host_id="host-a",
        worker_id="worker-a",
        state=state,
        observed_at=EARLIER,
        ttl_seconds=120,
        source="fixture",
        confidence=1.0,
        sequence=sequence,
        idempotency_key=f"handle:1:{sequence}",
        fence_token=1,
        reservation_id="reservation-1" if state == "running" else None,
        process_id="process-1" if state == "running" else None,
        reserved_usage=ResourceUsage(cpu_cores=2, ram_bytes=2_000),
        actual_usage=ResourceUsage(cpu_cores=1, ram_bytes=1_000),
        artifact_refs=("artifact:result",),
    )


class ContractSerializationTests(unittest.TestCase):
    def test_all_top_level_contracts_round_trip_through_canonical_json(self) -> None:
        values = (
            registration(),
            capabilities(),
            resources(),
            heartbeat(),
            execution_handle(),
        )
        for value in values:
            with self.subTest(type=type(value).__name__):
                encoded = value.to_json()
                self.assertEqual(encoded, type(value).from_json(encoded).to_json())
                self.assertEqual(value, type(value).from_dict(value.to_dict()))

    def test_unknown_values_round_trip_as_null_and_are_not_fabricated(self) -> None:
        snapshot = ResourceSnapshot(
            snapshot_id="unknown-resource",
            host_id="host-a",
            worker_id="worker-a",
            cpu=CpuResources(),
            ram=MemoryResources(),
            swap=MemoryResources(),
            cgroup=CgroupResources(),
            mounts=(MountResources(mount_path="/data"),),
            gpus=(),
            owned_processes=(),
            observed_at=EARLIER,
            ttl_seconds=None,
            source="fixture",
            confidence=None,
            sequence=1,
            idempotency_key="resource:unknown",
            fence_token=1,
        )
        payload = json.loads(snapshot.to_json())
        self.assertIsNone(payload["cpu"]["capacity_cores"])
        self.assertIsNone(payload["ram"]["available_bytes"])
        self.assertIsNone(payload["mounts"][0]["free_inodes"])
        self.assertIsNone(payload["ttl_seconds"])
        self.assertIsNone(payload["confidence"])
        self.assertEqual("unknown", snapshot.freshness(NOW))

    def test_version_unknown_fields_and_duplicate_json_keys_fail_closed(self) -> None:
        payload = registration().to_dict()
        payload["schema_version"] = 2
        with self.assertRaisesRegex(ContractValidationError, "schema_version"):
            HostRegistration.from_dict(payload)

        payload = registration().to_dict()
        payload["schema_version"] = True
        with self.assertRaisesRegex(ContractValidationError, "schema_version"):
            HostRegistration.from_dict(payload)

        payload = registration().to_dict()
        payload["endpoint"] = "not-part-of-v1"
        with self.assertRaisesRegex(ContractValidationError, "unknown field"):
            HostRegistration.from_dict(payload)

        with self.assertRaisesRegex(ContractValidationError, "duplicate JSON key"):
            HostRegistration.from_json(
                '{"schema_version":1,"schema_version":1}'
            )

    def test_exact_mounts_and_owned_process_contracts_reject_unsafe_shapes(self) -> None:
        with self.assertRaisesRegex(ContractValidationError, "absolute path"):
            MountResources(mount_path="relative/data")
        with self.assertRaisesRegex(ContractValidationError, "unknown field"):
            OwnedProcessResources.from_dict(
                {
                    **resources().owned_processes[0].to_dict(),
                    "argv": ["python", "secret.py"],
                }
            )
        with self.assertRaisesRegex(ContractValidationError, "must match"):
            replace(
                resources(),
                owned_processes=(
                    replace(resources().owned_processes[0], fence_token=2),
                ),
            )

    def test_resource_snapshot_tracks_all_required_resource_classes(self) -> None:
        snapshot = resources()
        self.assertEqual(8, snapshot.cpu.capacity_cores)
        self.assertEqual(10_000, snapshot.ram.available_bytes)
        self.assertEqual(3_000, snapshot.swap.available_bytes)
        self.assertEqual(8_000, snapshot.cgroup.memory_limit_bytes)
        self.assertEqual("/data", snapshot.mounts[0].mount_path)
        self.assertEqual(9_000, snapshot.mounts[0].free_inodes)
        self.assertEqual("gpu-0", snapshot.gpus[0].gpu_id)
        self.assertEqual(512, snapshot.owned_process_rss_bytes())

    def test_freshness_is_three_valued_and_future_evidence_is_unknown(self) -> None:
        self.assertEqual("fresh", resources().freshness(NOW))
        self.assertEqual("stale", resources().freshness(LATER))
        self.assertEqual("unknown", replace(resources(), ttl_seconds=None).freshness(NOW))
        future = replace(resources(), observed_at=LATER)
        self.assertEqual("unknown", future.freshness(NOW))

    def test_running_handle_requires_reservation_and_owned_process_reference(self) -> None:
        with self.assertRaisesRegex(ContractValidationError, "running execution"):
            replace(execution_handle(), process_id=None)

    def test_json_schemas_are_versioned_and_strict(self) -> None:
        schema_names = (
            "host_registration",
            "capability_snapshot",
            "resource_snapshot",
            "worker_heartbeat",
            "execution_handle",
        )
        for name in schema_names:
            with self.subTest(schema=name):
                schema = json.loads((ROOT / "schemas" / f"{name}.schema.json").read_text())
                self.assertFalse(schema["additionalProperties"])
                self.assertEqual(1, schema["properties"]["schema_version"]["const"])
                self.assertEqual(
                    "local-agent-dispatch.worker.v1",
                    schema["properties"]["api_version"]["const"],
                )


class WorkerProjectionTests(unittest.TestCase):
    def ready_state(self) -> WorkerState:
        state = WorkerState()
        state.apply_registration(registration())
        state.apply_capability_snapshot(capabilities())
        state.apply_resource_snapshot(resources())
        state.apply_heartbeat(heartbeat())
        return state

    def test_projection_becomes_ready_only_with_correlated_fresh_evidence(self) -> None:
        state = WorkerState()
        self.assertEqual("unknown", state.admission_status(NOW))
        state.apply_registration(registration())
        state.apply_heartbeat(heartbeat())
        self.assertEqual("unknown", state.admission_status(NOW))
        state.apply_capability_snapshot(capabilities())
        state.apply_resource_snapshot(resources())
        self.assertEqual("ready", state.admission_status(NOW))
        self.assertEqual("within", state.usage_reconciliation().status)

    def test_heartbeat_sequence_cannot_roll_back_or_conflict(self) -> None:
        state = WorkerState()
        state.apply_registration(registration())
        first = heartbeat(sequence=1)
        second = replace(
            heartbeat(sequence=2),
            capability_sequence=1,
            resource_sequence=1,
        )
        self.assertTrue(state.apply_heartbeat(first))
        self.assertFalse(state.apply_heartbeat(first))
        self.assertTrue(state.apply_heartbeat(second))
        with self.assertRaisesRegex(WorkerSequenceError, "rollback"):
            state.apply_heartbeat(replace(first, idempotency_key="heartbeat:late"))
        with self.assertRaisesRegex(WorkerSequenceError, "reused"):
            state.apply_heartbeat(
                replace(second, idempotency_key="heartbeat:same-sequence")
            )

    def test_idempotency_key_cannot_name_different_heartbeat_content(self) -> None:
        state = WorkerState()
        state.apply_registration(registration())
        first = heartbeat(key="heartbeat:stable")
        state.apply_heartbeat(first)
        with self.assertRaisesRegex(WorkerIdempotencyError, "different content"):
            state.apply_heartbeat(replace(first, state="busy"))

    def test_stale_heartbeat_is_lost_and_unverifiable_ttl_is_unknown(self) -> None:
        state = WorkerState()
        state.apply_registration(registration())
        state.apply_heartbeat(heartbeat(ttl_seconds=29))
        self.assertEqual("lost", state.worker_status(NOW))

        unknown = WorkerState()
        unknown.apply_registration(registration())
        unknown.apply_heartbeat(heartbeat(ttl_seconds=None))
        self.assertEqual("unknown", unknown.worker_status(NOW))

    def test_new_fence_clears_old_generation_and_rejects_old_messages(self) -> None:
        state = WorkerState()
        state.apply_registration(registration())
        state.apply_capability_snapshot(capabilities())
        state.apply_resource_snapshot(resources())
        old_heartbeat = heartbeat(key="heartbeat:reusable")
        state.apply_heartbeat(old_heartbeat)
        state.apply_execution_handle(execution_handle())
        state.apply_registration(registration(fence=2))
        self.assertIsNone(state.heartbeat)
        self.assertIsNone(state.resource_snapshot)
        self.assertEqual({}, state.execution_handles)

        new_heartbeat = heartbeat(fence=2, key="heartbeat:reusable")
        self.assertTrue(state.apply_heartbeat(new_heartbeat))
        self.assertFalse(state.apply_heartbeat(new_heartbeat))
        with self.assertRaisesRegex(WorkerFenceError, "does not match"):
            state.apply_heartbeat(old_heartbeat)
        with self.assertRaisesRegex(WorkerFenceError, "registration fence rollback"):
            state.apply_registration(registration())

    def test_apply_and_nested_projection_are_one_reentrant_lock_boundary(self) -> None:
        class BlockingWorkerState(WorkerState):
            def __init__(self) -> None:
                super().__init__()
                self.pause_heartbeat = False
                self.remember_entered = threading.Event()
                self.remember_release = threading.Event()

            def _remember(self, stream: str, value: object) -> None:
                if self.pause_heartbeat and stream == "heartbeat":
                    self.remember_entered.set()
                    if not self.remember_release.wait(timeout=2):
                        raise RuntimeError("test did not release heartbeat apply")
                super()._remember(stream, value)

        state = BlockingWorkerState()
        state.apply_registration(registration())
        state.pause_heartbeat = True
        self.addCleanup(state.remember_release.set)
        errors: list[BaseException] = []
        projections: list[dict[str, object]] = []
        projection_started = threading.Event()
        projection_done = threading.Event()

        def apply() -> None:
            try:
                state.apply_heartbeat(heartbeat())
            except BaseException as exc:  # pragma: no cover - reported below
                errors.append(exc)

        def project() -> None:
            projection_started.set()
            try:
                projections.append(state.to_dict(NOW))
            except BaseException as exc:  # pragma: no cover - reported below
                errors.append(exc)
            finally:
                projection_done.set()

        apply_thread = threading.Thread(target=apply, daemon=True)
        projection_thread = threading.Thread(target=project, daemon=True)
        apply_thread.start()
        self.assertTrue(state.remember_entered.wait(timeout=1))
        projection_thread.start()
        self.assertTrue(projection_started.wait(timeout=1))
        self.assertFalse(projection_done.wait(timeout=0.05))

        state.remember_release.set()
        apply_thread.join(timeout=2)
        projection_thread.join(timeout=2)
        self.assertFalse(apply_thread.is_alive())
        self.assertFalse(projection_thread.is_alive())
        self.assertEqual([], errors)
        self.assertEqual("ready", projections[0]["worker_status"])

    def test_usage_reconciliation_within_exceeded_and_unknown(self) -> None:
        within = reconcile_usage(
            ResourceUsage(cpu_cores=2, ram_bytes=2_000),
            ResourceUsage(cpu_cores=1, ram_bytes=1_500),
        )
        self.assertEqual("within", within.status)

        exceeded = reconcile_usage(
            ResourceUsage(cpu_cores=2, ram_bytes=2_000),
            ResourceUsage(cpu_cores=3, ram_bytes=1_500),
        )
        self.assertEqual("exceeded", exceeded.status)
        self.assertEqual({"cpu_cores": 1.0}, exceeded.to_dict()["overages"])

        unknown = reconcile_usage(
            ResourceUsage(cpu_cores=2), ResourceUsage(cpu_cores=None)
        )
        self.assertEqual("unknown", unknown.status)
        self.assertEqual(("cpu_cores",), unknown.unknown_dimensions)

    def test_overage_blocks_admission_and_unknown_confidence_fails_closed(self) -> None:
        state = self.ready_state()
        over = heartbeat(
            sequence=2,
            reserved=ResourceUsage(cpu_cores=1),
            actual=ResourceUsage(cpu_cores=2),
        )
        state.apply_heartbeat(over)
        self.assertEqual("blocked", state.admission_status(NOW))

        unknown = WorkerState()
        unknown.apply_registration(registration())
        unknown.apply_capability_snapshot(capabilities(confidence=None))
        unknown.apply_resource_snapshot(resources())
        unknown.apply_heartbeat(heartbeat())
        self.assertEqual("unknown", unknown.admission_status(NOW))

        confidence_cases = (
            (capabilities(confidence=0), resources(), heartbeat()),
            (capabilities(), resources(confidence=0), heartbeat()),
            (capabilities(), resources(), heartbeat(confidence=0)),
        )
        for index, (capability, resource, worker_heartbeat) in enumerate(
            confidence_cases
        ):
            with self.subTest(zero_confidence_source=index):
                zero = WorkerState()
                zero.apply_registration(registration())
                zero.apply_capability_snapshot(capability)
                zero.apply_resource_snapshot(resource)
                zero.apply_heartbeat(worker_heartbeat)
                self.assertEqual("unknown", zero.admission_status(NOW))

    def test_heartbeat_snapshot_sequence_mismatch_fails_closed(self) -> None:
        state = self.ready_state()
        state.apply_resource_snapshot(resources(sequence=2))
        self.assertEqual("unknown", state.admission_status(NOW))

    def test_execution_handle_sequences_and_terminal_state_do_not_regress(self) -> None:
        state = WorkerState()
        state.apply_registration(registration())
        running = execution_handle(sequence=1, state="running")
        exited = replace(
            execution_handle(sequence=2, state="exited"),
            reservation_id="reservation-1",
            process_id="process-1",
        )
        state.apply_execution_handle(running)
        state.apply_execution_handle(exited)
        self.assertEqual("exited", state.execution_status("handle-1", NOW))
        with self.assertRaisesRegex(WorkerSequenceError, "illegal execution transition"):
            state.apply_execution_handle(
                replace(execution_handle(sequence=3), idempotency_key="handle:restart")
            )

    def test_execution_handle_identity_is_immutable_and_exact_retry_is_idempotent(self) -> None:
        mutations = {
            "job": {"job_id": "job-2"},
            "attempt": {"attempt_id": "attempt-2"},
            "reservation": {"reservation_id": "reservation-2"},
            "process": {"process_id": "process-2"},
        }
        for label, changes in mutations.items():
            with self.subTest(identity_field=label):
                state = WorkerState()
                state.apply_registration(registration())
                original = execution_handle()
                self.assertTrue(state.apply_execution_handle(original))
                self.assertFalse(state.apply_execution_handle(original))
                rebound = replace(
                    original,
                    sequence=2,
                    idempotency_key=f"handle:rebind:{label}",
                    **changes,
                )
                with self.assertRaisesRegex(WorkerIdentityError, "cannot be rebound"):
                    state.apply_execution_handle(rebound)
                self.assertIs(original, state.execution_handles[original.handle_id])

    def test_execution_handle_id_cannot_be_reused_by_a_new_fence(self) -> None:
        state = WorkerState()
        state.apply_registration(registration())
        state.apply_execution_handle(execution_handle())
        state.apply_registration(registration(fence=2))
        rebound = replace(
            execution_handle(),
            fence_token=2,
            sequence=1,
            idempotency_key="handle:new-fence",
        )
        with self.assertRaisesRegex(WorkerIdentityError, "cannot be rebound"):
            state.apply_execution_handle(rebound)
        self.assertEqual({}, state.execution_handles)

    def test_active_handle_with_expired_ttl_projects_lost(self) -> None:
        state = WorkerState()
        state.apply_registration(registration())
        state.apply_execution_handle(
            replace(execution_handle(), ttl_seconds=29)
        )
        self.assertEqual("lost", state.execution_status("handle-1", NOW))


if __name__ == "__main__":
    unittest.main()
