from __future__ import annotations

import unittest

from local_agent_dispatch.domain.world_state import (
    CpuTopology,
    GpuState,
    Host,
    MountState,
    Observation,
    RamState,
    ResourceValues,
)
from local_agent_dispatch.scheduler.core import (
    CandidateTarget,
    ReservationBook,
    ReservationConflict,
    ResourceUsage,
    WorkloadRequirements,
    assess_candidate,
    rank_candidates,
)


NOW = "2026-09-22T08:00:00+00:00"
GIB = 1024**3


def observation(kind: str, *, observed_at: str = NOW, ttl: float | None = 60.0) -> Observation:
    return Observation(
        kind=kind,
        source="provider-free-test",
        observed_at=observed_at,
        ttl_seconds=ttl,
        confidence=1.0,
    )


def host(
    host_id: str,
    *,
    ram_gib: int = 32,
    disk_gib: int = 100,
    mount_path: str = "/work",
    gpu_mib: int | None = None,
    ram_observation: Observation | None = None,
) -> Host:
    gpu = ()
    if gpu_mib is not None:
        gpu = (
            GpuState(
                index="0",
                model="fixture-gpu",
                vram=ResourceValues(
                    units="MiB",
                    capacity=gpu_mib,
                    available_now=gpu_mib,
                    reserved=0,
                ),
                observation=observation("vram"),
            ),
        )
    return Host(
        host_id=host_id,
        name=host_id,
        execution_host=True,
        workload_host=True,
        cpu=CpuTopology(threads=16),
        ram=RamState(
            values=ResourceValues(
                units="bytes",
                capacity=ram_gib * GIB,
                allocatable=ram_gib * GIB,
                available_now=ram_gib * GIB,
                reserved=0,
            ),
            observation=ram_observation or observation("ram"),
        ),
        gpus=gpu,
        mounts=(
            MountState(
                path=mount_path,
                probed_path=mount_path,
                fs_type="fixturefs",
                writable=True,
                values=ResourceValues(
                    units="bytes",
                    capacity=disk_gib * GIB,
                    available_now=disk_gib * GIB,
                    reserved=0,
                ),
                free_bytes=disk_gib * GIB,
                free_inodes=1_000_000,
                observation=observation("mount"),
            ),
        ),
    )


def target(
    host_id: str,
    *,
    remote: bool = False,
    workspace_path: str = "/work/project",
    capabilities: tuple[str, ...] = ("coding", "python"),
    **host_options: object,
) -> CandidateTarget:
    return CandidateTarget(
        target_id=f"{host_id}:harness",
        host=host(host_id, **host_options),
        workspace_path=workspace_path,
        capabilities=capabilities,
        harness_id="fixture-harness",
        remote=remote,
        route_verified=True if remote else None,
        execution_ready=True,
        max_lanes=2,
        reliability=0.9,
    )


def requirements(job_id: str = "job-1", *, memory_gib: int = 4, disk_gib: int = 2) -> WorkloadRequirements:
    return WorkloadRequirements(
        job_id=job_id,
        memory_bytes=memory_gib * GIB,
        disk_bytes=disk_gib * GIB,
        disk_inodes=100,
        cpu_threads=2,
        required_capabilities=("coding",),
    )


class SchedulerCoreTests(unittest.TestCase):
    def test_server_preference_changes_score_not_hard_eligibility(self) -> None:
        local = target("local", remote=False)
        server = target("server", remote=True)

        report = rank_candidates([local, server], requirements(), now=NOW)

        self.assertEqual("place", report.decision)
        self.assertEqual(server.target_id, report.selected_target_id)
        self.assertEqual([server.target_id, local.target_id], [row.target_id for row in report.assessments])
        self.assertTrue(all(row.verdict == "eligible" for row in report.assessments))

    def test_unknown_and_stale_dynamic_evidence_fail_closed(self) -> None:
        unknown = target(
            "unknown",
            ram_observation=observation("ram", ttl=None),
        )
        stale = target(
            "stale",
            ram_observation=observation("ram", observed_at="2026-09-22T07:00:00+00:00"),
        )

        unknown_row = assess_candidate(unknown, requirements(), now=NOW)
        stale_row = assess_candidate(stale, requirements(), now=NOW)

        self.assertEqual("unknown", unknown_row.verdict)
        self.assertIn("RAM observation TTL is unknown", unknown_row.reasons)
        self.assertEqual("reject", stale_row.verdict)
        self.assertIn("RAM observation is stale", stale_row.reasons)

    def test_future_dynamic_evidence_is_unknown_not_fresh(self) -> None:
        candidate = target(
            "future",
            ram_observation=observation(
                "ram",
                observed_at="2026-09-22T08:00:01+00:00",
            ),
        )

        row = assess_candidate(candidate, requirements(), now=NOW)

        self.assertEqual("unknown", row.verdict)
        self.assertIn("RAM observation freshness is unverifiable", row.reasons)

    def test_exact_workspace_mount_is_required(self) -> None:
        candidate = target(
            "mount-mismatch",
            mount_path="/large",
            workspace_path="/small/project",
        )

        row = assess_candidate(candidate, requirements(), now=NOW)

        self.assertEqual("reject", row.verdict)
        self.assertTrue(any("no mount evidence covers" in reason for reason in row.reasons))

    def test_static_capability_and_remote_route_are_hard_gates(self) -> None:
        missing = target("missing", capabilities=("python",))
        no_route = CandidateTarget(
            target_id="remote:no-route",
            host=host("remote"),
            workspace_path="/work/project",
            capabilities=("coding",),
            harness_id="fixture",
            remote=True,
            route_verified=None,
            execution_ready=True,
        )

        missing_row = assess_candidate(missing, requirements(), now=NOW)
        route_row = assess_candidate(no_route, requirements(), now=NOW)

        self.assertEqual("reject", missing_row.verdict)
        self.assertIn("missing capabilities: coding", missing_row.reasons)
        self.assertEqual("unknown", route_row.verdict)
        self.assertIn("remote execution route evidence is unknown", route_row.reasons)

    def test_gpu_admission_uses_fresh_per_device_vram(self) -> None:
        candidate = target("gpu", gpu_mib=24_000)
        request = WorkloadRequirements(
            job_id="gpu-job",
            memory_bytes=2 * GIB,
            disk_bytes=GIB,
            gpu_vram_mib=20_000,
            required_capabilities=("coding",),
        )

        row = assess_candidate(candidate, request, now=NOW)

        self.assertEqual("eligible", row.verdict)
        self.assertEqual(24_000, row.available_gpu_vram_mib)

    def test_atomic_reservation_prevents_memory_oversubscription(self) -> None:
        book = ReservationBook()
        candidate = target("small", ram_gib=12)
        first = requirements("first", memory_gib=6, disk_gib=1)
        second = requirements("second", memory_gib=6, disk_gib=1)

        first_plan, first_reservation = book.reserve_best(
            [candidate], first, idempotency_key="request:first", now=NOW
        )
        second_plan, second_reservation = book.reserve_best(
            [candidate], second, idempotency_key="request:second", now=NOW
        )

        self.assertEqual("place", first_plan.decision)
        self.assertIsNotNone(first_reservation)
        self.assertEqual("blocked", second_plan.decision)
        self.assertIsNone(second_reservation)
        self.assertIn("RAM", " ".join(second_plan.assessments[0].reasons))

    def test_atomic_reservation_prevents_cpu_thread_oversubscription(self) -> None:
        book = ReservationBook()
        candidate = target("cpu", ram_gib=32)
        first = WorkloadRequirements(
            job_id="first",
            memory_bytes=GIB,
            disk_bytes=GIB,
            cpu_threads=10,
            required_capabilities=("coding",),
        )
        second = WorkloadRequirements(
            job_id="second",
            memory_bytes=GIB,
            disk_bytes=GIB,
            cpu_threads=10,
            required_capabilities=("coding",),
        )

        first_plan, first_reservation = book.reserve_best(
            [candidate], first, idempotency_key="cpu:first", now=NOW
        )
        second_plan, second_reservation = book.reserve_best(
            [candidate], second, idempotency_key="cpu:second", now=NOW
        )

        self.assertEqual("place", first_plan.decision)
        self.assertIsNotNone(first_reservation)
        self.assertEqual("blocked", second_plan.decision)
        self.assertIsNone(second_reservation)
        self.assertIn("CPU threads", " ".join(second_plan.assessments[0].reasons))

    def test_idempotency_fence_reconcile_and_release(self) -> None:
        book = ReservationBook()
        candidate = target("node")
        request = requirements()
        _, reservation = book.reserve_best(
            [candidate], request, idempotency_key="same", expected_revision=0, now=NOW
        )
        assert reservation is not None

        _, replay = book.reserve_best(
            [candidate], request, idempotency_key="same", expected_revision=0, now=NOW
        )
        self.assertEqual(reservation, replay)
        with self.assertRaises(ReservationConflict):
            book.reserve_best(
                [candidate],
                requirements("different"),
                idempotency_key="same",
                now=NOW,
            )
        with self.assertRaises(ReservationConflict):
            book.reconcile(
                reservation.reservation_id,
                fence_token=reservation.fence_token + 1,
                actual=ResourceUsage(),
            )

        reconciled = book.reconcile(
            reservation.reservation_id,
            fence_token=reservation.fence_token,
            actual=ResourceUsage(memory_bytes=8 * GIB, lanes=1),
        )
        self.assertTrue(reconciled.overage)
        self.assertEqual(reservation.fence_token, reconciled.fence_token)
        self.assertEqual(8 * GIB, book.usage_by_target()[candidate.target_id].memory_bytes)
        completed = book.reconcile(
            reservation.reservation_id,
            fence_token=reservation.fence_token,
            actual=reconciled.actual,
            terminal_state="completed",
        )
        self.assertEqual("completed", completed.state)
        self.assertEqual(reservation.fence_token, completed.fence_token)
        self.assertEqual({}, book.usage_by_target())

    def test_idempotent_replay_returns_original_plan_and_target(self) -> None:
        book = ReservationBook()
        original_target = target("small", ram_gib=8)
        request = requirements(memory_gib=6, disk_gib=1)

        original_plan, reservation = book.reserve_best(
            [original_target],
            request,
            idempotency_key="stable-response",
            now=NOW,
        )
        assert reservation is not None

        # A fresh plan would now be blocked by the reservation's own memory
        # charge.  Idempotent replay must return the original response even if
        # the caller's candidate view has changed.
        replay_plan, replay = book.reserve_best(
            [target("different")],
            request,
            idempotency_key="stable-response",
            now=NOW,
        )

        self.assertEqual(original_plan, replay_plan)
        self.assertEqual("place", replay_plan.decision)
        self.assertEqual(original_target.target_id, replay_plan.selected_target_id)
        self.assertEqual(reservation, replay)

    def test_terminal_reservation_cannot_regress_or_mutate(self) -> None:
        book = ReservationBook()
        candidate = target("node")
        request = requirements()
        _, reservation = book.reserve_best(
            [candidate], request, idempotency_key="terminal", now=NOW
        )
        assert reservation is not None
        actual = ResourceUsage(memory_bytes=2 * GIB, lanes=1)
        completed = book.reconcile(
            reservation.reservation_id,
            fence_token=reservation.fence_token,
            actual=actual,
            terminal_state="completed",
        )
        revision = book.revision

        replay = book.reconcile(
            reservation.reservation_id,
            fence_token=reservation.fence_token,
            actual=actual,
            terminal_state="completed",
        )
        self.assertEqual(completed, replay)
        self.assertEqual(revision, book.revision)

        with self.assertRaises(ReservationConflict):
            book.reconcile(
                reservation.reservation_id,
                fence_token=reservation.fence_token,
                actual=actual,
            )
        with self.assertRaises(ReservationConflict):
            book.reconcile(
                reservation.reservation_id,
                fence_token=reservation.fence_token,
                actual=actual,
                terminal_state="cancelled",
            )
        with self.assertRaises(ReservationConflict):
            book.reconcile(
                reservation.reservation_id,
                fence_token=reservation.fence_token,
                actual=ResourceUsage(memory_bytes=3 * GIB, lanes=1),
                terminal_state="completed",
            )


if __name__ == "__main__":
    unittest.main()
