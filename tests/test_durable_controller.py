"""Provider-free segment supervisor and lost-ACK tests."""

from __future__ import annotations

import datetime as dt
import pathlib
import tempfile
import unittest
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from durable_controller import DurableControllerSupervisor  # noqa: E402


class FakeClock:
    def __init__(self, value: str) -> None:
        self.value = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))

    def now_utc(self) -> dt.datetime:
        return self.value

    def set(self, value: str) -> None:
        self.value = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


class FakeController:
    fence_token = 7

    def __init__(self) -> None:
        self.calls: list[str] = []

    def begin_run_segment(self, **values):
        self.calls.append("begin")
        return {
            "segment_id": values["segment_id"],
            "sequence": values["sequence"],
            "fence_token": values["fence_token"],
            "status": "running",
            "started_at_utc": values["metadata"]["started_at_utc"],
        }

    def heartbeat(self, **_values):
        self.calls.append("heartbeat")
        return {"ok": True}

    def flush_checkpoints(self, **_values):
        self.calls.append("checkpoint")
        return {"checkpoint_flushed": True, "checkpoint_count": 1}

    def finish_run_segment(self, **values):
        self.calls.append("finish")
        return {"segment_id": values["segment_id"], "status": values["status"]}

    def reconcile(self, **_values):
        self.calls.append("reconcile")
        return {"ok": True}


class FakePBS:
    def __init__(self) -> None:
        self.effect_count = 0
        self.status_by_key: dict[str, dict] = {}

    def submit(self, *, idempotency_key, request_id, **values):
        self.effect_count += 1
        job_id = f"{self.effect_count}.compute-01"
        self.status_by_key[idempotency_key] = {
            "status": "accepted",
            "pbs_job_id": job_id,
            "run_id": values.get("run_id"),
            "request_id": request_id,
        }
        return dict(self.status_by_key[idempotency_key])

    def status(self, *, idempotency_key, request_id, **_values):
        return dict(self.status_by_key.get(idempotency_key, {"status": "pending", "pbs_job_id": "unknown.node"}))


class NoCheckpointController:
    fence_token = 7

    def begin_run_segment(self, **values):
        return {
            "segment_id": values["segment_id"],
            "sequence": values["sequence"],
            "fence_token": values["fence_token"],
            "status": "running",
            "started_at_utc": values["metadata"]["started_at_utc"],
        }


def manifest(*, planned_end: str = "2026-08-30T00:00:00Z") -> dict:
    return {
        "schema_version": 1,
        "run_id": "run-24h-test",
        "mode": "offline_soak",
        "evidence_level": "E1",
        "source_digest": "sha256:" + "a" * 64,
        "policy_digest": "sha256:" + "b" * 64,
        "capsule_digest": "sha256:" + "c" * 64,
        "segment_seconds": 3600,
        "rollover_guard_seconds": 300,
        "planned_end_at": planned_end,
    }


class DurableControllerTests(unittest.TestCase):
    def test_lost_qsub_ack_reuses_submission_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            clock = FakeClock("2026-08-29T23:00:00Z")
            pbs = FakePBS()
            supervisor = DurableControllerSupervisor(
                controller=FakeController(), manifest=manifest(), capsule={"capsule_spec_digest": "sha256:" + "d" * 64},
                pbs_client=pbs, clock=clock, run_root=pathlib.Path(tmp), owner_id="controller-a", execute=True,
            )
            first = supervisor.submit_segment(execute=True, simulate_ack_loss=True)
            second = supervisor.submit_segment(execute=True)
            self.assertEqual(first["submission_digest"], second["submission_digest"])
            self.assertEqual(1, pbs.effect_count)
            self.assertEqual("accepted", second["status"])
            self.assertTrue(second["idempotent"])
            self.assertTrue((pathlib.Path(tmp) / "segments" / "segment-000001.submission.json").exists())

    def test_rollover_checkpoints_before_new_segment(self) -> None:
        clock = FakeClock("2026-08-29T23:00:00Z")
        controller = FakeController()
        supervisor = DurableControllerSupervisor(
            controller=controller, manifest=manifest(planned_end="2026-08-30T02:00:00Z"),
            capsule={"capsule_spec_digest": "sha256:" + "d" * 64}, pbs_client=FakePBS(), clock=clock,
            owner_id="controller-a", execute=False,
        )
        supervisor.start()
        decision = supervisor.tick(now_utc="2026-08-29T23:55:00Z")
        self.assertEqual("checkpoint_and_roll", decision["action"])
        self.assertTrue(decision["checkpoint_flushed"])
        self.assertLess(controller.calls.index("checkpoint"), controller.calls.index("finish"))
        self.assertIn("begin", controller.calls[2:])

    def test_planned_end_does_not_create_an_unfinishable_next_segment(self) -> None:
        clock = FakeClock("2026-08-29T23:00:00Z")
        supervisor = DurableControllerSupervisor(
            controller=FakeController(), manifest=manifest(), capsule={"capsule_spec_digest": "sha256:" + "d" * 64},
            pbs_client=FakePBS(), clock=clock, owner_id="controller-a", execute=False,
        )
        supervisor.start()
        decision = supervisor.tick(now_utc="2026-08-29T23:55:00Z")
        self.assertEqual("checkpoint_and_roll", decision["action"])
        self.assertIsNone(decision["next_segment"])
        self.assertEqual("planned_end", decision["reason"])

    def test_missing_checkpoint_adapter_blocks_rollover(self) -> None:
        clock = FakeClock("2026-08-29T23:00:00Z")
        supervisor = DurableControllerSupervisor(
            controller=NoCheckpointController(), manifest=manifest(planned_end="2026-08-30T02:00:00Z"),
            capsule={"capsule_spec_digest": "sha256:" + "d" * 64}, pbs_client=FakePBS(), clock=clock,
            owner_id="controller-a", execute=False,
        )
        supervisor.start()
        decision = supervisor.tick(now_utc="2026-08-29T23:55:00Z")
        self.assertEqual("blocked_checkpoint", decision["action"])
        self.assertFalse(decision["checkpoint_flushed"])
        self.assertEqual("checkpoint_adapter_missing", decision["method"])


if __name__ == "__main__":
    unittest.main()
