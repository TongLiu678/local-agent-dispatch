from __future__ import annotations

import pathlib
import tempfile
import unittest
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from remote_envelope import build_envelope  # noqa: E402
from durable_controller import DurableControllerSupervisor  # noqa: E402
from sqlite_segment_controller import SQLiteSegmentControllerAdapter  # noqa: E402
from sqlite_store import JobTransitionError, SQLiteStore  # noqa: E402


_MANIFEST = "sha256:" + "a" * 64
_CAPSULE = "sha256:" + "b" * 64


class SQLiteSegmentControllerAdapterTests(unittest.TestCase):
    def _adapter(self, db: pathlib.Path, owner: str = "owner-a"):
        store = SQLiteStore(db, timeout_seconds=5)
        lease = store.acquire_controller_lease(owner, ttl_seconds=30)
        adapter = SQLiteSegmentControllerAdapter(
            store,
            owner_id=owner,
            fence_token=lease["fence_token"],
        )
        return store, lease, adapter

    def test_quiescence_is_explicit_and_segment_lifecycle_is_fenced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, lease, adapter = self._adapter(pathlib.Path(tmp) / "dispatch.sqlite3")
            try:
                segment = adapter.begin_run_segment(
                    run_id="run-1",
                    sequence=1,
                    segment_id="run-1:segment:1",
                    manifest_digest=_MANIFEST,
                    capsule_digest=_CAPSULE,
                )
                self.assertEqual("running", segment["status"])
                flushed = adapter.checkpoint_and_flush(
                    run_id="run-1",
                    segment_id=segment["segment_id"],
                )
                self.assertTrue(flushed["checkpoint_flushed"])
                self.assertEqual("sqlite_quiescent", flushed["method"])
                finished = adapter.finish_run_segment(
                    run_id="run-1",
                    segment_id=segment["segment_id"],
                    sequence=1,
                    status="finished",
                    reason="test",
                )
                self.assertEqual("finished", finished["status"])
                with self.assertRaises(JobTransitionError):
                    store.append_checkpoint(
                        run_id="run-1",
                        job_id="job-1",
                        attempt_id="attempt-1",
                        owner_id="owner-a",
                        fence_token=lease["fence_token"],
                        sequence=1,
                        payload_digest="sha256:" + "c" * 64,
                        state_digest="sha256:" + "d" * 64,
                        segment_id=segment["segment_id"],
                    )
            finally:
                store.close()

    def test_running_attempt_blocks_checkpoint_without_callback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, lease, adapter = self._adapter(pathlib.Path(tmp) / "dispatch.sqlite3")
            try:
                adapter.begin_run_segment(
                    run_id="run-2",
                    sequence=1,
                    segment_id="run-2:segment:1",
                    manifest_digest=_MANIFEST,
                    capsule_digest=_CAPSULE,
                )
                store.create_job(
                    "job-2",
                    {"kind": "bounded"},
                    run_id="run-2",
                    owner_id="owner-a",
                    fence_token=lease["fence_token"],
                )
                claim = store.claim_job("job-2", "owner-a", lease["fence_token"])
                self.assertIsNotNone(claim)
                blocked = adapter.checkpoint_and_flush(
                    run_id="run-2",
                    segment_id="run-2:segment:1",
                )
                self.assertFalse(blocked["checkpoint_flushed"])
                self.assertEqual("checkpoint_adapter_missing", blocked["method"])
                self.assertTrue(blocked["running_attempts"][0]["attempt_id"].startswith("attempt-"))
            finally:
                store.close()

    def test_restore_reads_segment_bound_pbs_receipt_from_outbox(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = pathlib.Path(tmp) / "dispatch.sqlite3"
            store, lease, adapter = self._adapter(db)
            try:
                envelope = build_envelope(
                    request_id="job-3:attempt-1",
                    source_id="controller",
                    target_id="worker-a",
                    operation="execute.prepared",
                    packet_digest="e" * 64,
                    payload_summary={
                        "job_id": "job-3",
                        "packet_id": "packet-3",
                        "attempt_id": "attempt-1",
                        "run_id": "run-3",
                        "segment_id": "run-3:segment:1",
                        "sequence": 1,
                        "manifest_digest": _MANIFEST,
                        "capsule_digest": _CAPSULE,
                        "model": "local/fake",
                        "provider": "server_local",
                        "pool_id": "server_local",
                        "host_id": "worker-a",
                        "execution_host": "worker-a",
                        "workload_host": "worker-a",
                        "write_scope": ".lad/job-3",
                    },
                )
                store.create_job(
                    "job-3",
                    {"kind": "bounded"},
                    run_id="run-3",
                    owner_id="owner-a",
                    fence_token=lease["fence_token"],
                    transport_envelope=envelope,
                )
                store.record_transport_receipt(
                    envelope["request_id"],
                    {
                        "status": "accepted",
                        "request_id": envelope["request_id"],
                        "payload_digest": envelope["payload_digest"],
                        "pbs_job_id": "123.compute-01",
                        "run_id": "run-3",
                        "segment_id": "run-3:segment:1",
                        "sequence": 1,
                        "manifest_digest": _MANIFEST,
                        "capsule_digest": _CAPSULE,
                    },
                    owner_id="owner-a",
                    fence_token=lease["fence_token"],
                )
                state = adapter.restore_run_state(
                    run_id="run-3",
                    manifest_digest=_MANIFEST,
                    capsule_digest=_CAPSULE,
                )
                self.assertEqual("sqlite", state["source"])
                self.assertEqual(1, len(state["submissions"]))
                self.assertEqual("123.compute-01", state["submissions"][0]["pbs_job_id"])
                self.assertEqual(1, state["submissions"][0]["sequence"])
                store.record_transport_receipt(
                    envelope["request_id"],
                    {
                        "status": "completed",
                        "request_id": envelope["request_id"],
                        "payload_digest": envelope["payload_digest"],
                        "pbs_job_id": "123.compute-01",
                        "result_digest": "sha256:" + "f" * 64,
                        "run_id": "run-3",
                        "segment_id": "run-3:segment:1",
                        "sequence": 1,
                        "manifest_digest": _MANIFEST,
                        "capsule_digest": _CAPSULE,
                    },
                    owner_id="owner-a",
                    fence_token=lease["fence_token"],
                )
                terminal_state = adapter.restore_run_state(run_id="run-3")
                self.assertEqual("completed", terminal_state["submissions"][0]["status"])
            finally:
                store.close()

    def test_supervisor_adopts_active_segment_from_sqlite_on_restart(self) -> None:
        class Clock:
            def now_utc(self):
                import datetime as dt
                return dt.datetime(2026, 8, 29, 23, 0, tzinfo=dt.timezone.utc)

        class PBS:
            def submit(self, **_values):
                return {"status": "accepted", "pbs_job_id": "77.compute-01"}

        with tempfile.TemporaryDirectory() as tmp:
            store, lease, adapter = self._adapter(pathlib.Path(tmp) / "dispatch.sqlite3")
            try:
                manifest = {
                    "run_id": "run-4",
                    "source_digest": _MANIFEST,
                    "capsule_digest": _CAPSULE,
                    "segment_seconds": 3600,
                    "planned_end_at": "2026-08-30T02:00:00Z",
                }
                segment_id = "run-4:segment:1"
                adapter.begin_run_segment(
                    run_id="run-4",
                    sequence=1,
                    segment_id=segment_id,
                    manifest_digest=_MANIFEST,
                    capsule_digest=_CAPSULE,
                )
                supervisor = DurableControllerSupervisor(
                    controller=adapter,
                    manifest=manifest,
                    capsule={"capsule_spec_digest": _CAPSULE},
                    pbs_client=PBS(),
                    clock=Clock(),
                    owner_id="owner-a",
                    execute=False,
                )
                self.assertEqual(segment_id, supervisor.current_segment["segment_id"])
                self.assertEqual("running", supervisor.state)
            finally:
                store.close()

    def test_new_fence_adopts_expired_controller_segment_without_new_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = pathlib.Path(tmp) / "dispatch.sqlite3"
            with SQLiteStore(db) as store:
                old = store.acquire_controller_lease("owner-old", ttl_seconds=30)
                old_adapter = SQLiteSegmentControllerAdapter(
                    store, owner_id="owner-old", fence_token=old["fence_token"]
                )
                old_adapter.begin_run_segment(
                    run_id="run-adopt",
                    sequence=1,
                    segment_id="run-adopt:segment:1",
                    manifest_digest=_MANIFEST,
                    capsule_digest=_CAPSULE,
                )
                store.create_job(
                    "job-adopt",
                    {"kind": "bounded"},
                    run_id="run-adopt",
                    owner_id="owner-old",
                    fence_token=old["fence_token"],
                )
                self.assertIsNotNone(store.claim_job("job-adopt", "owner-old", old["fence_token"]))
                store.release_controller_lease("owner-old", old["fence_token"])
                new = store.acquire_controller_lease("owner-new", ttl_seconds=30)
                new_adapter = SQLiteSegmentControllerAdapter(
                    store, owner_id="owner-new", fence_token=new["fence_token"]
                )
                state = new_adapter.restore_run_state(
                    run_id="run-adopt",
                    manifest_digest=_MANIFEST,
                    capsule_digest=_CAPSULE,
                )
                self.assertEqual(1, len(state["segments"]))
                self.assertEqual("owner-new", state["segments"][0]["owner_id"])
                self.assertEqual(new["fence_token"], state["segments"][0]["fence_token"])
                self.assertEqual(1, state["segments"][0]["sequence"])
                blocked = new_adapter.checkpoint_and_flush(
                    run_id="run-adopt", segment_id="run-adopt:segment:1"
                )
                self.assertFalse(blocked["checkpoint_flushed"])
                self.assertEqual("checkpoint_adapter_missing", blocked["method"])


if __name__ == "__main__":
    unittest.main()
