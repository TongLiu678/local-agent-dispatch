"""Provider-free controller outbox delivery and reconnect tests."""

from __future__ import annotations

import pathlib
import tempfile
import unittest
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from remote_envelope import build_envelope  # noqa: E402
from remote_outbox import reconcile_once, sync_once  # noqa: E402
from sqlite_store import FencingError, SQLiteStore  # noqa: E402


def envelope() -> dict:
    return build_envelope(
        request_id="job-1:attempt-1",
        source_id="controller",
        target_id="worker-a",
        operation="execute.prepared",
        packet_digest="a" * 64,
        payload_summary={
            "job_id": "job-1",
            "packet_id": "packet-1",
            "attempt_id": "attempt-1",
            "model": "opencode-go/deepseek-v4-flash",
            "variant": "max",
            "provider": "opencode",
            "pool_id": "opencode.go",
            "host_id": "worker-a",
            "execution_host": "worker-a",
            "workload_host": "worker-a",
            "write_scope": ".lad/job-1",
            "required_artifact_count": 1,
            "validation_required": True,
        },
    )


class FakeTransport:
    def __init__(self, *, fail_first: bool = False):
        self.fail_first = fail_first
        self.calls = 0
        self.status_calls = 0
        self.terminal = False

    def envelope_receive(self, *, host_id: str, envelope: dict, execute: bool):
        self.calls += 1
        if self.fail_first and self.calls == 1:
            raise RuntimeError("simulated disconnect")
        self.last_host = host_id
        return {
            "remote": {
                "status": "accepted",
                "receipt": {
                    "schema_version": 1,
                    "receipt_version": 1,
                    "request_id": envelope["request_id"],
                    "idempotency_key": envelope["idempotency_key"],
                    "payload_digest": envelope["payload_digest"],
                    "status": "accepted",
                    "effect_count": 0,
                    "receipt_digest": "c" * 64,
                },
            }
        }

    def envelope_status(self, *, host_id: str, request_id: str, execute: bool):
        self.status_calls += 1
        if not self.terminal:
            return {"remote": {"status": "accepted"}}
        return {
            "remote": {
                "status": "completed",
                "receipt": {
                    "schema_version": 1,
                    "receipt_version": 1,
                    "request_id": request_id,
                    "idempotency_key": envelope()["idempotency_key"],
                    "payload_digest": envelope()["payload_digest"],
                    "status": "completed",
                    "effect_count": 1,
                    "result_digest": "d" * 64,
                    "receipt_digest": "e" * 64,
                },
            }
        }


class RemoteOutboxTests(unittest.TestCase):
    def _db(self, root: pathlib.Path) -> pathlib.Path:
        with SQLiteStore(root / "dispatch.sqlite3") as store:
            lease = store.acquire_controller_lease("seed", ttl_seconds=30)
            store.create_job(
                "job-1", {"job_id": "job-1"}, owner_id="seed",
                fence_token=lease["fence_token"], transport_envelope=envelope(),
            )
            store.release_controller_lease("seed", lease["fence_token"])
        return root / "dispatch.sqlite3"

    def test_dry_run_does_not_mutate_pending_outbox(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._db(pathlib.Path(tmp))
            client = FakeTransport()
            report = sync_once(db, client=client, execute=False)
            self.assertTrue(report["ok"])
            self.assertEqual(1, report["planned"])
            self.assertEqual(0, report["delivered"])
            with SQLiteStore(db) as store:
                self.assertEqual("pending", store.list_transport_outbox()[0]["status"])

    def test_disconnect_keeps_pending_and_retry_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._db(pathlib.Path(tmp))
            client = FakeTransport(fail_first=True)
            first = sync_once(db, client=client, execute=True)
            self.assertFalse(first["ok"])
            with SQLiteStore(db) as store:
                self.assertEqual("pending", store.list_transport_outbox()[0]["status"])
            second = sync_once(db, client=client, execute=True)
            self.assertTrue(second["ok"])
            self.assertEqual(1, second["delivered"])
            third = sync_once(db, client=client, execute=True)
            self.assertTrue(third["ok"])
            self.assertEqual(0, third["attempted"])

    def test_stale_controller_fence_cannot_record_remote_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._db(pathlib.Path(tmp))
            with SQLiteStore(db) as store:
                lease = store.acquire_controller_lease("owner-a", ttl_seconds=30)
                store.release_controller_lease("owner-a", lease["fence_token"])
                store.acquire_controller_lease("owner-b", ttl_seconds=30)
                with self.assertRaises(FencingError):
                    store.record_transport_receipt(
                        "job-1:attempt-1",
                        {"status": "accepted", "request_id": "job-1:attempt-1"},
                        owner_id="owner-a", fence_token=lease["fence_token"],
                    )

    def test_reconcile_accepted_row_is_explicit_and_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._db(pathlib.Path(tmp))
            client = FakeTransport()
            delivered = sync_once(db, client=client, execute=True)
            self.assertTrue(delivered["ok"])
            self.assertEqual(1, delivered["delivered"])
            dry = reconcile_once(db, client=client, execute=False)
            self.assertTrue(dry["ok"])
            self.assertEqual(1, dry["planned"])
            self.assertEqual("accepted", dry["results"][0]["status_before"])
            with SQLiteStore(db) as store:
                self.assertEqual("accepted", store.list_transport_outbox()[0]["status"])
            client.terminal = True
            terminal = reconcile_once(db, client=client, execute=True)
            self.assertTrue(terminal["ok"])
            self.assertEqual(1, terminal["reconciled"])
            self.assertEqual("completed", terminal["results"][0]["status_after"])
            replay = reconcile_once(db, client=client, execute=True)
            self.assertTrue(replay["ok"])
            self.assertEqual(0, replay["attempted"])
            self.assertEqual(2, client.status_calls)

    def test_reconcile_pending_remote_status_does_not_promote_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._db(pathlib.Path(tmp))
            client = FakeTransport()
            sync_once(db, client=client, execute=True)
            report = reconcile_once(db, client=client, execute=True)
            self.assertTrue(report["ok"])
            self.assertEqual(1, report["reconciled"])
            self.assertEqual("accepted", report["results"][0]["status_before"])
            self.assertNotIn("status_after", report["results"][0])
            with SQLiteStore(db) as store:
                self.assertEqual("accepted", store.list_transport_outbox()[0]["status"])


if __name__ == "__main__":
    unittest.main()
