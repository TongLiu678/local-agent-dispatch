"""Provider-free cross-host delivery fault matrix.

These tests model the controller and worker as separate durable stores.  They
do not open SSH or execute a provider; the point is to prove that reconnect,
duplicate delivery, controller restart, and stale fencing preserve the
metadata-only receipt boundary.
"""

from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from remote_envelope import EnvelopeStore, build_envelope  # noqa: E402
from sqlite_store import FencingError, SQLiteStore  # noqa: E402


def _envelope() -> dict:
    return build_envelope(
        request_id="fault-job:attempt-1",
        source_id="controller",
        target_id="worker-a",
        operation="execute.prepared",
        packet_digest="a" * 64,
        payload_summary={
            "job_id": "fault-job",
            "packet_id": "fault-packet",
            "attempt_id": "attempt-1",
            "model": "opencode-go/deepseek-v4-flash",
            "variant": "max",
            "provider": "opencode",
            "pool_id": "opencode.go",
            "host_id": "worker-a",
            "execution_host": "worker-a",
            "workload_host": "worker-a",
            "write_scope": ".lad/fault-job",
            "required_artifact_count": 1,
            "validation_required": True,
        },
    )


class RemoteDeliveryFaultMatrixTests(unittest.TestCase):
    def _seed_controller(self, root: pathlib.Path, envelope: dict) -> pathlib.Path:
        db = root / "dispatch.sqlite3"
        with SQLiteStore(db) as store:
            lease = store.acquire_controller_lease("controller-a", ttl_seconds=30)
            store.create_job(
                "fault-job",
                {"job_id": "fault-job"},
                owner_id="controller-a",
                fence_token=lease["fence_token"],
                transport_envelope=envelope,
            )
            store.release_controller_lease("controller-a", lease["fence_token"])
        return db

    def test_restart_reconnect_duplicate_delivery_and_terminal_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            envelope = _envelope()
            db = self._seed_controller(root, envelope)
            worker = EnvelopeStore(root / "worker-spool")

            # A controller restart acquires a new fence and sees the durable
            # request even though no transport acknowledgement exists yet.
            with SQLiteStore(db) as store:
                lease = store.acquire_controller_lease("controller-b", ttl_seconds=30)
                self.assertEqual("pending", store.list_transport_outbox()[0]["status"])

                first = worker.receive(envelope)
                duplicate = worker.receive(envelope)
                self.assertFalse(first["duplicate"])
                self.assertTrue(duplicate["duplicate"])
                self.assertEqual(0, first["receipt"]["effect_count"])
                self.assertEqual(first["receipt"]["receipt_digest"], duplicate["receipt"]["receipt_digest"])

                terminal = worker.complete(
                    envelope["request_id"], result_digest="b" * 64
                )
                recorded = store.record_transport_receipt(
                    envelope["request_id"],
                    terminal["receipt"],
                    owner_id="controller-b",
                    fence_token=lease["fence_token"],
                )
                self.assertEqual("completed", recorded["status"])
                self.assertEqual("b" * 64, recorded["receipt"]["result_digest"])

    def test_old_controller_fence_cannot_publish_after_reconnect(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            envelope = _envelope()
            db = self._seed_controller(root, envelope)
            with SQLiteStore(db) as store:
                old = store.acquire_controller_lease("controller-old", ttl_seconds=30)
                store.release_controller_lease("controller-old", old["fence_token"])
                new = store.acquire_controller_lease("controller-new", ttl_seconds=30)
                with self.assertRaises(FencingError):
                    store.record_transport_receipt(
                        envelope["request_id"],
                        {
                            "status": "accepted",
                            "request_id": envelope["request_id"],
                            "payload_digest": envelope["payload_digest"],
                        },
                        owner_id="controller-old",
                        fence_token=old["fence_token"],
                    )
                self.assertEqual("pending", store.list_transport_outbox()[0]["status"])
                self.assertGreater(new["fence_token"], old["fence_token"])


if __name__ == "__main__":
    unittest.main()
