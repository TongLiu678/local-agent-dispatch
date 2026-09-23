"""Provider-free tests for the cross-host envelope boundary."""

from __future__ import annotations

import hashlib
import json
import pathlib
import tempfile
import unittest

import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from remote_envelope import EnvelopeError, EnvelopeStore, build_envelope  # noqa: E402


class RemoteEnvelopeTests(unittest.TestCase):
    def _envelope(self, *, request_id: str = "req-1", variant: str = "max") -> dict:
        return build_envelope(
            request_id=request_id,
            source_id="controller-a",
            target_id="worker-b",
            operation="execute.prepared",
            packet_digest="a" * 64,
            payload_summary={
                "job_id": "job-1",
                "packet_id": "packet-1",
                "attempt_id": "attempt-1",
                "model": "opencode-go/deepseek-v4-flash",
                "variant": variant,
                "execution_host": "controller-a",
                "workload_host": "worker-b",
                "write_scope": ".lad/jobs/job-1",
                "required_artifact_count": 1,
                "validation_required": True,
            },
        )

    def test_enqueue_receive_and_complete_are_atomic_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EnvelopeStore(tmp)
            envelope = self._envelope()
            queued = store.enqueue(envelope)
            self.assertEqual("pending", queued["status"])
            accepted = store.receive(envelope)
            self.assertEqual("accepted", accepted["status"])
            receipt = store.complete(
                "req-1",
                result_digest=hashlib.sha256(b"result").hexdigest(),
            )
            self.assertEqual("completed", receipt["status"])
            self.assertEqual(1, receipt["receipt"]["effect_count"])
            raw = "\n".join(path.read_text(encoding="utf-8") for path in pathlib.Path(tmp).rglob("*.json"))
            self.assertNotIn("prompt", raw)
            self.assertTrue((pathlib.Path(tmp) / "inbox" / "req-1.json").exists())

    def test_windows_unsafe_request_id_uses_portable_durable_filename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            store = EnvelopeStore(root)
            envelope = self._envelope(request_id="job-1:attempt-1")
            store.enqueue(envelope)
            store.receive(envelope)
            completed = store.complete("job-1:attempt-1", result_digest="b" * 64)

            self.assertEqual("completed", completed["status"])
            for folder in ("outbox", "inbox", "receipts"):
                files = list((root / folder).glob("*.json"))
                self.assertEqual(1, len(files))
                self.assertNotIn(":", files[0].name)
                self.assertLessEqual(len(files[0].name), 255)

    def test_duplicate_delivery_is_idempotent_and_does_not_increment_effect(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EnvelopeStore(tmp)
            envelope = self._envelope()
            store.enqueue(envelope)
            first = store.receive(envelope)
            second = store.receive(envelope)
            self.assertFalse(first["duplicate"])
            self.assertTrue(second["duplicate"])
            self.assertEqual(first["receipt"]["receipt_digest"], second["receipt"]["receipt_digest"])
            completed = store.complete("req-1", result_digest="b" * 64)
            replay = store.complete("req-1", result_digest="b" * 64)
            self.assertEqual(1, completed["receipt"]["effect_count"])
            self.assertTrue(replay["duplicate"])
            self.assertEqual(1, replay["receipt"]["effect_count"])

    def test_conflicting_request_id_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EnvelopeStore(tmp)
            store.enqueue(self._envelope())
            with self.assertRaises(EnvelopeError):
                store.enqueue(self._envelope(variant="low"))
            store.receive(self._envelope())
            with self.assertRaises(EnvelopeError):
                store.receive(self._envelope(variant="low"))

    def test_pending_survives_without_ack_and_terminal_receipt_removes_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EnvelopeStore(tmp)
            store.enqueue(self._envelope())
            self.assertEqual(["req-1"], [row["request_id"] for row in store.pending()])
            store.receive(self._envelope())
            self.assertEqual(["req-1"], [row["request_id"] for row in store.pending()])
            store.complete("req-1", status="failed", error_code="worker_lost")
            self.assertEqual([], store.pending())

    def test_status_is_read_only_and_reports_each_receipt_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EnvelopeStore(tmp)
            envelope = self._envelope()
            store.enqueue(envelope)
            pending = store.status("req-1")
            self.assertEqual("pending", pending["status"])
            self.assertIsNone(pending["receipt"])
            store.receive(envelope)
            accepted = store.status("req-1")
            self.assertEqual("accepted", accepted["status"])
            self.assertEqual("accepted", accepted["receipt"]["status"])
            completed = store.complete("req-1", result_digest="b" * 64)
            terminal = store.status("req-1")
            self.assertEqual("completed", terminal["status"])
            self.assertEqual(completed["receipt"], terminal["receipt"])
            self.assertEqual("completed", store.status("req-1")["status"])
            with self.assertRaises(EnvelopeError):
                store.status("unknown-request")

    def test_terminal_receipt_requires_matching_outcome_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EnvelopeStore(tmp)
            store.receive(self._envelope())
            with self.assertRaises(EnvelopeError):
                store.complete("req-1", status="completed")
            with self.assertRaises(EnvelopeError):
                store.complete("req-1", status="failed")

    def test_terminal_replay_rejects_conflicting_failure_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EnvelopeStore(tmp)
            store.receive(self._envelope())
            first = store.complete("req-1", status="failed", error_code="worker_lost")
            self.assertEqual("worker_lost", first["receipt"]["error_code"])
            with self.assertRaisesRegex(EnvelopeError, "conflicting terminal receipt"):
                store.complete("req-1", status="failed", error_code="timeout")

    def test_status_rejects_tampered_receipt_even_when_request_id_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            store = EnvelopeStore(root)
            store.receive(self._envelope())
            receipt_path = root / "receipts" / "req-1.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["payload_digest"] = "b" * 64
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(EnvelopeError, "payload_digest mismatch"):
                store.status("req-1")

    def test_duplicate_receive_rejects_tampered_receipt_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            store = EnvelopeStore(root)
            envelope = self._envelope()
            store.receive(envelope)
            receipt_path = root / "receipts" / "req-1.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["receipt_digest"] = "c" * 64
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(EnvelopeError, "digest mismatch"):
                store.receive(envelope)

    def test_secret_or_arbitrary_payload_fields_are_rejected(self) -> None:
        with self.assertRaises(EnvelopeError):
            build_envelope(
                request_id="req-prompt",
                source_id="controller-a",
                target_id="worker-b",
                operation="execute.prepared",
                packet_digest="a" * 64,
                payload_summary={"prompt": "do not persist"},
            )
        with self.assertRaises(EnvelopeError):
            build_envelope(
                request_id="req-secret",
                source_id="controller-a",
                target_id="worker-b",
                operation="execute.prepared",
                packet_digest="a" * 64,
                payload_summary={"api_key": "secret"},
            )
        with self.assertRaises(EnvelopeError):
            build_envelope(
                request_id="req-arbitrary",
                source_id="controller-a",
                target_id="worker-b",
                operation="execute.prepared",
                packet_digest="a" * 64,
                payload_summary={"raw_output": "not allowed"},
            )

    def test_unknown_or_tampered_durable_json_is_not_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EnvelopeStore(tmp)
            store.enqueue(self._envelope())
            path = pathlib.Path(tmp) / "outbox" / "req-1.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["payload_summary"]["variant"] = "low"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(EnvelopeError):
                store.pending()


if __name__ == "__main__":
    unittest.main()
