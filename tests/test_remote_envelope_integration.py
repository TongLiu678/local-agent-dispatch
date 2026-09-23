"""Provider-free integration tests for worker/client envelope wiring."""

from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import remote_worker as worker  # noqa: E402
import remote_worker_client as client  # noqa: E402
from remote_envelope import build_envelope  # noqa: E402


def _envelope() -> dict:
    return build_envelope(
        request_id="job-1-attempt-1",
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
            "execution_host": "controller",
            "workload_host": "worker-a",
            "write_scope": ".lad/jobs/job-1",
            "required_artifact_count": 1,
            "validation_required": True,
        },
    )


class RemoteEnvelopeIntegrationTests(unittest.TestCase):
    def test_worker_receive_complete_pending_is_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            spool = pathlib.Path(tmp) / "spool"
            envelope = _envelope()
            accepted = worker.receive_envelope(spool, envelope)
            self.assertEqual("accepted", accepted["status"])
            self.assertEqual("opencode-go/deepseek-v4-flash", accepted["envelope"]["model"])
            self.assertEqual("max", accepted["envelope"]["variant"])
            pending = worker.pending_envelopes(spool)
            self.assertEqual(["job-1-attempt-1"], [row["request_id"] for row in pending["envelopes"]])
            duplicate = worker.receive_envelope(spool, envelope)
            self.assertTrue(duplicate["duplicate"])
            completed = worker.complete_envelope(
                spool,
                "job-1-attempt-1",
                result_digest="b" * 64,
            )
            self.assertEqual("completed", completed["status"])
            status = worker.envelope_status(spool, "job-1-attempt-1")
            self.assertEqual("completed", status["status"])
            self.assertFalse(status["provider_execution"])
            self.assertEqual([], worker.pending_envelopes(spool)["envelopes"])
            text = "\n".join(path.read_text(encoding="utf-8") for path in spool.rglob("*.json"))
            self.assertNotIn("prompt", text)
            self.assertNotIn("argv", text)

    def test_client_envelope_operations_are_dry_run_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            inventory = {
                "hosts": [
                    {
                        "host_id": "worker-a",
                        "transport": "ssh",
                        "hostname": "worker-a.example.test",
                        "user": "runner",
                        "port": 2222,
                        "worker_script": "/srv/lad/remote_worker.py",
                        "project_path": "/srv/lad/project",
                        "spool_path": "/srv/lad/spool",
                    }
                ]
            }
            transport = client.RemoteWorkerClient(inventory)
            envelope = _envelope()
            received = transport.envelope_receive(host_id="worker-a", envelope=envelope)
            self.assertTrue(received["dry_run"])
            self.assertEqual("redacted_envelope", received["stdin_transport"])
            self.assertEqual("opencode-go/deepseek-v4-flash", received["model"])
            self.assertEqual("max", received["variant"])
            completed = transport.envelope_complete(
                host_id="worker-a",
                request_id="job-1-attempt-1",
                result_digest="b" * 64,
            )
            self.assertTrue(completed["dry_run"])
            status = transport.envelope_status(
                host_id="worker-a", request_id="job-1-attempt-1"
            )
            self.assertTrue(status["dry_run"])
            self.assertTrue(status["status_query"])
            self.assertFalse(status["provider_execution"])
            pending = transport.envelope_pending(host_id="worker-a")
            self.assertTrue(pending["dry_run"])

    def test_client_rejects_implicit_model_or_variant_for_prepared_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inventory = {
                "hosts": [
                    {
                        "host_id": "worker-a",
                        "transport": "ssh",
                        "hostname": "worker-a.example.test",
                        "user": "runner",
                        "port": 2222,
                        "worker_script": "/srv/lad/remote_worker.py",
                        "project_path": "/srv/lad/project",
                        "spool_path": "/srv/lad/spool",
                    }
                ]
            }
            transport = client.RemoteWorkerClient(inventory)
            envelope = _envelope()
            envelope["payload_summary"] = dict(envelope["payload_summary"])
            envelope["payload_summary"].pop("variant")
            with self.assertRaises(client.ClientError):
                transport.envelope_receive(host_id="worker-a", envelope=envelope)


if __name__ == "__main__":
    unittest.main()
