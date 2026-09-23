"""Provider-free SQLite packet -> remote prepare/receipt seam tests."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from remote_envelope import EnvelopeStore, build_envelope  # noqa: E402
from remote_prepare_orchestrator import _packet_identity, prepare_once  # noqa: E402
from sqlite_controller import build_transport_envelope  # noqa: E402
from sqlite_store import SQLiteStore  # noqa: E402


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _packet(root: pathlib.Path) -> dict:
    return {
        "schema_version": 1,
        "packet_id": "packet-orchestrator",
        "job_id": "job-orchestrator",
        "workspace": str(root),
        "execution_host": "remote-a",
        "workload_host": "remote-a",
        "write_scope": "out",
        "required_artifacts": ["out/result.json"],
        "validation_required": True,
        "validation_argv": ["python3", "-m", "unittest"],
        "provider": "server_local",
        "pool_id": "server_local.remote-a",
        "model": "local/fake",
        "variant": "max",
        "attempts": [
            {
                "attempt_id": "attempt-orchestrator",
                "adapter": "server_local",
                "transport": "ssh",
                "host_id": "remote-a",
                "workspace": str(root),
                "provider": "server_local",
                "pool_id": "server_local.remote-a",
                "model": "local/fake",
                "variant": "max",
            }
        ],
    }


def _envelope(packet: dict) -> dict:
    return build_envelope(
        request_id="job-orchestrator:attempt-orchestrator",
        source_id="controller",
        target_id="remote-a",
        operation="execute.prepared",
        packet_digest=_digest(packet),
        payload_summary={
            "job_id": packet["job_id"],
            "packet_id": packet["packet_id"],
            "attempt_id": packet["attempts"][0]["attempt_id"],
            "model": packet["model"],
            "variant": packet["variant"],
            "provider": packet["provider"],
            "pool_id": packet["pool_id"],
            "host_id": "remote-a",
            "execution_host": "remote-a",
            "workload_host": "remote-a",
            "write_scope": packet["write_scope"],
            "required_artifact_count": 1,
            "validation_required": True,
        },
    )


class FakeRemoteClient:
    def __init__(self, root: pathlib.Path) -> None:
        self.prepare_calls: list[bool] = []
        self.receive_calls: list[bool] = []
        self.envelopes = EnvelopeStore(root / "worker-envelope-spool")

    def prepare(self, *, host_id: str, packet: dict, execute: bool) -> dict:
        self.prepare_calls.append(execute)
        if not execute:
            return {
                "dry_run": True,
                "command_digest": "a" * 64,
                "packet_digest": "b" * 64,
            }
        return {
            "dry_run": False,
            "remote": {
                "status": "prepared",
                "job_id": packet["job_id"],
                "packet_id": packet["packet_id"],
                "packet_digest": "b" * 64,
            },
        }

    def envelope_receive(self, *, host_id: str, envelope: dict, execute: bool) -> dict:
        self.receive_calls.append(execute)
        if not execute:
            return {"dry_run": True, "command_digest": "c" * 64}
        return {"remote": self.envelopes.receive(envelope)}


class RemotePrepareOrchestratorTests(unittest.TestCase):
    def _seed(self, root: pathlib.Path, *, controller_marker: bool = False) -> pathlib.Path:
        db = root / "dispatch.sqlite3"
        packet = _packet(root / "project")
        packet["workspace"] = str(root / "project")
        packet["attempts"][0]["workspace"] = str(root / "project")
        envelope = _envelope(packet)
        if controller_marker:
            # SQLiteController adds this audit-only marker after the envelope
            # digest is built; the orchestrator must accept that one mutation.
            packet["packet_validation"] = {"mode": "strict", "backend": "sqlite"}
        with SQLiteStore(db) as store:
            lease = store.acquire_controller_lease("seed", ttl_seconds=30)
            store.create_job(
                packet["job_id"],
                packet,
                owner_id="seed",
                fence_token=lease["fence_token"],
                transport_envelope=envelope,
            )
            store.release_controller_lease("seed", lease["fence_token"])
        return db

    def test_dry_run_joins_packet_and_envelope_without_receipt_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            db = self._seed(root, controller_marker=True)
            client = FakeRemoteClient(root)
            report = prepare_once(db, client=client, execute=False)
            self.assertTrue(report["ok"])
            self.assertEqual(1, report["planned"])
            self.assertEqual(1, report["prepared"])
            self.assertEqual(0, report["receipted"])
            self.assertEqual([False], client.prepare_calls)
            self.assertEqual([], client.receive_calls)
            self.assertEqual("controller_packet_validation_omitted", report["results"][0]["packet_digest_binding"])
            with SQLiteStore(db) as store:
                self.assertEqual("pending", store.list_transport_outbox()[0]["status"])

            split_packet = {
                "schema_version": 1,
                "packet_id": "packet-split",
                "job_id": "job-split",
                "execution_host": "local_mac",
                "workload_host": "remote-gpu",
                "execution_transport": "local",
                "workload_transport": "ssh",
                "desktop_split_placement": {"contract_digest": "a" * 64},
                "provider": "codex",
                "pool_id": "codex.spark",
                "model": "gpt-5.3-codex-spark",
                "variant": "xhigh",
                "write_scope": "src",
                "attempts": [{
                    "attempt_id": "attempt-split",
                    "host_id": "local_mac",
                    "transport": "local",
                    "provider": "codex",
                    "pool_id": "codex.spark",
                    "model": "gpt-5.3-codex-spark",
                    "variant": "xhigh",
                }],
            }
            split_envelope = build_transport_envelope(split_packet)
            split_identity = _packet_identity(
                split_packet, split_envelope, target_id="remote-gpu"
            )
            self.assertEqual("remote-gpu", split_identity["target_id"])

    def test_execute_prepares_then_records_fenced_acceptance_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            db = self._seed(root)
            client = FakeRemoteClient(root)
            first = prepare_once(db, client=client, execute=True)
            self.assertTrue(first["ok"])
            self.assertEqual(1, first["prepared"])
            self.assertEqual(1, first["receipted"])
            self.assertEqual([True, False], client.prepare_calls)
            self.assertEqual([True], client.receive_calls)
            with SQLiteStore(db) as store:
                self.assertEqual("accepted", store.list_transport_outbox()[0]["status"])
            second = prepare_once(db, client=client, execute=True)
            self.assertTrue(second["ok"])
            self.assertEqual(0, second["attempted"])
            self.assertEqual([True, False], client.prepare_calls)

    def test_remote_prepare_identity_mismatch_keeps_outbox_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            db = self._seed(root)
            client = FakeRemoteClient(root)

            def wrong_prepare(*, host_id: str, packet: dict, execute: bool) -> dict:
                return {
                    "remote": {
                        "status": "prepared",
                        "job_id": "different-job",
                        "packet_id": packet["packet_id"],
                        "packet_digest": "b" * 64,
                    }
                }

            client.prepare = wrong_prepare  # type: ignore[method-assign]
            report = prepare_once(db, client=client, execute=True)
            self.assertFalse(report["ok"])
            self.assertEqual("PrepareOrchestratorError", report["errors"][0]["error"])
            self.assertEqual([], client.receive_calls)
            with SQLiteStore(db) as store:
                self.assertEqual("pending", store.list_transport_outbox()[0]["status"])


if __name__ == "__main__":
    unittest.main()
