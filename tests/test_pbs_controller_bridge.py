"""Provider-free SQLite -> PBS submission/reconcile bridge tests."""

from __future__ import annotations

import datetime as dt
import pathlib
import tempfile
import unittest
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from pbs_controller_bridge import (  # noqa: E402
    PBSBridgeError,
    PBSWorkerClient,
    _digest,
    _submission_receipt,
    reconcile_once,
    submit_once,
)
from pbs_scheduler_health import scheduler_health_from_outputs  # noqa: E402
from remote_envelope import build_envelope  # noqa: E402
from sqlite_store import SQLiteStore  # noqa: E402


def _envelope() -> dict:
    return build_envelope(
        request_id="pbs-job:attempt-1",
        source_id="controller",
        target_id="worker-a",
        operation="execute.prepared",
        packet_digest="a" * 64,
        payload_summary={
            "job_id": "pbs-job",
            "packet_id": "packet-pbs-job",
            "attempt_id": "attempt-1",
            "model": "local/fake",
            "variant": "max",
            "provider": "server_local",
            "pool_id": "server_local.worker-a",
            "host_id": "worker-a",
            "execution_host": "worker-a",
            "workload_host": "worker-a",
            "write_scope": ".lad/pbs-job",
            "required_artifact_count": 1,
            "validation_required": True,
        },
    )


class FakePBS:
    def __init__(self) -> None:
        self.submit_calls: list[bool] = []
        self.status_calls: list[bool] = []
        self.submit_owners: list[str] = []
        self.status_owners: list[str] = []
        self.fail_submit_once = False
        self.state = "accepted"

    def submit(self, *, host_id, job_id, owner, request_id, idempotency_key, payload_digest, execute):
        self.submit_calls.append(execute)
        self.submit_owners.append(owner)
        if self.fail_submit_once:
            self.fail_submit_once = False
            raise RuntimeError("simulated disconnect after no remote mutation")
        return {
            "remote": {
                "status": "accepted",
                "provider_execution": False,
                "job_id": job_id,
                "request_id": request_id,
                "payload_digest": payload_digest,
                "pbs_job_id": "5555.node1",
                "run_root": "/data/lad/runs/pbs-job",
                "submission_digest": "b" * 64,
            },
            "command_digest": "c" * 64,
            "run_root": "/data/lad/runs/pbs-job",
        }

    def status(self, *, host_id, job_id, owner, request_id, idempotency_key, payload_digest, execute):
        self.status_calls.append(execute)
        self.status_owners.append(owner)
        remote = {
            "status": self.state,
            "provider_execution": False,
            "job_id": job_id,
            "request_id": request_id,
            "payload_digest": payload_digest,
            "pbs_job_id": "5555.node1",
            "run_root": "/data/lad/runs/pbs-job",
            "submission_digest": "b" * 64,
        }
        if self.state == "completed":
            remote["result_digest"] = "d" * 64
            remote["worker_receipt_digest"] = "e" * 64
        return {"remote": remote, "command_digest": "f" * 64}


class ValidatedFakePBS(FakePBS):
    def status(self, **kwargs):
        report = super().status(**kwargs)
        remote = report["remote"]
        if remote["status"] == "completed":
            manifest = [{"path": "out/result.txt", "status": "present", "size": 1, "sha256": "a" * 64}]
            remote["artifact_manifest"] = manifest
            remote["validation"] = {
                "ok": True,
                "validator": "pbs_worker_wrapper.artifact_rehash_v1",
                "artifact_freshness_verified": True,
                "artifact_manifest_digest": _digest(manifest),
            }
        return report


class PBSControllerBridgeTests(unittest.TestCase):
    @staticmethod
    def _verified_scheduler_health() -> dict:
        return {
            "schema_version": 1,
            "kind": "center_pbs_health_live",
            "observed_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "resource_host": "compute-01",
            "report": scheduler_health_from_outputs(
                """Queue              Max   Tot   Ena   Str   Que   Run   Hld   Wat   Trn   Ext T
----------------   ---   ---   ---   ---   ---   ---   ---   ---   ---   --- -
workq                0    1    yes   yes     0     1     0     0     0     0 E
""",
                """compute-01
     state = free
     np = 20
     jobs =
     status = totmem=100000000kb,availmem=60000000kb,physmem=65864812kb,ncpus=20,state=free
""",
                meminfo_text="""MemTotal:       65864812 kB
MemAvailable:   60000000 kB
SwapTotal:             0 kB
SwapFree:              0 kB
""",
            ),
        }

    def test_scheduler_health_gate_blocks_before_client_or_db_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = pathlib.Path(tmp) / "dispatch.sqlite3"
            degraded = self._verified_scheduler_health()
            degraded["report"]["status"] = "degraded"
            degraded["report"]["admission_ready"] = False
            degraded["report"]["memory_admission_ready"] = False
            degraded["report"]["issues"] = ["availmem_exceeds_physmem"]
            client = FakePBS()
            with self.assertRaisesRegex(PBSBridgeError, "scheduler health admission blocked"):
                submit_once(
                    db,
                    client=client,
                    execute=True,
                    require_scheduler_health=True,
                    scheduler_health=degraded,
                    owner_id="pbs-owner",
                )
            self.assertEqual([], client.submit_calls)
            self.assertFalse(db.exists())

    def test_real_inventory_cannot_disable_scheduler_health_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = pathlib.Path(tmp) / "dispatch.sqlite3"
            client = FakePBS()
            with self.assertRaisesRegex(PBSBridgeError, "scheduler health admission blocked"):
                submit_once(
                    db,
                    inventory={"hosts": []},
                    client=client,
                    execute=True,
                    require_scheduler_health=False,
                    owner_id="pbs-owner",
                )
            self.assertEqual([], client.submit_calls)
            self.assertFalse(db.exists())

    def test_scheduler_health_gate_is_recorded_for_a_verified_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = self._seed(pathlib.Path(tmp))
            report = submit_once(
                db,
                client=FakePBS(),
                execute=False,
                require_scheduler_health=True,
                scheduler_health=self._verified_scheduler_health(),
            )
            self.assertTrue(report["ok"])
            self.assertTrue(report["scheduler_health"]["valid"])
            self.assertEqual("admit", report["scheduler_health"]["decision"])

    def test_segment_context_is_bound_and_transport_stage_is_recorded(self) -> None:
        envelope = build_envelope(
            request_id="pbs-segment:attempt-1",
            source_id="controller",
            target_id="worker-a",
            operation="execute.prepared",
            packet_digest="a" * 64,
            payload_summary={
                "job_id": "pbs-segment",
                "packet_id": "packet-segment",
                "attempt_id": "attempt-1",
                "run_id": "run-segment",
                "segment_id": "run-segment:segment:1",
                "sequence": 1,
                "manifest_digest": "sha256:" + "1" * 64,
                "capsule_digest": "sha256:" + "2" * 64,
            },
        )
        remote = {
            "status": "accepted",
            "pbs_job_id": "9.compute-01",
            "job_id": "pbs-segment",
            "request_id": envelope["request_id"],
            "payload_digest": envelope["payload_digest"],
            "run_id": "run-segment",
            "segment_id": "run-segment:segment:1",
            "sequence": 1,
            "manifest_digest": "sha256:" + "1" * 64,
            "capsule_digest": "sha256:" + "2" * 64,
        }
        receipt = _submission_receipt(
            remote,
            request_id=envelope["request_id"],
            envelope=envelope,
            network_execution=True,
        )
        self.assertEqual("run-segment", receipt["run_id"])
        self.assertEqual(1, receipt["sequence"])
        self.assertTrue(receipt["network_execution"])
        with self.assertRaises(PBSBridgeError):
            _submission_receipt(
                {**remote, "segment_id": "run-segment:segment:2"},
                request_id=envelope["request_id"],
                envelope=envelope,
            )

    def test_legacy_statusless_submission_receipt_is_accepted_only_by_type(self) -> None:
        envelope = _envelope()
        legacy = {
            "receipt_type": "local-agent-dispatch.pbs-submission",
            "pbs_job_id": "5555.node1",
            "job_id": "pbs-job",
            "request_id": envelope["request_id"],
            "payload_digest": envelope["payload_digest"],
            "run_root": "/data/lad/runs/pbs-job",
        }
        receipt = _submission_receipt(
            legacy,
            request_id=envelope["request_id"],
            envelope=envelope,
        )
        self.assertEqual("accepted", receipt["status"])
        with self.assertRaises(PBSBridgeError):
            _submission_receipt(
                {**legacy, "receipt_type": "local-agent-dispatch.pbs-worker"},
                request_id=envelope["request_id"],
                envelope=envelope,
            )

    def _seed(self, root: pathlib.Path) -> pathlib.Path:
        db = root / "dispatch.sqlite3"
        envelope = _envelope()
        with SQLiteStore(db) as store:
            lease = store.acquire_controller_lease("seed", ttl_seconds=30)
            store.create_job(
                "pbs-job",
                {"job_id": "pbs-job", "status": "approved"},
                owner_id="seed",
                fence_token=lease["fence_token"],
                transport_envelope=envelope,
            )
            store.record_transport_receipt(
                envelope["request_id"],
                {
                    "status": "accepted",
                    "request_id": envelope["request_id"],
                    "payload_digest": envelope["payload_digest"],
                },
                owner_id="seed",
                fence_token=lease["fence_token"],
            )
            store.release_controller_lease("seed", lease["fence_token"])
        return db

    def test_submit_persists_pbs_identity_and_duplicate_is_side_effect_free(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = self._seed(pathlib.Path(tmp))
            client = FakePBS()
            first = submit_once(db, client=client, execute=True, owner_id="pbs-owner")
            self.assertTrue(first["ok"])
            self.assertEqual(1, first["submitted"])
            second = submit_once(db, client=client, execute=True, owner_id="pbs-owner-2")
            self.assertTrue(second["ok"])
            self.assertTrue(second["results"][0]["idempotent"])
            self.assertEqual([True], client.submit_calls)
            with SQLiteStore(db) as store:
                row = store.list_transport_outbox()[0]
                self.assertEqual("accepted", row["status"])
                self.assertEqual("5555.node1", row["receipt"]["pbs_job_id"])
                self.assertEqual("pbs", row["receipt"]["executor"])

    def test_disconnect_keeps_worker_acceptance_and_retry_submits_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = self._seed(pathlib.Path(tmp))
            client = FakePBS()
            client.fail_submit_once = True
            first = submit_once(db, client=client, execute=True, owner_id="pbs-owner")
            self.assertFalse(first["ok"])
            second = submit_once(db, client=client, execute=True, owner_id="pbs-owner")
            self.assertTrue(second["ok"])
            self.assertEqual(2, client.submit_calls.__len__())
            self.assertEqual(1, second["submitted"])

    def test_reconcile_pending_then_terminal_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = self._seed(pathlib.Path(tmp))
            client = FakePBS()
            submit_once(db, client=client, execute=True, owner_id="pbs-owner")
            with SQLiteStore(db) as store:
                self.assertEqual("pbs-owner", store.list_transport_outbox()[0]["receipt"]["pbs_owner_id"])
            pending = reconcile_once(db, client=client, execute=True, owner_id="pbs-reconcile")
            self.assertTrue(pending["ok"])
            self.assertEqual(0, pending["reconciled"])
            client.state = "completed"
            terminal = reconcile_once(db, client=client, execute=True, owner_id="pbs-reconcile")
            self.assertTrue(terminal["ok"])
            self.assertEqual(1, terminal["reconciled"])
            self.assertEqual(["pbs-owner", "pbs-owner"], client.status_owners)
            replay = reconcile_once(db, client=client, execute=True, owner_id="pbs-reconcile-2")
            self.assertTrue(replay["ok"])
            self.assertEqual(0, replay["attempted"])
            with SQLiteStore(db) as store:
                row = store.list_transport_outbox()[0]
                self.assertEqual("completed", row["status"])
                self.assertEqual("d" * 64, row["receipt"]["result_digest"])
                self.assertEqual("pbs-owner", row["receipt"]["pbs_owner_id"])

    def test_reconcile_promotes_bound_attempt_only_with_validated_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            db = root / "dispatch.sqlite3"
            envelope = _envelope()
            owner = "pbs-reconcile"
            with SQLiteStore(db) as store:
                lease = store.acquire_controller_lease(owner, ttl_seconds=30)
                store.create_job(
                    "pbs-job", {"job_id": "pbs-job"},
                    owner_id=owner, fence_token=lease["fence_token"], transport_envelope=envelope,
                )
                claim = store.claim_job("pbs-job", owner, lease["fence_token"], lease_ttl_seconds=30)
                self.assertIsNotNone(claim)
                store.bind_transport_attempt(
                    envelope["request_id"], "pbs-job", claim["attempt"]["attempt_id"],
                    owner, lease["fence_token"],
                )
                store.record_transport_receipt(
                    envelope["request_id"],
                    {"status": "accepted", "request_id": envelope["request_id"],
                     "payload_digest": envelope["payload_digest"], "executor": "pbs",
                     "pbs_job_id": "5555.node1", "run_root": "/data/lad/runs/pbs-job"},
                    owner_id=owner, fence_token=lease["fence_token"],
                )
            client = ValidatedFakePBS()
            client.state = "completed"
            report = reconcile_once(db, client=client, execute=True, owner_id=owner)
            self.assertTrue(report["ok"])
            self.assertEqual(1, report["reconciled"])
            self.assertTrue(report["results"][0]["lifecycle_promoted"])
            with SQLiteStore(db) as store:
                self.assertEqual("completed", store.get_job("pbs-job")["status"])
                self.assertEqual("completed", store.list_transport_outbox()[0]["status"])

    def test_reconcile_keeps_bound_attempt_running_without_validation_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            db = root / "dispatch.sqlite3"
            envelope = _envelope()
            owner = "pbs-reconcile"
            with SQLiteStore(db) as store:
                lease = store.acquire_controller_lease(owner, ttl_seconds=30)
                store.create_job(
                    "pbs-job", {"job_id": "pbs-job"},
                    owner_id=owner, fence_token=lease["fence_token"], transport_envelope=envelope,
                )
                claim = store.claim_job("pbs-job", owner, lease["fence_token"], lease_ttl_seconds=30)
                self.assertIsNotNone(claim)
                store.bind_transport_attempt(
                    envelope["request_id"], "pbs-job", claim["attempt"]["attempt_id"],
                    owner, lease["fence_token"],
                )
                store.record_transport_receipt(
                    envelope["request_id"],
                    {"status": "accepted", "request_id": envelope["request_id"],
                     "payload_digest": envelope["payload_digest"], "executor": "pbs",
                     "pbs_job_id": "5555.node1", "run_root": "/data/lad/runs/pbs-job"},
                    owner_id=owner, fence_token=lease["fence_token"],
                )
            client = FakePBS()
            client.state = "completed"
            report = reconcile_once(db, client=client, execute=True, owner_id=owner)
            self.assertTrue(report["ok"])
            self.assertFalse(report["results"][0]["lifecycle_promoted"])
            self.assertEqual("validation_evidence_required", report["results"][0]["lifecycle_blocked"])
            with SQLiteStore(db) as store:
                self.assertEqual("running", store.get_job("pbs-job")["status"])
                self.assertEqual("completed", store.list_transport_outbox()[0]["status"])

    def test_dry_run_never_mutates_worker_accepted_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = self._seed(pathlib.Path(tmp))
            client = FakePBS()
            report = submit_once(db, client=client, execute=False)
            self.assertTrue(report["ok"])
            self.assertEqual(1, report["planned"])
            with SQLiteStore(db) as store:
                self.assertNotIn("executor", store.list_transport_outbox()[0]["receipt"])
            reconcile = reconcile_once(db, client=client, execute=False)
            self.assertTrue(reconcile["ok"])
            self.assertTrue(reconcile["results"][0]["awaiting_submission"])

    def test_remote_client_dry_run_requires_explicit_pbs_config_and_does_not_ssh(self) -> None:
        inventory = {
            "hosts": [{
                "host_id": "worker-a",
                "transport": "ssh",
                "hostname": "worker.example",
                "user": "root",
                "port": 22,
                "worker_script": "/data/lad/project/scripts/remote_worker.py",
                "project_path": "/data/lad/project",
                "spool_path": "/data/lad/spool",
                "pbs": {
                    "wrapper": "/data/lad/project/scripts/pbs_worker_wrapper.py",
                    "python": "/data/lad/python/bin/python3",
                    "qsub": "/opt/torque/bin/qsub",
                    "run_root": "/data/lad/runs",
                    "queue": "workq",
                    "nodes": 1,
                    "ppn": 1,
                },
            }]
        }
        client = PBSWorkerClient(inventory)
        report = client.submit(
            host_id="worker-a",
            job_id="pbs-job",
            owner="pbs-owner",
            request_id="pbs-job:attempt-1",
            idempotency_key="pbs-job:attempt-1",
            payload_digest="a" * 64,
            execute=False,
        )
        self.assertFalse(report["executed"])
        self.assertEqual("/data/lad/runs/pbs-job", report["run_root"])
        self.assertEqual(64, len(report["command_digest"]))
        with self.assertRaises(PBSBridgeError):
            PBSWorkerClient({"hosts": [{**inventory["hosts"][0], "pbs": None}]}).submit(
                host_id="worker-a", job_id="pbs-job", owner="pbs-owner",
                request_id="pbs-job:attempt-1", idempotency_key="pbs-job:attempt-1",
                payload_digest="a" * 64, execute=False,
            )

    def test_pbs_transport_carries_only_explicit_legacy_rsa_compatibility(self) -> None:
        inventory = {
            "hosts": [{
                "host_id": "worker-a",
                "transport": "ssh",
                "hostname": "worker.example",
                "user": "root",
                "port": 22,
                "ssh_legacy_rsa": True,
                "worker_script": "/data/lad/project/scripts/remote_worker.py",
                "project_path": "/data/lad/project",
                "spool_path": "/data/lad/spool",
                "pbs": {
                    "wrapper": "/data/lad/project/scripts/pbs_worker_wrapper.py",
                    "python": "/data/lad/python/bin/python3",
                    "qsub": "/opt/torque/bin/qsub",
                    "run_root": "/data/lad/runs",
                },
            }]
        }
        client = PBSWorkerClient(inventory)
        command = client._ssh_command(client.worker_client.hosts["worker-a"], ["true"])
        self.assertIn("HostKeyAlgorithms=+ssh-rsa", command)
        self.assertIn("PubkeyAcceptedAlgorithms=+ssh-rsa", command)


if __name__ == "__main__":
    unittest.main()
