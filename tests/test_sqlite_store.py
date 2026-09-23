from __future__ import annotations

import json
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from remote_envelope import build_envelope  # noqa: E402
import importlib.util
import sys


_SPEC = importlib.util.spec_from_file_location(
    "sqlite_store_under_test", ROOT / "scripts" / "sqlite_store.py"
)
assert _SPEC and _SPEC.loader
sqlite_store = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = sqlite_store
_SPEC.loader.exec_module(sqlite_store)


class SQLiteStoreTests(unittest.TestCase):
    def open_store(self, root: pathlib.Path):
        return sqlite_store.SQLiteStore(root / "dispatch.sqlite3", timeout_seconds=5)

    def test_versioned_wal_schema_is_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                self.assertEqual(7, store.schema_version)
                tables = {
                    row[0]
                    for row in store.connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                self.assertTrue({"schema_migrations", "jobs", "attempts", "events", "leases", "reservations", "governor_state", "transport_outbox", "run_segments", "checkpoints", "cleanup_intents"} <= tables)
                self.assertEqual("wal", str(store.connection.execute("PRAGMA journal_mode").fetchone()[0]).lower())
                migration = store.connection.execute(
                    "SELECT version, checksum FROM schema_migrations"
                ).fetchall()
                self.assertEqual([1, 2, 3, 4, 5, 6, 7], [int(row[0]) for row in migration])

    def _transport_envelope(self, request_id: str = "job-remote:attempt-1", variant: str = "max"):
        return build_envelope(
            request_id=request_id,
            source_id="controller",
            target_id="remote-a",
            operation="execute.prepared",
            packet_digest="a" * 64,
            payload_summary={
                "job_id": "job-remote",
                "packet_id": "packet-remote",
                "attempt_id": "attempt-1",
                "model": "opencode-go/deepseek-v4-flash",
                "variant": variant,
                "provider": "opencode",
                "pool_id": "opencode.go",
                "host_id": "remote-a",
                "execution_host": "remote-a",
                "workload_host": "remote-a",
                "write_scope": ".lad/jobs/job-remote",
                "required_artifact_count": 1,
                "validation_required": True,
            },
        )

    def test_transport_outbox_is_atomic_and_idempotent_with_job_insert(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("transport-owner", ttl_seconds=30)
                envelope = self._transport_envelope()
                payload = {"job_id": "job-remote", "attempts": [{"attempt_id": "attempt-1"}]}
                first = store.create_job(
                    "job-remote", payload, owner_id="transport-owner",
                    fence_token=lease["fence_token"], transport_envelope=envelope,
                )
                second = store.create_job(
                    "job-remote", payload, owner_id="transport-owner",
                    fence_token=lease["fence_token"], transport_envelope=envelope,
                )
                self.assertEqual(first["job_id"], second["job_id"])
                pending = store.list_transport_outbox(statuses=("pending",))
                self.assertEqual(1, len(pending))
                self.assertEqual("job-remote:attempt-1", pending[0]["request_id"])
                self.assertTrue(any(e["event_type"] == "transport_enqueued" for e in store.list_events()))
                with self.assertRaises(sqlite_store.JobConflict):
                    store.create_job(
                        "job-remote", payload, owner_id="transport-owner",
                        fence_token=lease["fence_token"],
                        transport_envelope=self._transport_envelope(variant="low"),
                    )

    def test_transport_receipt_is_fenced_and_requires_outcome_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("transport-owner", ttl_seconds=30)
                envelope = self._transport_envelope()
                store.create_job(
                    "job-remote", {"job_id": "job-remote"},
                    owner_id="transport-owner", fence_token=lease["fence_token"],
                    transport_envelope=envelope,
                )
                accepted = store.record_transport_receipt(
                    "job-remote:attempt-1",
                    {"status": "accepted", "request_id": "job-remote:attempt-1", "payload_digest": envelope["payload_digest"]},
                    owner_id="transport-owner", fence_token=lease["fence_token"],
                )
                self.assertEqual("accepted", accepted["status"])
                with self.assertRaises(sqlite_store.StoreError):
                    store.record_transport_receipt(
                        "job-remote:attempt-1", {"status": "completed"},
                        owner_id="transport-owner", fence_token=lease["fence_token"],
                    )
                completed = store.record_transport_receipt(
                    "job-remote:attempt-1",
                    {
                        "status": "completed",
                        "request_id": "job-remote:attempt-1",
                        "payload_digest": envelope["payload_digest"],
                        "result_digest": "b" * 64,
                    },
                    owner_id="transport-owner", fence_token=lease["fence_token"],
                )
                self.assertEqual("completed", completed["status"])
                replay = store.record_transport_receipt(
                    "job-remote:attempt-1", completed["receipt"],
                    owner_id="transport-owner", fence_token=lease["fence_token"],
                )
                self.assertEqual("completed", replay["status"])

    def _seed_bound_transport(self, store):
        lease = store.acquire_controller_lease("transport-owner", ttl_seconds=30)
        envelope = self._transport_envelope()
        store.create_job(
            "job-remote", {"job_id": "job-remote"},
            owner_id="transport-owner", fence_token=lease["fence_token"],
            transport_envelope=envelope,
        )
        claim = store.claim_job(
            "job-remote", "transport-owner", lease["fence_token"], lease_ttl_seconds=30
        )
        self.assertIsNotNone(claim)
        attempt_id = claim["attempt"]["attempt_id"]
        bound = store.bind_transport_attempt(
            envelope["request_id"],
            "job-remote",
            attempt_id,
            "transport-owner",
            lease["fence_token"],
        )
        self.assertEqual(attempt_id, bound["attempt_id"])
        return lease, envelope, claim

    def test_terminal_transport_receipt_promotes_bound_attempt_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.open_store(pathlib.Path(tmp)) as store:
                lease, envelope, claim = self._seed_bound_transport(store)
                accepted = store.record_transport_receipt(
                    envelope["request_id"],
                    {
                        "status": "accepted",
                        "request_id": envelope["request_id"],
                        "payload_digest": envelope["payload_digest"],
                    },
                    owner_id="transport-owner",
                    fence_token=lease["fence_token"],
                )
                self.assertEqual("accepted", accepted["status"])
                terminal = {
                    "status": "completed",
                    "request_id": envelope["request_id"],
                    "payload_digest": envelope["payload_digest"],
                    "result_digest": "b" * 64,
                    "pbs_job_id": "42.compute-01",
                }
                promoted = store.record_transport_receipt_and_complete(
                    envelope["request_id"],
                    terminal,
                    owner_id="transport-owner",
                    fence_token=lease["fence_token"],
                    validation={"ok": True, "validator": "fixture"},
                    artifact_manifest=[{"path": "out/result.txt", "sha256": "b" * 64}],
                )
                self.assertTrue(promoted["lifecycle_promoted"])
                self.assertFalse(promoted["idempotent"])
                self.assertEqual("completed", promoted["transport"]["status"])
                self.assertEqual("completed", promoted["job"]["status"])
                self.assertEqual("completed", promoted["attempt"]["status"])
                self.assertEqual("b" * 64, promoted["attempt"]["result"]["result_digest"])
                replay = store.record_transport_receipt_and_complete(
                    envelope["request_id"],
                    terminal,
                    owner_id="transport-owner",
                    fence_token=lease["fence_token"],
                    validation={"ok": True, "validator": "fixture"},
                    artifact_manifest=[{"path": "out/result.txt", "sha256": "b" * 64}],
                )
                self.assertTrue(replay["idempotent"])
                self.assertEqual(
                    1,
                    len([e for e in store.list_events("job-remote") if e["event_type"] == "job_completed"]),
                )
                self.assertEqual(
                    1,
                    len([e for e in store.list_events("job-remote") if e["event_type"] == "transport_attempt_bound"]),
                )

    def test_terminal_transport_promotion_rolls_back_receipt_when_attempt_is_unbound(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.open_store(pathlib.Path(tmp)) as store:
                lease = store.acquire_controller_lease("transport-owner", ttl_seconds=30)
                envelope = self._transport_envelope()
                store.create_job(
                    "job-remote", {"job_id": "job-remote"},
                    owner_id="transport-owner", fence_token=lease["fence_token"],
                    transport_envelope=envelope,
                )
                with self.assertRaises(sqlite_store.JobTransitionError):
                    store.record_transport_receipt_and_complete(
                        envelope["request_id"],
                        {
                            "status": "completed",
                            "request_id": envelope["request_id"],
                            "payload_digest": envelope["payload_digest"],
                            "result_digest": "c" * 64,
                        },
                        owner_id="transport-owner",
                        fence_token=lease["fence_token"],
                        validation={"ok": True},
                        artifact_manifest=[{"path": "out/result.txt"}],
                    )
                self.assertEqual("queued", store.get_job("job-remote")["status"])
                self.assertEqual("pending", store.list_transport_outbox()[0]["status"])
                self.assertFalse(
                    any(e["event_type"] == "transport_receipt" for e in store.list_events("job-remote"))
                )

    def test_terminal_transport_promotion_requires_validation_and_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.open_store(pathlib.Path(tmp)) as store:
                lease, envelope, _ = self._seed_bound_transport(store)
                store.record_transport_receipt(
                    envelope["request_id"],
                    {
                        "status": "accepted",
                        "request_id": envelope["request_id"],
                        "payload_digest": envelope["payload_digest"],
                    },
                    owner_id="transport-owner",
                    fence_token=lease["fence_token"],
                )
                with self.assertRaises(sqlite_store.StoreError):
                    store.record_transport_receipt_and_complete(
                        envelope["request_id"],
                        {
                            "status": "completed",
                            "request_id": envelope["request_id"],
                            "payload_digest": envelope["payload_digest"],
                            "result_digest": "d" * 64,
                        },
                        owner_id="transport-owner",
                        fence_token=lease["fence_token"],
                    )
                self.assertEqual("accepted", store.list_transport_outbox()[0]["status"])
                self.assertEqual("running", store.get_job("job-remote")["status"])

    def test_governor_state_round_trips_behind_controller_fence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("governor-owner", ttl_seconds=10)
                state = {
                    "schema_version": 1,
                    "effective_tier": "conserve",
                    "observed_tier": "critical",
                    "pending_samples": 0,
                }
                stored = store.put_governor_state(
                    state,
                    observed_at_utc="2026-08-12T12:00:00+00:00",
                    owner_id="governor-owner",
                    fence_token=lease["fence_token"],
                )
                self.assertEqual("conserve", stored["state"]["effective_tier"])
                self.assertEqual(state, store.get_governor_state())
                self.assertTrue(
                    any(event["event_type"] == "governor_state_updated" for event in store.list_events())
                )
                snapshot = store.snapshot()
                self.assertEqual("conserve", snapshot["governor_state"][0]["state"]["effective_tier"])

    def test_controller_lease_fence_increments_and_rejects_stale_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                first = store.acquire_controller_lease("controller-a", ttl_seconds=10)
                self.assertEqual(1, first["schema_version"])
                with self.assertRaises(sqlite_store.LeaseConflict):
                    store.acquire_controller_lease("controller-b", ttl_seconds=10)
                store.release_controller_lease("controller-a", first["fence_token"])
                second = store.acquire_controller_lease("controller-b", ttl_seconds=10)
                self.assertGreater(second["fence_token"], first["fence_token"])
                with self.assertRaises(sqlite_store.FencingError):
                    store.heartbeat_controller_lease(
                        "controller-a", first["fence_token"], ttl_seconds=10
                    )

    def test_atomic_claim_only_one_worker_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            path = root / "dispatch.sqlite3"
            first = sqlite_store.SQLiteStore(path)
            second = sqlite_store.SQLiteStore(path)
            try:
                lease = first.acquire_controller_lease("controller", ttl_seconds=10)
                first.create_job("job-1", {"prompt": "fake", "model": "spark"})
                barrier = threading.Barrier(2)
                results: list[dict | None] = []

                def claim(store):
                    barrier.wait(timeout=5)
                    results.append(
                        store.claim_next_job(
                            "controller", lease["fence_token"], lease_ttl_seconds=10
                        )
                    )

                threads = [threading.Thread(target=claim, args=(first,)), threading.Thread(target=claim, args=(second,))]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=5)
                self.assertEqual(2, len(results))
                self.assertEqual(1, sum(item is not None for item in results))
                attempts = first.list_attempts("job-1")
                self.assertEqual(1, len(attempts))
                self.assertEqual(1, attempts[0]["schema_version"])
                self.assertEqual("running", attempts[0]["status"])
            finally:
                first.close()
                second.close()

    def test_claim_jobs_reserves_multiple_lanes_in_one_transaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("controller", ttl_seconds=10)
                for index in range(4):
                    store.create_job(f"lane-{index}", {"lane": index}, priority=index)
                claims = store.claim_jobs(
                    "controller", lease["fence_token"], max_jobs=3, lease_ttl_seconds=10
                )
                self.assertEqual(3, len(claims))
                self.assertEqual(
                    ["lane-3", "lane-2", "lane-1"],
                    [item["job"]["job_id"] for item in claims],
                )
                self.assertEqual(
                    {"lane-0"},
                    {item["job_id"] for item in store.list_jobs(statuses=("queued",))},
                )

    def test_reserve_and_claim_binds_reservation_attempt_and_events_atomically(self):
        """A rejected admission must leave no half-created reservation/claim."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("controller", ttl_seconds=30)
                request = {
                    "host_id": "host-a",
                    "ram_gib": 2,
                    "cpu_cores": 1,
                }
                store.create_job(
                    "atomic-job",
                    {
                        "resource_reservation_required": True,
                        "resource_request": request,
                    },
                )
                outcome = store.reserve_and_claim_job(
                    "atomic-job",
                    "controller",
                    lease["fence_token"],
                    request,
                    admission={"allowed": True, "source": "test"},
                    capacity={"host": {"ram_gib": 4, "cpu_cores": 2}},
                    lease_ttl_seconds=30,
                )
                assert outcome is not None
                self.assertEqual("running", outcome["claim"]["job"]["status"])
                self.assertEqual("active", outcome["reservation"]["status"])
                event_types = [event["event_type"] for event in store.list_events("atomic-job")]
                self.assertIn("reservation_created", event_types)
                self.assertIn("job_claimed", event_types)

                store.create_job(
                    "rejected-atomic-job",
                    {
                        "resource_reservation_required": True,
                        "resource_request": {
                            "host_id": "host-a",
                            "ram_gib": 3,
                            "cpu_cores": 1,
                        },
                    },
                )
                with self.assertRaises(sqlite_store.ReservationAdmissionError):
                    store.reserve_and_claim_job(
                        "rejected-atomic-job",
                        "controller",
                        lease["fence_token"],
                        {"host_id": "host-a", "ram_gib": 3, "cpu_cores": 1},
                        admission={"allowed": True},
                        capacity={"host": {"ram_gib": 4, "cpu_cores": 2}},
                        lease_ttl_seconds=30,
                    )
                self.assertEqual("queued", store.get_job("rejected-atomic-job")["status"])
                self.assertEqual(
                    [], store.list_reservations("rejected-atomic-job", statuses=("active",))
                )
                self.assertFalse(
                    any(
                        event["event_type"] == "reservation_created"
                        for event in store.list_events("rejected-atomic-job")
                    )
                )

    def test_governor_state_and_reservation_claim_share_one_transaction(self):
        """A claim cannot commit a governor decision without its reservation."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("controller", ttl_seconds=30)
                request = {"host_id": "host-a", "ram_gib": 2, "cpu_cores": 1}
                store.create_job(
                    "governor-atomic-job",
                    {"resource_reservation_required": True, "resource_request": request},
                )
                state = {
                    "schema_version": 1,
                    "effective_tier": "normal",
                    "observed_tier": "normal",
                    "pending_samples": 0,
                }
                outcome = store.reserve_and_claim_job(
                    "governor-atomic-job",
                    "controller",
                    lease["fence_token"],
                    request,
                    admission={"allowed": True, "source": "test"},
                    capacity={"host": {"ram_gib": 4, "cpu_cores": 2}},
                    governor_state=state,
                    lease_ttl_seconds=30,
                )
                self.assertIsNotNone(outcome)
                self.assertEqual(state, store.get_governor_state())
                self.assertEqual("running", store.get_job("governor-atomic-job")["status"])
                self.assertEqual(1, len(store.list_reservations(statuses=("active",))))
                self.assertEqual(
                    1,
                    sum(event["event_type"] == "governor_state_updated" for event in store.list_events()),
                )

                # The second lane exceeds the remaining host capacity.  Its
                # attempted state transition must roll back with the rejected
                # reservation, leaving the previous state untouched.
                rejected_request = {"host_id": "host-a", "ram_gib": 3, "cpu_cores": 1}
                store.create_job(
                    "governor-rejected-job",
                    {"resource_reservation_required": True, "resource_request": rejected_request},
                )
                rejected_state = {**state, "effective_tier": "critical"}
                with self.assertRaises(sqlite_store.ReservationAdmissionError):
                    store.reserve_and_claim_job(
                        "governor-rejected-job",
                        "controller",
                        lease["fence_token"],
                        rejected_request,
                        admission={"allowed": True},
                        capacity={"host": {"ram_gib": 4, "cpu_cores": 2}},
                        governor_state=rejected_state,
                        lease_ttl_seconds=30,
                    )
                self.assertEqual(state, store.get_governor_state())
                self.assertEqual("queued", store.get_job("governor-rejected-job")["status"])
                self.assertEqual(1, len(store.list_reservations(statuses=("active",))))
                self.assertEqual(
                    1,
                    sum(event["event_type"] == "governor_state_updated" for event in store.list_events()),
                )

                # A compatibility write of the same state is idempotent and
                # does not produce a second audit event.
                store.put_governor_state(
                    state,
                    owner_id="controller",
                    fence_token=lease["fence_token"],
                )
                self.assertEqual(
                    1,
                    sum(event["event_type"] == "governor_state_updated" for event in store.list_events()),
                )

    def test_job_lease_heartbeat_renews_job_and_attempt_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("controller", ttl_seconds=10)
                store.create_job("heartbeat-job", {"kind": "fake"})
                claimed = store.claim_job(
                    "heartbeat-job",
                    "controller",
                    lease["fence_token"],
                    # Keep enough margin for a contended CI/PBS node; the
                    # test checks renewal ordering, not a one-second race.
                    lease_ttl_seconds=5,
                )
                assert claimed
                attempt_id = claimed["attempt"]["attempt_id"]
                before = store.get_job("heartbeat-job")
                before_attempt = store.get_attempt(attempt_id)
                time.sleep(0.1)
                renewed = store.heartbeat_job_lease(
                    "heartbeat-job",
                    attempt_id,
                    "controller",
                    lease["fence_token"],
                    ttl_seconds=10,
                )
                self.assertEqual("running", renewed["job"]["status"])
                self.assertGreater(
                    sqlite_store._parse_time(renewed["job"]["lease_expires_at_utc"]),
                    sqlite_store._parse_time(before["lease_expires_at_utc"]),
                )
                self.assertGreater(
                    sqlite_store._parse_time(renewed["attempt"]["lease_expires_at_utc"]),
                    sqlite_store._parse_time(before_attempt["lease_expires_at_utc"]),
                )
                with self.assertRaises(sqlite_store.FencingError):
                    store.heartbeat_job_lease(
                        "heartbeat-job",
                        attempt_id,
                        "other-controller",
                        lease["fence_token"],
                        ttl_seconds=10,
                    )

    def test_claim_complete_is_atomic_and_idempotent_for_same_fence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("controller", ttl_seconds=10)
                store.create_job("job-1", {"kind": "fake"})
                claimed = store.claim_job("job-1", "controller", lease["fence_token"], lease_ttl_seconds=10)
                assert claimed
                attempt_id = claimed["attempt"]["attempt_id"]
                completed = store.complete_job(
                    "job-1",
                    attempt_id,
                    "controller",
                    lease["fence_token"],
                    success=True,
                    result={"text": "done"},
                    artifact_manifest={"sha256": "abc"},
                    validation={"ok": True},
                )
                self.assertEqual("completed", completed["status"])
                self.assertEqual("completed", store.get_attempt(attempt_id)["status"])
                again = store.complete_job(
                    "job-1", attempt_id, "controller", lease["fence_token"], success=True
                )
                self.assertEqual("completed", again["status"])
                self.assertEqual(1, len([e for e in store.list_events("job-1") if e["event_type"] == "job_completed"]))

    def test_retry_backoff_blocks_claim_until_retry_at(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("controller", ttl_seconds=10)
                store.create_job("backoff-job", {"kind": "fake"})
                claim = store.claim_job(
                    "backoff-job", "controller", lease["fence_token"], lease_ttl_seconds=10
                )
                assert claim
                retry = store.complete_job(
                    "backoff-job",
                    claim["attempt"]["attempt_id"],
                    "controller",
                    lease["fence_token"],
                    success=False,
                    error_class="network",
                    retryable=True,
                    retry_delay_seconds=60,
                )
                self.assertEqual("retry", retry["status"])
                self.assertIsNotNone(retry["retry_at_utc"])
                self.assertIsNone(
                    store.claim_next_job("controller", lease["fence_token"], lease_ttl_seconds=10)
                )
                store.connection.execute(
                    "UPDATE jobs SET retry_at_utc = ? WHERE job_id = ?",
                    ("2000-01-01T00:00:00+00:00", "backoff-job"),
                )
                self.assertIsNotNone(
                    store.claim_next_job("controller", lease["fence_token"], lease_ttl_seconds=10)
                )

    def test_next_retry_at_utc_returns_earliest_valid_future_wake(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("controller", ttl_seconds=30)
                for job_id in ("retry-late", "retry-early", "retry-past", "retry-bad"):
                    store.create_job(job_id, {"kind": "fake"})
                    claim = store.claim_job(
                        job_id, "controller", lease["fence_token"], lease_ttl_seconds=30
                    )
                    assert claim
                    store.complete_job(
                        job_id,
                        claim["attempt"]["attempt_id"],
                        "controller",
                        lease["fence_token"],
                        success=False,
                        error_class="network",
                        retryable=True,
                        retry_at_utc={
                            "retry-late": "2099-01-01T00:10:00Z",
                            "retry-early": "2099-01-01T00:05:00Z",
                            "retry-past": "2000-01-01T00:00:00Z",
                            "retry-bad": "not-a-timestamp",
                        }[job_id],
                    )
                self.assertEqual(
                    "2099-01-01T00:05:00Z",
                    store.next_retry_at_utc(now="2099-01-01T00:00:00Z"),
                )

    def test_fenced_requeue_replaces_failed_packet_and_preserves_attempt_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("controller", ttl_seconds=10)
                store.create_job("replan-job", {"packet": "first"})
                claim = store.claim_job(
                    "replan-job", "controller", lease["fence_token"], lease_ttl_seconds=10
                )
                assert claim
                store.complete_job(
                    "replan-job",
                    claim["attempt"]["attempt_id"],
                    "controller",
                    lease["fence_token"],
                    success=False,
                    error_class="quota",
                    error={"class": "quota"},
                )
                requeued = store.requeue_job(
                    "replan-job",
                    "controller",
                    lease["fence_token"],
                    payload={"packet": "replanned"},
                    reason="monitor_cooldown",
                )
                self.assertEqual("queued", requeued["status"])
                self.assertEqual("replanned", requeued["payload"]["packet"])
                self.assertEqual(1, requeued["payload"]["_lad_replan_base_attempt_count"])
                self.assertEqual(1, requeued["attempt_count"])
                self.assertEqual(
                    1,
                    len([e for e in store.list_events("replan-job") if e["event_type"] == "job_requeued"]),
                )
                next_claim = store.claim_job(
                    "replan-job", "controller", lease["fence_token"], lease_ttl_seconds=10
                )
                self.assertIsNotNone(next_claim)
                self.assertEqual(2, next_claim["attempt"]["attempt_no"])

    def test_stale_fence_cannot_complete_after_restart_and_expiry_can_recover(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            path = root / "dispatch.sqlite3"
            old = sqlite_store.SQLiteStore(path)
            try:
                old_lease = old.acquire_controller_lease("old-controller", ttl_seconds=5)
                old.create_job("job-1", {"kind": "fake"})
                claimed = old.claim_job(
                    "job-1", "old-controller", old_lease["fence_token"], lease_ttl_seconds=5
                )
                assert claimed
                attempt_id = claimed["attempt"]["attempt_id"]
                time.sleep(5.15)
                restarted = sqlite_store.SQLiteStore(path)
                try:
                    new_lease = restarted.acquire_controller_lease("new-controller", ttl_seconds=10)
                    self.assertGreater(new_lease["fence_token"], old_lease["fence_token"])
                    self.assertEqual(
                        1,
                        restarted.recover_expired_jobs(
                            "new-controller",
                            new_lease["fence_token"],
                            liveness_by_job={"job-1": "dead"},
                        ),
                    )
                    self.assertEqual("retry", restarted.get_job("job-1")["status"])
                    with self.assertRaises(sqlite_store.FencingError):
                        old.complete_job(
                            "job-1", attempt_id, "old-controller", old_lease["fence_token"], success=True
                        )
                    reclaimed = restarted.claim_next_job(
                        "new-controller", new_lease["fence_token"], lease_ttl_seconds=10
                    )
                    self.assertIsNotNone(reclaimed)
                    self.assertEqual("new-controller", reclaimed["job"]["claimed_by"])
                finally:
                    restarted.close()
            finally:
                old.close()

    def test_process_crash_without_release_is_recoverable_after_expiry(self):
        """A killed worker leaves durable claim state that a new owner can reclaim."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            db_path = root / "dispatch.sqlite3"
            child = """
import os, pathlib, sys
sys.path.insert(0, sys.argv[2])
from sqlite_store import SQLiteStore
store = SQLiteStore(sys.argv[1])
lease = store.acquire_controller_lease('crashed-controller', ttl_seconds=5)
store.create_job('crash-job', {'kind': 'fake'})
assert store.claim_job('crash-job', 'crashed-controller', lease['fence_token'], lease_ttl_seconds=5)
os._exit(0)
"""
            process = subprocess.run(
                [sys.executable, "-c", child, str(db_path), str(ROOT / "scripts")],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, process.returncode, process.stderr)
            time.sleep(5.15)
            with sqlite_store.SQLiteStore(db_path) as restarted:
                lease = restarted.acquire_controller_lease("restarted-controller", ttl_seconds=10)
                self.assertEqual(
                    1,
                    restarted.recover_expired_jobs(
                        "restarted-controller",
                        lease["fence_token"],
                        liveness_by_job={"crash-job": "dead"},
                    ),
                )
                self.assertEqual("retry", restarted.get_job("crash-job")["status"])
                attempts = restarted.list_attempts("crash-job")
                self.assertEqual("abandoned", attempts[0]["status"])
                claim = restarted.claim_next_job(
                    "restarted-controller", lease["fence_token"], lease_ttl_seconds=10
                )
                self.assertIsNotNone(claim)

    def test_strict_recovery_blocks_unknown_or_live_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("controller", ttl_seconds=10)
                store.create_job("orphan-job", {"kind": "fake"})
                claim = store.claim_job(
                    "orphan-job", "controller", lease["fence_token"], lease_ttl_seconds=1
                )
                assert claim
                time.sleep(1.15)
                blocked = store.recover_expired_jobs(
                    "controller",
                    lease["fence_token"],
                    liveness_by_job={"orphan-job": "unknown"},
                    strict_liveness=True,
                )
                self.assertEqual(1, blocked)
                self.assertEqual("blocked", store.get_job("orphan-job")["status"])
                self.assertEqual(
                    "recovery_liveness_unknown",
                    store.get_job("orphan-job")["error_class"],
                )
                self.assertEqual(
                    "job_recovery_blocked",
                    store.list_events("orphan-job")[-1]["event_type"],
                )
                self.assertIsNone(
                    store.claim_next_job("controller", lease["fence_token"], lease_ttl_seconds=10)
                )

    def test_event_payloads_are_json_and_event_ids_are_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                event = store.append_event("diagnostic", event_id="event-fixed", payload={"ok": True})
                duplicate = store.append_event("diagnostic", event_id="event-fixed", payload={"ok": False})
                self.assertEqual(event["event_seq"], duplicate["event_seq"])
                self.assertEqual({"ok": True}, store.list_events()[0]["payload"])
                self.assertEqual(1, store.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def test_snapshot_is_restart_safe_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            path = root / "dispatch.sqlite3"
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("controller", ttl_seconds=10)
                store.create_job("job-1", {"nested": [1, 2, 3]})
                snapshot = store.snapshot()
                encoded = json.dumps(snapshot, ensure_ascii=False)
                self.assertIn('"schema_version": 1', encoded)
                self.assertEqual(1, len(snapshot["jobs"]))
                self.assertEqual(1, snapshot["leases"][0]["fence_token"])
                store.release_controller_lease("controller", lease["fence_token"])
            with sqlite_store.SQLiteStore(path) as restarted:
                self.assertEqual({1, 2, 3}, set(restarted.get_job("job-1")["payload"]["nested"]))
                self.assertEqual("released", restarted.get_lease()["status"])

    def test_segment_checkpoint_and_claim_commit_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("controller-a", ttl_seconds=30)
                store.create_job(
                    "job-1",
                    {"resource_reservation_required": True},
                )
                store.begin_run_segment(
                    run_id="r1",
                    owner_id="controller-a",
                    fence_token=lease["fence_token"],
                )
                claim = store.reserve_and_claim_job(
                    "job-1",
                    "controller-a",
                    lease["fence_token"],
                    {"host_id": "server-a", "ram_gib": 1},
                )
                assert claim is not None
                attempt_id = claim["claim"]["attempt"]["attempt_id"]
                store.append_checkpoint(
                    run_id="r1",
                    job_id="job-1",
                    attempt_id=attempt_id,
                    owner_id="controller-a",
                    fence_token=lease["fence_token"],
                    sequence=1,
                    payload_digest="sha256:" + "a" * 64,
                    state_digest="sha256:" + "b" * 64,
                )
                snapshot = store.snapshot()
            self.assertEqual("running", snapshot["jobs"][0]["status"])
            self.assertEqual(1, len(snapshot["run_segments"]))
            self.assertEqual(1, len(snapshot["checkpoints"]))
            self.assertTrue(any(e["event_type"] == "checkpoint.recorded" for e in snapshot["events"]))
            self.assertTrue(any(e["event_type"] == "checkpoint.recorded" for e in snapshot["provenance_events"]))

    def test_replayed_checkpoint_or_segment_finish_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("controller-a", ttl_seconds=30)
                store.create_job("job-1", {})
                claimed = store.claim_job(
                    "job-1", "controller-a", lease["fence_token"], lease_ttl_seconds=30
                )
                assert claimed
                segment = store.begin_run_segment(
                    "r1", "controller-a", lease["fence_token"], sequence=1
                )
                checkpoint_args = {
                    "run_id": "r1",
                    "job_id": "job-1",
                    "attempt_id": claimed["attempt"]["attempt_id"],
                    "owner_id": "controller-a",
                    "fence_token": lease["fence_token"],
                    "sequence": 1,
                    "payload_digest": "sha256:" + "a" * 64,
                    "state_digest": "sha256:" + "b" * 64,
                    "segment_id": segment["segment_id"],
                }
                first = store.append_checkpoint(**checkpoint_args)
                second = store.append_checkpoint(**checkpoint_args)
                self.assertEqual(first["checkpoint_id"], second["checkpoint_id"])
                finished = store.finish_run_segment(
                    "r1", "controller-a", lease["fence_token"], segment_id=segment["segment_id"]
                )
                replay = store.finish_run_segment(
                    "r1", "controller-a", lease["fence_token"], segment_id=segment["segment_id"]
                )
                self.assertEqual("finished", finished["status"])
                self.assertEqual(finished["segment_id"], replay["segment_id"])
                self.assertEqual(1, len([e for e in store.list_events() if e["event_type"] == "checkpoint.recorded"]))

    def test_cleanup_intent_is_durable_but_not_destructive(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.open_store(pathlib.Path(tmp)) as store:
                lease = store.acquire_controller_lease("controller-a", ttl_seconds=30)
                intent = store.record_cleanup_intent(
                    run_id="r1",
                    owner_id="controller-a",
                    fence_token=lease["fence_token"],
                    path_digest="sha256:" + "a" * 64,
                    action="archive",
                    payload={"bytes": 10},
                )
                replay = store.record_cleanup_intent(
                    run_id="r1",
                    owner_id="controller-a",
                    fence_token=lease["fence_token"],
                    path_digest="sha256:" + "a" * 64,
                    action="archive",
                    payload={"bytes": 10},
                )
                self.assertEqual(intent["cleanup_intent_id"], replay["cleanup_intent_id"])
                self.assertEqual("pending", intent["status"])
                self.assertEqual(1, len(store.list_cleanup_intents(run_id="r1")))


if __name__ == "__main__":
    unittest.main()
