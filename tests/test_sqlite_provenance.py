"""Provider-free tests for SQLite's durable EventV2 transaction seam."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest

SRC = pathlib.Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from local_agent_dispatch.domain import events as ev


ROOT = pathlib.Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "sqlite_store_provenance_under_test", ROOT / "scripts" / "sqlite_store.py"
)
assert _SPEC and _SPEC.loader
sqlite_store = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sqlite_store)


def event(*, event_type: str, attempt_id: str, key: str, parent: str | None = None, **payload):
    return ev.new_event(
        event_type=event_type,
        source="test:sqlite",
        idempotency_key=key,
        causal_parent=parent,
        confidence=1.0,
        timestamp="2026-08-13T00:00:00+00:00",
        privacy_class="internal",
        attempt_id=attempt_id,
        **payload,
    )


class SQLiteProvenanceTests(unittest.TestCase):
    def open_store(self, root: pathlib.Path):
        return sqlite_store.SQLiteStore(root / "dispatch.sqlite3", timeout_seconds=5)

    def test_eventv2_is_idempotent_and_conflicts_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.open_store(pathlib.Path(tmp)) as store:
                first = event(
                    event_type="attempt.started",
                    attempt_id="attempt-1",
                    key="started:attempt-1",
                )
                self.assertEqual(first, store.append_provenance_event(first))
                self.assertEqual(first, store.append_provenance_event(dict(first)))
                conflict = dict(first)
                conflict["source"] = "test:other"
                with self.assertRaises(sqlite_store.ProvenanceEventConflict):
                    store.append_provenance_event(conflict)
                self.assertEqual([first], store.list_provenance_events(attempt_id="attempt-1"))

    def test_orphan_and_secret_events_are_rejected_without_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.open_store(pathlib.Path(tmp)) as store:
                orphan = event(
                    event_type="attempt.heartbeat",
                    attempt_id="attempt-1",
                    key="heartbeat:orphan",
                    parent="event:missing",
                )
                with self.assertRaises(sqlite_store.ProvenanceOrphanError):
                    store.append_provenance_event(orphan)
                secret = event(
                    event_type="attempt.started",
                    attempt_id="attempt-1",
                    key="started:secret",
                    prompt="must-not-persist",
                )
                with self.assertRaises(sqlite_store.ProvenanceSecretError):
                    store.append_provenance_event(secret)
                self.assertEqual([], store.list_provenance_events())

    def test_complete_and_event_commit_or_rollback_together(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.open_store(pathlib.Path(tmp)) as store:
                lease = store.acquire_controller_lease("controller", ttl_seconds=30)
                store.create_job("job-1", {"kind": "fake"})
                claim = store.claim_job("job-1", "controller", lease["fence_token"])
                assert claim
                attempt_id = str(claim["attempt"]["attempt_id"])
                invalid = event(
                    event_type="attempt.completed",
                    attempt_id=attempt_id,
                    key="completed:invalid",
                    parent="event:missing",
                )
                with self.assertRaises(sqlite_store.ProvenanceOrphanError):
                    store.complete_job(
                        "job-1",
                        attempt_id,
                        "controller",
                        lease["fence_token"],
                        success=True,
                        provenance_event=invalid,
                    )
                self.assertEqual("running", store.get_job("job-1")["status"])
                self.assertEqual("running", store.get_attempt(attempt_id)["status"])
                self.assertEqual(
                    ["attempt.claimed"],
                    [item["event_type"] for item in store.list_provenance_events(attempt_id=attempt_id)],
                )

                started = event(
                    event_type="attempt.started",
                    attempt_id=attempt_id,
                    key="started:valid",
                )
                store.append_provenance_event(started)
                completed = event(
                    event_type="attempt.completed",
                    attempt_id=attempt_id,
                    key="completed:valid",
                    parent=started["event_id"],
                    result_digest=ev.digest("done"),
                )
                result = store.complete_job(
                    "job-1",
                    attempt_id,
                    "controller",
                    lease["fence_token"],
                    success=True,
                    provenance_event=completed,
                )
                self.assertEqual("completed", result["status"])
                self.assertEqual(
                    ["attempt.claimed", "attempt.started", "attempt.completed"],
                    [item["event_type"] for item in store.list_provenance_events(attempt_id=attempt_id)],
                )

    def test_reservation_and_event_commit_or_rollback_together(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.open_store(pathlib.Path(tmp)) as store:
                lease = store.acquire_controller_lease("controller", ttl_seconds=30)
                store.create_job("job-1", {"resource_request": {"ram_gib": 1}})
                claim = store.claim_job("job-1", "controller", lease["fence_token"])
                assert claim
                attempt_id = str(claim["attempt"]["attempt_id"])
                bad = event(
                    event_type="attempt.reserved",
                    attempt_id=attempt_id,
                    key="reserved:bad",
                    parent="event:missing",
                )
                with self.assertRaises(sqlite_store.ProvenanceOrphanError):
                    store.reserve_resources(
                        "job-1",
                        "controller",
                        lease["fence_token"],
                        {"ram_gib": 1},
                        admission={"allowed": True},
                        provenance_event=bad,
                    )
                self.assertEqual([], store.list_reservations(statuses=("active",)))
                self.assertEqual(
                    ["attempt.claimed"],
                    [item["event_type"] for item in store.list_provenance_events(attempt_id=attempt_id)],
                )

                good = event(
                    event_type="attempt.reserved",
                    attempt_id=attempt_id,
                    key="reserved:good",
                )
                reservation = store.reserve_resources(
                    "job-1",
                    "controller",
                    lease["fence_token"],
                    {"ram_gib": 1},
                    admission={"allowed": True},
                    provenance_event=good,
                )
                self.assertEqual("active", reservation["status"])
                self.assertEqual(
                    ["attempt.claimed", "attempt.reserved"],
                    [item["event_type"] for item in store.list_provenance_events(attempt_id=attempt_id)],
                )

    def _crash_child(
        self,
        db_path: pathlib.Path,
        owner: str,
        fence: int,
        *,
        before_commit: bool,
    ) -> subprocess.CompletedProcess[str]:
        """Run an isolated controller and terminate at a transaction boundary."""

        module_path = (ROOT / "scripts" / "sqlite_store.py").as_posix()
        hook_line = (
            "store._append_event_tx = lambda *args, **kwargs: os._exit(17)"
            if before_commit
            else "# commit is allowed to complete"
        )
        code = textwrap.dedent(
            f"""
            import importlib.util, os, pathlib, sys
            spec = importlib.util.spec_from_file_location("sqlite_store_child", {module_path!r})
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            db = pathlib.Path(sys.argv[1])
            with module.SQLiteStore(db, timeout_seconds=5) as store:
                {hook_line}
                store.reserve_resources(
                    "crash-job", {owner!r}, int({fence}), {{"ram_gib": 1}},
                    admission={{"allowed": True}},
                )
                os._exit(0)
            """
        )
        return subprocess.run(
            [sys.executable, "-c", code, str(db_path)],
            check=False,
            capture_output=True,
            text=True,
            # The child deliberately exits at a SQLite transaction boundary;
            # a remote worker can still experience bounded shared-storage
            # lock latency.  Keep a finite ceiling while avoiding a false
            # negative in an otherwise healthy provider-free suite.
            timeout=20,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )

    def test_process_crash_before_commit_rolls_back_reservation_and_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("controller", ttl_seconds=30)
                store.create_job("crash-job", {"kind": "fake"})
                result = self._crash_child(
                    root / "dispatch.sqlite3",
                    "controller",
                    lease["fence_token"],
                    before_commit=True,
                )
                self.assertEqual(17, result.returncode, result.stderr)
                self.assertEqual([], store.list_reservations(statuses=("active",)))
                self.assertEqual(
                    [],
                    [
                        item
                        for item in store.list_events("crash-job")
                        if item["event_type"] == "reservation_created"
                    ],
                )
                self.assertEqual([], store.list_provenance_events())

    def test_process_crash_after_commit_preserves_reservation_and_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.open_store(root) as store:
                lease = store.acquire_controller_lease("controller", ttl_seconds=30)
                store.create_job("crash-job", {"kind": "fake"})
                result = self._crash_child(
                    root / "dispatch.sqlite3",
                    "controller",
                    lease["fence_token"],
                    before_commit=False,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                active = store.list_reservations(statuses=("active",))
                self.assertEqual(1, len(active))
                self.assertEqual(
                    "reservation_created",
                    [item["event_type"] for item in store.list_events("crash-job")][-1],
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
