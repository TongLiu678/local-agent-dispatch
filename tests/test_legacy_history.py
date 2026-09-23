from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import legacy_history  # noqa: E402
import sqlite_store  # noqa: E402
from sqlite_store import SQLiteStore  # noqa: E402


class LegacyHistoryTests(unittest.TestCase):
    def test_discover_runs_is_sorted_before_bounded_selection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for name in ("run-c", "run-a", "run-b"):
                run = root / name
                run.mkdir()
                (run / "state.json").write_text(
                    json.dumps({"run_id": name, "status": "completed"}),
                    encoding="utf-8",
                )
            discovered = legacy_history.discover_runs(root, max_runs=2)
            self.assertEqual([root.resolve() / "run-a", root.resolve() / "run-b"], discovered)

    def test_build_report_is_read_only_and_drops_sensitive_legacy_bodies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "run-sensitive"
            root.mkdir()
            (root / "state.json").write_text(
                json.dumps({
                    "run_id": "run-sensitive",
                    "status": "completed",
                    "jobs": [{
                        "job_id": "job-a",
                        "status": "completed",
                        "model": "spark",
                        "prompt": "PROMPT MUST NOT ESCAPE",
                        "argv": ["ARG MUST NOT ESCAPE"],
                        "artifact": "ARTIFACT MUST NOT ESCAPE",
                        "credentials": "CREDENTIAL MUST NOT ESCAPE",
                    }],
                }),
                encoding="utf-8",
            )
            (root / "events.jsonl").write_text(
                json.dumps({"event": "job_completed", "prompt": "EVENT BODY MUST NOT ESCAPE"}) + "\n",
                encoding="utf-8",
            )
            report = legacy_history.build_report(root)
            encoded = json.dumps(report)
            for secret in (
                "PROMPT MUST NOT ESCAPE",
                "ARG MUST NOT ESCAPE",
                "ARTIFACT MUST NOT ESCAPE",
                "CREDENTIAL MUST NOT ESCAPE",
                "EVENT BODY MUST NOT ESCAPE",
            ):
                self.assertNotIn(secret, encoded)
            self.assertTrue(report["read_only"])
            self.assertFalse(report["provider_execution"])
            self.assertEqual({"runs": 1, "jobs_by_status": {"completed": 1}}, report["counts"])

    def test_summary_is_metadata_only_and_marks_legacy_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "run-a"
            root.mkdir()
            (root / "state.json").write_text(
                json.dumps({
                    "run_id": "run-a",
                    "status": "running",
                    "pid": 99999999,
                    "jobs": [{
                        "job_id": "job-a",
                        "status": "queued",
                        "model": "gpt-5.3-codex-spark",
                        "prompt": "DO NOT PERSIST",
                        "attempts": [{"adapter": "command", "argv": ["secret"]}],
                    }],
                }),
                encoding="utf-8",
            )
            (root / "events.jsonl").write_text('{"event":"job_started"}\nnot-json\n', encoding="utf-8")
            report = legacy_history.summarize_run(root, reconcile=True, liveness_probe=lambda _pid: "dead")
            encoded = json.dumps(report)
            self.assertNotIn("DO NOT PERSIST", encoded)
            self.assertNotIn("secret", encoded)
            self.assertEqual("legacy_incomplete", report["evidence_quality"])
            self.assertEqual(1, report["events"]["malformed_lines"])
            self.assertEqual("dead", report["liveness"]["job-a"])

    def test_import_writes_only_sanitized_job_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            report = {
                "run_id": "run-a",
                "run_dir": "/private/run-a",
                "jobs": [{
                    "job_id": "job-a",
                    "status": "completed",
                    "model": "spark",
                    "adapter": "command",
                    "prompt": "secret must not be imported",
                }],
            }
            db = root / "import.sqlite3"
            result = legacy_history.import_to_sqlite([report], db)
            self.assertEqual(1, result["imported_jobs"])
            with SQLiteStore(db) as store:
                payload = store.list_jobs()[0]["payload"]
                self.assertNotIn("prompt", payload)
                self.assertEqual("legacy_incomplete", payload["legacy_evidence_quality"])
                self.assertEqual("completed", store.list_jobs()[0]["status"])
                attempts = store.list_attempts("legacy:run-a:job-a")
                self.assertEqual(1, len(attempts))
                self.assertEqual("review", attempts[0]["status"])
                self.assertEqual("legacy_incomplete", attempts[0]["payload"]["evidence_quality"])
                events = store.list_provenance_events(attempt_id=attempts[0]["attempt_id"])
                self.assertEqual(["attempt.queued"], [item["event_type"] for item in events])
                self.assertEqual("legacy_incomplete", events[0]["evidence_quality"])
                self.assertEqual("completed", events[0]["legacy_status"])

    def test_import_never_requeues_legacy_live_or_queued_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = pathlib.Path(tmp) / "import.sqlite3"
            report = {
                "run_id": "run-stale",
                "run_dir": "/private/run-stale",
                "liveness": {"job-queued": "dead", "job-running": "unknown"},
                "jobs": [
                    {"job_id": "job-queued", "status": "queued", "model": "spark"},
                    {"job_id": "job-running", "status": "running", "model": "spark"},
                ],
            }
            result = legacy_history.import_to_sqlite([report], db)
            self.assertEqual(2, result["reviewed_jobs"])
            self.assertEqual({"review": 2}, result["status_by_import"])
            with SQLiteStore(db) as store:
                rows = {row["job_id"]: row for row in store.list_jobs()}
                self.assertEqual("review", rows["legacy:run-stale:job-queued"]["status"])
                self.assertEqual("queued", rows["legacy:run-stale:job-queued"]["payload"]["legacy_status"])
                self.assertEqual("dead", rows["legacy:run-stale:job-queued"]["payload"]["legacy_liveness"])
                self.assertEqual("fail_closed_review", rows["legacy:run-stale:job-running"]["payload"]["import_policy"])
                owner = "test-claim"
                with store.controller_lease(owner, ttl_seconds=30) as lease:
                    self.assertIsNone(
                        store.claim_next_job(owner, int(lease["fence_token"]))
                    )
                event_rows = store.list_provenance_events()
                # The running/unknown row receives a causal review event;
                # queued work remains a review-only import with no fabricated
                # execution terminal.
                self.assertEqual(3, len(event_rows))
                self.assertTrue(all(item["legacy_liveness"] == "unknown" or item["legacy_liveness"] == "dead" for item in event_rows))
                self.assertTrue(all(item["evidence_quality"] == "legacy_incomplete" for item in event_rows))

    def test_running_dead_import_is_abandoned_without_completion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = pathlib.Path(tmp) / "import.sqlite3"
            report = {
                "run_id": "run-dead",
                "run_dir": "/private/run-dead",
                "liveness": {"job-running": "dead"},
                "jobs": [{"job_id": "job-running", "status": "running", "model": "spark"}],
            }
            result = legacy_history.import_to_sqlite([report], db)
            self.assertEqual(1, result["imported_jobs"])
            with SQLiteStore(db) as store:
                job = store.get_job("legacy:run-dead:job-running")
                self.assertEqual("review", job["status"])
                attempt = store.list_attempts(job["job_id"])[0]
                self.assertEqual("abandoned", attempt["status"])
                events = store.list_provenance_events(attempt_id=attempt["attempt_id"])
                self.assertEqual(
                    ["attempt.queued", "attempt.abandoned"],
                    [event["event_type"] for event in events],
                )
                self.assertEqual("legacy_stale_dead_pid", events[-1]["reason"])
                self.assertTrue(events[-1]["preserves_evidence"])
                self.assertNotIn("attempt.completed", [event["event_type"] for event in events])

    def test_running_alive_import_is_reviewed_without_requeue(self) -> None:
        """A live breadcrumb is evidence for review, never runnable work."""
        with tempfile.TemporaryDirectory() as tmp:
            db = pathlib.Path(tmp) / "import.sqlite3"
            report = {
                "run_id": "run-alive",
                "run_dir": "/private/run-alive",
                "liveness": {"job-running": "alive"},
                "jobs": [{"job_id": "job-running", "status": "running", "model": "spark"}],
            }
            result = legacy_history.import_to_sqlite([report], db)
            self.assertEqual(1, result["imported_jobs"])
            with SQLiteStore(db) as store:
                job = store.get_job("legacy:run-alive:job-running")
                self.assertEqual("review", job["status"])
                attempt = store.list_attempts(job["job_id"])[0]
                self.assertEqual("review", attempt["status"])
                self.assertEqual("confirmed_alive", attempt["payload"]["legacy_liveness_classification"])
                events = store.list_provenance_events(attempt_id=attempt["attempt_id"])
                self.assertEqual(
                    ["attempt.queued", "attempt.review"],
                    [event["event_type"] for event in events],
                )
                self.assertEqual("legacy_process_alive", events[-1]["reason"])
                self.assertTrue(events[-1]["preserves_evidence"])
                with store.controller_lease("test-claim", ttl_seconds=30) as lease:
                    self.assertIsNone(
                        store.claim_next_job("test-claim", int(lease["fence_token"])),
                        "legacy live work must not be requeued",
                    )
                self.assertNotIn("attempt.completed", [event["event_type"] for event in events])
            retry_db = pathlib.Path(tmp) / "retry-import.sqlite3"
            retry_report = {
                "run_id": "run-retry-liveness",
                "run_dir": "/private/run-retry-liveness",
                "liveness": {"retry-dead": "dead", "retry-alive": "alive"},
                "jobs": [
                    {"job_id": "retry-dead", "status": "retry", "model": "spark"},
                    {"job_id": "retry-alive", "status": "retry", "model": "spark"},
                ],
            }
            retry_result = legacy_history.import_to_sqlite([retry_report], retry_db)
            self.assertEqual(2, retry_result["imported_jobs"])
            self.assertEqual({"review": 2}, retry_result["status_by_import"])
            with SQLiteStore(retry_db) as retry_store:
                retry_rows = {row["job_id"]: row for row in retry_store.list_jobs()}
                self.assertEqual(
                    "confirmed_dead",
                    retry_rows["legacy:run-retry-liveness:retry-dead"]["payload"]
                    ["legacy_liveness_classification"],
                )
                self.assertEqual(
                    "confirmed_alive",
                    retry_rows["legacy:run-retry-liveness:retry-alive"]["payload"]
                    ["legacy_liveness_classification"],
                )
                for raw_job_id in ("retry-dead", "retry-alive"):
                    retry_job_id = f"legacy:run-retry-liveness:{raw_job_id}"
                    retry_attempt = retry_store.list_attempts(retry_job_id)[0]
                    self.assertEqual(
                        "abandoned" if raw_job_id == "retry-dead" else "review",
                        retry_attempt["status"],
                    )
                    event_types = [
                        event["event_type"]
                        for event in retry_store.list_provenance_events(
                            attempt_id=retry_attempt["attempt_id"]
                        )
                    ]
                    self.assertEqual(
                        [
                            "attempt.queued",
                            "attempt.abandoned"
                            if raw_job_id == "retry-dead"
                            else "attempt.review",
                        ],
                        event_types,
                    )
                with retry_store.controller_lease("test-claim", ttl_seconds=30) as lease:
                    self.assertIsNone(
                        retry_store.claim_next_job("test-claim", int(lease["fence_token"])),
                        "legacy retry rows must not be requeued",
                    )

    def test_running_without_probe_does_not_fabricate_review_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = pathlib.Path(tmp) / "import.sqlite3"
            report = {
                "run_id": "run-unprobed",
                "jobs": [{"job_id": "job-running", "status": "running"}],
            }
            legacy_history.import_to_sqlite([report], db)
            with SQLiteStore(db) as store:
                events = store.list_provenance_events()
                self.assertEqual(["attempt.queued"], [event["event_type"] for event in events])
                self.assertEqual("unknown", store.list_jobs()[0]["payload"]["legacy_liveness"])

    def test_summary_prefers_matching_worker_pid_over_run_pid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "run-workers"
            root.mkdir()
            (root / "state.json").write_text(
                json.dumps({
                    "run_id": "run-workers",
                    "pid": 99999999,
                    "jobs": [{"job_id": "job-a", "status": "running"}],
                    "workers": [{"job_id": "job-a", "pid": 4321}],
                }),
                encoding="utf-8",
            )
            observed: list[object] = []
            report = legacy_history.summarize_run(
                root,
                reconcile=True,
                liveness_probe=lambda pid: (observed.append(pid) or "dead"),
            )
            self.assertEqual([4321], observed)
            self.assertEqual("dead", report["liveness"]["job-a"])

    def test_pid_path_is_confined_to_the_selected_run_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run = base / "run-confined"
            run.mkdir()
            outside = base / "outside.pid"
            outside.write_text("9876\n", encoding="utf-8")
            (run / "state.json").write_text(
                json.dumps({
                    "run_id": "run-confined",
                    "jobs": [{
                        "job_id": "job-escape",
                        "status": "running",
                        "pid_path": "../outside.pid",
                    }],
                }),
                encoding="utf-8",
            )
            observed: list[object] = []
            report = legacy_history.summarize_run(
                run,
                reconcile=True,
                liveness_probe=lambda pid: (observed.append(pid) or "unknown"),
            )
            self.assertEqual([None], observed)
            self.assertEqual("unknown", report["liveness"]["job-escape"])

    def test_pid_path_symlink_escape_is_unknown_and_internal_path_still_works(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run = base / "run-symlink"
            run.mkdir()
            outside = base / "outside.pid"
            outside.write_text("9876\n", encoding="utf-8")
            try:
                (run / "escape.pid").symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            (run / "inside.pid").write_text("4321\n", encoding="utf-8")
            (run / "state.json").write_text(
                json.dumps({
                    "run_id": "run-symlink",
                    "jobs": [
                        {"job_id": "job-escape", "status": "running", "pid_path": "escape.pid"},
                        {"job_id": "job-inside", "status": "running", "pid_path": "inside.pid"},
                    ],
                }),
                encoding="utf-8",
            )
            observed: list[object] = []
            report = legacy_history.summarize_run(
                run,
                reconcile=True,
                liveness_probe=lambda pid: (observed.append(pid) or "unknown"),
            )
            self.assertEqual([None, "4321"], observed)
            self.assertEqual("unknown", report["liveness"]["job-escape"])
            self.assertEqual("unknown", report["liveness"]["job-inside"])

    def test_import_is_idempotent_and_fails_closed_on_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = pathlib.Path(tmp) / "import.sqlite3"
            report = {
                "run_id": "run-terminal",
                "jobs": [{"job_id": "job-done", "status": "completed"}],
            }
            first = legacy_history.import_to_sqlite([report], db)
            second = legacy_history.import_to_sqlite([report], db)
            self.assertEqual(1, first["imported_jobs"])
            self.assertEqual(1, first["imported_attempts"])
            self.assertEqual(1, first["imported_provenance_events"])
            self.assertEqual(1, second["skipped"])
            self.assertEqual(0, second["imported_attempts"])
            with SQLiteStore(db) as store:
                row = store.get_job("legacy:run-terminal:job-done")
                self.assertEqual("completed", row["status"])
                self.assertEqual("preserve_terminal_only", row["payload"]["import_policy"])
                attempts = store.list_attempts(row["job_id"])
                self.assertEqual("review", attempts[0]["status"])
                self.assertEqual(1, len(store.list_provenance_events(attempt_id=attempts[0]["attempt_id"])))
                self.assertEqual(1, len([e for e in store.list_events() if e["event_type"] == "legacy_job_imported"]))
                self.assertNotIn("attempt.completed", [
                    item["event_type"] for item in store.list_provenance_events()
                ])
            conflict_db = pathlib.Path(tmp) / "conflict.sqlite3"
            conflict_report = {
                "run_id": "run-conflict",
                "jobs": [{"job_id": "job-a", "status": "completed", "model": "spark"}],
            }
            legacy_history.import_to_sqlite([conflict_report], conflict_db)
            conflicting = json.loads(json.dumps(conflict_report))
            conflicting["jobs"][0]["model"] = "gemini"

            with self.assertRaises(sqlite_store.JobConflict):
                legacy_history.import_to_sqlite([conflicting], conflict_db)

            with SQLiteStore(conflict_db) as store:
                job = store.get_job("legacy:run-conflict:job-a")
                self.assertEqual("spark", job["payload"]["model"])
                self.assertEqual(
                    1,
                    len(
                        [
                            event
                            for event in store.list_events()
                            if event["event_type"] == "legacy_import_completed"
                        ]
                    ),
                )

    def test_missing_timestamp_is_deterministic_and_marked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = pathlib.Path(tmp) / "import.sqlite3"
            report = {"run_id": "run-no-time", "jobs": [{"job_id": "job-a", "status": "queued"}]}
            first = legacy_history.import_to_sqlite([report], db)
            self.assertEqual(1, first["imported_jobs"])
            with SQLiteStore(db) as store:
                event = store.list_provenance_events()[0]
                self.assertTrue(event["legacy_timestamp_missing"])
                self.assertEqual("unknown", event["legacy_liveness"])
                timestamp = event["timestamp"]
            # A second database receives exactly the same stable observation
            # timestamp and event id even though no historical time existed.
            db2 = pathlib.Path(tmp) / "import-2.sqlite3"
            legacy_history.import_to_sqlite([report], db2)
            with SQLiteStore(db2) as store:
                event2 = store.list_provenance_events()[0]
                self.assertEqual(timestamp, event2["timestamp"])

    def test_batch_import_is_idempotent_and_never_requeues_legacy_statuses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "legacy"
            root.mkdir()
            (root / "run-a").mkdir()
            (root / "run-a" / "state.json").write_text(
                json.dumps({
                    "run_id": "run-a",
                    "jobs": [
                        {"job_id": "job-completed", "status": "completed", "model": "spark"},
                        {
                            "job_id": "job-queued",
                            "status": "queued",
                            "model": "spark",
                            "prompt": "never import this prompt",
                            "argv": ["never import this argv"],
                            "artifact": {"path": "never import this artifact"},
                            "credentials": {"token": "never import this credential"},
                        },
                        {"job_id": "job-running", "status": "running", "model": "spark"},
                        {"job_id": "job-retry", "status": "retry", "model": "spark"},
                    ],
                    "workers": [
                        {"job_id": "job-running", "pid": 1002},
                        {"job_id": "job-retry", "pid": 1003},
                    ],
                }),
                encoding="utf-8",
            )
            db = root / "import.sqlite3"
            liveness = {1002: "alive", 1003: "dead"}
            probe = lambda pid: liveness.get(pid, "unknown")
            first = legacy_history.import_discovered_runs(
                root,
                db,
                reconcile=True,
                liveness_probe=probe,
            )
            second = legacy_history.import_discovered_runs(
                root,
                db,
                reconcile=True,
                liveness_probe=probe,
            )
            self.assertFalse(first["read_only"])
            self.assertFalse(first["provider_execution"])
            self.assertEqual(4, first["migration"]["imported_jobs"])
            self.assertEqual(3, first["migration"]["reviewed_jobs"])
            self.assertEqual(4, second["migration"]["skipped"])
            encoded = json.dumps(first)
            for secret in (
                "never import this prompt",
                "never import this argv",
                "never import this artifact",
                "never import this credential",
            ):
                self.assertNotIn(secret, encoded)
            with SQLiteStore(db) as store:
                rows = {row["job_id"]: row for row in store.list_jobs()}
                self.assertEqual(4, len(rows))
                self.assertEqual("completed", rows["legacy:run-a:job-completed"]["status"])
                for raw_job_id in ("job-queued", "job-running", "job-retry"):
                    self.assertEqual("review", rows[f"legacy:run-a:{raw_job_id}"]["status"])
                self.assertEqual(
                    "confirmed_alive",
                    rows["legacy:run-a:job-running"]["payload"]["legacy_liveness_classification"],
                )
                self.assertEqual(
                    "confirmed_dead",
                    rows["legacy:run-a:job-retry"]["payload"]["legacy_liveness_classification"],
                )
                with store.controller_lease("batch-test", ttl_seconds=30) as lease:
                    self.assertIsNone(store.claim_next_job("batch-test", int(lease["fence_token"])))
                self.assertEqual(
                    6,
                    len(store.list_provenance_events()),
                    "stable EventV2 ids make the repeated batch import idempotent",
                )

    def test_cli_output_db_uses_bounded_batch_import_contract(self) -> None:
        """The write-enabled CLI must use the same importer as the API.

        This protects the migration boundary from silently growing a second
        implementation: the CLI result must expose the batch migration
        counters and persist only the review-safe legacy projection.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "legacy"
            run = root / "run-cli"
            run.mkdir(parents=True)
            (run / "state.json").write_text(
                json.dumps(
                    {
                        "run_id": "run-cli",
                        "jobs": [
                            {
                                "job_id": "job-cli",
                                "status": "running",
                                "model": "spark",
                                "prompt": "must never be persisted",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            db = root / "import.sqlite3"
            output = root / "report.json"

            self.assertEqual(
                0,
                legacy_history.main(
                    [
                        "--root",
                        str(root),
                        "--output-db",
                        str(db),
                        "--output",
                        str(output),
                    ]
                ),
            )
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertFalse(report["read_only"])
            self.assertFalse(report["provider_execution"])
            self.assertEqual(1, report["migration"]["imported_jobs"])
            self.assertEqual(1, report["migration"]["reviewed_jobs"])
            with SQLiteStore(db) as store:
                job = store.get_job("legacy:run-cli:job-cli")
                self.assertEqual("review", job["status"])
                self.assertNotIn("must never be persisted", json.dumps(job))


if __name__ == "__main__":
    unittest.main()
