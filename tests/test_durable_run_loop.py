from __future__ import annotations

import pathlib
import json
import tempfile
import unittest
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from durable_run_loop import run_loop  # noqa: E402
from durable_run_loop import main as run_loop_main  # noqa: E402


class FakeSupervisor:
    run_id = "loop-test"

    def __init__(self, *, fail: bool = False) -> None:
        self._state = "created"
        self.calls = 0
        self.fail = fail

    @property
    def state(self) -> str:
        return self._state

    def start(self):
        self._state = "running"
        return {"action": "segment_started"}

    def tick(self):
        self.calls += 1
        if self.fail:
            raise RuntimeError("transient")
        if self.calls >= 2:
            self._state = "finished"
        return {
            "action": "continue" if self._state == "running" else "checkpoint_and_roll",
            "remaining_seconds": 42,
        }

    def stop(self, reason: str):
        self._state = "stopped"
        return {"action": "stopped", "reason": reason}


class LargeReportSupervisor(FakeSupervisor):
    def start(self):
        self._state = "running"
        return {"action": "segment_started", "report_blob": "x" * 100_000}

    def tick(self):
        self.calls += 1
        self._state = "finished"
        return {"action": "checkpoint_and_roll", "report_blob": "y" * 100_000}


class DurableRunLoopTests(unittest.TestCase):
    def test_loop_records_each_tick_without_retaining_event_stream(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "monitor.jsonl"
            report = run_loop(
                FakeSupervisor(),
                poll_interval_seconds=1,
                max_runtime_seconds=None,
                event_log=path,
                sleep_fn=lambda _seconds: None,
            )
            self.assertTrue(report["ok"])
            self.assertEqual("finished", report["status"])
            self.assertEqual(2, report["ticks"])
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(3, len(lines))
            self.assertEqual("start", json.loads(lines[0])["kind"])
            last = json.loads(lines[-1])
            self.assertEqual("tick", last["kind"])
            self.assertIn("loop_elapsed_seconds", last)
            self.assertIsNone(last["loop_remaining_seconds"])
            self.assertEqual(42, last["segment_remaining_seconds"])
            self.assertEqual("monotonic_runner", last["progress_clock"])

    def test_repeated_errors_fail_closed_and_are_receipted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "monitor.jsonl"
            report = run_loop(
                FakeSupervisor(fail=True),
                poll_interval_seconds=1,
                max_runtime_seconds=None,
                max_consecutive_errors=2,
                event_log=path,
                sleep_fn=lambda _seconds: None,
            )
            self.assertFalse(report["ok"])
            self.assertEqual("blocked", report["status"])
            self.assertEqual("consecutive_errors", report["reason"])
            self.assertEqual(2, report["errors"])
            self.assertEqual(3, len(path.read_text(encoding="utf-8").splitlines()))

    def test_large_reports_are_compacted_before_the_monitor_ledger_grows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "monitor.jsonl"
            report = run_loop(
                LargeReportSupervisor(),
                poll_interval_seconds=1,
                max_runtime_seconds=None,
                max_record_bytes=4096,
                event_log=path,
                sleep_fn=lambda _seconds: None,
            )
            self.assertTrue(report["ok"])
            self.assertEqual(2, report["truncated_records"])
            lines = path.read_bytes().splitlines()
            self.assertEqual(2, len(lines))
            self.assertTrue(all(len(line) <= 4096 for line in lines))
            first = json.loads(lines[0])
            self.assertTrue(first["record_truncated"])
            self.assertTrue(first["report_digest"].startswith("sha256:"))
            self.assertNotIn("report_blob", first)
            self.assertIn("loop_elapsed_seconds", first)
            self.assertIn("loop_remaining_seconds", first)
            self.assertEqual("monotonic_runner", first["progress_clock"])

    def test_cli_dry_run_uses_sqlite_lease_and_does_not_open_ssh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            manifest = root / "continuous-run.json"
            capsule = root / "project-capsule.json"
            inventory = root / "inventory.json"
            manifest.write_text(
                json.dumps({
                    "run_id": "run-cli",
                    "source_digest": "sha256:" + "a" * 64,
                    "capsule_digest": "sha256:" + "b" * 64,
                    "segment_seconds": 3600,
                    "planned_end_at": "2099-01-01T00:00:00Z",
                    "target_id": "worker-a",
                    "payload_digest": "c" * 64,
                }),
                encoding="utf-8",
            )
            capsule.write_text(json.dumps({"capsule_spec_digest": "sha256:" + "b" * 64}), encoding="utf-8")
            # A controller-only host intentionally has no PBS stanza.  The
            # provider-free path must not parse or contact the execution
            # inventory when --execute is absent.
            inventory.write_text(json.dumps({"hosts": []}), encoding="utf-8")
            rc = run_loop_main([
                "--db", str(root / "dispatch.sqlite3"),
                "--manifest", str(manifest),
                "--capsule", str(capsule),
                "--inventory", str(inventory),
                "--run-root", str(root / "run"),
                "--poll-seconds", "0.001",
                "--max-runtime-seconds", "1",
                "--max-ticks", "1",
            ])
            self.assertEqual(1, rc)
            self.assertTrue((root / "run" / "monitor" / "continuous-loop.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
