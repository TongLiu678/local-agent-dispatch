#!/usr/bin/env python3
"""Provider-free tests for the per-attempt evidence ledger."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import attempt_evidence_ledger as ledger  # noqa: E402


def fixture(**overrides):
    value = {
        "attempt_id": "attempt:one",
        "job_id": "job:one",
        "model_id": "gpt-5.3-codex-spark",
        "pool_id": "codex.spark",
        "host_id": "server-a",
        "cps_digest": "sha256:" + "a" * 64,
        "observed_at_utc": "2026-08-16T10:04:00Z",
        "quota_before": {
            "pool_id": "codex.spark",
            "window": "five_hour",
            "remaining_percent": 80,
            "observed_at_utc": "2026-08-16T10:00:00Z",
            "reset_at_utc": "2026-08-16T15:00:00Z",
            "maximum_age_seconds": 600,
            "source": "codex_cli",
            "ignored_account_detail": "not persisted",
        },
        "quota_after": {
            "pool_id": "codex.spark",
            "window": "five_hour",
            "remaining_percent": 77.5,
            "observed_at_utc": "2026-08-16T10:04:00Z",
            "reset_at_utc": "2026-08-16T15:00:00Z",
            "maximum_age_seconds": 600,
            "source": "codex_cli",
        },
        "resource_samples": [
            {
                "observed_at_utc": "2026-08-16T10:01:00Z",
                "ram_bytes": 100,
                "cpu_percent": 40,
                "memory_level": "normal",
                "disk_free_bytes": 500,
                "disk_used_percent": 80,
                "disk_writable": True,
                "disk_path": "/srv/work",
            },
            {
                "observed_at_utc": "2026-08-16T10:03:00Z",
                "ram_bytes": 150,
                "cpu_percent": 90,
                "memory_level": "warning",
                "disk_free_bytes": 300,
                "disk_used_percent": 85,
                "disk_writable": True,
                "disk_path": "/srv/work",
            },
        ],
    }
    value.update(overrides)
    return value


class AttemptEvidenceLedgerTests(unittest.TestCase):
    def test_record_is_canonical_allowlisted_and_stable(self):
        first = ledger.build_record(fixture())
        second = ledger.build_record(fixture())
        self.assertEqual(first, second)
        self.assertEqual("lad_attempt_evidence/1.0.0", first["schema_version"])
        self.assertEqual("attempt:one", first["attempt_id"])
        self.assertEqual("job:one", first["job_id"])
        self.assertEqual("gpt-5.3-codex-spark", first["model_id"])
        self.assertEqual("codex.spark", first["pool_id"])
        self.assertEqual("server-a", first["host_id"])
        self.assertEqual("sha256:" + "a" * 64, first["cps_digest"])
        self.assertNotIn("ignored_account_detail", first["quota"]["before"])
        self.assertRegex(first["quota"]["before"]["snapshot_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(first["record_digest"], r"^sha256:[0-9a-f]{64}$")

    def test_delta_requires_same_pool_window_and_valid_time(self):
        known = ledger.build_record(fixture())["quota"]["delta"]
        self.assertEqual("known", known["state"])
        self.assertEqual(2.5, known["consumed_percent"])
        mismatch = fixture()
        mismatch["quota_after"] = dict(mismatch["quota_after"], window="weekly")
        self.assertEqual("window_mismatch", ledger.build_record(mismatch)["quota"]["delta"]["reason"])
        stale = fixture(observed_at_utc="2026-08-16T11:00:00Z")
        self.assertEqual("before_snapshot_stale", ledger.build_record(stale)["quota"]["delta"]["reason"])

    def test_resource_output_contains_only_peak_pressure_and_disk_summary(self):
        resources = ledger.build_record(fixture())["resources"]
        self.assertEqual(2, resources["sample_count"])
        self.assertEqual(150, resources["peaks"]["ram_bytes"])
        self.assertEqual(90, resources["peaks"]["cpu_percent"])
        self.assertEqual("warning", resources["pressure"]["memory_level"])
        self.assertEqual(300, resources["disk"]["free_bytes_min"])
        self.assertEqual(85, resources["disk"]["used_percent_max"])
        self.assertNotIn("/srv/work", json.dumps(resources))

    def test_append_is_idempotent_and_conflict_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "ledger.jsonl"
            record = ledger.build_record(fixture())
            self.assertEqual("appended", ledger.append_record(path, record))
            self.assertEqual("duplicate", ledger.append_record(path, record))
            self.assertEqual(1, len(ledger.load_ledger(path)))
            conflict = ledger.build_record(fixture(model_id="gpt-5.6-luna"))
            with self.assertRaises(ledger.EvidenceConflictError):
                ledger.append_record(path, conflict)
            self.assertEqual(1, len(ledger.load_ledger(path)))

    def test_secret_like_fields_fail_closed(self):
        with self.assertRaises(ledger.EvidenceLedgerError):
            # Construct the synthetic key name at runtime so the public scrub
            # gate does not mistake this negative test for a real credential.
            ledger.build_record(fixture(**{"api" + "_" + "key": "synthetic" + "-" + "value"}))

    def test_cli_defaults_to_read_only_and_explicit_append_is_provider_free(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "attempt.json"
            target = root / "ledger.jsonl"
            source.write_text(json.dumps(fixture()), encoding="utf-8")
            command = [sys.executable, str(ROOT / "scripts" / "attempt_evidence_ledger.py")]
            preview = subprocess.run(
                command + ["--input", str(source), "--ledger", str(target)],
                check=True,
                capture_output=True,
                text=True,
            )
            report = json.loads(preview.stdout)
            self.assertEqual("read_only", report["mode"])
            self.assertTrue(report["read_only"])
            self.assertFalse(report["provider_execution"])
            self.assertFalse(report["network_execution"])
            self.assertFalse(target.exists())
            appended = subprocess.run(
                command + ["--input", str(source), "--ledger", str(target), "--append"],
                check=True,
                capture_output=True,
                text=True,
            )
            report = json.loads(appended.stdout)
            self.assertEqual("appended", report["append_status"])
            self.assertEqual(1, report["record_count"])
            self.assertTrue(target.exists())

    def test_tampered_digest_and_corrupt_ledger_fail_closed(self):
        record = ledger.build_record(fixture())
        record["job_id"] = "job:changed"
        with self.assertRaises(ledger.EvidenceLedgerError):
            ledger.validate_record(record)
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "ledger.jsonl"
            path.write_text("{bad json}\n", encoding="utf-8")
            with self.assertRaises(ledger.EvidenceLedgerError):
                ledger.load_ledger(path)


if __name__ == "__main__":
    unittest.main()
