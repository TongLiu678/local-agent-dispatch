from __future__ import annotations

import pathlib
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "scripts"))

import local_storage_pressure as pressure  # noqa: E402


class LocalStoragePressureTests(unittest.TestCase):
    def test_report_is_read_only_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "sessions"
            root.mkdir()
            (root / "large.log").write_bytes(b"x" * 32)
            (root / "nested").mkdir()
            (root / "nested" / "small.log").write_bytes(b"y")
            before = sorted(path.name for path in root.rglob("*"))
            with mock.patch.object(
                pressure,
                "_disk",
                return_value={
                    "path": str(root),
                    "evidence": "complete",
                    "total_bytes": 1000,
                    "free_bytes": 10,
                    "free_percent": 1.0,
                },
            ):
                report = pressure.build_report([root], temporary_directory=root, max_entries=1)
            self.assertTrue(report["read_only"])
            self.assertTrue(report["disk_pressure"])
            self.assertTrue(report["policy"]["cleanup_required_by_user"])
            self.assertTrue(report["roots"][0]["truncated"])
            self.assertEqual(before, sorted(path.name for path in root.rglob("*")))

    def test_healthy_report_allows_control_plane(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with mock.patch.object(
                pressure,
                "_disk",
                return_value={
                    "path": str(root),
                    "evidence": "complete",
                    "total_bytes": 1000,
                    "free_bytes": 900,
                    "free_percent": 90.0,
                },
            ):
                report = pressure.build_report(
                    [root], temporary_directory=root, minimum_free_bytes=100
                )
            self.assertFalse(report["disk_pressure"])
            self.assertTrue(report["policy"]["new_local_launch_allowed"])
            self.assertFalse(report["policy"]["automatic_delete"])

    def test_shallow_scan_reports_unseen_deep_bytes_as_lower_bound(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            nested = root / "session" / "attempt" / "artifacts"
            nested.mkdir(parents=True)
            (nested / "large.bin").write_bytes(b"x" * 128)
            with mock.patch.object(
                pressure,
                "_disk",
                return_value={
                    "path": str(root),
                    "evidence": "complete",
                    "total_bytes": 1000,
                    "free_bytes": 900,
                    "free_percent": 90.0,
                },
            ):
                report = pressure.build_report(
                    [root], temporary_directory=root, max_depth=0
                )
            root_report = report["roots"][0]
            self.assertTrue(root_report["depth_limited"])
            self.assertTrue(root_report["bytes_seen_is_lower_bound"])
            self.assertFalse(root_report["scan_complete"])

    def test_previous_report_comparison_is_directional_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "new.log").write_bytes(b"x" * 8)
            prior = {
                "schema_version": 1,
                "observed_at_utc": "2026-08-13T00:00:00+00:00",
                "disks": [{"path": str(root), "free_bytes": 1000}],
                "roots": [{
                    "path": str(root), "bytes_seen": 2,
                    "bytes_seen_is_lower_bound": True,
                }],
            }
            with mock.patch.object(
                pressure,
                "_disk",
                return_value={
                    "path": str(root),
                    "evidence": "complete",
                    "total_bytes": 2000,
                    "free_bytes": 900,
                    "free_percent": 45.0,
                },
            ):
                report = pressure.build_report(
                    [root], temporary_directory=root, minimum_free_bytes=100,
                    previous_report=prior,
                )
            self.assertEqual(-100, report["comparison"]["disk_deltas"][0]["free_bytes_delta"])
            self.assertTrue(report["comparison"]["root_observed_deltas"][0]["lower_bound"])
            self.assertEqual(
                "directional_only_lower_bound_for_roots",
                report["comparison"]["interpretation"],
            )


if __name__ == "__main__":
    unittest.main()
