from __future__ import annotations

import pathlib
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import resource_admission  # noqa: E402


class LocalLaunchAdmissionTests(unittest.TestCase):
    def test_workspace_and_temp_filesystems_are_both_checked(self) -> None:
        rows = iter(
            [
                {
                    "evidence": "complete",
                    "path": "/workspace",
                    "free_bytes": 2_000_000_000,
                    "total_bytes": 4_000_000_000,
                    "free_percent": 50.0,
                    "probe_path": "/workspace",
                },
                {
                    "evidence": "complete",
                    "path": "/tmp",
                    "free_bytes": 100,
                    "total_bytes": 4_000_000_000,
                    "free_percent": 0.0,
                    "probe_path": "/tmp",
                },
            ]
        )
        with mock.patch.object(resource_admission, "_filesystem", side_effect=lambda path: next(rows)):
            report = resource_admission.check_local_launch("/workspace", temporary_directory="/tmp")
        self.assertFalse(report["allowed"])
        self.assertIn("free_bytes_below_floor", " ".join(report["reasons"]))
        self.assertEqual("run_remote_or_free_space_with_user_approval", report["next_action"])

    def test_additional_database_or_log_path_is_checked(self) -> None:
        rows = iter(
            [
                {"evidence": "complete", "path": "/workspace", "free_bytes": 2_000_000_000, "total_bytes": 4_000_000_000, "free_percent": 50.0, "probe_path": "/workspace"},
                {"evidence": "complete", "path": "/tmp", "free_bytes": 2_000_000_000, "total_bytes": 4_000_000_000, "free_percent": 50.0, "probe_path": "/tmp"},
                {"evidence": "complete", "path": "/db", "free_bytes": 1, "total_bytes": 4_000_000_000, "free_percent": 50.0, "probe_path": "/db"},
            ]
        )
        with mock.patch.object(resource_admission, "_filesystem", side_effect=lambda path: next(rows)):
            report = resource_admission.check_local_launch(
                "/workspace", temporary_directory="/tmp", additional_paths=("/db/dispatch.sqlite3",)
            )
        self.assertFalse(report["allowed"])
        self.assertIn("/db", " ".join(report["reasons"]))

    def test_unknown_filesystem_fails_closed_without_side_effects(self) -> None:
        with mock.patch.object(
            resource_admission, "_filesystem", return_value={"path": "/x", "evidence": "unknown"}
        ):
            report = resource_admission.check_local_launch("/x", temporary_directory="/x")
        self.assertFalse(report["allowed"])
        self.assertIn("filesystem_evidence_unknown", report["reasons"][0])


if __name__ == "__main__":
    unittest.main()
