from __future__ import annotations

import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import resource_hygiene as hygiene  # noqa: E402


class ResourceHygieneTests(unittest.TestCase):
    def test_pressure_attributes_storage_and_rss_then_queues_remote(self) -> None:
        session_path = "/example/codex/sessions"
        snapshot = {
            "schema_version": 1,
            "scanned_at_utc": "2026-08-13T00:00:00+00:00",
            "capacity_gates": {
                "disk_pressure": True,
                "unknown_disks": [],
                "memory_pressure_state": "conserve",
                "local_agent_launch_allowed": False,
            },
            "ram": {"pressure_state": "conserve"},
            "agent_model_processes": {
                "scan_ok": True,
                "arguments_collected": False,
                "processes": [
                    {"pid": 10, "command_name": "codex", "kind": "agent", "rss_kib": 2048},
                    {"pid": 20, "command_name": "opencode", "kind": "agent", "rss_kib": 1024},
                ],
            },
        }
        storage = {
            "schema_version": 1,
            "disk_pressure": True,
            "roots": [
                {
                    "path": session_path,
                    "exists": True,
                    "scan_complete": False,
                    "bytes_seen_is_lower_bound": True,
                    "entries_seen": 100,
                    "bytes_seen": 4096,
                }
            ],
        }

        report = hygiene.build_report(
            snapshot, storage, storage_labels={session_path: "codex_sessions"}
        )

        self.assertEqual("queue_for_verified_remote", report["placement"]["decision"])
        self.assertEqual(
            ["local_disk_pressure", "local_memory_pressure_conserve"],
            report["placement"]["queue_reason_codes"],
        )
        self.assertFalse(report["placement"]["new_local_agent_launch_allowed"])
        self.assertEqual("codex_sessions", report["attribution"]["storage"][0]["role"])
        self.assertTrue(report["evidence"]["storage_measurements_may_be_lower_bounds"])
        self.assertEqual(3 * 1024 * 1024, report["attribution"]["agent_rss"]["rss_total_bytes"])
        self.assertFalse(report["safety"]["automatic_delete"])
        self.assertFalse(report["safety"]["automatic_kill"])
        self.assertFalse(report["safety"]["automatic_agent_start"])

    def test_healthy_evidence_still_prefers_server_first_without_queue(self) -> None:
        snapshot = {
            "schema_version": 1,
            "scanned_at_utc": "2026-08-13T00:00:00+00:00",
            "capacity_gates": {
                "disk_pressure": False,
                "unknown_disks": [],
                "memory_pressure_state": "normal",
                "local_agent_launch_allowed": True,
            },
            "agent_model_processes": {
                "scan_ok": True,
                "arguments_collected": False,
                "processes": [],
            },
        }
        storage = {"schema_version": 1, "disk_pressure": False, "roots": []}

        report = hygiene.build_report(snapshot, storage)

        self.assertEqual("server_first_preferred", report["placement"]["decision"])
        self.assertEqual([], report["placement"]["queue_reason_codes"])
        self.assertTrue(report["placement"]["new_local_agent_launch_allowed"])
        self.assertTrue(report["placement"]["remote_preflight_required"])
        self.assertFalse(report["placement"]["automatic_remote_start"])

    def test_unknown_rss_never_becomes_zero_confidence_complete(self) -> None:
        snapshot = {
            "capacity_gates": {"local_agent_launch_allowed": True},
            "agent_model_processes": {
                "scan_ok": True,
                "processes": [
                    {"pid": 7, "command_name": "codex", "kind": "agent"}
                ],
            },
        }
        report = hygiene.build_report(
            snapshot, {"schema_version": 1, "disk_pressure": False, "roots": []}
        )
        rss = report["attribution"]["agent_rss"]
        self.assertEqual("partial", rss["rss_evidence"])
        self.assertEqual(1, rss["unknown_rss_processes"])
        self.assertEqual(0, rss["rss_total_bytes"])

    def test_cgroup_stat_does_not_promote_file_cache_to_model_rss(self) -> None:
        snapshot = {
            "schema_version": 1,
            "cgroup_memory_current_bytes": 10_000,
            "cgroup_memory_stat": {
                "anon": 4_000,
                "file": 5_000,
                "active_file": 3_000,
                "inactive_file": 2_000,
                "slab": 1_000,
            },
            "agent_model_processes": {
                "scan_ok": True,
                "processes": [
                    {"pid": 7, "command_name": "codex", "kind": "agent", "rss_bytes": 600}
                ],
            },
        }
        report = hygiene.build_report(
            snapshot, {"schema_version": 1, "disk_pressure": False, "roots": []}
        )
        cgroup = report["attribution"]["cgroup_memory"]
        self.assertEqual("complete", cgroup["evidence"])
        self.assertEqual(4_000, cgroup["anon_bytes"])
        self.assertEqual(5_000, cgroup["file_cache_bytes"])
        self.assertEqual(3_000, cgroup["active_file_bytes"])
        self.assertEqual(2_000, cgroup["inactive_file_bytes"])
        self.assertEqual(1_000, cgroup["kernel_slab_bytes"])
        self.assertIsNone(cgroup["agent_model_rss_bytes"])
        self.assertTrue(cgroup["file_cache_excluded_from_agent_rss"])
        self.assertEqual(600, report["attribution"]["agent_rss"]["rss_total_bytes"])


if __name__ == "__main__":
    unittest.main()
