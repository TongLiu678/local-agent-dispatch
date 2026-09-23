from __future__ import annotations

import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "dispatch_preflight_readiness_under_test",
    ROOT / "scripts" / "dispatch_preflight_scan.py",
)
assert SPEC and SPEC.loader
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


class DispatchPreflightReadinessTests(unittest.TestCase):
    def test_inventory_hosts_survive_outer_compute_timeout_as_unknown(self) -> None:
        rows = preflight.merge_inventory_compute_hosts(
            {},
            {
                "central_cluster": {
                    "host_id": "central_cluster",
                    "transport": "ssh",
                    "hostname": "cluster.invalid",
                    "user": "worker",
                    "project_path": "/srv/EXAMPLE_001",
                    "tags": ["private-inventory"],
                }
            },
            {"ok": False, "returncode": 124, "error": "timeout"},
            "2026-08-29T00:00:00+00:00",
        )
        row = rows["central_cluster"]
        self.assertFalse(row["reachable"])
        self.assertIsNone(row["project_path_exists"])
        self.assertIsNone(row["project_path_writable"])
        self.assertEqual("compute_probe_timeout", row["probe_failure_code"])
        self.assertEqual("inventory_unreachable_fallback", row["resource_source"])
        self.assertEqual(["private-inventory"], row["tags"])
        cases = (
            ("Connection refused", "compute_probe_connection_refused"),
            ("could not resolve host", "compute_probe_dns_failure"),
            ("Permission denied (publickey)", "compute_probe_auth_failed"),
        )
        for error, expected in cases:
            with self.subTest(error=error):
                self.assertEqual(
                    expected,
                    preflight.compute_probe_failure_code(
                        {"ok": False, "returncode": 255, "error": error}
                    ),
                )

        refused_rows = preflight.merge_inventory_compute_hosts(
            {},
            {
                "central_cluster": {
                    "host_id": "central_cluster",
                    "transport": "ssh",
                    "hostname": "cluster.invalid",
                    "user": "worker",
                    "project_path": "/srv/EXAMPLE_001",
                }
            },
            {"ok": False, "returncode": 255, "error": "Connection refused"},
            "2026-09-01T00:00:00+00:00",
        )
        refused = refused_rows["central_cluster"]
        self.assertFalse(refused["reachable"])
        self.assertEqual("compute_probe_connection_refused", refused["probe_failure_code"])
        self.assertEqual(
            "compute probe connection was refused before a per-host result was returned",
            refused["probe_error"],
        )

    def test_keychain_and_ssh_signing_failures_are_not_network_refusals(self) -> None:
        cases = (
            "User interaction is not allowed",
            "security: SecKeychainUnlock: The specified keychain is locked",
            "sign_and_send_pubkey: signing failed: agent refused operation",
        )
        for error in cases:
            with self.subTest(error=error):
                self.assertEqual(
                    "compute_probe_auth_context_unavailable",
                    preflight.compute_probe_failure_code(
                        {"ok": False, "returncode": 255, "error": error}
                    ),
                )

    def test_partial_keychain_error_outranks_outer_timeout(self) -> None:
        self.assertEqual(
            "compute_probe_auth_context_unavailable",
            preflight.compute_probe_failure_code(
                {
                    "ok": False,
                    "returncode": 124,
                    "error": "The login keychain is locked; probe timeout followed",
                }
            ),
        )

    def test_visible_pool_and_stale_local_host_are_only_planning_ready(self) -> None:
        report = preflight.build_execution_readiness(
            {"ok": True},
            {
                "local_system": {
                    "transport": "local",
                    "reachable": True,
                    "project_path_exists": True,
                    "project_path_writable": True,
                    "local_agent_launch_allowed": False,
                }
            },
            {
                "cursor.other": {
                    "provider": "cursor",
                    "health": "ready",
                    "default_model": "gpt-5.3-codex",
                }
            },
            {"compute": {"returncode": 124}},
        )
        self.assertTrue(report["planning_candidate_ready"])
        self.assertEqual(["cursor.other"], report["execution_candidate_pools"])
        self.assertFalse(report["ready"])
        self.assertFalse(report["desktop_control_plane_ready"])
        self.assertIn("compute_probe_failed", report["blockers"])
        self.assertIn("desktop_provider_local_launch_blocked_or_unknown", report["blockers"])

    def test_server_local_pool_requires_live_writable_remote_host(self) -> None:
        report = preflight.build_execution_readiness(
            {"ok": True},
            {
                "node-a": {
                    "transport": "ssh",
                    "reachable": True,
                    "project_path_exists": True,
                    "project_path_writable": True,
                }
            },
            {
                "server_local.node-a": {
                    "provider": "server_local",
                    "health": "ready",
                    "default_model": "local/fake",
                }
            },
        )
        self.assertTrue(report["ready"])
        self.assertTrue(report["server_local_execution_ready"])
        self.assertEqual(["node-a"], report["eligible_remote_hosts"])


if __name__ == "__main__":
    unittest.main()
