from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("m0_lane_bundle", ROOT / "scripts" / "m0_lane_bundle.py")
assert SPEC and SPEC.loader
BUNDLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUNDLE)


def _plan(**overrides):
    plan = {
        "plan_id": "m0-source-truth",
        "tasks": [{"task_id": "source-truth-audit"}],
        "lane_write_root": ".lad/m0/source-truth",
        "model": "opencode-go/deepseek-v4-flash",
        "variant": "max",
        "quota": {
            "pool_id": "opencode.go",
            "remaining_percent": 80,
            "reserve_percent": 10,
            "cost_percent_per_lane": 5,
        },
        "resources": {
            "cpu_cores": 2,
            "ram_gib": 4,
            "gpu_count": 0,
            "disk_gib": 1,
        },
    }
    plan.update(overrides)
    return plan


def _hosts(slots=5):
    return {
        "external_consumers": {
            "scan_ok": True,
            "inflight_by_pool": {"opencode.go": 0},
        },
        "compute_hosts": {
            "bjb2": {
                "host_id": "bjb2",
                "transport": "ssh",
                "reachable": True,
                "project_path": "/srv/lad",
                "project_path_writable": True,
                "lane_slots": slots,
                "estimated_idle_cpu_cores": 32,
                "memory_available_gib": 64,
                "disk_free_gib": 100,
            },
            "westd": {
                "host_id": "westd",
                "transport": "ssh",
                "reachable": True,
                "project_path": "/srv/lad",
                "project_path_writable": True,
                "lane_slots": slots,
                "estimated_idle_cpu_cores": 32,
                "memory_available_gib": 64,
                "disk_free_gib": 100,
            },
        }
    }


class ExternalEvidenceSafetyTests(unittest.TestCase):
    def test_missing_opencode_external_scan_is_fail_closed(self):
        hosts = _hosts()
        hosts.pop("external_consumers")
        bundle = BUNDLE.build_lane_bundle(
            _plan(), "opencode-go/deepseek-v4-flash", "max", hosts, lane_count=1
        )
        self.assertEqual(0, bundle["resource_admission"]["admitted_lanes"])
        self.assertEqual(
            "external_consumer_state_unknown", bundle["deferred"][0]["reasons"][0]
        )

    def test_preflight_binds_redacted_busy_and_current_quota(self):
        preflight = {
            "external_consumers": {
                "scan_ok": True,
                "inflight_by_pool": {"opencode.go": 2},
                "processes": [{"pid": 123, "model": "must-not-copy"}],
            },
            "pools": {"opencode.go": {"effective_remaining_percent": 6}},
            "scan_policy": {"credential_queries": False},
        }
        bundle = BUNDLE.build_lane_bundle(
            _plan(),
            "opencode-go/deepseek-v4-flash",
            "max",
            _hosts(),
            lane_count=1,
            preflight=preflight,
        )
        self.assertEqual(0, bundle["resource_admission"]["admitted_lanes"])
        self.assertEqual("external_consumer_pool_busy", bundle["deferred"][0]["reasons"][0])
        self.assertEqual(6.0, bundle["quota_admission"]["remaining_percent"])
        self.assertEqual({"scan_ok": True, "inflight_by_pool": {"opencode.go": 2}}, bundle["external_consumer_evidence"])


class M0LaneBundleTests(unittest.TestCase):
    def test_default_ten_lanes_are_disjoint_balanced_and_deterministic(self):
        first = BUNDLE.build_lane_bundle(
            _plan(), "opencode-go/deepseek-v4-flash", "max", _hosts()
        )
        second = BUNDLE.build_lane_bundle(
            _plan(), "opencode-go/deepseek-v4-flash", "max", _hosts()
        )
        self.assertEqual(first, second)
        BUNDLE.validate_bundle(first, expected_lane_count=10)
        self.assertEqual(10, len(first["lanes"]))
        self.assertEqual(10, len(first["digests"]["lanes"]))
        self.assertEqual(10, first["resource_admission"]["admitted_lanes"])
        self.assertEqual([], first["deferred"])
        self.assertTrue(BUNDLE.scopes_are_disjoint([row["write_scope"] for row in first["lanes"]]))
        self.assertEqual({"bjb2": 5, "westd": 5}, {
            host: sum(row["host_id"] == host for row in first["lanes"])
            for host in ("bjb2", "westd")
        })
        self.assertFalse(first["provider_execution"])
        self.assertFalse(first["ssh_execution"])
        self.assertFalse(first["real_run_directory_written"])

    def test_quota_admission_defers_after_reserve(self):
        plan = _plan(quota={
            "pool_id": "opencode.go",
            "remaining_percent": 30,
            "reserve_percent": 10,
            "cost_percent_per_lane": 5,
        })
        bundle = BUNDLE.build_lane_bundle(
            plan, "opencode-go/deepseek-v4-flash", "max", _hosts(slots=10)
        )
        self.assertEqual(4, bundle["resource_admission"]["admitted_lanes"])
        self.assertEqual(6, len(bundle["deferred"]))
        self.assertEqual("quota_reserve_exceeded", bundle["deferred"][0]["reasons"][0])
        self.assertTrue(all(row["status"] == "deferred" for row in bundle["lanes"][4:]))

    def test_live_quota_explicit_pilot_cap_needs_no_fake_cost(self):
        plan = _plan(quota={
            "pool_id": "opencode.go",
            "remaining_percent": 80,
            "reserve_percent": 10,
            "max_admitted_lanes": 1,
        })
        bundle = BUNDLE.build_lane_bundle(
            plan, "opencode-go/deepseek-v4-flash", "max", _hosts(slots=10)
        )
        self.assertEqual(1, bundle["resource_admission"]["admitted_lanes"])
        self.assertEqual(9, len(bundle["deferred"]))
        self.assertEqual("explicit_pilot_cap", bundle["quota_admission"]["reason"])
        self.assertIsNone(bundle["quota_admission"]["cost_percent_per_lane"])
        self.assertEqual(1, bundle["quota_admission"]["explicit_lane_cap"])
        self.assertEqual("explicit_pilot_cap", bundle["deferred"][0]["reasons"][0])

    def test_external_pool_consumer_blocks_new_lane(self):
        plan = _plan()
        hosts = _hosts(slots=2)
        hosts["compute_hosts"]["bjb2"]["external_consumers"] = {
            "scan_ok": True,
            "inflight_by_pool": {"opencode.go": 1},
        }
        bundle = BUNDLE.build_lane_bundle(
            plan, "opencode-go/deepseek-v4-flash", "max", hosts, lane_count=1
        )
        self.assertEqual(0, bundle["resource_admission"]["admitted_lanes"])
        self.assertIn(
            "external_consumer_pool_busy",
            bundle["deferred"][0]["reasons"],
        )
        self.assertEqual("external_consumer_pool_busy", bundle["quota_admission"]["reason"])

    def test_external_consumer_scan_failure_is_fail_closed(self):
        plan = _plan()
        hosts = _hosts(slots=2)
        hosts["compute_hosts"]["bjb2"]["external_consumers"] = {"scan_ok": False}
        bundle = BUNDLE.build_lane_bundle(
            plan, "opencode-go/deepseek-v4-flash", "max", hosts, lane_count=1
        )
        self.assertEqual(0, bundle["resource_admission"]["admitted_lanes"])
        self.assertIn(
            "external_consumer_state_unknown",
            bundle["deferred"][0]["reasons"],
        )
        self.assertEqual("external_consumer_state_unknown", bundle["quota_admission"]["reason"])

    def test_host_capacity_and_writable_gate_are_explicit(self):
        hosts = _hosts(slots=2)
        hosts["compute_hosts"]["westd"]["project_path_writable"] = False
        bundle = BUNDLE.build_lane_bundle(
            _plan(), "opencode-go/deepseek-v4-flash", "max", hosts
        )
        self.assertEqual(2, bundle["resource_admission"]["admitted_lanes"])
        self.assertEqual(8, len(bundle["deferred"]))
        self.assertIn("no_host_admission", bundle["deferred"][0]["reasons"])
        self.assertTrue(any("write_path_not_writable:westd" in reason for reason in bundle["deferred"][0]["reasons"]))

    def test_unknown_quota_is_fail_closed_and_model_is_pinned(self):
        plan = _plan(quota={"pool_id": "opencode.go"})
        bundle = BUNDLE.build_lane_bundle(
            plan, "opencode-go/deepseek-v4-flash", "max", _hosts(slots=10)
        )
        self.assertEqual(0, bundle["resource_admission"]["admitted_lanes"])
        self.assertEqual("quota_unknown", bundle["deferred"][0]["reasons"][0])
        self.assertTrue(all(row["model_selection"] == "exact_caller_pin" for row in bundle["lanes"]))
        with self.assertRaises(BUNDLE.LaneBundleError):
            BUNDLE.build_lane_bundle(plan, "opencode-go/kimi-k3", "max", _hosts())

    def test_scope_and_secret_inputs_fail_closed(self):
        with self.assertRaises(BUNDLE.LaneBundleError):
            BUNDLE.build_lane_bundle(_plan(lane_write_root="../outside"), "m", None, _hosts())
        with self.assertRaises(BUNDLE.LaneBundleError):
            plan = _plan()
            plan["api_key"] = "synthetic-key-value"
            BUNDLE.build_lane_bundle(plan, "opencode-go/deepseek-v4-flash", "max", _hosts())

    def test_safety_and_scan_assertions_are_not_credentials(self):
        plan = _plan(
            safety={
                "no_credentials": True,
                "credentials_copied_or_emitted": False,
                "credential_values_emitted": False,
                "provider_auth_queries": False,
            }
        )
        hosts = _hosts()
        hosts["scan_policy"] = {
            "credential_queries": False,
            "provider_auth_queries": False,
        }
        bundle = BUNDLE.build_lane_bundle(
            plan, "opencode-go/deepseek-v4-flash", "max", hosts, lane_count=1
        )
        self.assertEqual(1, len(bundle["lanes"]))
        self.assertFalse(bundle["provider_execution"])

    def test_cli_defaults_to_stdout_without_creating_run_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            plan = root / "plan.json"
            hosts = root / "hosts.json"
            plan.write_text(json.dumps(_plan()), encoding="utf-8")
            hosts.write_text(json.dumps(_hosts()), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = BUNDLE.main([
                    "--plan", str(plan),
                    "--hosts", str(hosts),
                    "--model", "opencode-go/deepseek-v4-flash",
                    "--variant", "max",
                ])
            self.assertEqual(0, code)
            report = json.loads(output.getvalue())
            self.assertEqual("local-agent-dispatch.m0_lane_bundle", report["report_type"])
            self.assertFalse((root / ".lad").exists())


if __name__ == "__main__":
    unittest.main()
