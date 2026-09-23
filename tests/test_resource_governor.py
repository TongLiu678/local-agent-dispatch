from __future__ import annotations

import importlib.util
import json
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "resource_governor.py"
SPEC = importlib.util.spec_from_file_location("resource_governor", SCRIPT)
assert SPEC and SPEC.loader
GOV = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GOV)


class ResourceGovernorTests(unittest.TestCase):
    def test_process_parser_drops_prompt_and_keeps_mcp_process(self) -> None:
        rows = GOV.parse_unix_processes(
            "101 2097152 439000000 120.0 /opt/homebrew/bin/codebase-memory-mcp --prompt SECRET\n"
            "102 100000 400000000 2.0 /Applications/ChatGPT.app/codex --task PRIVATE\n",
            current_pid=999,
        )
        self.assertEqual(rows[0]["process_class"], "codebase_memory_mcp")
        serialized = json.dumps(rows)
        self.assertNotIn("SECRET", serialized)
        self.assertNotIn("PRIVATE", serialized)
        self.assertNotIn("--prompt", serialized)
        self.assertEqual(rows[1]["process_class"], "codex")

    def test_high_swap_enters_conserve_even_when_pressure_text_is_normal(self) -> None:
        self.assertEqual(
            GOV.pressure_tier(
                total_bytes=32 * GOV.GIB,
                available_bytes=8 * GOV.GIB,
                swap_total_bytes=2304 * GOV.MIB,
                swap_used_bytes=2010 * GOV.MIB,
                pressure_state="normal",
            ),
            "conserve",
        )

    def test_conserve_blocks_new_lanes_and_routes_remote(self) -> None:
        report = GOV.build_report(
            ram={
                "total_bytes": 32 * GOV.GIB,
                "available_bytes": 8 * GOV.GIB,
                "swap_total_bytes": 2304 * GOV.MIB,
                "swap_used_bytes": 2010 * GOV.MIB,
                "pressure_state": "normal",
            },
            processes=[
                {"pid": 1, "process_class": "codebase_memory_mcp", "rss_bytes": 2 * GOV.GIB},
            ],
            requested_lanes=5,
            per_lane_peak_bytes=1536 * GOV.MIB,
            max_local_lanes=5,
        )
        self.assertEqual(report["ram"]["pressure_tier"], "conserve")
        self.assertFalse(report["admission"]["local_agent_launch_allowed"])
        self.assertEqual(report["admission"]["max_new_local_lanes"], 0)
        self.assertEqual(report["admission"]["decision"], "throttle")
        self.assertTrue(any(a["action"] == "route_compatible_work_remote" for a in report["actions"]))
        self.assertFalse(report["safety"]["automatic_kill"])

    def test_critical_only_lists_owned_pids_for_pause(self) -> None:
        report = GOV.build_report(
            ram={
                "total_bytes": 32 * GOV.GIB,
                "available_bytes": 2 * GOV.GIB,
                "swap_total_bytes": 2 * GOV.GIB,
                "swap_used_bytes": 2 * GOV.GIB,
                "pressure_state": "critical",
            },
            processes=[
                {"pid": 10, "process_class": "opencode", "rss_bytes": GOV.GIB},
                {"pid": 11, "process_class": "codex", "rss_bytes": GOV.GIB},
            ],
            requested_lanes=1,
            per_lane_peak_bytes=GOV.GIB,
            max_local_lanes=2,
            owned_pids=[10],
        )
        self.assertEqual(report["ram"]["pressure_tier"], "emergency")
        pause = next(a for a in report["actions"] if a["action"] == "pause_owned_lanes")
        self.assertEqual(pause["pids"], [10])
        self.assertTrue(any(a["action"] == "do_not_kill_unowned_processes" for a in report["actions"]))

    def test_pause_requires_complete_process_identity_chain(self) -> None:
        observed = {
            "pid": 10,
            "start_time": "boot-100",
            "process_group": 10,
            "run_id": "run-1",
            "fence": "fence-1",
        }
        self.assertTrue(GOV.validate_pause_identity(observed, dict(observed))["valid"])
        mismatch = dict(observed, fence="fence-2")
        mismatch_result = GOV.validate_pause_identity(observed, mismatch)
        self.assertFalse(mismatch_result["valid"])
        self.assertIn("identity_fence_mismatch", mismatch_result["reasons"])

        ram = {
            "total_bytes": 32 * GOV.GIB,
            "available_bytes": 2 * GOV.GIB,
            "swap_total_bytes": 2 * GOV.GIB,
            "swap_used_bytes": 2 * GOV.GIB,
            "pressure_state": "critical",
        }
        complete = GOV.build_report(
            ram=ram,
            processes=[dict(observed, process_class="codex", rss_bytes=GOV.GIB)],
            requested_lanes=1,
            per_lane_peak_bytes=GOV.GIB,
            max_local_lanes=1,
            owned_pids=[10],
            owned_identity_records=[observed],
        )
        pause = next(a for a in complete["actions"] if a["action"] == "pause_owned_lanes")
        self.assertTrue(pause["identity_gate"]["execution_allowed"])

        incomplete = GOV.build_report(
            ram=ram,
            processes=[dict(observed, process_class="codex", rss_bytes=GOV.GIB)],
            requested_lanes=1,
            per_lane_peak_bytes=GOV.GIB,
            max_local_lanes=1,
            owned_pids=[10],
            owned_identity_records=[{"pid": 10, "run_id": "run-1"}],
        )
        blocked_pause = next(a for a in incomplete["actions"] if a["action"] == "pause_owned_lanes")
        self.assertFalse(blocked_pause["identity_gate"]["execution_allowed"])
        self.assertIn("expected_identity_incomplete", blocked_pause["identity_gate"]["blocked"][0]["reasons"])

    def test_normal_headroom_computes_bounded_lane_capacity(self) -> None:
        report = GOV.build_report(
            ram={
                "total_bytes": 32 * GOV.GIB,
                "available_bytes": 16 * GOV.GIB,
                "swap_total_bytes": 2 * GOV.GIB,
                "swap_used_bytes": 0,
                "pressure_state": "normal",
            },
            processes=[],
            requested_lanes=2,
            per_lane_peak_bytes=2 * GOV.GIB,
            max_local_lanes=5,
        )
        self.assertEqual(report["ram"]["pressure_tier"], "normal")
        self.assertEqual(report["admission"]["max_new_local_lanes"], 4)
        self.assertEqual(report["admission"]["decision"], "admit")

    def test_existing_reservations_reduce_headroom_before_new_lane(self) -> None:
        report = GOV.build_report(
            ram={
                "total_bytes": 32 * GOV.GIB,
                "available_bytes": 16 * GOV.GIB,
                "swap_total_bytes": 2 * GOV.GIB,
                "swap_used_bytes": 0,
                "pressure_state": "normal",
            },
            processes=[],
            requested_lanes=1,
            per_lane_peak_bytes=8 * GOV.GIB,
            max_local_lanes=4,
            reserved_bytes=8 * GOV.GIB,
        )
        self.assertEqual(8 * GOV.GIB, report["ram"]["already_reserved_bytes"])
        self.assertEqual(0, report["admission"]["max_new_local_lanes"])
        self.assertEqual("throttle", report["admission"]["decision"])

    def test_recovery_requires_two_consecutive_healthy_samples(self) -> None:
        state = {"effective_tier": "critical"}
        first = GOV.update_hysteresis(state, "normal")
        self.assertEqual(first["effective_tier"], "critical")
        self.assertEqual(first["pending_samples"], 1)
        second = GOV.update_hysteresis(first, "normal")
        self.assertEqual(second["effective_tier"], "normal")
        self.assertTrue(second["transitioned"])

    def test_worsening_pressure_transitions_immediately(self) -> None:
        state = {"effective_tier": "normal"}
        result = GOV.update_hysteresis(state, "critical")
        self.assertEqual(result["effective_tier"], "critical")
        self.assertTrue(result["transitioned"])

    def test_hysteresis_state_controls_admission_without_killing(self) -> None:
        report = GOV.build_report(
            ram={
                "total_bytes": 32 * GOV.GIB,
                "available_bytes": 16 * GOV.GIB,
                "swap_total_bytes": 2 * GOV.GIB,
                "swap_used_bytes": 0,
                "pressure_state": "normal",
            },
            processes=[],
            requested_lanes=1,
            per_lane_peak_bytes=GOV.GIB,
            max_local_lanes=2,
            hysteresis_state={"effective_tier": "critical"},
        )
        self.assertEqual(report["ram"]["observed_pressure_tier"], "normal")
        self.assertEqual(report["ram"]["pressure_tier"], "critical")
        self.assertEqual(report["admission"]["max_new_local_lanes"], 0)
        self.assertFalse(report["safety"]["automatic_signal"])

    def test_cgroup_limit_is_effective_boundary_and_persists_pressure_evidence(self) -> None:
        report = GOV.build_report(
            ram={
                # Host-sized procfs numbers must not override the worker's
                # finite cgroup-v2 boundary.
                "total_bytes": 128 * GOV.GIB,
                "available_bytes": 100 * GOV.GIB,
                "source": "procfs",
                "cgroup_required": True,
                "cgroup_memory_evidence_status": "complete",
                "cgroup_memory_max_bytes": 16 * GOV.GIB,
                "cgroup_memory_current_bytes": 15 * GOV.GIB,
                "cgroup_memory_available_bytes": GOV.GIB,
                "cgroup_memory_events_high": 3,
                "cgroup_memory_events_oom": 0,
                "cgroup_memory_events_oom_kill": 0,
                "psi_some_avg10": 1.0,
                "pressure_state": "normal",
                "swap_total_bytes": 0,
                "swap_used_bytes": 0,
            },
            processes=[],
            requested_lanes=1,
            p90_peak_bytes=2 * GOV.GIB,
            max_local_lanes=2,
        )
        self.assertEqual("cgroup_v2_current_max", report["ram"]["memory_source"])
        self.assertEqual(GOV.GIB, report["ram"]["available_bytes"])
        self.assertEqual(2 * GOV.GIB, report["request"]["p90_peak_bytes"])
        self.assertFalse(report["admission"]["local_agent_launch_allowed"])
        self.assertTrue(report["admission"]["evidence_complete"])

    def test_unbounded_cgroup_v1_uses_host_capacity_without_unknown_block(self) -> None:
        report = GOV.build_report(
            ram={
                "total_bytes": 64 * GOV.GIB,
                "available_bytes": 48 * GOV.GIB,
                "source": "procfs_legacy_estimate",
                "cgroup_required": True,
                "cgroup_memory_source": "cgroup_v1",
                "cgroup_memory_evidence_status": "unbounded",
                "cgroup_memory_unbounded": True,
                "cgroup_memory_current_bytes": 4 * GOV.GIB,
                "pressure_state": "normal",
                "swap_total_bytes": 0,
                "swap_used_bytes": 0,
            },
            processes=[],
            requested_lanes=1,
            p90_peak_bytes=2 * GOV.GIB,
            max_local_lanes=2,
        )
        self.assertTrue(report["admission"]["local_agent_launch_allowed"])
        self.assertTrue(report["admission"]["evidence_complete"])
        self.assertTrue(report["ram"]["cgroup_memory_unbounded"])
        self.assertEqual("procfs_legacy_estimate", report["ram"]["memory_source"])

    def test_required_cgroup_or_p90_evidence_fails_closed_without_signals(self) -> None:
        report = GOV.build_report(
            ram={
                "total_bytes": 32 * GOV.GIB,
                "available_bytes": 24 * GOV.GIB,
                "pressure_state": "normal",
                "cgroup_required": True,
                "cgroup_memory_evidence_status": "unknown",
                "swap_total_bytes": 0,
                "swap_used_bytes": 0,
            },
            processes=[],
            requested_lanes=1,
            p90_peak_bytes=None,
            per_lane_peak_bytes=None,
            max_local_lanes=2,
        )
        self.assertFalse(report["admission"]["local_agent_launch_allowed"])
        self.assertEqual(0, report["admission"]["max_new_local_lanes"])
        self.assertEqual(
            {"cgroup_memory_evidence_unknown", "p90_lane_peak_unknown"},
            set(report["admission"]["evidence_block_reasons"]),
        )
        self.assertFalse(report["safety"]["automatic_kill"])

    def test_psi_pressure_degrades_without_killing(self) -> None:
        report = GOV.build_report(
            ram={
                "total_bytes": 32 * GOV.GIB,
                "available_bytes": 24 * GOV.GIB,
                "pressure_state": "normal",
                "psi_some_avg10": 25.0,
                "swap_total_bytes": 0,
                "swap_used_bytes": 0,
            },
            processes=[],
            requested_lanes=1,
            per_lane_peak_bytes=GOV.GIB,
            max_local_lanes=2,
        )
        self.assertIn(report["ram"]["pressure_tier"], {"critical", "emergency"})
        self.assertFalse(report["safety"]["automatic_signal"])


if __name__ == "__main__":
    unittest.main()
