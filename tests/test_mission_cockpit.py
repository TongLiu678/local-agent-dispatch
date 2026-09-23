from __future__ import annotations

import pathlib
import json
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import mission_cockpit  # noqa: E402


class MissionCockpitTests(unittest.TestCase):
    def test_continuous_monitor_projection_keeps_loop_and_segment_clocks_distinct(self) -> None:
        record = {
            "kind": "tick",
            "record_type": "local-agent-dispatch.continuous-loop",
            "run_id": "run-24h",
            "tick": 17,
            "observed_at_utc": "2026-09-01T09:00:00Z",
            "report": {
                "action": "continue",
                "now_utc": "2026-09-01T09:00:00Z",
                "segment_id": "run-24h:segment:5",
                "segment_remaining_seconds": 845,
                "loop_elapsed_seconds": 15200.5,
                "loop_remaining_seconds": 71200.5,
                "progress_clock": "monotonic_runner",
                "provider_execution": False,
                "heartbeat": {
                    "ok": True,
                    "lease": {"status": "active", "fence_token": 3},
                },
                "reconciliation": {
                    "controller": {
                        "segment_count": 5,
                        "transport_pending": 0,
                    }
                },
            },
        }

        projection = mission_cockpit.project_continuous_monitor(record)

        self.assertEqual("run-24h", projection["run_id"])
        self.assertEqual(17, projection["tick"])
        self.assertEqual("run-24h:segment:5", projection["segment_id"])
        self.assertEqual(845, projection["segment_remaining_seconds"])
        self.assertEqual(15200.5, projection["loop_elapsed_seconds"])
        self.assertEqual(71200.5, projection["loop_remaining_seconds"])
        self.assertEqual("monotonic_runner", projection["progress_clock"])
        self.assertTrue(projection["heartbeat_ok"])
        self.assertEqual("active", projection["lease_status"])
        self.assertEqual(0, projection["transport_pending"])
        self.assertFalse(projection["provider_execution"])

    def test_continuous_monitor_projection_falls_back_to_legacy_nested_remaining_seconds(self) -> None:
        record = {
            "run_id": "run-old",
            "tick": 9,
            "report": {
                "action": "continue",
                "remaining_seconds": 120,
                "heartbeat": {"segment_id": "run-old:segment:2", "ok": True},
                "reconciliation": {
                    "controller": {
                        "active_segments": [{
                            "segment_id": "run-old:segment:2",
                            "sequence": 2,
                            "status": "running",
                        }],
                    }
                },
            },
        }

        projection = mission_cockpit.project_continuous_monitor(record)

        self.assertEqual(120, projection["segment_remaining_seconds"])
        self.assertIsNone(projection["loop_remaining_seconds"])
        self.assertEqual("unknown", projection["progress_clock"])
        self.assertEqual("run-old:segment:2", projection["segment_id"])

    def test_continuous_monitor_projection_is_allowlisted_and_drops_prompt_like_fields(self) -> None:
        projection = mission_cockpit.project_continuous_monitor({
            "run_id": "run-safe",
            "prompt": "must not cross the L0 boundary",
            "report": {
                "action": "continue",
                "argv": ["secret"],
                "heartbeat": {"ok": True},
            },
        })

        encoded = json.dumps(projection, ensure_ascii=False)
        self.assertNotIn("must not cross", encoded)
        self.assertNotIn("secret", encoded)
        self.assertTrue(projection["read_only"])
        self.assertIsNone(projection["provider_execution"])

    def test_cockpit_includes_continuous_monitor_projection_without_changing_lifecycle_counts(self) -> None:
        report = mission_cockpit.build_cockpit(
            {"jobs": [{"job_id": "j1", "status": "running"}]},
            monitor={
                "run_id": "run-24h",
                "tick": 3,
                "report": {
                    "action": "continue",
                    "remaining_seconds": 30,
                    "provider_execution": False,
                    "heartbeat": {"ok": True},
                },
            },
        )

        self.assertEqual("execution_and_validation", report["current_gate"])
        self.assertEqual("run-24h", report["continuous_monitor"]["run_id"])
        self.assertEqual(30, report["continuous_monitor"]["segment_remaining_seconds"])
        self.assertEqual(1, report["delta"]["total_jobs"])

    def test_load_monitor_reads_last_nonempty_jsonl_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "continuous-loop.jsonl"
            path.write_text(
                '{"run_id":"run-1","tick":1}\n\n'
                '{"run_id":"run-1","tick":2}\n',
                encoding="utf-8",
            )
            self.assertEqual(2, mission_cockpit._load_monitor(str(path))["tick"])

    def test_load_monitor_uses_bounded_tail_for_large_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "large-continuous-loop.jsonl"
            path.write_text(
                (('{"run_id":"old","tick":1}\n') * 100000)
                + '{"run_id":"new","tick":2}\n',
                encoding="utf-8",
            )
            with mock.patch.object(
                pathlib.Path,
                "read_text",
                side_effect=AssertionError("must not load the whole monitor")
            ):
                self.assertEqual(2, mission_cockpit._load_monitor(str(path))["tick"])

    def test_l0_exposes_gate_risk_and_safe_decision_without_prompt(self) -> None:
        report = mission_cockpit.build_cockpit(
            {
                "jobs": [{"job_id": "j1", "status": "running", "model": "spark", "pool_id": "codex.spark"}],
                "workers": [{"job_id": "j1", "status": "running", "model": "spark", "execution_host": "local", "workload_host": "remote"}],
            },
            mission={"mission_id": "m1", "goal": {"value": "bounded work"}, "claim_envelope": {"forbidden": ["full claim"]}},
            governor={"ram": {"pressure_tier": "conserve", "available_bytes": 10}, "admission": {"decision": "throttle", "max_new_local_lanes": 0}, "observed_at_utc": "now"},
        )
        self.assertEqual("execution_and_validation", report["current_gate"])
        self.assertEqual("local_memory_pressure", report["risks"][0]["kind"])
        self.assertEqual("keep_new_local_lanes_blocked", report["decision_required"]["safe_default"])
        self.assertEqual("remote", report["active_assignments"][0]["workload_host"])
        self.assertFalse(report["sources"]["raw_prompt_persisted"])

    def test_completed_is_not_validated_without_validation_and_freshness(self) -> None:
        report = mission_cockpit.build_cockpit(
            {"jobs": [{"job_id": "j1", "status": "completed"}]},
        )
        self.assertEqual("validation_review", report["current_gate"])
        self.assertEqual(1, report["delta"]["execution_completed"])
        self.assertEqual(0, report["delta"]["validated_completed"])
        self.assertEqual(0, report["verified_progress"]["completed_jobs"])
        self.assertEqual("execution_only", report["verified_progress"]["evidence"])

    def test_monitor_only_workers_remain_visible_as_tasks(self) -> None:
        report = mission_cockpit.build_cockpit(
            {"workers": [{"job_id": "j1", "status": "running", "model": "spark"}]},
        )
        self.assertEqual(1, report["delta"]["total_jobs"])
        self.assertEqual("execution_and_validation", report["current_gate"])
        self.assertEqual("monitor_workers", report["delta"]["history_source"])
        self.assertEqual("j1", report["active_assignments"][0]["job_id"])

    def test_claim_promotion_is_not_implied_by_validation(self) -> None:
        report = mission_cockpit.build_cockpit(
            {
                "jobs": [{"job_id": "j1", "status": "completed"}],
                "workers": [{
                    "job_id": "j1",
                    "controller_status": "completed",
                    "validation_ok": True,
                    "artifact_freshness_verified": True,
                }],
            },
        )
        self.assertEqual(1, report["delta"]["validated_completed"])
        self.assertEqual(0, report["delta"]["claim_promoted"])
        self.assertEqual("claim_or_release_review", report["current_gate"])

    def test_l0_projects_quota_blocker_reset_and_recent_receipt(self) -> None:
        report = mission_cockpit.build_cockpit(
            {
                "jobs": [{"job_id": "j1", "status": "queued"}],
                "events": [{
                    "event_id": "evt-7",
                    "event_type": "quota_blocked",
                    "event_seq": 7,
                    "job_id": "j1",
                    "at_utc": "2026-08-29T16:00:00Z",
                    "payload": {"prompt": "must not be projected"},
                }],
            },
            replan={
                "quota_window_watch": {
                    "pools": [{
                        "pool_id": "codex.spark",
                        "decision": "cooldown_until_reset",
                        "execution_state": "blocked",
                        "reset_at_utc": "2026-08-29T16:47:03Z",
                    }],
                },
                "quota_replan_schedule": {
                    "decision": "wait_bounded",
                    "due": False,
                    "sleep_seconds": 30.0,
                    "wake_at_utc": "2026-08-29T16:00:30+00:00",
                    "target_replan_at_utc": "2026-08-29T16:47:03+00:00",
                    "quota_reset_pool_id": "codex.spark",
                },
            },
        )
        self.assertEqual("degraded", report["health_level"])
        self.assertEqual("quota_pool_blocked", report["blocker"]["kind"])
        self.assertEqual("codex.spark", report["blocker"]["pool_id"])
        self.assertEqual("keep_new_local_lanes_blocked", report["next_action"])
        self.assertEqual("codex.spark", report["quota_summary"]["blocked_pools"][0]["pool_id"])
        self.assertEqual("evt-7", report["recent_receipt"]["event_id"])
        self.assertNotIn("prompt", report["recent_receipt"])

    def test_l0_projects_route_blocker_and_unvalidated_capability_without_private_topology(self) -> None:
        report = mission_cockpit.build_cockpit(
            {"jobs": []},
            placement={
                "host": "autodl-container-private-name",
                "capabilities": [{
                    "name": "opencode",
                    "status": "installed_attested",
                    "execution_validated": False,
                    "path": "/private/provider-home/opencode",
                }],
                "routes": [{
                    "name": "CLUSTER_ROUTE",
                    "status": "blocked",
                    "verified": False,
                    "reason": "bridge_peer_offline",
                    "endpoint": "192.0.2.1:22",
                }],
            },
        )

        self.assertEqual("route_blocked", report["blocker"]["kind"])
        self.assertEqual("CLUSTER_ROUTE", report["blocker"]["route_id"])
        self.assertEqual("restore_or_verify_route_before_dispatch", report["next_action"])
        self.assertEqual("do_not_dispatch_to_route", report["decision_required"]["safe_default"])
        self.assertEqual("installed_attested", report["placement"]["capabilities"][0]["status"])
        self.assertEqual("opencode", report["evidence_gaps"][0]["name"])
        self.assertEqual("action_required", report["attention_inbox"][0]["level"])
        encoded = json.dumps(report, ensure_ascii=False)
        self.assertNotIn("autodl-container-private-name", encoded)
        self.assertNotIn("/private/provider-home/opencode", encoded)
        self.assertNotIn("192.0.2.1:22", encoded)
        self.assertNotIn("endpoint", encoded)

    def test_resume_surface_projects_active_segment_attention_and_l3_refs(self) -> None:
        report = mission_cockpit.build_cockpit(
            {
                "run_id": "run-24h",
                "run_segments": [{
                    "run_id": "run-24h",
                    "segment_id": "segment-2",
                    "sequence": 2,
                    "status": "running",
                    "owner_id": "controller-a",
                    "fence_token": 9,
                    "manifest_digest": "sha256:" + "a" * 64,
                    "capsule_digest": "sha256:" + "b" * 64,
                    "started_at_utc": "2026-08-29T16:00:00Z",
                }],
                "jobs": [{"job_id": "j1", "status": "running"}],
                "attempts": [{"attempt_id": "a1", "job_id": "j1"}],
                "events": [{
                    "event_id": "evt-9",
                    "event_seq": 9,
                    "event_type": "segment.heartbeat",
                    "attempt_id": "a1",
                    "at_utc": "2026-08-29T16:01:00Z",
                    "payload": {"prompt": "private text must not cross L0"},
                }],
            },
            governor={"ram": {"pressure_tier": "critical"}},
            now_utc="2026-08-29T16:02:00Z",
        )
        self.assertEqual("segment-2", report["active_segment"]["segment_id"])
        self.assertEqual(2, report["active_segment"]["sequence"])
        self.assertEqual("safety_stop", report["attention_inbox"][0]["level"])
        self.assertEqual("segment-2", report["resume_digest"]["content"]["active_segment"]["segment_id"])
        self.assertTrue(report["resume_digest"]["digest"].startswith("sha256:"))
        self.assertEqual(9, report["l3_references"]["event_seq_max"])
        self.assertEqual(["a1"], report["l3_references"]["attempt_ids"])
        self.assertNotIn("private text must not cross L0", json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
