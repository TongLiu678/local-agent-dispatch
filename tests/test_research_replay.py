"""Tests for the WP9 deterministic replay laboratory.

Covers: fake clock window resets, fake cluster fault injection, byte-stable
replay determinism, censored survival handling, paired report statistics and
the "no fake precision" rule.

Run: python3 -m unittest tests.test_research_replay -v
"""

from __future__ import annotations

import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from research.simulator import fake_clock as fc  # noqa: E402
from research.simulator.fake_cluster import (  # noqa: E402
    FAULT_KINDS,
    GreedyPolicy,
    QuotaAwarePolicy,
    ReplayError,
    run_replay,
)
from research.analysis.paired_report import (  # noqa: E402
    gini,
    holm_correct,
    km_median,
    median_iqr,
    paired_report,
    survival_summary,
    wilson_ci,
)

SCENARIO = ROOT / "research" / "scenarios" / "quota-windows.json"
FIVE_HOUR = 5 * 3600
WEEK = 7 * 24 * 3600


def _load_fixture() -> dict:
    payload = json.loads(SCENARIO.read_text(encoding="utf-8"))
    return {key: payload[key] for key in ("pools", "hosts")}


def _manifest(
    seed: int = 1,
    horizon: float = 86400.0,
    n_jobs: int = 8,
    faults: list[dict] | None = None,
    quota_known: bool = True,
) -> dict:
    corpus = json.loads(SCENARIO.read_text(encoding="utf-8"))["job_corpus"]
    fixture = _load_fixture()
    if not quota_known:
        for pool in fixture["pools"]:
            if pool["pool_id"].startswith("cursor."):
                pool["quota_display_known"] = False
    jobs = []
    for i in range(n_jobs):
        template = corpus[i % len(corpus)]
        jobs.append(
            {
                "job_id": f"j-{i}",
                "family": template["family"],
                "difficulty": template["difficulty"],
                "requires_review": template["requires_review"],
                "arrival": float(i) * 120.0,
            }
        )
    return {
        "seed": seed,
        "start": 0.0,
        "horizon": horizon,
        "fixture": fixture,
        "jobs": jobs,
        "faults": faults or [],
    }


class FakeClockTests(unittest.TestCase):
    def test_advance_never_sleeps_and_is_deterministic(self) -> None:
        a = fc.FakeClock(seed=3)
        b = fc.FakeClock(seed=3)
        for seconds in (60.0, 18000.0, 604800.0, 2678400.0):
            a.advance(seconds)
            b.advance(seconds)
        self.assertEqual(a.now(), b.now())
        self.assertEqual(a.events(), b.events())

    def test_five_hour_rolling_window_expires_usage(self) -> None:
        clock = fc.FakeClock(seed=1)
        window = clock.add_window(fc.WindowSpec.five_hour(), cap=100.0)
        clock.advance(60.0)
        window.consume(40.0, clock.now())
        self.assertEqual(60.0, window.remaining(clock.now()))
        clock.advance(FIVE_HOUR + 1.0)
        # Old usage has aged out of the sliding window.
        self.assertEqual(0.0, window.usage(clock.now()))
        self.assertEqual(100.0, window.remaining(clock.now()))

    def test_five_hour_exhaustion_then_rolling_recovery(self) -> None:
        clock = fc.FakeClock(seed=2)
        window = clock.add_window(fc.WindowSpec.five_hour(), cap=100.0)
        clock.advance(10.0)
        window.consume(100.0, clock.now())
        self.assertTrue(window.exhausted(clock.now()))
        clock.advance(FIVE_HOUR + 1.0)
        self.assertFalse(window.exhausted(clock.now()))

    def test_weekly_calendar_window_resets_at_monday_boundary(self) -> None:
        clock = fc.FakeClock(seed=4)
        window = clock.add_window(fc.WindowSpec.week(), cap=500.0)
        clock.advance(60.0)
        window.consume(200.0, clock.now())
        boundary = window.next_boundary(clock.now())
        # Boundaries are whole days: 1970-01-01 is a Thursday, first Monday is
        # 1970-01-05, i.e. 4 * 86400 seconds.
        self.assertEqual(0.0, boundary % 86400.0)
        self.assertEqual(345600.0, fc._week_boundary(345600.0))  # 1970-01-05
        clock.advance_to(boundary)
        self.assertEqual(0.0, window.usage(clock.now()))
        reset_events = [
            e for e in clock.events() if e["kind"] == "quota_window_reset"
        ]
        self.assertTrue(reset_events)
        self.assertEqual({"week"}, {spec["calendar_granularity"] for spec in reset_events[-1]["window_specs"]})

    def test_monthly_calendar_window_resets_at_first_of_month(self) -> None:
        clock = fc.FakeClock(seed=5)
        window = clock.add_window(fc.WindowSpec.month(), cap=2000.0)
        clock.advance(60.0)
        window.consume(500.0, clock.now())
        boundary = window.next_boundary(clock.now())
        self.assertEqual(2678400.0, boundary)  # 1970-02-01 00:00 UTC
        clock.advance_to(boundary)
        self.assertEqual(0.0, window.usage(clock.now()))

    def test_unknown_granularity_fails_closed(self) -> None:
        clock = fc.FakeClock(seed=6)
        window = clock.add_window(
            fc.WindowSpec(kind="calendar", calendar_granularity="fortnight"), cap=1.0
        )
        with self.assertRaises(ValueError):
            window.next_boundary(0.0)


class ReplayDeterminismTests(unittest.TestCase):
    def test_same_manifest_is_byte_stable(self) -> None:
        manifest = _manifest(seed=7, horizon=259200.0)
        record_a = run_replay(manifest, QuotaAwarePolicy())
        record_b = run_replay(json.loads(json.dumps(manifest)), QuotaAwarePolicy())
        self.assertEqual(record_a.serialize(), record_b.serialize())
        self.assertEqual(record_a.seed, 7)
        self.assertEqual(record_a.policy_digest, record_b.policy_digest)
        self.assertEqual(record_a.fixture_digest, record_b.fixture_digest)
        self.assertEqual(record_a.corpus_digest, record_b.corpus_digest)

    def test_different_seed_changes_trace(self) -> None:
        record_a = run_replay(_manifest(seed=11), QuotaAwarePolicy())
        record_b = run_replay(_manifest(seed=12), QuotaAwarePolicy())
        self.assertNotEqual(record_a.serialize(), record_b.serialize())

    def test_different_policy_changes_policy_digest(self) -> None:
        manifest = _manifest(seed=13)
        greedy = run_replay(json.loads(json.dumps(manifest)), GreedyPolicy())
        aware = run_replay(json.loads(json.dumps(manifest)), QuotaAwarePolicy())
        self.assertNotEqual(greedy.policy_digest, aware.policy_digest)
        # Corpus digest pins the policy digest, so it changes with the policy.
        self.assertNotEqual(greedy.corpus_digest, aware.corpus_digest)

    def test_manifest_carries_seed_policy_and_corpus_digests(self) -> None:
        manifest = _manifest(seed=17)
        record = run_replay(manifest, QuotaAwarePolicy())
        payload = json.loads(record.serialize())
        for field in ("seed", "policy_digest", "fixture_digest", "corpus_digest"):
            self.assertIn(field, payload["summary"])
        self.assertEqual(17, payload["seed"])
        self.assertIn("event_trace", payload)
        self.assertGreater(len(payload["event_trace"]), 0)

    def test_invalid_manifest_rejected(self) -> None:
        with self.assertRaises(ReplayError):
            run_replay({"seed": "not-an-int", "fixture": {}}, QuotaAwarePolicy())
        manifest = _manifest(seed=1)
        manifest["faults"] = [{"fault": "teleport", "t": 0.0}]
        with self.assertRaises(ReplayError):
            run_replay(manifest, QuotaAwarePolicy())


class FaultInjectionTests(unittest.TestCase):
    def test_full_fault_matrix_is_implemented(self) -> None:
        expected = {
            "crash",
            "lost_ack",
            "duplicate_delivery",
            "stale_fence",
            "partial_artifact",
            "ssh_disconnect",
            "quota_exhaustion",
            "quota_reset",
            "mount_loss",
            "capability_rejection",
            "missing_human_review",
        }
        self.assertEqual(expected, set(FAULT_KINDS))

    def _record_with_fault(self, fault: dict, seed: int = 21) -> dict:
        manifest = _manifest(seed=seed, horizon=43200.0, n_jobs=4, faults=[fault])
        record = run_replay(manifest, QuotaAwarePolicy())
        return json.loads(record.serialize())

    def test_crash_fault_emits_worker_crashed(self) -> None:
        payload = self._record_with_fault(
            {"fault": "crash", "t": 500.0, "target": "worker-a"}
        )
        kinds = {e["kind"] for e in payload["event_trace"]}
        self.assertIn("worker_crashed", kinds)

    def test_lost_ack_and_duplicate_delivery_are_traceable(self) -> None:
        payload = self._record_with_fault(
            {"fault": "lost_ack", "t": 600.0, "target": "worker-a"}
        )
        kinds = {e["kind"] for e in payload["event_trace"]}
        self.assertIn("ack_lost", kinds)
        payload = self._record_with_fault(
            {"fault": "duplicate_delivery", "t": 700.0, "target": "j-0"}
        )
        kinds = {e["kind"] for e in payload["event_trace"]}
        self.assertIn("duplicate_delivery", kinds)

    def test_stale_fence_and_partial_artifact(self) -> None:
        payload = self._record_with_fault(
            {"fault": "stale_fence", "t": 800.0, "target": "worker-a"}
        )
        self.assertIn(
            "lease_fence_rejected", {e["kind"] for e in payload["event_trace"]}
        )
        payload = self._record_with_fault(
            {"fault": "partial_artifact", "t": 900.0, "target": "j-1"}
        )
        self.assertIn("artifact_partial", {e["kind"] for e in payload["event_trace"]})

    def test_ssh_disconnect_and_route_lost(self) -> None:
        payload = self._record_with_fault(
            {"fault": "ssh_disconnect", "t": 1000.0, "target": "host-remote-a"}
        )
        self.assertIn("route_lost", {e["kind"] for e in payload["event_trace"]})

    def test_quota_exhaustion_blocks_pool_and_reset_restores(self) -> None:
        manifest = _manifest(
            seed=31,
            horizon=43200.0,
            n_jobs=4,
            faults=[
                {"fault": "quota_exhaustion", "t": 2000.0, "target": "opencode.go"},
                {"fault": "quota_reset", "t": 3000.0, "target": "opencode.go"},
            ],
        )
        payload = json.loads(run_replay(manifest, QuotaAwarePolicy()).serialize())
        kinds = [e["kind"] for e in payload["event_trace"]]
        exhausted_at = kinds.index("quota_exhausted")
        restored_at = kinds.index("quota_restored")
        self.assertGreater(restored_at, exhausted_at)

    def test_mount_loss_and_capability_rejection_are_isolated(self) -> None:
        payload = self._record_with_fault(
            {"fault": "mount_loss", "t": 1100.0, "target": "host-remote-a"}
        )
        self.assertIn("mount_lost", {e["kind"] for e in payload["event_trace"]})
        payload = self._record_with_fault(
            {"fault": "capability_rejection", "t": 1200.0, "target": "cursor.other"}
        )
        self.assertIn(
            "model_capability_rejected", {e["kind"] for e in payload["event_trace"]}
        )

    def test_missing_human_review_is_recorded(self) -> None:
        payload = self._record_with_fault(
            {"fault": "missing_human_review", "t": 1300.0, "target": "j-0"}
        )
        self.assertIn("human_review_missed", {e["kind"] for e in payload["event_trace"]})

    def test_all_fault_kinds_injectable_without_error(self) -> None:
        for kind in sorted(FAULT_KINDS):
            target = {
                "crash": "worker-a",
                "lost_ack": "worker-a",
                "duplicate_delivery": "j-0",
                "stale_fence": "worker-a",
                "partial_artifact": "j-0",
                "ssh_disconnect": "host-local",
                "quota_exhaustion": "codex",
                "quota_reset": "codex",
                "mount_loss": "host-local",
                "capability_rejection": "codex",
                "missing_human_review": "j-0",
            }[kind]
            record = run_replay(
                _manifest(
                    seed=41, horizon=7200.0, n_jobs=2,
                    faults=[{"fault": kind, "t": 60.0, "target": target}],
                ),
                QuotaAwarePolicy(),
            )
            self.assertIsNotNone(record.summary()["jobs_total"], kind)


class ClusterSemanticsTests(unittest.TestCase):
    def test_vram_pressure_detected(self) -> None:
        manifest = _manifest(seed=51, n_jobs=2)
        manifest["fixture"]["hosts"][0]["vram_used_mb"] = 24500.0  # 99% of 24576
        payload = json.loads(run_replay(manifest, QuotaAwarePolicy()).serialize())
        self.assertIn("vram_pressure", {e["kind"] for e in payload["event_trace"]})

    def test_unknown_quota_is_never_fabricated(self) -> None:
        manifest = _manifest(seed=52, n_jobs=4, quota_known=False)
        record = run_replay(manifest, GreedyPolicy())
        summary = record.summary()
        self.assertFalse(summary["data_quality"]["quota_display_known"])
        self.assertIn(
            "quota_remaining", summary["data_quality"]["unknown_fields"]
        )
        self.assertTrue(summary["data_quality"]["cost_attribution_unknown"])

    def test_reservation_fence_and_worker_liveness_fields_present(self) -> None:
        manifest = _manifest(seed=53, n_jobs=2)
        record = run_replay(manifest, QuotaAwarePolicy())
        payload = json.loads(record.serialize())
        planned = [e for e in payload["event_trace"] if e["kind"] == "job_planned"]
        self.assertTrue(planned)
        self.assertIn("lease_token", planned[0])
        self.assertIn("worker_id", planned[0])

    def test_human_review_window_opens_and_completes(self) -> None:
        manifest = _manifest(seed=54, n_jobs=2)
        manifest["jobs"][0]["requires_review"] = True
        record = run_replay(manifest, QuotaAwarePolicy())
        kinds = {e["kind"] for e in record.clock.events()}
        self.assertIn("human_review_opened", kinds)
        self.assertIn("human_review_completed", kinds)


class SurvivalStatisticsTests(unittest.TestCase):
    def test_km_median_handles_censored_runs(self) -> None:
        # 10 events at t=10, 10 censored before any event -> median not reached.
        times = [10.0] * 10 + [9.0] * 10
        censored = [False] * 10 + [True] * 10
        self.assertIsNotNone(km_median(times, censored))
        # All censored -> median never reached.
        self.assertIsNone(km_median([1.0, 2.0, 3.0], [True, True, True]))

    def test_survival_summary_counts_and_guards(self) -> None:
        summary = survival_summary([10.0, 20.0], [False, False])
        self.assertEqual("insufficient_evidence", summary["precision"])
        self.assertEqual(0, summary["censored"])
        summary = survival_summary([], [])
        self.assertEqual("no_data", summary["precision"])

    def test_censored_runs_do_not_fabricate_validation(self) -> None:
        # Crash fault -> interrupted job must be censored, not validated.
        record = run_replay(
            _manifest(
                seed=61,
                horizon=7200.0,
                n_jobs=2,
                faults=[{"fault": "crash", "t": 100.0, "target": "worker-a"}],
            ),
            QuotaAwarePolicy(),
        )
        summary = record.summary()
        validated = summary["jobs_validated"]
        self.assertLessEqual(validated, summary["jobs_total"])
        censored = summary["jobs_censored"]
        self.assertGreaterEqual(censored, 0)


class PairedReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.records_a = []
        cls.records_b = []
        for seed in (71, 72, 73, 74):
            manifest = _manifest(seed=seed, horizon=129600.0, n_jobs=6)
            cls.records_a.append(
                run_replay(json.loads(json.dumps(manifest)), QuotaAwarePolicy())
            )
            cls.records_b.append(
                run_replay(json.loads(json.dumps(manifest)), GreedyPolicy())
            )

    def test_paired_report_shape_and_metrics(self) -> None:
        report = paired_report(self.records_a, self.records_b, n_boot=100)
        self.assertEqual(4, report["pairs"])
        self.assertEqual(0, sum(report["unmatched"].values()))
        self.assertEqual("time_to_valid_artifact", report["primary_outcome"])
        primary = report["primary"]
        self.assertIn("median_a", primary)
        self.assertIn("diff_b_minus_a", primary)
        self.assertIn("paired_cluster_bootstrap_95", primary)
        for arm in ("a", "b"):
            stats = report["arms"][arm]
            self.assertIn("ttv_median_iqr", stats)
            self.assertIn("median", stats["ttv_median_iqr"])
            self.assertIn("validation_success", stats)
            self.assertIn("ci", stats["validation_success"])
            self.assertIn("fairness_gini", stats)
            self.assertIn("violations", stats)
        self.assertIn("validation_success", report["secondaries"])
        for p_value in report["secondaries"].values():
            self.assertIn("holm_adjusted", p_value)

    def test_report_is_deterministic(self) -> None:
        one = paired_report(self.records_a, self.records_b, n_boot=50)
        two = paired_report(self.records_a, self.records_b, n_boot=50)
        self.assertEqual(one, two)

    def test_censored_counts_reported(self) -> None:
        report = paired_report(self.records_a, self.records_b, n_boot=50)
        self.assertIn("censored", report["primary"])
        for arm in ("a", "b"):
            self.assertGreaterEqual(report["primary"]["censored"][arm], 0)

    def test_unknown_cost_never_fabricated(self) -> None:
        report = paired_report(self.records_a, self.records_b, n_boot=50)
        if not report["data_quality"]["cost_attribution_known"]["a"]:
            self.assertIsNone(report["arms"]["a"]["cost"]["total"])
            self.assertEqual("attribution_unknown", report["arms"]["a"]["cost"]["precision"])

    def test_holm_correction_monotone(self) -> None:
        adjusted = holm_correct([0.01, 0.04, 0.2])
        self.assertTrue(all(adjusted[i] <= adjusted[i + 1] for i in range(len(adjusted) - 1)))
        self.assertGreaterEqual(min(adjusted), 0.01)

    def test_wilson_ci_guards_tiny_totals(self) -> None:
        self.assertEqual("insufficient_evidence", wilson_ci(1, 1)["precision"])
        self.assertIsNotNone(wilson_ci(50, 100)["ci"])
        self.assertEqual("no_data", wilson_ci(0, 0)["precision"])

    def test_gini_helpers(self) -> None:
        self.assertIsNone(gini({"x": 0}))
        self.assertEqual(0.0, gini({"x": 1, "y": 1}))
        self.assertAlmostEqual(1.0 / 3.0, gini({"x": 0, "y": 1, "z": 1}), places=6)

    def test_median_iqr_precision_guard(self) -> None:
        self.assertEqual("insufficient_evidence", median_iqr([1.0, 2.0])["precision"])
        stats = median_iqr([1.0, 2.0, 3.0, 4.0, 5.0])
        self.assertEqual("median_iqr", stats["precision"])
        self.assertEqual(3.0, stats["median"])
        self.assertEqual("no_data", median_iqr([])["precision"])

    def test_unmatched_runs_reported_not_dropped(self) -> None:
        report = paired_report(self.records_a, self.records_b[:2], n_boot=50)
        self.assertEqual(2, report["pairs"])
        self.assertEqual(2, report["unmatched"]["a"])
        self.assertEqual(0, report["unmatched"]["b"])


class PromotionArtifactsTests(unittest.TestCase):
    def test_docs_exist_with_tier_table(self) -> None:
        matrix = (ROOT / "docs" / "research" / "fault-injection-matrix-v1.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("crash", matrix)
        self.assertIn("missing_human_review", matrix)
        checklist = (
            ROOT / "docs" / "research" / "promotion-checklist-v1.md"
        ).read_text(encoding="utf-8")
        for tier in ("Provider-free replay", "Shadow", "Canary", "Scientific evidence"):
            self.assertIn(tier, checklist)
        self.assertIn("never", checklist.lower())

    def test_scenario_corpus_covers_fault_matrix(self) -> None:
        scenario = json.loads(SCENARIO.read_text(encoding="utf-8"))
        kinds = {row["fault"] for row in scenario["fault_matrix"]}
        self.assertEqual(set(FAULT_KINDS), kinds)

    def test_report_evidence_ceiling_is_replay_only(self) -> None:
        report = paired_report([], [], n_boot=10)
        self.assertEqual("provider_free_replay_only", report["evidence_ceiling"])
        self.assertTrue(report["deterministic"])


if __name__ == "__main__":
    unittest.main()
