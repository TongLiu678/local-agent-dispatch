#!/usr/bin/env python3
"""Tests for OpenCode Go quota evidence and conservative scheduling."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import unittest
from unittest import mock

REPO_ROOT = pathlib.Path(__file__).parents[1]
EVIDENCE_PATH = REPO_ROOT / "src" / "local_agent_dispatch" / "quota" / "evidence.py"
CLI_PATH = REPO_ROOT / "scripts" / "opencode_go_quota_snapshot.py"
FIXTURE_PATH = REPO_ROOT / "research" / "fixtures" / "quota_console.json"
SCHEMA_PATH = REPO_ROOT / "schemas" / "quota_evidence.schema.json"


def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


evidence = _load("quota_evidence", EVIDENCE_PATH)
cli = _load("opencode_go_quota_snapshot", CLI_PATH)


def run_cli(*argv: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = cli.main(list(argv))
    return code, stdout.getvalue(), stderr.getvalue()


class UnknownEvidenceTests(unittest.TestCase):
    def test_record_defaults_never_map_unknown_to_zero_or_full(self) -> None:
        record = evidence.make_record(source="history", window="five_hour")
        self.assertIsNone(record["remaining_percent"])
        self.assertIsNone(record["remaining_amount"])
        self.assertIsNone(record["reset_at_utc"])
        self.assertEqual("unknown", evidence.balance_state([record]))
        self.assertIsNone(evidence.effective_remaining_percent([record]))

    def test_zero_or_full_requires_exact_evidence(self) -> None:
        record = evidence.make_record(
            source="console",
            window="weekly",
            remaining_percent=0.0,
            exact_balance=True,
        )
        self.assertEqual(0.0, record["remaining_percent"])
        full = evidence.make_record(
            source="manual", window="monthly", remaining_percent=100.0, exact_balance=True
        )
        self.assertEqual(100.0, full["remaining_percent"])

    def test_spend_bounds_without_cap_are_withheld(self) -> None:
        bounds = evidence.spend_bounds([{"cost_usd": 5.0, "attribution": "exclusive"}])
        for window in ("five_hour", "weekly", "monthly"):
            row = bounds["windows"][window]
            if row["count"]:
                self.assertIsNone(row["remaining_percent_bounds"]["lower"])
                self.assertIsNone(row["remaining_percent_bounds"]["upper"])
        self.assertTrue(bounds["exact_balance_unavailable"])

    def test_absent_receipts_are_not_zero_spend(self) -> None:
        bounds = evidence.spend_bounds([])
        self.assertIsNone(bounds["windows"]["five_hour"]["spend_min_usd"])
        self.assertIn("not evidence of zero spend", bounds["windows"]["five_hour"]["note"])


class ConsoleImportTests(unittest.TestCase):
    def test_exact_console_import_from_fixture(self) -> None:
        data = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        result = evidence.parse_console_snapshot(data)
        self.assertEqual("console", result["source"])
        self.assertEqual("disabled", result["overage_fallback_state"])
        by_window = {record["window"]: record for record in result["records"]}
        self.assertEqual(82.0, by_window["five_hour"]["remaining_percent"])
        self.assertEqual(4100.0, by_window["five_hour"]["remaining_amount"])
        self.assertEqual(55.0, by_window["weekly"]["remaining_percent"])
        self.assertEqual(30.0, by_window["monthly"]["remaining_percent"])
        self.assertEqual("2026-08-12T12:00:00+00:00", by_window["five_hour"]["reset_at_utc"])
        for record in result["records"]:
            self.assertTrue(record["exact_balance"])
            self.assertFalse(record["discrepancy"])
        self.assertEqual([], result["validation"]["discrepancy_windows"])
        self.assertEqual([], result["validation"]["contradictory_window_pairs"])
        self.assertEqual(
            "known",
            evidence.balance_state(result["records"], "2026-08-12T11:00:00Z"),
        )
        self.assertEqual(
            30.0,
            evidence.effective_remaining_percent(
                result["records"], "2026-08-12T11:00:00Z"
            ),
        )

    def test_console_unknown_window_stays_null(self) -> None:
        data = {
            "observed_at_utc": "2026-08-12T10:00:00Z",
            "windows": {"five_hour": {"remaining_percent": 90.0}},
        }
        result = evidence.parse_console_snapshot(data)
        by_window = {record["window"]: record for record in result["records"]}
        self.assertIsNone(by_window["weekly"]["remaining_percent"])
        self.assertIsNone(by_window["monthly"]["remaining_percent"])
        self.assertIn("weekly", result["validation"]["unknown_windows"])
        self.assertIn("monthly", result["validation"]["unknown_windows"])

    def test_console_import_refuses_sensitive_keys_without_values(self) -> None:
        data = {
            "observed_at_utc": "2026-08-12T10:00:00Z",
            "windows": {"five_hour": {"remaining_percent": 90.0}},
            "auth": {"api_token": "synthetic-secret-value"},
        }
        with self.assertRaises(ValueError) as ctx:
            evidence.parse_console_snapshot(data)
        self.assertIn("api_token", str(ctx.exception))
        self.assertNotIn("synthetic-secret-value", str(ctx.exception))

    def test_console_import_rejects_foreign_pool(self) -> None:
        with self.assertRaises(ValueError):
            evidence.parse_console_snapshot(
                {"pool_id": "cursor.other", "windows": {"five_hour": {}}}
            )


class UsageApiTests(unittest.TestCase):
    def test_usage_api_defaults_to_official_endpoint(self) -> None:
        args = cli.parse_args(["--usage-api", "--usage-api-key-env", "LAD_TEST_GO_KEY"])
        self.assertEqual(cli.OFFICIAL_USAGE_ENDPOINT, args.usage_endpoint)

    def test_documented_usage_response_maps_used_to_remaining(self) -> None:
        result = evidence.parse_usage_api_response(
            {
                "useBalance": True,
                "usage": {
                    "rolling": {"percent": 3, "resetsAt": "2026-08-12T04:56:11Z", "status": "ok"},
                    "weekly": {"percent": 4, "resetsAt": "2026-08-17T00:00:00Z", "status": "ok"},
                    "monthly": {"percent": 2, "resetsAt": "2026-09-09T00:00:00Z", "status": "ok"},
                },
            },
            observed_at_utc="2026-08-12T01:00:00Z",
        )
        by_window = {row["window"]: row for row in result["records"]}
        self.assertEqual("enabled", result["overage_fallback_state"])
        self.assertEqual(97.0, by_window["five_hour"]["remaining_percent"])
        self.assertEqual(96.0, by_window["weekly"]["remaining_percent"])
        self.assertEqual(98.0, by_window["monthly"]["remaining_percent"])
        self.assertTrue(all(row["exact_balance"] for row in result["records"]))
        self.assertEqual("rolling", result["api_metadata"]["windows"]["five_hour"]["provider_window"])

    def test_rate_limited_is_exact_zero_remaining_evidence(self) -> None:
        result = evidence.parse_usage_api_response(
            {
                "usage": {
                    "rolling": {
                        "percent": 100,
                        "resetsAt": "2026-08-12T14:56:18Z",
                        "status": "rate-limited",
                    },
                    "weekly": {
                        "percent": 55,
                        "resetsAt": "2026-08-17T00:00:00Z",
                        "status": "ok",
                    },
                    "monthly": {
                        "percent": 27,
                        "resetsAt": "2026-09-09T00:00:00Z",
                        "status": "ok",
                    },
                }
            },
            observed_at_utc="2026-08-12T14:00:00Z",
        )
        rolling = next(row for row in result["records"] if row["window"] == "five_hour")
        self.assertEqual(0.0, rolling["remaining_percent"])
        self.assertTrue(rolling["exact_balance"])
        self.assertFalse(rolling["discrepancy"])
        self.assertEqual([], result["validation"]["discrepancy_windows"])

    def test_cli_usage_api_is_explicit_and_never_emits_key(self) -> None:
        response = {
            "ok": True,
            "http_status": 200,
            "body": {
                "usage": {
                    "rolling": {"percent": 3, "resetsAt": "2026-08-12T04:56:11Z", "status": "ok"},
                    "weekly": {"percent": 4, "resetsAt": "2026-08-17T00:00:00Z", "status": "ok"},
                    "monthly": {"percent": 2, "resetsAt": "2026-09-09T00:00:00Z", "status": "ok"},
                }
            },
        }
        with mock.patch.object(cli, "_fetch_usage_api", return_value=response), mock.patch.dict(
            os.environ, {"LAD_TEST_GO_KEY": "synthetic-go-key"}, clear=False
        ):
            code, stdout, stderr = run_cli(
                "--skip-discovery",
                "--usage-api",
                "--usage-endpoint",
                "https://usage.example.test/v1/usage",
                "--usage-api-key-env",
                "LAD_TEST_GO_KEY",
                "--now-utc",
                "2026-08-12T01:00:00Z",
            )
        self.assertEqual(0, code, stderr)
        bundle = json.loads(stdout)
        self.assertEqual("2026-08-12T01:00:00Z", bundle["fetched_at_utc"])
        self.assertEqual("known", bundle["balance_state"])
        self.assertEqual(96.0, bundle["pilot"]["effective_remaining_percent"])
        self.assertTrue(bundle["security"]["documented_usage_endpoint_called"])
        self.assertTrue(bundle["security"]["credential_values_inspected"])
        self.assertNotIn("synthetic-go-key", stdout)
        self.assertNotIn("synthetic-go-key", stderr)


class StaleTTLTests(unittest.TestCase):
    def test_expired_record_is_stale_and_not_usable(self) -> None:
        observed = "2026-08-12T11:30:00Z"
        now = "2026-08-12T12:00:00Z"
        record = evidence.make_record(
            source="console",
            window="five_hour",
            observed_at_utc=observed,
            remaining_percent=90.0,
            exact_balance=True,
            ttl_seconds=3600,
        )
        self.assertFalse(evidence.is_stale(record, now))
        stale = evidence.make_record(
            source="console",
            window="weekly",
            observed_at_utc="2026-08-12T08:00:00Z",
            remaining_percent=50.0,
            exact_balance=True,
            ttl_seconds=3600,
        )
        self.assertTrue(evidence.is_stale(stale, now))
        self.assertEqual("unknown", evidence.balance_state([stale], now))
        self.assertIsNone(evidence.effective_remaining_percent([stale], now))


class ContradictoryWindowsTests(unittest.TestCase):
    def test_reset_ordering_contradiction_is_flagged(self) -> None:
        data = {
            "observed_at_utc": "2026-08-12T10:00:00Z",
            "windows": {
                "five_hour": {"remaining_percent": 80.0, "reset_at_utc": "2026-08-12T12:00:00Z"},
                "weekly": {"remaining_percent": 60.0, "reset_at_utc": "2026-08-11T00:00:00Z"},
                "monthly": {"remaining_percent": 40.0, "reset_at_utc": "2026-09-01T00:00:00Z"},
            },
        }
        result = evidence.parse_console_snapshot(data)
        self.assertIn(["five_hour", "weekly"], result["validation"]["contradictory_window_pairs"])
        for record in result["records"]:
            if record["window"] in ("five_hour", "weekly"):
                self.assertTrue(record["discrepancy"])

    def test_reset_in_the_past_is_a_discrepancy(self) -> None:
        data = {
            "observed_at_utc": "2026-08-12T10:00:00Z",
            "windows": {
                "five_hour": {"remaining_percent": 80.0, "reset_at_utc": "2026-08-12T09:00:00Z"}
            },
        }
        result = evidence.parse_console_snapshot(data)
        record = next(r for r in result["records"] if r["window"] == "five_hour")
        self.assertTrue(record["discrepancy"])
        self.assertIn("precedes", record["note"])

    def test_percent_amount_conflict_is_flagged(self) -> None:
        data = {
            "observed_at_utc": "2026-08-12T10:00:00Z",
            "windows": {
                "weekly": {
                    "remaining_percent": 80.0,
                    "remaining_amount": 1000.0,
                    "cap_amount": 10000.0,
                }
            },
        }
        result = evidence.parse_console_snapshot(data)
        record = next(r for r in result["records"] if r["window"] == "weekly")
        self.assertTrue(record["discrepancy"])
        self.assertIn("weekly", result["validation"]["invalid_windows"])

    def test_out_of_range_percent_never_becomes_full_or_zero(self) -> None:
        data = {
            "observed_at_utc": "2026-08-12T10:00:00Z",
            "windows": {"monthly": {"remaining_percent": 150.0}},
        }
        result = evidence.parse_console_snapshot(data)
        record = next(r for r in result["records"] if r["window"] == "monthly")
        self.assertIsNone(record["remaining_percent"])
        self.assertTrue(record["discrepancy"])


class OverageFallbackTests(unittest.TestCase):
    def test_overage_states_round_trip(self) -> None:
        for state in ("unknown", "enabled", "disabled"):
            data = {
                "observed_at_utc": "2026-08-12T10:00:00Z",
                "overage_fallback_state": state,
                "windows": {},
            }
            result = evidence.parse_console_snapshot(data)
            self.assertEqual(state, result["overage_fallback_state"])

    def test_zen_balance_is_not_free_quota(self) -> None:
        data = {
            "observed_at_utc": "2026-08-12T10:00:00Z",
            "windows": {},
            "zen_balance": {"state": "available", "amount_usd": 1.25},
        }
        result = evidence.parse_console_snapshot(data)
        self.assertFalse(result["zen_balance"]["is_free_quota"])
        self.assertIn("not free OpenCode Go quota", result["zen_balance"]["note"])
        for record in result["records"]:
            self.assertIsNone(record["remaining_percent"])
            self.assertFalse(record["exact_balance"])

    def test_unknown_overage_default(self) -> None:
        result = evidence.parse_console_snapshot(
            {"observed_at_utc": "2026-08-12T10:00:00Z", "windows": {}}
        )
        self.assertEqual("unknown", result["overage_fallback_state"])


class RuntimeFailureClassificationTests(unittest.TestCase):
    def test_429_with_reset_hint_acts_on_shared_pool(self) -> None:
        classified = evidence.classify_runtime_failure(
            "429 rate limit exceeded for opencode-go/deepseek-v4-flash; "
            "quota resets in 2 hours",
            model_id="opencode-go/deepseek-v4-flash",
            variant="max",
            observed_at_utc="2026-08-12T10:00:00Z",
        )
        event = classified["event"]
        self.assertEqual("rate_limit", event["kind"])
        self.assertTrue(event["pool_level"])
        self.assertEqual("opencode.go", event["pool_id"])
        self.assertEqual("opencode-go/deepseek-v4-flash", event["model_id"])
        self.assertEqual("max", event["variant"])
        self.assertEqual("five_hour", event["window_hint"])
        self.assertTrue(event["reset_estimated"])
        self.assertEqual(
            "2026-08-12T12:00:00+00:00",
            evidence._parse_utc(event["reset_at_utc"]).isoformat(),
        )
        record = classified["record"]
        self.assertEqual("runtime_error", record["source"])
        self.assertIsNone(record["remaining_percent"])

    def test_quota_exhaustion_blocks_shared_pool(self) -> None:
        classified = evidence.classify_runtime_failure(
            "insufficient balance: weekly quota exhausted",
            model_id="opencode-go/mimo-v2.5",
            observed_at_utc="2026-08-12T10:00:00Z",
        )
        self.assertEqual("quota", classified["event"]["kind"])
        self.assertTrue(classified["event"]["pool_level"])
        self.assertEqual("weekly", classified["event"]["window_hint"])

    def test_capability_rejection_never_cools_shared_pool(self) -> None:
        classified = evidence.classify_runtime_failure(
            "Cannot use this model: opencode-go/deepseek-v4-flash. Available models: ...",
            model_id="opencode-go/deepseek-v4-flash",
            variant="max",
            observed_at_utc="2026-08-12T10:00:00Z",
        )
        self.assertEqual("capability", classified["event"]["kind"])
        self.assertFalse(classified["event"]["pool_level"])
        pool = {"pool_id": "opencode.go", "health": "unknown"}
        evidence.apply_pool_event(pool, classified["event"])
        self.assertEqual("unknown", pool["health"])
        self.assertEqual(
            "rejected",
            pool["model_runtime_states"]["opencode-go/deepseek-v4-flash"]["runtime_state"],
        )

    def test_location_restriction_is_exact_model_scoped_and_actionable(self) -> None:
        classified = evidence.classify_runtime_failure(
            "FAILED_PRECONDITION (code 400): User location is not supported for the API use.",
            model_id="opencode-go/deepseek-v4-flash",
            variant=None,
            observed_at_utc="2026-08-15T00:00:00Z",
            pool_id="opencode.go",
        )
        event = classified["event"]
        self.assertEqual("location_restricted", event["kind"])
        self.assertFalse(event["pool_level"])
        self.assertFalse(event["retryable"])
        self.assertTrue(event["route_change_required"])
        self.assertEqual("gcp_project_or_supported_region", event["recovery_action"])

    def test_location_restriction_does_not_cool_shared_pool(self) -> None:
        classified = evidence.classify_runtime_failure(
            "User location is not supported for the API use.",
            model_id="opencode-go/deepseek-v4-flash",
            observed_at_utc="2026-08-15T00:00:00Z",
            pool_id="opencode.go",
        )
        pool = {"pool_id": "opencode.go", "health": "ready"}
        evidence.apply_pool_event(pool, classified["event"])
        self.assertEqual("ready", pool["health"])
        state = pool["model_runtime_states"]["opencode-go/deepseek-v4-flash"]
        self.assertEqual("rejected", state["runtime_state"])
        self.assertEqual("gcp_project_or_supported_region", state["recovery_action"])

    def test_retry_after_header_sets_estimated_reset(self) -> None:
        classified = evidence.classify_runtime_failure(
            "HTTP 429; Retry-After: 900",
            model_id="opencode-go/kimi-k2.7-code",
            observed_at_utc="2026-08-12T10:00:00Z",
        )
        reset = evidence._parse_utc(classified["event"]["reset_at_utc"])
        self.assertEqual(
            "2026-08-12T10:15:00+00:00",
            reset.isoformat(),
        )

    def test_unclassified_failure_does_not_claim_pool_level(self) -> None:
        classified = evidence.classify_runtime_failure(
            "mysterious crash: segmentation fault",
            model_id="opencode-go/gpt-5.6-luna",
            observed_at_utc="2026-08-12T10:00:00Z",
        )
        self.assertEqual("unclassified", classified["event"]["kind"])
        self.assertFalse(classified["event"]["pool_level"])

    def test_secret_in_failure_text_is_redacted(self) -> None:
        classified = evidence.classify_runtime_failure(
            "429 too many requests; Authorization: Bearer synthetic",
            model_id="opencode-go/deepseek-v4-flash",
            observed_at_utc="2026-08-12T10:00:00Z",
        )
        self.assertNotIn("synthetic", classified["event"]["redacted_text"])
        self.assertIn("<redacted>", classified["event"]["redacted_text"])


class SharedPoolUpdateTests(unittest.TestCase):
    def test_console_record_updates_shared_pool_quota(self) -> None:
        pool = {"pool_id": "opencode.go", "health": "unknown", "quota": {"state": "unknown", "windows": {}}}
        record = evidence.make_record(
            source="console",
            window="weekly",
            remaining_percent=40.0,
            exact_balance=True,
            ttl_seconds=3600,
        )
        evidence.update_pool(pool, record)
        self.assertEqual("known", pool["quota"]["state"])
        self.assertEqual(40.0, pool["quota"]["windows"]["weekly"]["remaining_percent"])
        self.assertFalse(pool["quota"]["blocked"])

    def test_zero_window_blocks_shared_pool(self) -> None:
        pool = {"pool_id": "opencode.go", "health": "unknown", "quota": {"state": "unknown", "windows": {}}}
        record = evidence.make_record(
            source="console",
            window="five_hour",
            remaining_percent=0.0,
            exact_balance=True,
            ttl_seconds=3600,
        )
        evidence.update_pool(pool, record)
        self.assertTrue(pool["quota"]["blocked"])
        self.assertEqual("blocked", pool["health"])

    def test_runtime_429_cooldowns_pool_but_keeps_model_in_event(self) -> None:
        pool = {"pool_id": "opencode.go", "health": "unknown", "quota": {"state": "unknown", "windows": {}}}
        classified = evidence.classify_runtime_failure(
            "429 rate limit",
            model_id="opencode-go/deepseek-v4-flash",
            variant="max",
            observed_at_utc="2026-08-12T10:00:00Z",
        )
        evidence.apply_pool_event(pool, classified["event"])
        self.assertEqual("cooldown", pool["health"])
        self.assertEqual("rate_limited", pool["runtime_state"])
        self.assertIn("opencode-go/deepseek-v4-flash", pool["runtime_reason"])
        self.assertNotIn("deepseek", pool["quota"]["windows"])

    def test_quota_runtime_failure_blocks_pool(self) -> None:
        pool = {"pool_id": "opencode.go", "health": "unknown", "quota": {"state": "unknown", "windows": {}}}
        classified = evidence.classify_runtime_failure(
            "quota exhausted",
            model_id="opencode-go/mimo-v2.5",
            observed_at_utc="2026-08-12T10:00:00Z",
        )
        evidence.apply_pool_event(pool, classified["event"])
        self.assertTrue(pool["quota"]["blocked"])


class ModelMultiplierTests(unittest.TestCase):
    def test_exact_model_multiplier_beats_family_and_default(self) -> None:
        multipliers = {
            "opencode-go/deepseek-v4-flash": 1.5,
            "opencode-go/gpt-5.6-luna": 2.0,
            "opencode-go": 1.0,
        }
        self.assertEqual(
            1.5,
            evidence.effective_multiplier("opencode-go/deepseek-v4-flash", multipliers),
        )
        self.assertEqual(
            2.0,
            evidence.effective_multiplier("opencode-go/gpt-5.6-luna", multipliers),
        )
        self.assertEqual(
            1.0,
            evidence.effective_multiplier("opencode-go/kimi-k2.7-code", multipliers),
        )

    def test_family_prefix_beats_pool_default(self) -> None:
        self.assertEqual(
            1.25,
            evidence.effective_multiplier(
                "opencode-go/gpt-5.6-luna",
                {"opencode-go/gpt-5.6-luna": 1.25},
                default_multiplier=2.0,
            ),
        )

    def test_missing_multiplier_uses_default_not_fabricated(self) -> None:
        self.assertEqual(
            1.0,
            evidence.effective_multiplier("opencode-go/unknown-model", {}, default_multiplier=1.0),
        )

    def test_scale_cost_applies_multiplier_inside_shared_pool(self) -> None:
        self.assertEqual(7.5, evidence.scale_cost(5.0, 1.5))
        self.assertIsNone(evidence.scale_cost(None, 2.0))


class PilotDecisionTests(unittest.TestCase):
    def test_unknown_balance_blocks_without_explicit_pilot(self) -> None:
        decision = evidence.pilot_decision(
            [], catalog_visible=True, auth_state="configured", unknown_quota_policy=None
        )
        self.assertFalse(decision["pilot_allowed"])
        self.assertFalse(decision["ready_claim"])
        self.assertFalse(decision["unknown_mapped_to_zero"])
        self.assertFalse(decision["unknown_mapped_to_full"])

    def test_unknown_balance_pilot_requires_catalog_and_auth(self) -> None:
        decision = evidence.pilot_decision(
            [],
            catalog_visible=True,
            auth_state="configured",
            unknown_quota_policy="pilot",
            unknown_quota_pilot_percent=5.0,
            lanes=2,
            lane_cost_cap_usd=1.0,
            lane_token_cap=100_000,
        )
        self.assertTrue(decision["pilot_allowed"])
        self.assertFalse(decision["ready_claim"])
        self.assertEqual({"cost_cap_usd": 1.0, "token_cap": 100_000, "max_attempts": 1}, decision["per_lane_caps"])
        self.assertEqual(10.0, decision["reserve"]["percent"])

    def test_catalog_visibility_alone_never_sets_ready(self) -> None:
        decision = evidence.pilot_decision(
            [],
            catalog_visible=True,
            auth_state="configured",
            unknown_quota_policy="pilot",
        )
        self.assertTrue(decision["catalog_visibility_alone_does_not_set_ready"])
        self.assertFalse(decision["ready_claim"])

    def test_known_balance_allows_pilot_but_ready_requires_reserve_headroom(self) -> None:
        record = evidence.make_record(
            source="console",
            window="five_hour",
            remaining_percent=20.0,
            exact_balance=True,
            ttl_seconds=3600,
        )
        decision = evidence.pilot_decision(
            [record], catalog_visible=True, auth_state="configured", reserve_percent=10.0
        )
        self.assertTrue(decision["pilot_allowed"])
        self.assertTrue(decision["ready_claim"])
        self.assertEqual("known", decision["balance_state"])
        self.assertEqual(20.0, decision["effective_remaining_percent"])

    def test_exact_zero_blocks_pilot_even_with_explicit_pilot_policy(self) -> None:
        record = evidence.make_record(
            source="console",
            window="weekly",
            remaining_percent=0.0,
            exact_balance=True,
            ttl_seconds=3600,
        )
        decision = evidence.pilot_decision(
            [record],
            catalog_visible=True,
            auth_state="configured",
            unknown_quota_policy="pilot",
            unknown_quota_pilot_percent=5.0,
        )
        self.assertTrue(decision["blocked"])
        self.assertFalse(decision["pilot_allowed"])


class NoPromptNoSecretTests(unittest.TestCase):
    def test_runtime_root_is_forwarded_and_recorded(self) -> None:
        discovery = {
            "ok": True,
            "pools": {
                "opencode.go": {
                    "auth_state": "configured",
                    "catalog_state": "visible",
                }
            },
            "stats": {"state": "empty"},
            "commands": [],
            "runtime_context": {
                "mode": "pinned_runtime_root",
                "runtime_root": "/srv/lad/runtime-01",
                "evidence": "all probes share the pinned context",
            },
        }
        fake_snapshot = mock.Mock()
        fake_snapshot.collect_snapshot.return_value = discovery
        with mock.patch.object(cli, "_default_snapshot", return_value=fake_snapshot):
            code, stdout, stderr = run_cli(
                "--opencode",
                "/srv/EXAMPLE_001/opencode",
                "--runtime-root",
                "/srv/lad/runtime-01",
            )
        self.assertEqual(0, code, stderr)
        fake_snapshot.collect_snapshot.assert_called_once_with(
            "/srv/EXAMPLE_001/opencode", 20.0, 30, None, "/srv/lad/runtime-01", None, None
        )
        bundle = json.loads(stdout)
        self.assertEqual("pinned_runtime_root", bundle["runtime_context"]["mode"])
        self.assertEqual("/srv/lad/runtime-01", bundle["runtime_context"]["runtime_root"])
        self.assertFalse(bundle["security"]["model_prompt_sent"])

    def test_auth_data_root_is_forwarded_for_history_context(self) -> None:
        discovery = {
            "ok": True,
            "pools": {"opencode.go": {"auth_state": "configured", "catalog_state": "visible"}},
            "stats": {
                "state": "visible",
                "overview": {"sessions": 2},
                "models": [{"model": "opencode-go/kimi-k2.7-code", "messages": 1}],
                "opencode_go_models": ["opencode-go/kimi-k2.7-code"],
            },
            "commands": [],
            "runtime_context": {"mode": "pinned_runtime_root", "runtime_root": "/srv/lad/runtime-01"},
        }
        fake_snapshot = mock.Mock()
        fake_snapshot.collect_snapshot.return_value = discovery
        with mock.patch.object(cli, "_default_snapshot", return_value=fake_snapshot):
            code, stdout, stderr = run_cli(
                "--opencode",
                "/srv/EXAMPLE_001/opencode",
                "--runtime-root",
                "/srv/lad/runtime-01",
                "--auth-data-root",
                "/srv/opencode-server-home/.local/share",
            )
        self.assertEqual(0, code, stderr)
        fake_snapshot.collect_snapshot.assert_called_once_with(
            "/srv/EXAMPLE_001/opencode",
            20.0,
            30,
            None,
            "/srv/lad/runtime-01",
            "/srv/opencode-server-home/.local/share",
            None,
        )
        bundle = json.loads(stdout)
        self.assertEqual("visible", bundle["history_summary"]["state"])
        self.assertEqual(
            ["opencode-go/kimi-k2.7-code"],
            bundle["history_summary"]["opencode_go_models"],
        )

    def test_cli_offline_console_import_is_provider_free_and_redacted(self) -> None:
        code, stdout, stderr = run_cli(
            "--skip-discovery",
            "--console",
            str(FIXTURE_PATH),
            "--unknown-quota-policy",
            "pilot",
            "--pilot-lanes",
            "2",
            "--model-multiplier",
            "opencode-go/deepseek-v4-flash=1.5",
            "--now-utc",
            "2026-08-12T11:00:00Z",
        )
        self.assertEqual(0, code, stderr)
        bundle = json.loads(stdout)
        self.assertEqual("opencode_go_quota_evidence", bundle["kind"])
        self.assertEqual("opencode.go", bundle["pool_id"])
        self.assertEqual("known", bundle["balance_state"])
        self.assertEqual(3, len(bundle["records"]))
        self.assertEqual("disabled", bundle["overage_fallback_state"])
        self.assertFalse(bundle["zen_balance"]["is_free_quota"])
        self.assertEqual(1.5, bundle["model_usage_multipliers"]["opencode-go/deepseek-v4-flash"])
        self.assertFalse(bundle["security"]["model_prompt_sent"])
        self.assertFalse(bundle["security"]["credential_values_inspected"])
        self.assertFalse(bundle["security"]["undocumented_balance_endpoint_called"])
        self.assertTrue(bundle["pilot"]["pilot_allowed"])
        self.assertTrue(bundle["pilot"]["ready_claim"])
        self.assertFalse(bundle["pilot"]["unknown_mapped_to_full"])
        rendered = json.dumps(bundle, sort_keys=True)
        self.assertEqual(rendered, json.dumps(json.loads(rendered), sort_keys=True))

    def test_cli_refuses_sensitive_console_snapshot(self) -> None:
        bad = REPO_ROOT / "research" / "fixtures" / "quota_console_bad.json"
        try:
            bad.write_text(
                json.dumps(
                    {
                        "observed_at_utc": "2026-08-12T10:00:00Z",
                        "windows": {},
                        "credentials": {"api_token": "synthetic-fixture-value"},
                    }
                ),
                encoding="utf-8",
            )
            code, stdout, stderr = run_cli("--skip-discovery", "--console", str(bad))
            self.assertEqual(3, code)
            self.assertEqual("", stdout)
            self.assertIn("refused", stderr)
            self.assertIn("credentials", stderr)
            self.assertNotIn("synthetic-fixture-value", stderr)
        finally:
            bad.unlink(missing_ok=True)

    def test_cli_runtime_failure_retains_exact_model_and_variant(self) -> None:
        code, stdout, _ = run_cli(
            "--skip-discovery",
            "--failure-text",
            "429 too many requests; resets in 30 minutes",
            "--failure-model",
            "opencode-go/deepseek-v4-flash",
            "--failure-variant",
            "max",
        )
        self.assertEqual(0, code)
        bundle = json.loads(stdout)
        self.assertEqual("unknown", bundle["balance_state"])
        event = bundle["runtime_events"][0]
        self.assertEqual("opencode-go/deepseek-v4-flash", event["model_id"])
        self.assertEqual("max", event["variant"])
        self.assertTrue(event["pool_level"])
        self.assertEqual("rate_limit", event["kind"])

    def test_cli_skips_undocumented_balance_calls(self) -> None:
        code, stdout, _ = run_cli("--skip-discovery")
        self.assertEqual(2, code)
        bundle = json.loads(stdout)
        self.assertEqual("unknown", bundle["balance_state"])
        self.assertEqual([], bundle["records"])
        self.assertFalse(bundle["security"]["undocumented_balance_endpoint_called"])


class SchemaSanityTests(unittest.TestCase):
    def test_schema_is_valid_json_with_required_fields(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual("http://json-schema.org/draft-07/schema#", schema["$schema"])
        record = schema["definitions"]["quota_evidence_record"]
        for field in (
            "source",
            "observed_at_utc",
            "window",
            "remaining_percent",
            "remaining_amount",
            "reset_at_utc",
            "confidence",
            "ttl_seconds",
            "discrepancy",
        ):
            self.assertIn(field, record["properties"])
        self.assertIn("scope_hash", record["properties"])
        self.assertIn("console", record["properties"]["source"]["enum"])
        self.assertIn("runtime_error", record["properties"]["source"]["enum"])
        runtime_event = schema["definitions"]["runtime_event"]
        self.assertIn(
            "location_restricted", runtime_event["properties"]["kind"]["enum"]
        )
        self.assertIn("recovery_action", runtime_event["properties"])


if __name__ == "__main__":
    unittest.main()
