from __future__ import annotations

import datetime as dt
import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("quota_window_watcher", ROOT / "scripts" / "quota_window_watcher.py")
assert SPEC and SPEC.loader
watcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(watcher)


class QuotaWindowWatcherTests(unittest.TestCase):
    NOW = "2026-08-29T16:00:00Z"

    def test_zero_spark_schedules_reset_without_rotating_models(self):
        snapshot = {
            "fetched_at_utc": self.NOW,
            "source": "codex app-server",
            "pools": {
                "codex.spark": {
                    "provider": "codex",
                    "health": "blocked",
                    "effective_remaining_percent": 0,
                    "primary": {"remaining_percent": 0, "resets_at_utc": "2026-08-29T16:47:03Z"},
                    "schedulable_models": ["gpt-5.3-codex-spark"],
                }
            },
        }
        result = watcher.watch([snapshot], now_utc=self.NOW)
        row = result["pools"][0]
        self.assertEqual("cooldown_until_reset", row["decision"])
        self.assertEqual("codex.spark", result["replan_feedback"]["quota_reset_pool_id"])
        self.assertEqual("2026-08-29T16:47:03+00:00", result["next_wake_at_utc"])
        self.assertEqual([], result["provider_invocations"])

    def test_antigravity_g1_wallet_does_not_override_model_quota_but_auth_conflict_blocks_execution(self):
        snapshot = {
            "observed_at_utc": self.NOW,
            "source": "/usage",
            "g1_credit_status_bar": "Out of credits",
            "raw_excerpt": "Welcome to the Antigravity CLI. You are currently not signed in.",
            "pools": {
                "antigravity.gemini": {
                    "provider": "antigravity",
                    "health": "ready",
                    "effective_percent_displayed": 99.16,
                    "schedulable_models": ["gemini-3.6-flash-high"],
                }
            },
        }
        result = watcher.watch([snapshot], now_utc=self.NOW)
        row = result["pools"][0]
        self.assertEqual("known", row["quota_state"])
        self.assertEqual("needs_reauth", row["decision"])
        self.assertEqual("blocked", row["execution_state"])
        self.assertEqual([], result["ready_pools"])

    def test_unknown_balance_requires_explicit_bounded_pilot(self):
        snapshot = {
            "observed_at_utc": self.NOW,
            "source": "opencode usage unavailable",
            "auth_state": "configured",
            "pools": {
                "opencode.go": {
                    "provider": "opencode",
                    "health": "unknown",
                    "catalog_visible": True,
                    "schedulable_models": ["opencode-go/mimo-v2.5"],
                }
            },
        }
        blocked = watcher.watch([snapshot], now_utc=self.NOW)
        self.assertEqual("blocked_unknown", blocked["pools"][0]["decision"])
        pilot = watcher.watch([snapshot], now_utc=self.NOW, unknown_quota_policy="pilot")
        self.assertEqual("bounded_pilot", pilot["pools"][0]["decision"])
        self.assertEqual(["opencode.go"], pilot["ready_pools"])
        self.assertEqual(5.0, pilot["pools"][0]["pilot_percent"])

    def test_stale_snapshot_does_not_inherit_a_reset(self):
        snapshot = {
            "observed_at_utc": "2026-08-29T14:00:00Z",
            "ttl_seconds": 60,
            "pools": {
                "codex.spark": {
                    "health": "blocked",
                    "effective_remaining_percent": 0,
                    "primary": {"resets_at_utc": "2026-08-29T17:00:00Z"},
                }
            },
        }
        result = watcher.watch([snapshot], now_utc=self.NOW)
        self.assertEqual("blocked_stale", result["pools"][0]["decision"])
        self.assertEqual("bounded_poll", result["wake_source"])
        self.assertNotEqual("2026-08-29T17:00:00+00:00", result["next_wake_at_utc"])

    def test_duplicate_pool_keeps_newest_observation_without_adding_balances(self):
        old = {
            "observed_at_utc": "2026-08-29T15:59:00Z",
            "pools": {"codex.spark": {"effective_remaining_percent": 20, "health": "ready"}},
        }
        new = {
            "observed_at_utc": self.NOW,
            "pools": {"codex.spark": {"effective_remaining_percent": 0, "health": "blocked"}},
        }
        result = watcher.watch([old, new], now_utc=self.NOW)
        self.assertEqual(1, len(result["pools"]))
        self.assertEqual(0, result["pools"][0]["remaining_percent"])

    def test_sensitive_snapshot_is_rejected_without_echoing_value(self):
        result = watcher.watch([{"observed_at_utc": self.NOW, "api_key": "do-not-echo"}], now_utc=self.NOW)
        self.assertEqual("sensitive_key", result["invalid_snapshots"][0]["reason"])
        self.assertNotIn("do-not-echo", json.dumps(result))

    def test_historical_token_usage_metadata_is_not_a_credential(self):
        snapshot = {
            "fetched_at_utc": self.NOW,
            "token_usage": {"summary": {"lifetimeTokens": 123}},
            "pools": {"codex.spark": {"health": "blocked", "effective_remaining_percent": 0}},
        }
        result = watcher.watch([snapshot], now_utc=self.NOW)
        self.assertEqual([], result["invalid_snapshots"])
        self.assertEqual("blocked_quota", result["pools"][0]["decision"])

    def test_invalid_now_and_poll_are_fail_closed(self):
        with self.assertRaises(watcher.QuotaWatchError):
            watcher.watch([], now_utc="2026-08-29T16:00:00")
        with self.assertRaises(watcher.QuotaWatchError):
            watcher.watch([], now_utc=self.NOW, poll_seconds=0)


if __name__ == "__main__":
    unittest.main()
