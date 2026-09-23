from __future__ import annotations

import datetime as dt
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from local_agent_dispatch.discovery import (
    build_probe_plan,
    build_search_plan,
    resolve_capability,
    resolve_gate,
)


NOW = "2026-08-12T00:00:00+00:00"


class EvidenceDiscoveryTests(unittest.TestCase):
    def test_search_plan_is_deterministic_and_search_precedes_probe(self) -> None:
        plan = build_search_plan(
            provider="opencode",
            capability="usage_endpoint",
            version="1.18.15",
            model="opencode-go/deepseek-v4-flash",
            official_domains=("opencode.ai", "github.com/anomalyco/opencode"),
        )
        self.assertEqual(plan["network_side_effect"], "read_only_search_only")
        self.assertTrue(plan["probe_requires_explicit_opt_in"])
        self.assertEqual(plan["queries"][0]["source_kind"], "official_docs")
        self.assertEqual(plan["plan_digest"], build_search_plan(
            provider="opencode",
            capability="usage_endpoint",
            version="1.18.15",
            model="opencode-go/deepseek-v4-flash",
            official_domains=("opencode.ai", "github.com/anomalyco/opencode"),
        )["plan_digest"])

    def test_probe_plan_is_bounded_and_prompt_free(self) -> None:
        plan = build_probe_plan(
            executable=["opencode", "models", "opencode-go"],
            timeout_seconds=20,
            side_effect_class="read_only_local",
        )
        self.assertEqual(plan["prompt_allowed"], False)
        self.assertEqual(plan["timeout_seconds"], 20)
        with self.assertRaises(ValueError):
            build_probe_plan(executable=["opencode"], timeout_seconds=301)

    def test_official_version_matched_evidence_wins_over_community(self) -> None:
        records = [
            {
                "evidence_id": "community",
                "provider": "opencode",
                "capability": "usage_endpoint",
                "claim": "https://old.example/usage",
                "source_kind": "community",
                "version": "1.18.15",
                "observed_at_utc": NOW,
                "ttl_seconds": 3600,
                "confidence": 0.9,
            },
            {
                "evidence_id": "official",
                "provider": "opencode",
                "capability": "usage_endpoint",
                "claim": "https://opencode.ai/zen/go/v1/usage",
                "source_kind": "official_source",
                "version": "1.18.15",
                "observed_at_utc": NOW,
                "ttl_seconds": 3600,
                "confidence": 0.95,
            },
        ]
        result = resolve_capability({"provider": "opencode", "capability": "usage_endpoint", "version": "1.18.15"}, records, now_utc=NOW)
        self.assertEqual(result["state"], "conflict")
        self.assertFalse(result["resolved"])
        self.assertEqual(len(result["conflict_claims"]), 2)

    def test_stale_evidence_never_makes_ready(self) -> None:
        records = [{
            "provider": "cursor",
            "capability": "runtime",
            "claim": "accepted",
            "source_kind": "runtime",
            "observed_at_utc": "2026-08-11T00:00:00+00:00",
            "ttl_seconds": 60,
            "confidence": 1.0,
        }]
        result = resolve_capability({"provider": "cursor", "capability": "runtime"}, records, now_utc=NOW)
        self.assertEqual(result["state"], "stale_or_out_of_scope")
        self.assertFalse(result["resolved"])

    def test_sensitive_values_are_redacted(self) -> None:
        result = resolve_capability(
            {"provider": "opencode", "capability": "usage_endpoint"},
            [{
                "provider": "opencode",
                "capability": "usage_endpoint",
                "claim": "https://opencode.ai/zen/go/v1/usage",
                "source_kind": "official_source",
                "observed_at_utc": NOW,
                "ttl_seconds": 3600,
                "confidence": 0.9,
                "authorization": "Bearer super-secret",
                "metadata": {"api_key": "should-not-persist"},
            }],
            now_utc=NOW,
        )
        serialized = str(result)
        self.assertNotIn("super-secret", serialized)
        self.assertNotIn("should-not-persist", serialized)
        self.assertEqual(result["state"], "known")

    def test_gate_requires_each_explicit_status(self) -> None:
        records = [
            {"provider": "p", "status": "visible", "source_kind": "official_docs", "observed_at_utc": NOW, "ttl_seconds": 3600, "confidence": 1.0},
            {"provider": "p", "status": "accepted", "source_kind": "runtime", "observed_at_utc": NOW, "ttl_seconds": 3600, "confidence": 1.0},
        ]
        gate = resolve_gate(records, required_statuses=("visible", "accepted", "quota_known"), question={"provider": "p"}, now_utc=NOW)
        self.assertFalse(gate["ready"])
        self.assertEqual(gate["missing"], ["quota_known"])


if __name__ == "__main__":
    unittest.main()
