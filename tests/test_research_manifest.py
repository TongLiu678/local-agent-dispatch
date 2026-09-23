"""Tests for the WP0 provider-free run-manifest validator.

A run manifest is the machine-readable envelope every research result must
carry: policy digest, seed, source/fixture digest, start commit or source
digest, evidence level, validator identity, and result digest. Validation
fails closed: a result without a manifest, without validator identity, or
without an evidence level is rejected before it can be used.

All fixtures are deterministic, in-memory, and provider-free: no network, no
provider, no SSH, no downloads.

Run: python3 -m unittest tests.test_research_manifest -v
"""

from __future__ import annotations

import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from research.replay.run_manifest import (  # noqa: E402
    EVIDENCE_LEVELS,
    MANIFEST_SCHEMA_VERSION,
    build_manifest,
    seal_run_manifest,
    validate_run_manifest,
    verify_fixture,
    verify_result,
)


def _policy_payload() -> dict:
    return {
        "policy": "quota-aware-v1",
        "max_lanes": 4,
        "unknown_quota_policy": "pilot",
    }


def _fixture_payload() -> dict:
    return {
        "pools": [
            {"pool_id": "codex", "weekly_percent": 100.0, "quota_display_known": True},
            {"pool_id": "opencode.go", "weekly_percent": 100.0, "quota_display_known": True},
        ],
        "hosts": [
            {
                "host_id": "host-local",
                "ram_mb": 16384.0,
                "vram_mb": 24576.0,
                "vram_used_mb": 12000.0,
            }
        ],
    }


def _result_payload() -> dict:
    return {
        "summary": {
            "jobs_total": 8,
            "jobs_validated": 8,
            "jobs_censored": 0,
            "quota_violations": 0,
        },
        "event_trace": [
            {"kind": "job_planned", "t": 0.0, "job_id": "j-0", "lease_token": "L1"},
            {"kind": "artifact_validated", "t": 100.0, "job_id": "j-0"},
        ],
    }


def _sealed_manifest(**overrides) -> dict:
    manifest = seal_run_manifest(
        policy_payload=_policy_payload(),
        fixture_payload=_fixture_payload(),
        result_payload=_result_payload(),
        seed=7,
        evidence_level="E1",
        validator_id="replay-run_manifest-v1",
        start_commit="a" * 40,
    )
    manifest.update(overrides)
    return manifest


class FailClosedTests(unittest.TestCase):
    def test_valid_sealed_manifest_accepted(self) -> None:
        manifest = _sealed_manifest()
        report = validate_run_manifest(manifest)
        self.assertTrue(report["valid"], report["errors"])
        self.assertEqual([], report["errors"])
        self.assertEqual(MANIFEST_SCHEMA_VERSION, report["fields"]["schema_version"])
        self.assertEqual("E1", report["fields"]["evidence_level"])

    def test_no_manifest_at_all_rejected(self) -> None:
        for bad in (None, "", [], 42):
            report = validate_run_manifest(bad)
            self.assertFalse(report["valid"], bad)
            self.assertIn("missing_manifest", report["errors"])

    def test_result_without_required_fields_fails_closed(self) -> None:
        required = (
            ("policy_digest", "missing_policy_digest"),
            ("seed", "missing_seed"),
            ("fixture_digest", "missing_fixture_digest"),
            ("evidence_level", "missing_evidence_level"),
            ("validator_id", "missing_validator_id"),
            ("result_digest", "missing_result_digest"),
        )
        for field, error_code in required:
            manifest = _sealed_manifest()
            del manifest[field]
            report = validate_run_manifest(manifest)
            self.assertFalse(report["valid"], field)
            self.assertIn(error_code, report["errors"], field)

    def test_missing_start_commit_and_source_digest_rejected(self) -> None:
        manifest = _sealed_manifest()
        del manifest["start_commit"]
        self.assertNotIn("source_digest", manifest)
        report = validate_run_manifest(manifest)
        self.assertFalse(report["valid"])
        self.assertIn("missing_start_source", report["errors"])

    def test_unknown_evidence_level_rejected(self) -> None:
        for level in ("E5", "e1", "", "provider_free", 1, None):
            report = validate_run_manifest(_sealed_manifest(evidence_level=level))
            self.assertFalse(report["valid"], level)
            self.assertIn("unknown_evidence_level", report["errors"])

    def test_missing_validator_and_evidence_never_pass(self) -> None:
        manifest = _sealed_manifest()
        del manifest["validator_id"]
        del manifest["evidence_level"]
        report = validate_run_manifest(manifest)
        self.assertFalse(report["valid"])
        self.assertIn("missing_validator_id", report["errors"])
        self.assertIn("missing_evidence_level", report["errors"])

    def test_malformed_digests_rejected(self) -> None:
        for field in ("policy_digest", "fixture_digest", "result_digest", "source_digest"):
            for bad in ("deadbeef", "A" * 64, "x" * 64, "", None):
                manifest = _sealed_manifest()
                manifest[field] = bad
                report = validate_run_manifest(manifest)
                self.assertFalse(report["valid"], (field, bad))
                self.assertIn(f"malformed_{field}", report["errors"])

    def test_malformed_start_commit_rejected(self) -> None:
        for bad in ("", "zz" * 40, "a" * 6, "A" * 40):
            report = validate_run_manifest(_sealed_manifest(start_commit=bad))
            self.assertFalse(report["valid"], bad)
            self.assertIn("malformed_start_commit", report["errors"])

    def test_invalid_seed_rejected(self) -> None:
        for bad in ("7", 7.5, True, None, [7]):
            report = validate_run_manifest(_sealed_manifest(seed=bad))
            self.assertFalse(report["valid"], bad)
            self.assertIn("invalid_seed", report["errors"])

    def test_malformed_validator_id_rejected(self) -> None:
        for bad in ("", "has space", "../escape", "UPPER", "x" * 129):
            report = validate_run_manifest(_sealed_manifest(validator_id=bad))
            self.assertFalse(report["valid"], bad)
            self.assertIn("malformed_validator_id", report["errors"])

    def test_unsupported_schema_version_rejected(self) -> None:
        for bad in (0, 2, "1", None):
            report = validate_run_manifest(_sealed_manifest(schema_version=bad))
            self.assertFalse(report["valid"], bad)
            self.assertIn("unsupported_schema_version", report["errors"])


class VerificationTests(unittest.TestCase):
    def test_fixture_mismatch_fails_closed(self) -> None:
        manifest = _sealed_manifest()
        self.assertTrue(verify_fixture(manifest, _fixture_payload()))
        tampered = dict(_fixture_payload())
        tampered["pools"][0]["weekly_percent"] = 50.0
        self.assertFalse(verify_fixture(manifest, tampered))

    def test_result_mismatch_fails_closed(self) -> None:
        manifest = _sealed_manifest()
        self.assertTrue(verify_result(manifest, _result_payload()))
        tampered = dict(_result_payload())
        tampered["summary"]["jobs_validated"] = 9
        self.assertFalse(verify_result(manifest, tampered))

    def test_verify_without_manifest_fails_closed(self) -> None:
        self.assertFalse(verify_fixture({}, _fixture_payload()))
        self.assertFalse(verify_result({}, _result_payload()))


class DeterminismTests(unittest.TestCase):
    def test_seal_is_deterministic(self) -> None:
        one = _sealed_manifest()
        two = _sealed_manifest()
        self.assertEqual(one, two)
        self.assertEqual(json.dumps(one, sort_keys=True), json.dumps(two, sort_keys=True))

    def test_seed_does_not_change_fixture_or_result_digest(self) -> None:
        base = _sealed_manifest()
        other = _sealed_manifest(seed=8)
        self.assertEqual(base["seed"], 7)
        self.assertEqual(other["seed"], 8)
        self.assertEqual(base["fixture_digest"], other["fixture_digest"])
        self.assertEqual(base["result_digest"], other["result_digest"])

    def test_different_result_changes_result_digest_only(self) -> None:
        base = _sealed_manifest()
        other_result = dict(_result_payload())
        other_result["summary"]["jobs_validated"] = 7
        other = seal_run_manifest(
            policy_payload=_policy_payload(),
            fixture_payload=_fixture_payload(),
            result_payload=other_result,
            seed=7,
            evidence_level="E1",
            validator_id="replay-run_manifest-v1",
            start_commit="a" * 40,
        )
        self.assertEqual(base["fixture_digest"], other["fixture_digest"])
        self.assertNotEqual(base["result_digest"], other["result_digest"])

    def test_provider_free_ceiling_enforced_on_seal(self) -> None:
        with self.assertRaises(ValueError):
            seal_run_manifest(
                policy_payload=_policy_payload(),
                fixture_payload=_fixture_payload(),
                result_payload=_result_payload(),
                seed=7,
                evidence_level="E3",
                validator_id="replay-run_manifest-v1",
                start_commit="a" * 40,
            )

    def test_evidence_levels_are_stable_e0_to_e4(self) -> None:
        self.assertEqual(("E0", "E1", "E2", "E3", "E4"), EVIDENCE_LEVELS)


class ProviderFreeRulesTests(unittest.TestCase):
    def test_replay_results_may_only_claim_e0_e1(self) -> None:
        manifest = _sealed_manifest(evidence_level="E1")
        report = validate_run_manifest(manifest)
        self.assertTrue(report["valid"])
        self.assertEqual("E1", report["fields"]["evidence_level"])
        self.assertEqual("sha256", report["fields"]["digest_algorithm"])

    def test_e0_design_review_manifest_accepted(self) -> None:
        manifest = _sealed_manifest(evidence_level="E0")
        self.assertTrue(validate_run_manifest(manifest)["valid"])


def _continuous_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": 1,
        "run_id": "run-20260829-001",
        "mode": "offline_soak",
        "evidence_level": "E1",
        "source_digest": "sha256:" + "a" * 64,
        "policy_digest": "sha256:" + "b" * 64,
        "capsule_digest": "sha256:" + "c" * 64,
        "planned_end_at": "2026-08-30T00:00:00+00:00",
        "stop_conditions": {
            "accepted_task_loss": 0,
            "duplicate_irreversible_effect": 0,
            "unowned_process_signal": 0,
            "oom_or_enospc_unrecorded": 0,
        },
        "validator_id": "continuous-run-validator-v1",
    }
    payload.update(overrides)
    return payload


class ContinuousManifestTests(unittest.TestCase):
    def test_continuous_manifest_requires_evidence_and_stop_conditions(self) -> None:
        with self.assertRaises(ValueError):
            build_manifest({"run_id": "r1", "mode": "soak"})
        manifest = build_manifest(_continuous_payload())
        self.assertEqual("offline_soak", manifest["mode"])
        self.assertEqual("E1", manifest["evidence_level"])
        self.assertEqual(3600, manifest["segment_seconds"])

    def test_continuous_manifest_rejects_provider_free_boundary_violations(self) -> None:
        with self.assertRaisesRegex(ValueError, "provider execution"):
            build_manifest(_continuous_payload(provider_execution=True))
        with self.assertRaisesRegex(ValueError, "network execution"):
            build_manifest(_continuous_payload(network_execution=True))
        with self.assertRaisesRegex(ValueError, "scheduler"):
            build_manifest(_continuous_payload(segment_seconds=600, scheduler_max_wall_seconds=300))

    def test_continuous_manifest_rejects_bad_digests_ids_and_stop_fields(self) -> None:
        with self.assertRaises(ValueError):
            build_manifest(_continuous_payload(source_digest="a" * 64))
        with self.assertRaises(ValueError):
            build_manifest(_continuous_payload(run_id="../escape"))
        bad_stop = dict(_continuous_payload()["stop_conditions"])
        del bad_stop["accepted_task_loss"]
        with self.assertRaises(ValueError):
            build_manifest(_continuous_payload(stop_conditions=bad_stop))

    def test_continuous_manifest_rejects_non_integer_or_too_short_segments(self) -> None:
        for segment in (True, 59, 86401, 1.5):
            with self.assertRaises(ValueError):
                build_manifest(_continuous_payload(segment_seconds=segment))


if __name__ == "__main__":
    unittest.main()
