#!/usr/bin/env python3
"""Fake-only tests for the provider-free bounded task estimator."""

from __future__ import annotations

import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT / "scripts"))

import task_estimator as estimator  # noqa: E402


class TaskEstimatorTests(unittest.TestCase):
    def test_history_produces_p50_and_p90_with_evidence(self) -> None:
        task = {
            "job_id": "history-job",
            "resources": {"cpu_cores": 4, "ram_gib": 8},
            "history": {
                "runtime_minutes": [10, 20, 30, 40, 50],
                "cpu_cores": [2, 4, 4, 6, 8],
                "ram_gib": [4, 8, 8, 12, 16],
            },
        }
        report = estimator.estimate_task(task)
        self.assertEqual(30, report["metrics"]["runtime_minutes"]["p50"])
        self.assertEqual(46, report["metrics"]["runtime_minutes"]["p90"])
        self.assertEqual("high", report["metrics"]["runtime_minutes"]["confidence"])
        self.assertIn("history.runtime_minutes (5 observation(s))", report["evidence"])

    def test_single_hint_is_explicit_low_confidence_not_a_fake_default(self) -> None:
        report = estimator.estimate_task(
            {"job_id": "hint", "resources": {"runtime_minutes": 3, "cpu_cores": 2}}
        )
        runtime = report["metrics"]["runtime_minutes"]
        self.assertEqual(3, runtime["p50"])
        self.assertEqual(3, runtime["p90"])
        self.assertEqual("low", runtime["confidence"])
        self.assertEqual("explicit_hint", runtime["source"])

    def test_explicit_percentile_hint_is_preserved(self) -> None:
        report = estimator.estimate_task(
            {
                "job_id": "percentiles",
                "resources": {
                    "runtime_minutes": {"p50": 4, "p90": 12},
                    "cpu_cores_p50": 2,
                    "cpu_cores_p90": 4,
                },
            }
        )
        runtime = report["metrics"]["runtime_minutes"]
        self.assertEqual(4, runtime["p50"])
        self.assertEqual(12, runtime["p90"])
        self.assertEqual("explicit_percentile_hint", runtime["source"])

    def test_unknown_values_remain_unknown_and_require_pilot(self) -> None:
        report = estimator.estimate_task({"job_id": "unknown", "description": "inspect code"})
        self.assertIsNone(report["metrics"]["runtime_minutes"]["p50"])
        self.assertIsNone(report["metrics"]["ram_gib"]["p90"])
        self.assertEqual("unknown", report["server_first"])
        self.assertTrue(report["pilot_required"])
        self.assertIn("unknown_runtime_minutes", report["pilot_reasons"])
        self.assertIsNone(report["resources"]["storage"]["download"]["p90"])
        self.assertIsNone(report["resources"]["compute"]["network"]["p50"])

    def test_token_bounds_are_preserved_for_cost_planning_without_gating(self) -> None:
        report = estimator.estimate_task(
            {
                "job_id": "priced",
                "resources": {
                    "input_gib": 0,
                    "download_gib": 0,
                    "environment_gib": 0,
                    "temporary_gib": 0,
                    "cache_gib": 0,
                    "output_gib": 0,
                    "runtime_minutes": 4,
                    "cpu_cores": 1,
                    "ram_gib": 1,
                },
                "token_estimate": {
                    "input_tokens": {"p50": 10000, "p90": 20000},
                    "output_tokens": {"p50": 2000, "p90": 5000},
                },
            }
        )
        self.assertEqual(10000, report["metrics"]["input_tokens"]["p50"])
        self.assertEqual(5000, report["metrics"]["output_tokens"]["p90"])
        self.assertEqual(12000, report["resources"]["tokens"]["total"]["p50"])
        self.assertEqual(25000, report["resources"]["tokens"]["total"]["p90"])
        self.assertFalse(report["pilot_required"])

    def test_complete_known_small_task_is_not_server_first(self) -> None:
        report = estimator.estimate_task(
            {
                "job_id": "small",
                "resources": {
                    "input_gib": 0.1,
                    "download_gib": 0,
                    "environment_gib": 0.1,
                    "temporary_gib": 0.1,
                    "cache_gib": 0.1,
                    "output_gib": 0.1,
                    "cpu_cores": 2,
                    "ram_gib": 2,
                    "gpu_count": 0,
                    "vram_gib": 0,
                    "runtime_minutes": 2,
                },
            }
        )
        self.assertFalse(report["server_first"])
        self.assertFalse(report["pilot_required"])
        self.assertEqual([], report["storage"]["unknown_components"])

    def test_large_and_gpu_task_triggers_server_first_reasons(self) -> None:
        report = estimator.estimate_task(
            {
                "job_id": "train",
                "resources": {
                    "download_gib": 2,
                    "environment_gib": 1,
                    "temporary_gib": 2,
                    "cache_gib": 1,
                    "output_gib": 1,
                    "input_gib": 1,
                    "cpu_cores": 8,
                    "ram_gib": 32,
                    "gpu_count": 1,
                    "vram_gib": 20,
                    "runtime_minutes": 30,
                },
            }
        )
        self.assertTrue(report["server_first"])
        self.assertIn("runtime_p50_over_10_minutes", report["server_first_reasons"])
        self.assertIn("gpu_is_useful", report["server_first_reasons"])
        self.assertIn("download_over_1_gib", report["server_first_reasons"])

    def test_manifest_is_bounded_metadata_only_and_used_when_complete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "a.txt").write_text("1234", encoding="utf-8")
            (root / "nested").mkdir()
            (root / "nested" / "b.bin").write_bytes(b"x" * 8)
            manifest = estimator.build_light_manifest(root, max_files=10, max_depth=3)
            self.assertEqual(2, manifest["file_count"])
            self.assertEqual(12, manifest["total_bytes"])
            self.assertFalse(manifest["truncated"])
            report = estimator.estimate_task({"job_id": "manifest"}, manifest=manifest)
            self.assertEqual(12 / 1024**3, report["metrics"]["input_gib"]["p50"])
            self.assertEqual("bounded_manifest", report["metrics"]["input_gib"]["source"])
            self.assertIn("file contents not read", manifest["evidence"])

    def test_truncated_manifest_does_not_understate_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for index in range(3):
                (root / f"{index}.bin").write_bytes(b"x" * 10)
            manifest = estimator.build_light_manifest(root, max_files=1)
            self.assertTrue(manifest["truncated"])
            report = estimator.estimate_task({"job_id": "partial"}, manifest=manifest)
            self.assertIsNone(report["metrics"]["input_gib"]["p50"])

    def test_cli_reads_fake_task_and_repo_without_provider(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            task_path = root / "task.json"
            output_path = root / "report.json"
            task_path.write_text(
                json.dumps(
                    {
                        "job_id": "cli",
                        "description": "bounded metadata test",
                        "resources": {
                            "cpu_cores": 1,
                            "ram_gib": 1,
                            "runtime_minutes": 1,
                        },
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                0,
                estimator.main(
                    [
                        "--task",
                        str(task_path),
                        "--repo-root",
                        str(root),
                        "--output",
                        str(output_path),
                    ]
                ),
            )
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertTrue(payload["read_only"])
            self.assertFalse(payload["provider_prompts_sent"])
            self.assertFalse(payload["project_executed"])
            self.assertEqual("cli", payload["task"]["task_id"])
            self.assertTrue(payload["task"]["description_sha256"])


if __name__ == "__main__":
    unittest.main()
