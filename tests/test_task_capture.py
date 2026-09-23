"""Provider-free tests for task capture, DAG normalization, and calibration."""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import task_capture as capture  # noqa: E402


class TaskCaptureTests(unittest.TestCase):
    def test_implicit_capture_is_read_only_and_preserves_unknowns(self) -> None:
        packet = capture.capture_task("audit the repository")
        self.assertTrue(packet["read_only"])
        self.assertFalse(packet["provider_prompts_sent"])
        self.assertFalse(packet["project_executed"])
        self.assertEqual("analysis", packet["task_family"])
        self.assertEqual(["task"], packet["dag"]["topological_order"])
        self.assertTrue(packet["dag"]["valid"])
        self.assertEqual("unknown", packet["estimate"]["metrics"]["runtime_minutes"]["confidence"])
        self.assertEqual("unknown", packet["unknown_semantics"]["missing_resource"])

    def test_explicit_dag_has_parallel_waves_and_stable_order(self) -> None:
        dag = capture.build_dag(
            [
                {"id": "fetch", "description": "download data"},
                {"id": "lint", "description": "run tests"},
                {"id": "report", "description": "build report", "depends_on": ["fetch", "lint"]},
            ]
        )
        self.assertTrue(dag["valid"])
        self.assertEqual([["fetch", "lint"], ["report"]], dag["parallel_waves"])
        self.assertEqual(["fetch", "lint", "report"], dag["topological_order"])
        self.assertEqual(
            [{"from": "fetch", "to": "report"}, {"from": "lint", "to": "report"}],
            dag["edges"],
        )

    def test_obvious_serial_request_is_captured_as_inferred_dag(self) -> None:
        dag = capture.build_dag(description="run tests then build report")
        self.assertEqual("inferred_sequence", dag["source"])
        self.assertEqual(["step-1", "step-2"], dag["topological_order"])
        self.assertEqual([{"from": "step-1", "to": "step-2"}], dag["edges"])
        packet = capture.capture_task({"task_id": "serial", "description": "run tests then build report"})
        self.assertEqual(["serial-step-1", "serial-step-2"], [row["job_id"] for row in packet["planner_jobs"]])
        self.assertEqual(["serial-step-1"], packet["planner_jobs"][1]["depends_on"])

    def test_task_and_planner_ids_are_safe_for_remote_spool_paths(self) -> None:
        packet = capture.capture_task(
            {"task_id": "review/2026:unsafe", "description": "inspect source then report"}
        )
        ids = [row["job_id"] for row in packet["planner_jobs"]]
        self.assertEqual(["review-2026-unsafe-step-1", "review-2026-unsafe-step-2"], ids)
        self.assertTrue(all("/" not in value and ":" not in value for value in ids))

    def test_dag_unknown_dependency_and_cycle_fail_closed(self) -> None:
        unknown = capture.build_dag([{"id": "run", "depends_on": ["missing"]}])
        self.assertFalse(unknown["valid"])
        self.assertEqual("dag_invalid", unknown["gate"])
        self.assertEqual("missing", unknown["unknown_dependencies"][0]["dependency"])

        cycle = capture.build_dag(
            [
                {"id": "a", "depends_on": ["b"]},
                {"id": "b", "depends_on": ["a"]},
            ]
        )
        self.assertFalse(cycle["valid"])
        self.assertEqual(["a", "b"], cycle["cycle_nodes"])
        self.assertEqual([], cycle["topological_order"])

    def test_calibration_filters_exact_bucket_and_computes_bounds_ewma_bias(self) -> None:
        rows = [
            {
                "task_family": "test",
                "model": "codex.spark",
                "host": "remote-a",
                "actual": {"runtime_minutes": 10, "cpu_cores": 4},
                "estimated": {"runtime_minutes": 8, "cpu_cores": 4},
            },
            {
                "task_family": "test",
                "model": "codex.spark",
                "host": "remote-a",
                "actual": {"runtime_minutes": 20, "cpu_cores": 6},
                "estimated": {"runtime_minutes": 10, "cpu_cores": 4},
            },
            {
                "task_family": "test",
                "model": "codex.spark",
                "host": "remote-a",
                "actual": {"runtime_minutes": 30, "cpu_cores": 8},
                "estimated": {"runtime_minutes": 20, "cpu_cores": 4},
            },
            # This row must not leak into the selected host bucket.
            {
                "task_family": "test",
                "model": "codex.spark",
                "host": "remote-b",
                "actual": {"runtime_minutes": 100},
                "estimated": {"runtime_minutes": 10},
            },
        ]
        result = capture.calibrate_history(
            rows,
            task_family="test",
            model="codex.spark",
            host="remote-a",
            alpha=0.5,
            min_observations=3,
        )
        runtime = result["metrics"]["runtime_minutes"]
        self.assertEqual("calibrated", result["status"])
        self.assertEqual(3, result["matched_row_count"])
        self.assertEqual(20, runtime["p50"])
        self.assertEqual(28, runtime["p90"])
        self.assertEqual(22.5, runtime["ewma"])
        self.assertEqual(1.5625, runtime["bias_factor"])
        self.assertEqual("medium", runtime["confidence"])
        # No observations for this metric remain unknown rather than zero.
        self.assertIsNone(result["metrics"]["input_gib"]["p50"])
        self.assertIn("input_gib", result["unknown_metrics"])

    def test_calibration_legacy_metric_arrays_and_pilot_status(self) -> None:
        result = capture.calibrate_history(
            {"runtime_minutes": [2, 4], "cpu_cores": [1, 2]},
            min_observations=3,
        )
        self.assertEqual("pilot", result["status"])
        self.assertEqual(2, result["metrics"]["runtime_minutes"]["observation_count"])
        self.assertEqual(3, result["metrics"]["runtime_minutes"]["p50"])
        self.assertEqual(3.8, result["metrics"]["runtime_minutes"]["p90"])

    def test_apply_calibration_requires_measured_bias(self) -> None:
        estimate = {
            "metrics": {
                "runtime_minutes": {
                    "p50": 10,
                    "p90": 20,
                    "source": "explicit_hint",
                    "evidence": [],
                },
                "ram_gib": {"p50": None, "p90": None, "source": "unknown", "evidence": []},
            }
        }
        calibration = {
            "status": "calibrated",
            "bucket": {"host": "remote-a"},
            "metrics": {
                "runtime_minutes": {"bias_factor": 1.5},
                "ram_gib": {"bias_factor": None},
            },
        }
        adjusted = capture.apply_history_calibration(estimate, calibration)
        self.assertEqual(15, adjusted["metrics"]["runtime_minutes"]["p50"])
        self.assertEqual(30, adjusted["metrics"]["runtime_minutes"]["p90"])
        self.assertEqual("history_calibration", adjusted["metrics"]["runtime_minutes"]["source"])
        self.assertIsNone(adjusted["metrics"]["ram_gib"]["p50"])
        self.assertEqual(["runtime_minutes"], adjusted["calibration"]["applied_metrics"])

    def test_capture_repo_policy_git_and_node_estimates_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "README.md").write_text("metadata only", encoding="utf-8")
            packet = capture.capture_task(
                {
                    "task_id": "repo-task",
                    "description": "run tests then build report",
                    "steps": [
                        {"id": "tests", "description": "run tests", "resources": {"runtime_minutes": 2}},
                        {"id": "report", "description": "build report", "depends_on": ["tests"]},
                    ],
                },
                repo_root=root,
                policy={"write_scope": ["reports/"], "secret": "must-not-be-copied"},
                git_metadata={"branch": "main", "changed_files": ["README.md"], "token": "drop"},
            )
            self.assertEqual("repo-task", packet["task_id"])
            self.assertEqual(1, packet["repository"]["file_count"])
            self.assertEqual(["tests", "report"], packet["dag"]["topological_order"])
            self.assertEqual(2, len(packet["dag"]["nodes"]))
            self.assertEqual(
                ["repo-task-tests", "repo-task-report"],
                [row["job_id"] for row in packet["planner_jobs"]],
            )
            self.assertEqual(["write_scope"], list(packet["policy"]))
            self.assertEqual(["branch", "changed_files"], sorted(packet["git"]))
            self.assertFalse(packet["provider_prompts_sent"])

    def test_external_network_policy_reaches_planner_job(self) -> None:
        packet = capture.capture_task(
            {
                "task_id": "network-task",
                "description": "download a public model",
                "policy": {"requires_external_network": True},
            }
        )
        self.assertTrue(packet["policy"]["requires_external_network"])
        self.assertTrue(packet["planner_jobs"][0]["requires_external_network"])

    def test_cli_emits_json_without_provider_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            task_path = root / "task.json"
            output_path = root / "capture.json"
            task_path.write_text(
                json.dumps({"task_id": "cli-task", "description": "inspect source"}),
                encoding="utf-8",
            )
            self.assertEqual(
                0,
                capture.main(["--task", str(task_path), "--output", str(output_path)]),
            )
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual("cli-task", payload["task_id"])
            self.assertTrue(payload["read_only"])
            self.assertFalse(payload["project_executed"])


if __name__ == "__main__":
    unittest.main()
