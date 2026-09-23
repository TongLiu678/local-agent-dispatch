from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m0_gate_snapshot", ROOT / "scripts" / "m0_gate_snapshot.py"
)
assert SPEC and SPEC.loader
SNAPSHOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SNAPSHOT)


class M0GateSnapshotTests(unittest.TestCase):
    def test_step_gate_requires_each_contract(self) -> None:
        self.assertEqual(
            "pass",
            SNAPSHOT._step_gate(
                "source_truth",
                {
                    "canonical_state": "ancestry_reconciled",
                    "working_tree_dirty": False,
                    "denied_candidates": [],
                },
            ),
        )
        self.assertEqual("blocked", SNAPSHOT._step_gate("public_scrub", {"gate": "blocked"}))
        self.assertEqual("pass", SNAPSHOT._step_gate("holdout", {"valid": True}))
        self.assertEqual("blocked", SNAPSHOT._step_gate("baseline", {"gate": "blocked"}))

    def test_path_confinement_accepts_relative_and_rejects_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp).resolve()
            self.assertEqual("research/corpus.json", SNAPSHOT._safe_relative(root, "research/corpus.json"))
            with self.assertRaises(ValueError):
                SNAPSHOT._safe_relative(root, "../outside.json")

    def test_run_step_keeps_only_digests_when_output_is_not_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            step = SNAPSHOT._run_step(
                root,
                "fake",
                [sys.executable, "-c", "print('not-json')"],
                5,
            )
            self.assertEqual("invalid_output", step["status"])
            self.assertIsNone(step["report"])
            self.assertEqual(64, len(step["stdout_sha256"]))
            self.assertNotIn("not-json", json.dumps(step))

    def test_skip_baseline_produces_read_only_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "scripts").mkdir()
            report = SNAPSHOT.build_report(root, include_baseline=False)
            self.assertEqual("blocked", report["gate"])
            self.assertEqual(["source_truth", "public_scrub", "holdout"], list(report["gates"]))
            self.assertFalse(report["provider_execution"])
            self.assertFalse(report["network_execution"])
            self.assertTrue(report["read_only"])
            self.assertEqual(64, len(report["report_sha256"]))

    def test_public_scrub_uses_the_configured_public_ref(self) -> None:
        calls: list[tuple[str, list[str]]] = []

        def fake_run_step(
            root: pathlib.Path,
            name: str,
            argv: list[str],
            timeout_seconds: float,
        ) -> dict[str, object]:
            calls.append((name, argv))
            return {"name": name, "gate": "pass"}

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "scripts").mkdir()
            with mock.patch.object(SNAPSHOT, "_run_step", side_effect=fake_run_step):
                SNAPSHOT.build_report(
                    root,
                    public_ref="refs/tags/public-v9",
                    include_baseline=False,
                )

        scrub_argv = next(argv for name, argv in calls if name == "public_scrub")
        ref_index = scrub_argv.index("--ref")
        self.assertEqual("refs/tags/public-v9", scrub_argv[ref_index + 1])


if __name__ == "__main__":
    unittest.main()
