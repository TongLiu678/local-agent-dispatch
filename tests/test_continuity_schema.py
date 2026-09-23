from __future__ import annotations

import argparse
import json
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import continuity_controller as continuity  # noqa: E402


class ContinuitySchemaTests(unittest.TestCase):
    def test_save_state_backfills_schema_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = pathlib.Path(tmp)
            continuity.save_state(run_dir, {"jobs": []})
            payload = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(1, payload["schema_version"])

    def test_enqueue_backfills_task_packet_schema_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            run_dir = root / "run"
            run_dir.mkdir()
            continuity.atomic_write(
                run_dir / "state.json",
                {"schema_version": 1, "jobs": [], "workspace": str(root)},
            )
            job_file = root / "job.json"
            job_file.write_text(
                json.dumps({"job_id": "job-1", "legacy_compatibility": True}),
                encoding="utf-8",
            )
            args = argparse.Namespace(run_dir=str(run_dir), job_file=str(job_file))
            self.assertEqual(0, continuity.command_enqueue(args))
            payload = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(1, payload["jobs"][0]["schema_version"])
            self.assertEqual("legacy", payload["jobs"][0]["packet_validation"]["mode"])

    def test_modern_enqueue_rejects_packet_without_attempts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            run_dir = root / "run"
            run_dir.mkdir()
            continuity.atomic_write(
                run_dir / "state.json",
                {"schema_version": 1, "jobs": [], "workspace": str(root)},
            )
            job_file = root / "job.json"
            job_file.write_text(
                json.dumps({
                    "schema_version": 1,
                    "packet_id": "packet-bad",
                    "job_id": "bad",
                    "write_scope": "artifacts/bad",
                    "validation_required": True,
                    "required_artifacts": ["out.txt"],
                }),
                encoding="utf-8",
            )
            args = argparse.Namespace(run_dir=str(run_dir), job_file=str(job_file))
            with self.assertRaisesRegex(ValueError, "non-empty attempts"):
                continuity._command_enqueue_unlocked(args)
            payload = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
            self.assertEqual([], payload["jobs"])

    def test_modern_enqueue_rejects_secret_like_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            run_dir = root / "run"
            run_dir.mkdir()
            continuity.atomic_write(
                run_dir / "state.json",
                {"schema_version": 1, "jobs": [], "workspace": str(root)},
            )
            job_file = root / "job.json"
            job_file.write_text(
                json.dumps({
                    "schema_version": 1,
                    "packet_id": "packet-secret",
                    "job_id": "secret",
                    "write_scope": "artifacts/secret",
                    "validation_required": True,
                    "validation_argv": ["python3", "-c", "pass"],
                    "required_artifacts": ["out.txt"],
                    "api_key": "should-never-be-queued",
                    "attempts": [{
                        "attempt_id": "attempt-secret",
                        "adapter": "command",
                        "transport": "local",
                        "model": "gpt-5.3-codex-spark",
                        "argv": ["python3", "-c", "pass"],
                    }],
                }),
                encoding="utf-8",
            )
            args = argparse.Namespace(run_dir=str(run_dir), job_file=str(job_file))
            with self.assertRaisesRegex(ValueError, "schema validation failed"):
                continuity._command_enqueue_unlocked(args)


if __name__ == "__main__":
    unittest.main()
