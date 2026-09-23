from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m0_baseline_runner", ROOT / "scripts" / "m0_baseline_runner.py"
)
assert SPEC and SPEC.loader
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


class M0BaselineRunnerTests(unittest.TestCase):
    def make_repo(self, root: pathlib.Path) -> None:
        git(root, "init", "-q")
        git(root, "config", "user.name", "Test")
        git(root, "config", "user.email", "test@example.invalid")
        (root / "fixture.json").write_text('{"stable": true}\n', encoding="utf-8")
        git(root, "add", "fixture.json")
        git(root, "commit", "-qm", "initial")

    def test_two_stable_runs_produce_a_pass_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            command = [sys.executable, "-c", "print('stable')"]
            first = RUNNER.build_report(repo, command, fixture_paths=["fixture.json"])
            second = RUNNER.build_report(repo, command, fixture_paths=["fixture.json"])
            self.assertEqual(first, second)
            self.assertEqual("pass", first["gate"])
            self.assertTrue(first["byte_stable"])
            self.assertFalse(first["provider_execution"])
            self.assertEqual(64, len(first["report_sha256"]))

    def test_dirty_workspace_is_a_block_when_required_clean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            (repo / "fixture.json").write_text("changed\n", encoding="utf-8")
            report = RUNNER.build_report(
                repo,
                [sys.executable, "-c", "print('stable')"],
                require_clean=True,
            )
            self.assertEqual("blocked", report["gate"])
            self.assertIn("workspace_was_dirty", report["blocking_reasons"])

    def test_workspace_mutation_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            command = [
                sys.executable,
                "-c",
                "from pathlib import Path; Path('fixture.json').write_text('x\\n')",
            ]
            report = RUNNER.build_report(repo, command)
            self.assertEqual("blocked", report["gate"])
            self.assertIn("command_mutated_workspace", report["blocking_reasons"])

    def test_provider_and_shell_commands_are_rejected(self) -> None:
        for command in (["opencode", "run"], ["sh", "-c", "true"], ["curl", "https://example.invalid"]):
            with self.assertRaises(ValueError):
                RUNNER.validate_command(command)

    def test_only_declared_harness_metadata_is_normalized(self) -> None:
        first = (
            b'{"created_at":"2026-08-12T10:00:00.123Z",'
            b'"project_root":"/private/var/folders/a/b/T/tmpone",'
            b'"packet_digest":"' + b"a" * 64 + b'"}\n'
        )
        second = (
            b'{"created_at":"2026-08-12T10:01:00.456Z",'
            b'"project_root":"/private/var/folders/c/d/T/tmptwo",'
            b'"packet_digest":"' + b"b" * 64 + b'"}\n'
        )
        self.assertEqual(RUNNER._stable_output(first), RUNNER._stable_output(second))

    def test_remote_harness_temp_paths_are_normalized(self) -> None:
        first = b'"project_root":"/srv/LAD_TEST_TMP/tmpone"\n'
        second = b'"project_root":"/srv/LAD_TEST_TMP/tmptwo"\n'
        self.assertEqual(RUNNER._stable_output(first), RUNNER._stable_output(second))

    def test_monitor_loop_timing_is_normalized_but_other_numbers_are_not(self) -> None:
        first = (
            b'{"loop_elapsed_seconds":0.125,'
            b'"loop_remaining_seconds":0.875,"ticks":1}\n'
        )
        second = (
            b'{"loop_elapsed_seconds":0.236,'
            b'"loop_remaining_seconds":0.764,"ticks":2}\n'
        )
        first_stable = RUNNER._stable_output(first)
        second_stable = RUNNER._stable_output(second)
        self.assertNotEqual(first_stable, second_stable)
        self.assertIn(b'"ticks":1', first_stable)
        self.assertIn(b'"ticks":2', second_stable)
        self.assertIn(b'"loop_elapsed_seconds":<runtime>', first_stable)
        self.assertIn(b'"loop_remaining_seconds":<runtime>', second_stable)

    def test_secret_environment_is_not_forwarded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            old = os.environ.get("LAD_TEST_API_KEY")
            os.environ["LAD_TEST_API_KEY"] = "synthetic-test-key"
            try:
                report = RUNNER.build_report(
                    repo,
                    [sys.executable, "-c", "import os; print(os.getenv('LAD_TEST_API_KEY'))"],
                )
            finally:
                if old is None:
                    os.environ.pop("LAD_TEST_API_KEY", None)
                else:
                    os.environ["LAD_TEST_API_KEY"] = old
            self.assertEqual("pass", report["gate"])
            self.assertTrue(report["environment_policy"]["credential_like_environment_removed"])


if __name__ == "__main__":
    unittest.main()
