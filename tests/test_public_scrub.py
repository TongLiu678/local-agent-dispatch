from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
REDACTION_FIXTURE = ROOT / "tests" / "fixtures" / "redaction" / "public_scrub_private.txt"
SPEC = importlib.util.spec_from_file_location(
    "public_scrub", ROOT / "scripts" / "public_scrub.py"
)
assert SPEC and SPEC.loader
SCRUB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCRUB)


def git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout.strip()


class PublicScrubTests(unittest.TestCase):
    def make_repo(self, root: pathlib.Path) -> None:
        git(root, "init", "-q")
        git(root, "config", "user.name", "Test")
        git(root, "config", "user.email", "test@example.invalid")
        (root / "README.md").write_text("public placeholder /Users/...\n", encoding="utf-8")
        git(root, "add", "README.md")
        git(root, "commit", "-qm", "initial")

    @staticmethod
    def fixture_text() -> str:
        return REDACTION_FIXTURE.read_text(encoding="utf-8")

    @classmethod
    def fixture_line_for(cls, category: str) -> str:
        pattern = dict(SCRUB._RULES)[category]
        for line in cls.fixture_text().splitlines():
            if pattern.search(line):
                return line
        raise AssertionError(f"missing redaction fixture category: {category}")

    @staticmethod
    def private_topology_lines() -> list[str]:
        posix = lambda *parts: "/" + "/".join(parts)
        windows = "C:" + "\\" + "Users" + "\\" + "alice" + "\\" + "work"
        dotted = lambda *parts: ".".join(str(part) for part in parts)
        return [
            posix("Users", "alice", "work") + "/",
            posix("home", "alice", "work") + "/",
            windows + "\\",
            posix("root", "private-project") + "/",
            posix("data", "alice", "project"),
            posix("srv", "internal-team", "project"),
            posix("var", "tmp", "lad-live-preflight-20260922.json"),
            dotted(10, 23, 4, 5),
            dotted(172, 20, 4, 5),
            dotted(192, 168, 4, 5),
            dotted(100, 100, 4, 5),
            "builder" + ".internal",
            "laptop" + ".tail123.ts.net",
        ]

    def test_private_content_blocks_without_persisting_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            (repo / "config.txt").write_text(
                self.fixture_text(),
                encoding="utf-8",
            )
            git(repo, "add", "config.txt")
            git(repo, "commit", "-qm", "private fixture")
            report = SCRUB.build_report(repo)
            self.assertEqual("blocked", report["gate"])
            self.assertGreaterEqual(report["blocking_finding_count"], 2)
            self.assertFalse(report["matched_text_persisted"])
            rendered = json.dumps(report)
            for fixture_line in self.fixture_text().splitlines():
                self.assertNotIn(fixture_line, rendered)

    def test_explicit_fixture_allowlist_is_visible_but_nonblocking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            fixture = repo / "fixtures" / "redaction" / "config.txt"
            fixture.parent.mkdir(parents=True)
            fixture.write_text(self.fixture_text(), encoding="utf-8")
            git(repo, "add", "fixtures/redaction/config.txt")
            git(repo, "commit", "-qm", "fixture")
            report = SCRUB.build_report(
                repo, allow_path_prefixes=["fixtures/redaction"]
            )
            self.assertEqual("pass", report["gate"])
            self.assertEqual(0, report["blocking_finding_count"])
            self.assertGreater(report["allowlisted_finding_count"], 0)
            self.assertTrue(all(row["allowlisted"] for row in report["findings"]))

    def test_private_paths_topology_and_internal_hosts_are_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            private_lines = self.private_topology_lines()
            (repo / "config.txt").write_text(
                "\n".join(private_lines) + "\n", encoding="utf-8"
            )
            git(repo, "add", "config.txt")
            git(repo, "commit", "-qm", "private topology")
            report = SCRUB.build_report(repo)
            categories = {row["category"] for row in report["findings"]}
            self.assertEqual("blocked", report["gate"])
            self.assertTrue(
                {
                    "private_home_path",
                    "private_cluster_path",
                    "private_ip",
                    "internal_hostname",
                }.issubset(categories)
            )
            rendered = json.dumps(report)
            for private_value in private_lines:
                self.assertNotIn(private_value, rendered)

    def test_generic_public_examples_do_not_create_topology_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            posix = lambda *parts: "/" + "/".join(parts)
            public_address = ".".join(str(part) for part in (203, 0, 113, 9))
            (repo / "examples.txt").write_text(
                "\n".join(
                    [
                        posix("data", "PROJECT", "work"),
                        posix("data", "<project>", "work"),
                        posix("srv", "project", "work"),
                        posix("var", "tmp", "lad-controller", "dispatch.sqlite3"),
                        posix("home", "user", "work") + "/",
                        public_address,
                        "example.invalid",
                        "fake" + ".local",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            git(repo, "add", "examples.txt")
            git(repo, "commit", "-qm", "public examples")
            report = SCRUB.build_report(repo)
            self.assertEqual("pass", report["gate"])
            self.assertEqual([], report["findings"])

    def test_exact_export_placeholders_do_not_create_path_findings(self) -> None:
        examples = (
            "/data/EXAMPLE_001/work",
            "/srv/EXAMPLE_002/work",
            "/var/tmp/EXAMPLE_003/work",
            "/root/EXAMPLE_004/work",
            "/Users/EXAMPLE_001/work",
            "C:\\Users\\EXAMPLE_002\\work",
            "/srv/LAD_TEST_TMP/work",
        )
        self.assertTrue(
            all(not SCRUB._semantic_categories(line) for line in examples)
        )

    def test_export_placeholder_lookalikes_remain_private(self) -> None:
        lookalikes = (
            "/data/" + "EXAMPLE_" + "005/work",
            "/srv/" + "example_001/work",
            "/root/" + "LAD_TEST_TMP_2/work",
        )
        for line in lookalikes:
            with self.subTest(line=line):
                self.assertTrue(SCRUB._semantic_categories(line))

    def test_topology_findings_can_only_be_allowlisted_under_fixture_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            fixture = repo / "tests" / "fixtures" / "topology" / "private.txt"
            fixture.parent.mkdir(parents=True)
            fixture.write_text(
                "\n".join(self.private_topology_lines()) + "\n", encoding="utf-8"
            )
            git(repo, "add", "tests/fixtures/topology/private.txt")
            git(repo, "commit", "-qm", "synthetic topology")
            report = SCRUB.build_report(
                repo, allow_path_prefixes=["tests/fixtures/topology"]
            )
            self.assertEqual("pass", report["gate"])
            self.assertGreater(report["allowlisted_finding_count"], 0)
            self.assertTrue(all(row["allowlisted"] for row in report["findings"]))
            with self.assertRaisesRegex(ValueError, "synthetic fixture root"):
                SCRUB.build_report(repo, allow_path_prefixes=["docs"])

    def test_denied_path_remains_blocking_when_allowlisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            denied = repo / "tests" / "fixtures" / "runtime-state" / "auth.json"
            denied.parent.mkdir(parents=True)
            denied.write_text("fixture", encoding="utf-8")
            git(repo, "add", "tests/fixtures/runtime-state/auth.json")
            git(repo, "commit", "-qm", "runtime state")
            report = SCRUB.build_report(
                repo, allow_path_prefixes=["tests/fixtures/runtime-state"]
            )
            self.assertEqual("blocked", report["gate"])
            self.assertEqual(1, report["blocking_finding_count"])
            self.assertEqual("denied_path", report["findings"][0]["category"])
            self.assertFalse(report["findings"][0]["allowlisted"])

    def test_runtime_evidence_artifact_paths_are_denied_without_reading_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            evidence = repo / "attempt-receipts" / "result.json"
            evidence.parent.mkdir()
            evidence.write_text("not inspected", encoding="utf-8")
            git(repo, "add", "attempt-receipts/result.json")
            git(repo, "commit", "-qm", "runtime evidence")
            report = SCRUB.build_report(repo)
            self.assertEqual("blocked", report["gate"])
            self.assertEqual("denied_path", report["findings"][0]["category"])

    def test_ignored_worktree_path_is_reported_without_reading_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            (repo / "ignored-cache").mkdir()
            (repo / ".gitignore").write_text("ignored-cache/\n", encoding="utf-8")
            git(repo, "add", ".gitignore")
            git(repo, "commit", "-qm", "ignore cache")
            (repo / "ignored-cache" / "secret.txt").write_text(
                "must not be read", encoding="utf-8"
            )
            report = SCRUB.build_report(repo, include_worktree=True)
            ignored = [
                row for row in report["findings"] if row["category"] == "ignored_path"
            ]
            self.assertEqual(
                ["ignored-cache/secret.txt"], [row["path"] for row in ignored]
            )
            self.assertEqual("blocked", report["gate"])
            self.assertEqual(1, report["blocking_finding_count"])

    def test_denied_path_is_blocked_even_without_reading_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            (repo / "server-home").mkdir()
            (repo / "server-home" / "auth.json").write_text("private", encoding="utf-8")
            git(repo, "add", "server-home/auth.json")
            git(repo, "commit", "-qm", "runtime")
            report = SCRUB.build_report(repo)
            self.assertEqual("blocked", report["gate"])
            self.assertEqual("denied_path", report["findings"][0]["category"])

    def test_sensitive_key_home_and_ssh_variants_are_detected_without_echo(self) -> None:
        private_lines = self.fixture_text().splitlines()
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            (repo / "sensitive.txt").write_text(
                "\n".join(private_lines) + "\n", encoding="utf-8"
            )
            git(repo, "add", "sensitive.txt")
            git(repo, "commit", "-qm", "sensitive variants")

            report = SCRUB.build_report(repo)

        categories = {finding["category"] for finding in report["findings"]}
        self.assertTrue(
            {"private_key", "private_home_path", "ssh_endpoint"}.issubset(categories)
        )
        rendered = json.dumps(report)
        for private_line in private_lines:
            self.assertNotIn(private_line, rendered)
        harmless = "Use SSH for access; email support@example.com"
        harmless_categories = SCRUB._semantic_categories(harmless)
        for category, pattern in SCRUB._RULES:
            if pattern.search(harmless):
                harmless_categories.add(category)
        self.assertNotIn("ssh_endpoint", harmless_categories)

    def test_git_modes_ref_validation_and_promisor_gate(self) -> None:
        legacy = SCRUB._git_prefix((2, 27, 0))
        modern = SCRUB._git_prefix((2, 45, 0))
        self.assertNotIn("--no-lazy-fetch", legacy)
        self.assertIn("--no-lazy-fetch", modern)
        for prefix in (legacy, modern):
            self.assertTrue(pathlib.Path(prefix[0]).is_absolute())
            self.assertIn("--no-replace-objects", prefix)
            self.assertIn("--no-optional-locks", prefix)
            self.assertIn("core.fsmonitor=", prefix)

        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            with mock.patch.object(
                SCRUB, "_require_git_version", return_value=(2, 27, 0)
            ):
                legacy_report = SCRUB.build_report(repo)
            self.assertEqual("pass", legacy_report["gate"])

            with self.assertRaisesRegex(ValueError, "invalid_ref"):
                SCRUB.build_report(repo, ref="--help")

            git(repo, "config", "remote.origin.url", "lad-sentinel::payload")
            git(repo, "config", "remote.origin.promisor", "true")
            with mock.patch.object(
                SCRUB, "_require_git_version", return_value=(2, 27, 0)
            ), mock.patch.object(SCRUB, "_resolve_commit") as resolve_commit:
                with self.assertRaisesRegex(ValueError, "unsupported_promisor_repository"):
                    SCRUB.build_report(repo)
            resolve_commit.assert_not_called()

    def test_git_environment_and_discovery_ignore_ambient_injection(self) -> None:
        real_git = pathlib.Path(SCRUB._git_executable())
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            fake_git = repo / ("git.exe" if os.name == "nt" else "git")
            fake_git.write_text("not an executable Git", encoding="utf-8")
            fake_git.chmod(0o755)
            trace = repo / "ambient-trace"
            redirect = repo / "ambient-redirect"
            ambient = {
                "PATH": "." + os.pathsep + os.pathsep + str(real_git.parent),
                "GIT_DIR": str(repo / "wrong.git"),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.fsmonitor",
                "GIT_CONFIG_VALUE_0": "malicious-command",
                "GIT_TRACE": str(trace),
                "GIT_REDIRECT_STDOUT": str(redirect),
            }
            previous = pathlib.Path.cwd()
            try:
                os.chdir(repo)
                with mock.patch.dict(os.environ, ambient, clear=False):
                    discovered = pathlib.Path(SCRUB._git_executable())
                    child_environment = SCRUB._git_environment()
                    report = SCRUB.build_report(repo)
            finally:
                os.chdir(previous)

        self.assertTrue(discovered.samefile(real_git))
        self.assertEqual(os.devnull, child_environment["PATH"])
        self.assertEqual(os.devnull, child_environment["GIT_EXEC_PATH"])
        self.assertEqual("pass", report["gate"])
        self.assertIsNotNone(report["source_commit"])
        self.assertFalse(trace.exists())
        self.assertFalse(redirect.exists())

    def test_replace_object_cannot_change_scanned_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            public_commit = git(repo, "rev-parse", "HEAD")
            (repo / "private.txt").write_text(
                self.fixture_line_for("private_key") + "\n", encoding="utf-8"
            )
            git(repo, "add", "private.txt")
            git(repo, "commit", "-qm", "private replacement")
            private_commit = git(repo, "rev-parse", "HEAD")
            git(repo, "replace", public_commit, private_commit)

            report = SCRUB.build_report(repo, ref=public_commit)

        self.assertEqual("pass", report["gate"])
        self.assertEqual(public_commit, report["source_commit"])
        self.assertFalse(any(row["path"] == "private.txt" for row in report["findings"]))

    def test_oversized_ref_and_worktree_file_are_skipped_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            large = repo / "large.txt"
            large.write_bytes(b"x" * 101)
            invalid_utf8 = repo / "invalid-utf8.txt"
            invalid_utf8.write_bytes(b"\xff")
            git(repo, "add", "large.txt", "invalid-utf8.txt")
            git(repo, "commit", "-qm", "large")

            with mock.patch.object(SCRUB, "_ref_blob", wraps=SCRUB._ref_blob) as ref_blob:
                ref_report = SCRUB.build_report(repo, max_file_bytes=100)
            self.assertTrue(
                any(
                    row["path"] == "large.txt" and row["reason"] == "file_too_large"
                    for row in ref_report["skipped"]
                )
            )
            self.assertTrue(
                any(
                    row["path"] == "invalid-utf8.txt"
                    and row["reason"] == "invalid_utf8"
                    for row in ref_report["skipped"]
                )
            )
            self.assertTrue(all(call.args[2] <= 100 for call in ref_blob.call_args_list))

            with mock.patch.object(SCRUB.os, "open", wraps=os.open) as opened:
                worktree_report = SCRUB.build_report(
                    repo, include_worktree=True, max_file_bytes=100
                )
            self.assertTrue(
                any(
                    row["path"] == "large.txt" and row["reason"] == "file_too_large"
                    for row in worktree_report["skipped"]
                )
            )
            self.assertTrue(
                all(pathlib.Path(call.args[0]) != large for call in opened.call_args_list)
            )

    def test_path_validation_errors_do_not_echo_rejected_input(self) -> None:
        rejected = "../private-path-should-not-echo"
        with self.assertRaises(ValueError) as caught:
            SCRUB._safe_relative(rejected)
        self.assertNotIn(rejected, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
