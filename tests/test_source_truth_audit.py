from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PUBLIC_STATUS = ROOT / "docs" / "status.md"
SPEC = importlib.util.spec_from_file_location(
    "source_truth_audit", ROOT / "scripts" / "source_truth_audit.py"
)
assert SPEC and SPEC.loader
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


class SourceTruthAuditTests(unittest.TestCase):
    def make_repo(self, root: pathlib.Path) -> None:
        git(root, "init", "-q")
        git(root, "config", "user.name", "Test")
        git(root, "config", "user.email", "test@example.invalid")
        (root / "src").mkdir()
        (root / "src" / "app.py").write_text("print('v1')\n", encoding="utf-8")
        (root / ".gitignore").write_text(".hermes/\nruns/\n", encoding="utf-8")
        git(root, "add", "src/app.py", ".gitignore")
        git(root, "commit", "-qm", "initial")

    def test_report_is_stable_and_records_public_changes(self) -> None:
        self.assertTrue(
            PUBLIC_STATUS.is_file(),
            "the current public status must exist outside private run history",
        )
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            (repo / "src" / "app.py").write_text("print('v2')\n", encoding="utf-8")
            (repo / "README.md").write_text("alpha\n", encoding="utf-8")
            public_status = repo / "docs" / PUBLIC_STATUS.name
            public_status.parent.mkdir(parents=True)
            public_status.write_text("# current public status\n", encoding="utf-8")
            first = AUDIT.build_report(repo)
            second = AUDIT.build_report(repo)
            self.assertEqual(first, second)
            by_path = {row["path"]: row for row in first["files"]}
            self.assertEqual("modified", by_path["src/app.py"]["status"])
            self.assertEqual("untracked", by_path["README.md"]["status"])
            self.assertEqual(64, len(by_path["README.md"]["sha256"]))
            self.assertEqual(
                "untracked",
                by_path["docs/status.md"]["status"],
            )
            self.assertEqual([], first["denied_candidates"])

    def test_denied_paths_are_named_but_never_hashed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            (repo / ".hermes").mkdir()
            (repo / ".hermes" / "plan.md").write_text("private", encoding="utf-8")
            (repo / "runtime-state.json").write_text("secret", encoding="utf-8")
            (repo / "server-home").mkdir()
            (repo / "server-home" / "opencode.db").write_text("runtime", encoding="utf-8")
            (repo / "downloads").mkdir()
            (repo / "downloads" / "model.bin").write_text("bulk", encoding="utf-8")
            (repo / "build").mkdir()
            (repo / "build" / "wheel.txt").write_text("generated", encoding="utf-8")
            (repo / "src" / "local_agent_dispatch.egg-info").mkdir()
            (repo / "src" / "local_agent_dispatch.egg-info" / "PKG-INFO").write_text(
                "generated", encoding="utf-8"
            )
            (repo / ".pytest_cache").mkdir()
            (repo / ".pytest_cache" / "CACHEDIR.TAG").write_text(
                "generated", encoding="utf-8"
            )
            report = AUDIT.build_report(
                repo,
                extra_candidates=[
                    ".hermes/plan.md",
                    "runtime-state.json",
                    "server-home/opencode.db",
                    "downloads/model.bin",
                    "build/wheel.txt",
                    "src/local_agent_dispatch.egg-info/PKG-INFO",
                    ".pytest_cache/CACHEDIR.TAG",
                    "opencode-context-snapshot.json",
                    "m0-report.json",
                ],
            )
            self.assertEqual([], report["files"])
            self.assertEqual(
                [
                    ".hermes/plan.md",
                    ".pytest_cache",
                    ".pytest_cache/CACHEDIR.TAG",
                    "build",
                    "build/wheel.txt",
                    "downloads",
                    "downloads/model.bin",
                    "m0-report.json",
                    "opencode-context-snapshot.json",
                    "runtime-state.json",
                    "server-home",
                    "server-home/opencode.db",
                    "src/local_agent_dispatch.egg-info",
                    "src/local_agent_dispatch.egg-info/PKG-INFO",
                ],
                [row["path"] for row in report["denied_candidates"]],
            )
            self.assertTrue(all("sha256" not in row for row in report["denied_candidates"]))

    def test_runner_prompt_and_summary_artifacts_are_denied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            (repo / "task-prompt.md").write_text("lane task packet\n", encoding="utf-8")
            (repo / "runner-summary.json").write_text("{}\n", encoding="utf-8")
            (repo / "._README.md").write_bytes(b"\x00junk")
            report = AUDIT.build_report(repo)
            self.assertEqual([], report["files"])
            self.assertEqual(
                ["._README.md", "runner-summary.json", "task-prompt.md"],
                [row["path"] for row in report["denied_candidates"]],
            )
            self.assertTrue(
                all("sha256" not in row for row in report["denied_candidates"])
            )

    def test_shipped_gitignore_covers_lane_runner_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            (repo / ".gitignore").write_text(
                (ROOT / ".gitignore").read_text(encoding="utf-8"), encoding="utf-8"
            )
            git(repo, "add", ".gitignore")
            for name in ("task-prompt.md", "runner-summary.json", "._README.md"):
                (repo / name).write_text("synthetic ignored artifact\n", encoding="utf-8")
            # Git 1.7 on the PBS compute nodes predates ``check-ignore``.
            # The source-of-truth check only needs to prove that the shipped
            # patterns cover these generated names, so inspect the text
            # directly and keep this test portable across the node images.
            gitignore = (repo / ".gitignore").read_text(encoding="utf-8")
            self.assertIn("task-prompt*.md", gitignore)
            self.assertIn("runner-summary*.json", gitignore)
            self.assertIn("._*", gitignore)

    def test_report_records_unreconciled_public_head_without_mutating_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            local_head = git(repo, "rev-parse", "HEAD")
            report = AUDIT.build_report(
                repo,
                public_ref="v0.1.0-alpha.4",
                public_head="0000000000000000000000000000000000000000",
            )
            self.assertEqual(local_head, report["local_head"])
            self.assertEqual("diverged_unreconciled", report["canonical_state"])
            self.assertFalse(report["working_tree_dirty"])
            self.assertTrue(report["read_only"])

    def test_annotated_public_tag_is_peeled_and_proves_alignment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            commit = git(repo, "rev-parse", "HEAD")
            git(repo, "tag", "-a", "v0.1.0-alpha.4", "-m", "alpha release")
            tag_object = git(repo, "rev-parse", "v0.1.0-alpha.4")
            self.assertNotEqual(tag_object, commit)
            report = AUDIT.build_report(repo, public_ref="v0.1.0-alpha.4")
            self.assertEqual("aligned", report["canonical_state"])
            self.assertEqual("ref_peeled", report["public_head_source"])
            self.assertEqual(commit, report["public_head"])
            self.assertEqual(commit, report["local_head"])
            self.assertTrue(report["read_only"])

    def test_missing_public_ref_stays_unresolved_without_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            report = AUDIT.build_report(repo, public_ref="v9.9.9-does-not-exist")
            self.assertEqual("public_ref_unresolved", report["canonical_state"])
            self.assertIsNone(report["public_head"])
            self.assertIsNone(report["public_head_source"])
            self.assertEqual("v9.9.9-does-not-exist", report["public_ref"])

    def test_required_public_ref_fails_closed_when_missing_or_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            with self.assertRaisesRegex(ValueError, "public_ref is required"):
                AUDIT.build_report(repo, require_public_ref=True)
            with self.assertRaisesRegex(ValueError, "could not be resolved"):
                AUDIT.build_report(
                    repo,
                    public_ref="public-v9.9.9-alpha.4",
                    require_public_ref=True,
                )

    def test_actual_public_release_ref_is_reconciled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            public_head = git(repo, "rev-parse", "HEAD")
            (repo / "src" / "app.py").write_text(
                "print('research')\n", encoding="utf-8"
            )
            git(repo, "add", "src/app.py")
            git(repo, "commit", "-qm", "research follow-up")
            git(repo, "tag", "public-v0.1.0-alpha.4", public_head)
            report = AUDIT.build_report(
                repo,
                public_ref="public-v0.1.0-alpha.4",
                require_public_ref=True,
                require_reconciled=True,
            )
            self.assertEqual("ancestry_reconciled", report["canonical_state"])
            self.assertEqual(public_head, report["public_head"])

    def test_reconciled_gate_rejects_unrelated_public_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            # Compute nodes still run Git 1.7, which predates
            # ``checkout --orphan``.  ``commit-tree`` creates an unrelated
            # root commit without relying on newer checkout flags.
            tree = git(repo, "write-tree")
            public_head = subprocess.run(
                ["git", "commit-tree", tree],
                cwd=repo,
                check=True,
                input="unrelated\n",
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout.strip()
            (repo / "src" / "app.py").write_text("print('research')\n", encoding="utf-8")
            git(repo, "add", "src/app.py")
            git(repo, "commit", "-qm", "research follow-up")
            git(repo, "tag", "public-v0.1.0-alpha.4", public_head)
            with self.assertRaisesRegex(ValueError, "not reconciled"):
                AUDIT.build_report(
                    repo,
                    public_ref="public-v0.1.0-alpha.4",
                    require_public_ref=True,
                    require_reconciled=True,
                )

    def test_operator_supplied_public_head_is_not_overridden_by_peeling(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            git(repo, "tag", "-a", "v0.1.0", "-m", "tag")
            report = AUDIT.build_report(
                repo,
                public_ref="v0.1.0",
                public_head="0" * 40,
            )
            self.assertEqual("diverged_unreconciled", report["canonical_state"])
            self.assertEqual("operator_supplied", report["public_head_source"])

    def test_public_ancestor_is_reported_as_reconciled_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            public_head = git(repo, "rev-parse", "HEAD")
            (repo / "src" / "app.py").write_text("print('research')\n", encoding="utf-8")
            git(repo, "add", "src/app.py")
            git(repo, "commit", "-qm", "research follow-up")
            report = AUDIT.build_report(repo, public_head=public_head)
            self.assertEqual("ancestry_reconciled", report["canonical_state"])
            self.assertEqual("public_is_ancestor", report["public_head_relationship"])

    def test_report_includes_verifiable_self_digest_and_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            (repo / "src" / "app.py").write_text("print('v2')\n", encoding="utf-8")
            first = AUDIT.build_report(repo)
            second = AUDIT.build_report(repo)
            self.assertEqual(first, second)
            self.assertEqual(64, len(first["report_sha256"]))
            payload = {
                key: value for key, value in first.items() if key != "report_sha256"
            }
            canonical = json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            self.assertEqual(
                hashlib.sha256(canonical).hexdigest(), first["report_sha256"]
            )

    def test_absolute_and_parent_paths_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            self.make_repo(repo)
            with self.assertRaises(ValueError):
                AUDIT.build_report(repo, extra_candidates=["../outside"])
            with self.assertRaises(ValueError):
                AUDIT.build_report(repo, extra_candidates=["/private/file"])


if __name__ == "__main__":
    unittest.main()
