"""Provider-free tests for the server-side single-writer Git integrator."""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import unittest

from scripts.server_git_integrator import IntegratorError, ServerGitIntegrator


def git(repo: pathlib.Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def digest(letter: str) -> str:
    return "sha256:" + letter * 64


class ServerGitIntegratorTests(unittest.TestCase):
    def make_repo(self, root: pathlib.Path) -> tuple[str, str]:
        git(root, "init", "-q")
        git(root, "config", "user.name", "Integrator Test")
        git(root, "config", "user.email", "integrator@example.invalid")
        (root / "README.md").write_text("base\n", encoding="utf-8")
        git(root, "add", "README.md")
        git(root, "commit", "-qm", "base")
        git(root, "branch", "-M", "main")
        base = git(root, "rev-parse", "HEAD")
        # Git 2.9 (the version available on the CLUSTER_ROUTE controller) does
        # not yet provide ``git switch``.  The legacy checkout spelling is
        # equivalent here and keeps this provider-free regression portable
        # across the server and local development environments.
        git(root, "checkout", "-q", "-b", "worker")
        (root / "README.md").write_text("candidate\n", encoding="utf-8")
        git(root, "add", "README.md")
        git(root, "commit", "-qm", "candidate")
        candidate = git(root, "rev-parse", "HEAD")
        git(root, "checkout", "-q", "main")
        return base, candidate

    @staticmethod
    def capsule() -> dict[str, object]:
        return {
            "schema_version": 1,
            "project_id": "project-a",
            "workspace_id": "project-a-ws",
            "capsule_generation": 1,
            "capsule_spec_digest": digest("a"),
            "status": "bound",
            "write_scopes": ["src/lane-a"],
        }

    @staticmethod
    def receipts(base: str, candidate: str, *, review: str = "approved") -> tuple[dict[str, object], dict[str, object]]:
        source = digest("b")
        validation = {
            "gate": "pass",
            "source_digest": source,
            "artifact_digest": digest("c"),
            "base_commit": base,
            "candidate_commit": candidate,
            "review_decision": review,
            "prompt": "must never be persisted",
        }
        scrub = {
            "gate": "pass",
            "blocking_finding_count": 0,
            "matched_text_persisted": False,
            "report_sha256": "d" * 64,
        }
        return validation, scrub

    def test_propose_is_safe_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "repo"
            root.mkdir()
            base, candidate = self.make_repo(root)
            spool = pathlib.Path(tmp) / "spool"
            integrator = ServerGitIntegrator(root, proposals_dir=spool)
            validation, scrub = self.receipts(base, candidate)
            first = integrator.propose(
                capsule=self.capsule(),
                source_digest=validation["source_digest"],
                validation_receipt=validation,
                scrub_receipt=scrub,
            )
            second = integrator.propose(
                capsule=self.capsule(),
                source_digest=validation["source_digest"],
                validation_receipt=validation,
                scrub_receipt=scrub,
            )
            self.assertEqual(first["proposal_id"], second["proposal_id"])
            self.assertEqual("proposed", first["status"])
            self.assertEqual(base, git(root, "rev-parse", "HEAD"))
            stored = json.loads((spool / f"{first['proposal_id']}.json").read_text())
            self.assertNotIn("prompt", stored)
            self.assertNotIn("artifact", stored)
            self.assertEqual(first["proposal_digest"], stored["proposal_digest"])

    def test_apply_requires_review_and_is_single_writer_fast_forward(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "repo"
            root.mkdir()
            base, candidate = self.make_repo(root)
            integrator = ServerGitIntegrator(root, proposals_dir=pathlib.Path(tmp) / "spool")
            validation, scrub = self.receipts(base, candidate, review="pending")
            proposal = integrator.propose(
                capsule=self.capsule(),
                source_digest=validation["source_digest"],
                validation_receipt=validation,
                scrub_receipt=scrub,
            )
            with self.assertRaisesRegex(IntegratorError, "review approval"):
                integrator.apply_local(proposal["proposal_id"])

            validation["review_decision"] = "approved"
            # A changed review receipt is a different proposal identity, so
            # explicitly construct a fresh integrator proposal.
            proposal = integrator.propose(
                capsule=self.capsule(),
                source_digest=validation["source_digest"],
                validation_receipt=validation,
                scrub_receipt=scrub,
            )
            applied = integrator.apply_local(proposal["proposal_id"])
            self.assertEqual("applied", applied["status"])
            self.assertEqual(candidate, git(root, "rev-parse", "HEAD"))
            again = integrator.apply_local(proposal["proposal_id"])
            self.assertTrue(again["idempotent"])

    def test_push_is_separate_explicit_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "repo"
            root.mkdir()
            base, candidate = self.make_repo(root)
            bare = pathlib.Path(tmp) / "origin.git"
            git(pathlib.Path(tmp), "init", "--bare", "-q", str(bare))
            git(root, "remote", "add", "origin", str(bare))
            git(root, "push", "-q", "-u", "origin", "main")
            integrator = ServerGitIntegrator(root, proposals_dir=pathlib.Path(tmp) / "spool")
            validation, scrub = self.receipts(base, candidate)
            proposal = integrator.propose(
                capsule=self.capsule(),
                source_digest=validation["source_digest"],
                validation_receipt=validation,
                scrub_receipt=scrub,
            )
            blocked = integrator.push(proposal["proposal_id"], approved=False)
            self.assertEqual("blocked", blocked["status"])
            integrator.apply_local(proposal["proposal_id"])
            pushed = integrator.push(proposal["proposal_id"], approved=True)
            self.assertEqual("pushed", pushed["status"])
            self.assertEqual(candidate, git(bare, "rev-parse", "refs/heads/main"))

    def test_sensitive_capsule_and_stale_base_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "repo"
            root.mkdir()
            base, candidate = self.make_repo(root)
            integrator = ServerGitIntegrator(root, proposals_dir=pathlib.Path(tmp) / "spool")
            validation, scrub = self.receipts(base, candidate)
            secret_capsule = {**self.capsule(), "metadata": {"api_key": "do-not-store"}}
            with self.assertRaisesRegex(IntegratorError, "sensitive"):
                integrator.propose(
                    capsule=secret_capsule,
                    source_digest=validation["source_digest"],
                    validation_receipt=validation,
                    scrub_receipt=scrub,
                )
            # Move main independently; the old candidate must not be applied.
            (root / "README.md").write_text("independent\n", encoding="utf-8")
            git(root, "add", "README.md")
            git(root, "commit", "-qm", "independent")
            with self.assertRaisesRegex(IntegratorError, "stale"):
                integrator.propose(
                    capsule=self.capsule(),
                    source_digest=validation["source_digest"],
                    validation_receipt=validation,
                    scrub_receipt=scrub,
                )


if __name__ == "__main__":
    unittest.main()
