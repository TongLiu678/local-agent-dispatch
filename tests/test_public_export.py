from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "public_export", ROOT / "scripts" / "public_export.py"
)
assert SPEC and SPEC.loader
EXPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPORT)


def git(repo: pathlib.Path, *args: str, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout.strip()


def git_bytes(
    repo: pathlib.Path,
    *args: str,
    input_data: bytes,
    env: dict[str, str] | None = None,
) -> bytes:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        env=env,
        input=input_data,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout


class PublicExportTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        # Keep fixture commits and the exporter's isolated status check on the
        # same line-ending policy, regardless of a Windows user's global Git
        # configuration.
        git(self.repo, "config", "--local", "core.autocrlf", "false")
        git(self.repo, "config", "user.name", "Test")
        git(self.repo, "config", "user.email", "test@example.invalid")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def commit(self, message: str = "snapshot") -> str:
        git(self.repo, "add", "-A")
        return self.commit_index(message)

    def commit_index(self, message: str) -> str:
        environment = dict(os.environ)
        environment.update(
            {
                "GIT_AUTHOR_DATE": "2001-02-03T04:05:06Z",
                "GIT_COMMITTER_DATE": "2001-02-03T04:05:06Z",
            }
        )
        git(self.repo, "commit", "-qm", message, env=environment)
        return git(self.repo, "rev-parse", "HEAD")

    def policy(self, **overrides: object) -> pathlib.Path:
        payload: dict[str, object] = {
            "schema_version": 1,
            "policy_type": "local-agent-dispatch.public_export_policy",
            "exclude_paths": [],
            "exclude_prefixes": [],
            "literal_replacements": [],
        }
        payload.update(overrides)
        path = self.root / f"policy-{len(list(self.root.glob('policy-*.json')))}.json"
        path.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True), encoding="utf-8"
        )
        return path

    def export(
        self,
        ref: str,
        destination: pathlib.Path,
        policy: pathlib.Path | None = None,
        *,
        allow_dirty_source: bool = False,
    ) -> dict[str, object]:
        return EXPORT.export_public_snapshot(
            repo=self.repo,
            ref=ref,
            destination=destination,
            policy_path=policy or self.policy(),
            allow_dirty_source=allow_dirty_source,
        )

    def test_exports_exact_ref_with_explicit_exclusions_and_replacements(self) -> None:
        raw_value = "private-" + "literal-123456"
        (self.repo / "keep.txt").write_text(
            f"before {raw_value} and {raw_value} after\n", encoding="utf-8"
        )
        (self.repo / "drop.txt").write_text("drop\n", encoding="utf-8")
        (self.repo / "private").mkdir()
        (self.repo / "private" / "one.txt").write_text("one\n", encoding="utf-8")
        (self.repo / "private" / "two.txt").write_text("two\n", encoding="utf-8")
        executable = self.repo / "run.sh"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        ref = self.commit()
        policy = self.policy(
            exclude_paths=["drop.txt"],
            exclude_prefixes=["private"],
            literal_replacements=[
                {
                    "path": "keep.txt",
                    "match": raw_value,
                    "replacement": "PUBLIC_VALUE",
                    "expected_count": 2,
                }
            ],
        )
        destination = self.root / "public"

        manifest = self.export(ref, destination, policy)

        self.assertEqual({"categories", "counts", "hashes"}, set(manifest))
        self.assertEqual("exported", manifest["categories"]["result"])
        self.assertEqual(5, manifest["counts"]["source_entry_count"])
        self.assertEqual(2, manifest["counts"]["exported_file_count"])
        self.assertEqual(3, manifest["counts"]["excluded_file_count"])
        self.assertEqual(2, manifest["counts"]["replacement_occurrence_count"])
        self.assertEqual(
            "before PUBLIC_VALUE and PUBLIC_VALUE after\n",
            (destination / "keep.txt").read_text(encoding="utf-8"),
        )
        self.assertFalse((destination / "drop.txt").exists())
        self.assertFalse((destination / "private").exists())
        if os.name != "nt":
            self.assertTrue((destination / "run.sh").stat().st_mode & stat.S_IXUSR)
        else:
            self.assertTrue((destination / "run.sh").is_file())
        rendered = json.dumps(manifest, sort_keys=True)
        self.assertNotIn(raw_value, rendered)
        self.assertNotIn(str(self.repo), rendered)
        self.assertNotIn(str(destination), rendered)

    def test_same_ref_and_policy_produce_identical_manifest_and_filesystem(self) -> None:
        (self.repo / "a.txt").write_text("alpha\n", encoding="utf-8")
        script = self.repo / "b.sh"
        script.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
        script.chmod(0o755)
        ref = self.commit()
        policy = self.policy()

        first = self.export(ref, self.root / "first", policy)
        second = self.export(ref, self.root / "second", policy)

        self.assertEqual(first, second)
        for relative in ("a.txt", "b.sh"):
            left = self.root / "first" / relative
            right = self.root / "second" / relative
            self.assertEqual(left.read_bytes(), right.read_bytes())
            self.assertEqual(stat.S_IMODE(left.stat().st_mode), stat.S_IMODE(right.stat().st_mode))
            self.assertEqual(left.stat().st_mtime_ns, right.stat().st_mtime_ns)

    def test_dirty_source_is_rejected_by_default_and_override_exports_ref(self) -> None:
        (self.repo / "value.txt").write_text("committed\n", encoding="utf-8")
        ref = self.commit()
        (self.repo / "value.txt").write_text("working tree\n", encoding="utf-8")
        (self.repo / "untracked.txt").write_text("untracked\n", encoding="utf-8")
        destination = self.root / "blocked"

        with self.assertRaisesRegex(EXPORT.PublicExportError, "dirty_source"):
            self.export(ref, destination)
        self.assertFalse(destination.exists())

        allowed = self.root / "allowed"
        manifest = self.export(ref, allowed, allow_dirty_source=True)
        self.assertEqual("dirty_allowed", manifest["categories"]["source_worktree"])
        self.assertEqual("committed\n", (allowed / "value.txt").read_text())
        self.assertFalse((allowed / "untracked.txt").exists())

    def test_existing_destination_and_destination_inside_source_are_rejected(self) -> None:
        (self.repo / "file.txt").write_text("data\n", encoding="utf-8")
        ref = self.commit()
        existing = self.root / "existing"
        existing.mkdir()

        with self.assertRaisesRegex(EXPORT.PublicExportError, "destination_exists"):
            self.export(ref, existing)
        with self.assertRaisesRegex(EXPORT.PublicExportError, "destination_inside_source"):
            self.export(ref, self.repo / "public")
        for name in ("CONIN$", "bad?.txt", " leading"):
            with self.subTest(destination_name=name):
                with self.assertRaisesRegex(
                    EXPORT.PublicExportError, "invalid_destination_name"
                ):
                    self.export(ref, self.root / name)

    def test_invalid_destination_name_precedes_win32_device_existence(self) -> None:
        with mock.patch.object(EXPORT.os.path, "lexists", return_value=True):
            with self.assertRaisesRegex(
                EXPORT.PublicExportError, "invalid_destination_name"
            ):
                EXPORT._destination(self.repo, self.root / "CONIN$")

    def test_case_alias_cannot_bypass_policy_or_destination_containment(self) -> None:
        (self.repo / "data.txt").write_text("data\n", encoding="utf-8")
        in_repo_policy = self.repo / "private-policy.json"
        in_repo_policy.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "policy_type": "local-agent-dispatch.public_export_policy",
                    "exclude_paths": [],
                    "exclude_prefixes": [],
                    "literal_replacements": [],
                }
            ),
            encoding="utf-8",
        )
        ref = self.commit()
        alias_repo = self.repo.with_name(self.repo.name.upper())
        try:
            same_repo = alias_repo.samefile(self.repo)
        except OSError:
            same_repo = False
        if not same_repo:
            self.skipTest("filesystem is case-sensitive")

        with self.assertRaisesRegex(EXPORT.PublicExportError, "policy_inside_source"):
            self.export(
                ref,
                self.root / "case-policy-out",
                alias_repo / in_repo_policy.name,
            )

        with self.assertRaisesRegex(
            EXPORT.PublicExportError, "destination_inside_source"
        ):
            self.export(ref, alias_repo / "case-destination-out", self.policy())

    def test_tracked_policy_is_rejected_without_disclosing_its_literal(self) -> None:
        raw_value = "tracked-policy-secret-123456"
        (self.repo / "data.txt").write_text(raw_value, encoding="utf-8")
        policy = self.repo / "private-policy.json"
        policy.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "policy_type": "local-agent-dispatch.public_export_policy",
                    "exclude_paths": [],
                    "exclude_prefixes": [],
                    "literal_replacements": [
                        {
                            "path": "data.txt",
                            "match": raw_value,
                            "replacement": "PUBLIC",
                            "expected_count": 1,
                        }
                    ],
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        ref = self.commit()
        destination = self.root / "tracked-policy-out"
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = EXPORT.main(
                [
                    "--repo",
                    str(self.repo),
                    "--ref",
                    ref,
                    "--destination",
                    str(destination),
                    "--policy",
                    str(policy),
                ]
            )

        self.assertEqual(2, code)
        self.assertEqual("", stderr.getvalue())
        payload = json.loads(stdout.getvalue())
        self.assertEqual("policy_inside_source", payload["categories"]["failure"])
        self.assertFalse(destination.exists())
        for forbidden in (raw_value, str(self.repo), str(policy), str(destination)):
            self.assertNotIn(forbidden, stdout.getvalue())

    def test_policy_reached_through_symlinked_parent_is_rejected(self) -> None:
        (self.repo / "data.txt").write_text("data\n", encoding="utf-8")
        policy = self.repo / "private-policy.json"
        policy.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "policy_type": "local-agent-dispatch.public_export_policy",
                    "exclude_paths": [],
                    "exclude_prefixes": [],
                    "literal_replacements": [],
                }
            ),
            encoding="utf-8",
        )
        ref = self.commit()
        alias = self.root / "source-alias"
        try:
            alias.symlink_to(self.repo, target_is_directory=True)
        except (NotImplementedError, OSError):
            self.skipTest("directory symlinks are not available")

        with self.assertRaisesRegex(EXPORT.PublicExportError, "policy_inside_source"):
            self.export(ref, self.root / "symlink-policy-out", alias / policy.name)

    def test_policy_in_git_metadata_is_rejected_but_sibling_policy_succeeds(self) -> None:
        (self.repo / "data.txt").write_text("data\n", encoding="utf-8")
        ref = self.commit()
        metadata_policy = pathlib.Path(
            git(self.repo, "rev-parse", "--absolute-git-dir")
        ) / "private-policy.json"
        metadata_policy.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "policy_type": "local-agent-dispatch.public_export_policy",
                    "exclude_paths": [],
                    "exclude_prefixes": [],
                    "literal_replacements": [],
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            EXPORT.PublicExportError, "policy_inside_git_metadata"
        ):
            self.export(ref, self.root / "metadata-policy-out", metadata_policy)

        linked = self.root / "linked-source"
        git(self.repo, "worktree", "add", "-q", "--detach", str(linked), ref)
        with self.assertRaisesRegex(
            EXPORT.PublicExportError, "policy_inside_git_metadata"
        ):
            EXPORT.export_public_snapshot(
                repo=linked,
                ref=ref,
                destination=self.root / "linked-metadata-policy-out",
                policy_path=metadata_policy,
            )

        sibling_policy = self.policy()
        manifest = self.export(ref, self.root / "sibling-policy-out", sibling_policy)
        self.assertEqual("exported", manifest["categories"]["result"])

    def test_symlink_and_submodule_entries_fail_closed(self) -> None:
        target = self.repo / "target.txt"
        target.write_text("target\n", encoding="utf-8")
        link_blob_source = self.root / "link-blob"
        link_blob_source.write_text("target.txt", encoding="utf-8")
        link_blob = git(self.repo, "hash-object", "-w", str(link_blob_source))
        git(self.repo, "add", "target.txt")
        git(
            self.repo,
            "update-index",
            "--add",
            "--cacheinfo",
            f"120000,{link_blob},link.txt",
        )
        symlink_ref = self.commit_index("symlink")
        with self.assertRaisesRegex(EXPORT.PublicExportError, "unsupported_symlink"):
            self.export(
                symlink_ref,
                self.root / "symlink-out",
                allow_dirty_source=True,
            )
        self.assertFalse((self.root / "symlink-out").exists())

        git(self.repo, "update-index", "--force-remove", "link.txt")
        git(
            self.repo,
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{symlink_ref},vendor/submodule",
        )
        submodule_ref = self.commit_index("gitlink")
        with self.assertRaisesRegex(EXPORT.PublicExportError, "unsupported_submodule"):
            self.export(
                submodule_ref,
                self.root / "submodule-out",
                allow_dirty_source=True,
            )
        self.assertFalse((self.root / "submodule-out").exists())

    def test_unsafe_git_path_fails_closed(self) -> None:
        blob = git_bytes(
            self.repo, "hash-object", "-w", "--stdin", input_data=b"data\n"
        ).decode("ascii").strip()
        tree = git_bytes(
            self.repo,
            "mktree",
            "-z",
            input_data=f"100644 blob {blob}\tbad?.txt\0".encode("ascii"),
        ).decode("ascii").strip()
        environment = dict(os.environ)
        environment.update(
            {
                "GIT_AUTHOR_DATE": "2001-02-03T04:05:06Z",
                "GIT_COMMITTER_DATE": "2001-02-03T04:05:06Z",
            }
        )
        ref = git_bytes(
            self.repo,
            "commit-tree",
            tree,
            input_data=b"unsafe path\n",
            env=environment,
        ).decode("ascii").strip()

        with self.assertRaisesRegex(EXPORT.PublicExportError, "unsafe_repository_path"):
            self.export(ref, self.root / "unsafe-out")
        self.assertFalse((self.root / "unsafe-out").exists())

    def test_repository_paths_reject_win32_characters_and_devices(self) -> None:
        unsafe_paths = [
            "bad<name.txt",
            "bad>name.txt",
            'bad"name.txt',
            "bad:name.txt",
            "bad\\name.txt",
            "bad|name.txt",
            "bad?name.txt",
            "bad*name.txt",
            " leading.txt",
            "dir/ child.txt",
            "CONIN$",
            "conout$.txt",
            "CLOCK$.log",
            "COM¹.txt",
            "LPT².log",
        ]
        for value in unsafe_paths:
            with self.subTest(value=value):
                with self.assertRaisesRegex(EXPORT.PublicExportError, "invalid_policy"):
                    EXPORT._safe_repository_path(value)

    def test_policy_is_closed_bounded_and_must_match_exactly(self) -> None:
        raw_value = "sensitive-" + "literal-654321"
        (self.repo / "file.txt").write_text(raw_value + "\n", encoding="utf-8")
        ref = self.commit()
        cases = [
            (
                "unknown_field",
                self.policy(unexpected=True),
                "invalid_policy",
            ),
            (
                "stale_exclude",
                self.policy(exclude_paths=["missing.txt"]),
                "stale_exclude_path",
            ),
            (
                "count_mismatch",
                self.policy(
                    literal_replacements=[
                        {
                            "path": "file.txt",
                            "match": raw_value,
                            "replacement": "PUBLIC",
                            "expected_count": 2,
                        }
                    ]
                ),
                "replacement_count_mismatch",
            ),
            (
                "oversized_literal",
                self.policy(
                    literal_replacements=[
                        {
                            "path": "file.txt",
                            "match": "x" * 4097,
                            "replacement": "PUBLIC",
                            "expected_count": 1,
                        }
                    ]
                ),
                "invalid_policy",
            ),
            (
                "replacement_residue",
                self.policy(
                    literal_replacements=[
                        {
                            "path": "file.txt",
                            "match": raw_value,
                            "replacement": raw_value + "-PUBLIC",
                            "expected_count": 1,
                        }
                    ]
                ),
                "replacement_residue",
            ),
        ]

        for index, (label, policy, category) in enumerate(cases):
            with self.subTest(label=label):
                destination = self.root / f"blocked-{index}"
                with self.assertRaisesRegex(EXPORT.PublicExportError, category) as caught:
                    self.export(ref, destination, policy)
                self.assertNotIn(raw_value, str(caught.exception))
                self.assertFalse(destination.exists())

    def test_duplicate_policy_keys_are_rejected(self) -> None:
        (self.repo / "file.txt").write_text("data\n", encoding="utf-8")
        ref = self.commit()
        policy = self.root / "duplicate.json"
        policy.write_text(
            '{"schema_version":1,"schema_version":1,'
            '"policy_type":"local-agent-dispatch.public_export_policy",'
            '"exclude_paths":[],"exclude_prefixes":[],"literal_replacements":[]}',
            encoding="utf-8",
        )

        with self.assertRaisesRegex(EXPORT.PublicExportError, "invalid_policy"):
            self.export(ref, self.root / "duplicate-out", policy)

    def test_executable_candidate_content_is_never_run(self) -> None:
        sentinel = self.root / "must-not-exist"
        payload = self.repo / "payload.sh"
        payload.write_text(f"#!/bin/sh\nprintf x > {sentinel}\n", encoding="utf-8")
        payload.chmod(0o755)
        ref = self.commit()

        self.export(ref, self.root / "no-execute")

        self.assertFalse(sentinel.exists())

    def test_repository_fsmonitor_command_is_never_run(self) -> None:
        sentinel = self.root / "fsmonitor-must-not-run"
        monitor = self.root / "malicious-fsmonitor.sh"
        monitor.write_text(
            f"#!/bin/sh\nprintf x > {sentinel}\nexit 0\n", encoding="utf-8"
        )
        monitor.chmod(0o755)
        (self.repo / "file.txt").write_text("data\n", encoding="utf-8")
        ref = self.commit()
        git(self.repo, "config", "core.fsmonitor", str(monitor))

        self.export(ref, self.root / "no-fsmonitor")

        self.assertFalse(sentinel.exists())

    def test_git_version_selects_modern_and_legacy_offline_modes(self) -> None:
        legacy_prefix = EXPORT._git_prefix((2, 27, 0))
        modern_prefix = EXPORT._git_prefix((2, 45, 0))
        self.assertNotIn("--no-lazy-fetch", legacy_prefix)
        self.assertIn("--no-lazy-fetch", modern_prefix)
        for prefix in (legacy_prefix, modern_prefix):
            self.assertTrue(pathlib.Path(prefix[0]).is_absolute())
            self.assertIn("--no-replace-objects", prefix)
            self.assertIn("--no-optional-locks", prefix)
            self.assertIn("protocol.allow=never", prefix)
            self.assertIn("core.fsmonitor=", prefix)
            self.assertNotIn("core.fsmonitor=false", prefix)

        completed = subprocess.CompletedProcess(
            args=["git", "--version"],
            returncode=0,
            stdout=b"git version 2.27.0.windows.1\n",
            stderr=b"",
        )
        with mock.patch.object(EXPORT.subprocess, "run", return_value=completed):
            self.assertEqual((2, 27, 0), EXPORT._require_git_version())

        unsupported = subprocess.CompletedProcess(
            args=["git", "--version"],
            returncode=0,
            stdout=b"git version 2.26.9\n",
            stderr=b"",
        )
        with mock.patch.object(EXPORT.subprocess, "run", return_value=unsupported):
            with self.assertRaisesRegex(
                EXPORT.PublicExportError, "unsupported_git_version"
            ):
                EXPORT._require_git_version()

    def test_ref_resolution_uses_only_version_supported_option_boundary(self) -> None:
        commit = "a" * 40
        tree = "b" * 40
        responses = [commit.encode("ascii"), tree.encode("ascii"), b"123\n"]
        with mock.patch.object(EXPORT, "_git", side_effect=responses) as legacy_git:
            self.assertEqual(
                (commit, tree, 123),
                EXPORT._resolve_commit(
                    self.repo,
                    "HEAD",
                    (2, 27, 0),
                    EXPORT._git_prefix((2, 27, 0)),
                ),
            )
        self.assertNotIn("--end-of-options", legacy_git.call_args_list[0].args)
        self.assertNotIn("--end-of-options", legacy_git.call_args_list[1].args)

        responses = [commit.encode("ascii"), tree.encode("ascii"), b"123\n"]
        with mock.patch.object(EXPORT, "_git", side_effect=responses) as modern_git:
            self.assertEqual(
                (commit, tree, 123),
                EXPORT._resolve_commit(
                    self.repo,
                    "HEAD",
                    (2, 30, 0),
                    EXPORT._git_prefix((2, 30, 0)),
                ),
            )
        self.assertIn("--end-of-options", modern_git.call_args_list[0].args)
        self.assertIn("--end-of-options", modern_git.call_args_list[1].args)

        with mock.patch.object(EXPORT, "_git") as rejected_git:
            with self.assertRaisesRegex(EXPORT.PublicExportError, "invalid_ref"):
                EXPORT._resolve_commit(
                    self.repo,
                    "--upload-pack=malicious",
                    (2, 27, 0),
                    EXPORT._git_prefix((2, 27, 0)),
                )
        rejected_git.assert_not_called()

    def test_legacy_full_repository_is_exported_offline(self) -> None:
        (self.repo / "data.txt").write_text("data\n", encoding="utf-8")
        ref = self.commit()

        with mock.patch.object(
            EXPORT, "_require_git_version", return_value=(2, 27, 0)
        ):
            manifest = self.export(ref, self.root / "legacy-full-out")

        self.assertEqual("exported", manifest["categories"]["result"])
        self.assertEqual(
            "data\n",
            (self.root / "legacy-full-out" / "data.txt").read_text(encoding="utf-8"),
        )

    def test_legacy_promisor_repository_is_blocked_before_object_reads(self) -> None:
        (self.repo / "data.txt").write_text("data\n", encoding="utf-8")
        ref = self.commit()
        sentinel = self.root / "remote-helper-must-not-run"
        helper_directory = self.root / "helpers"
        helper_directory.mkdir()
        if os.name == "nt":
            helper = helper_directory / "git-remote-lad-sentinel.cmd"
            helper.write_text(
                f'@echo touched>"{sentinel}"\r\n', encoding="utf-8"
            )
        else:
            helper = helper_directory / "git-remote-lad-sentinel"
            helper.write_text(
                f"#!/bin/sh\nprintf touched > '{sentinel}'\n", encoding="utf-8"
            )
            helper.chmod(0o755)
        git(self.repo, "config", "remote.origin.url", "lad-sentinel::payload")
        git(self.repo, "config", "remote.origin.promisor", "true")
        environment = {
            "PATH": str(helper_directory) + os.pathsep + os.environ.get("PATH", ""),
        }

        with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
            EXPORT, "_require_git_version", return_value=(2, 27, 0)
        ), mock.patch.object(EXPORT, "_resolve_commit") as resolve_commit:
            with self.assertRaisesRegex(
                EXPORT.PublicExportError, "unsupported_promisor_repository"
            ):
                self.export(ref, self.root / "legacy-promisor-out")

        resolve_commit.assert_not_called()
        self.assertFalse(sentinel.exists())
        self.assertFalse((self.root / "legacy-promisor-out").exists())

    def test_sealed_git_lookup_blocks_even_allowlisted_foreign_helper(self) -> None:
        sentinel = self.root / "transport-helper-must-not-run"
        helper_directory = self.root / "transport-helpers"
        helper_directory.mkdir()
        helper_name = f"git-remote-{EXPORT._NO_TRANSPORT_PROTOCOL}"
        if os.name == "nt":
            helper = helper_directory / f"{helper_name}.cmd"
            helper.write_text(
                f'@echo touched>"{sentinel}"\r\n', encoding="utf-8"
            )
        else:
            helper = helper_directory / helper_name
            helper.write_text(
                f"#!/bin/sh\nprintf touched > '{sentinel}'\n", encoding="utf-8"
            )
            helper.chmod(0o755)
        version = EXPORT._require_git_version()
        prefix = EXPORT._git_prefix(version)
        git(self.repo, "config", "remote.origin.url", "payload")
        git(self.repo, "config", "remote.origin.vcs", EXPORT._NO_TRANSPORT_PROTOCOL)
        ambient_path = str(helper_directory) + os.pathsep + os.environ.get("PATH", "")

        with mock.patch.dict(os.environ, {"PATH": ambient_path}, clear=False):
            child_environment = EXPORT._git_environment()
            with self.assertRaisesRegex(
                EXPORT.PublicExportError, "transport_probe_failed"
            ):
                EXPORT._git(
                    self.repo,
                    "ls-remote",
                    "origin",
                    category="transport_probe_failed",
                    git_prefix=prefix,
                )

        self.assertEqual(os.devnull, child_environment["PATH"])
        self.assertEqual(os.devnull, child_environment["GIT_EXEC_PATH"])
        self.assertFalse(sentinel.exists())

    def test_git_environment_ignores_ambient_routing_config_and_trace(self) -> None:
        (self.repo / "data.txt").write_text("data\n", encoding="utf-8")
        ref = self.commit()
        trace = self.root / "ambient-git-trace"
        redirected = self.root / "ambient-git-redirect"
        ambient = {
            "GIT_DIR": str(self.root / "wrong.git"),
            "GIT_WORK_TREE": str(self.root / "wrong-tree"),
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": "malicious-command",
            "GIT_TRACE": str(trace),
            "GIT_REDIRECT_STDOUT": str(redirected),
            "GIT_ALLOW_PROTOCOL": "file:ssh:http:https",
        }

        with mock.patch.dict(os.environ, ambient, clear=False):
            child_environment = EXPORT._git_environment()
            manifest = self.export(ref, self.root / "isolated-environment-out")

        for removed in (
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_0",
            "GIT_TRACE",
            "GIT_REDIRECT_STDOUT",
        ):
            self.assertNotIn(removed, child_environment)
        self.assertEqual(
            EXPORT._NO_TRANSPORT_PROTOCOL,
            child_environment["GIT_ALLOW_PROTOCOL"],
        )
        self.assertEqual("0", child_environment["GIT_PROTOCOL_FROM_USER"])
        self.assertEqual(os.devnull, child_environment["GIT_CONFIG_GLOBAL"])
        self.assertEqual(os.devnull, child_environment["GIT_EXEC_PATH"])
        self.assertEqual(os.devnull, child_environment["HOME"])
        self.assertEqual(os.devnull, child_environment["PATH"])
        self.assertEqual(os.devnull, child_environment["XDG_CONFIG_HOME"])
        self.assertEqual("exported", manifest["categories"]["result"])
        self.assertFalse(trace.exists())
        self.assertFalse(redirected.exists())

    def test_git_discovery_ignores_cwd_and_relative_path_entries(self) -> None:
        real_git = pathlib.Path(EXPORT._git_executable())
        fake_git = self.repo / ("git.exe" if os.name == "nt" else "git")
        fake_git.write_text("not an executable Git", encoding="utf-8")
        fake_git.chmod(0o755)
        previous = pathlib.Path.cwd()
        try:
            os.chdir(self.repo)
            with mock.patch.dict(
                os.environ,
                {"PATH": "." + os.pathsep + os.pathsep + str(real_git.parent)},
                clear=False,
            ):
                discovered = pathlib.Path(EXPORT._git_executable())
        finally:
            os.chdir(previous)

        self.assertTrue(discovered.samefile(real_git))
        self.assertFalse(discovered.samefile(fake_git))

    def test_git_timeout_is_redacted_and_stable(self) -> None:
        (self.repo / "data.txt").write_text("data\n", encoding="utf-8")
        ref = self.commit()
        policy = self.policy()
        destination = self.root / "timeout-out"
        stdout = io.StringIO()
        stderr = io.StringIO()
        timed_out = subprocess.TimeoutExpired(
            cmd=["git", "--version"], timeout=EXPORT.GIT_COMMAND_TIMEOUT_SECONDS
        )

        with mock.patch.object(
            EXPORT.subprocess, "run", side_effect=timed_out
        ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = EXPORT.main(
                [
                    "--repo",
                    str(self.repo),
                    "--ref",
                    ref,
                    "--destination",
                    str(destination),
                    "--policy",
                    str(policy),
                ]
            )

        self.assertEqual(2, code)
        self.assertEqual("", stderr.getvalue())
        payload = json.loads(stdout.getvalue())
        self.assertEqual("git_command_timeout", payload["categories"]["failure"])
        for forbidden in (str(self.repo), str(policy), str(destination)):
            self.assertNotIn(forbidden, stdout.getvalue())
        self.assertFalse(destination.exists())

    def test_cli_failure_is_redacted_and_emits_only_bounded_manifest_shape(self) -> None:
        raw_value = "never-" + "print-this-123456"
        (self.repo / "file.txt").write_text(raw_value + "\n", encoding="utf-8")
        ref = self.commit()
        policy = self.policy(
            literal_replacements=[
                {
                    "path": "file.txt",
                    "match": raw_value,
                    "replacement": "PUBLIC",
                    "expected_count": 3,
                }
            ]
        )
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = EXPORT.main(
                [
                    "--repo",
                    str(self.repo),
                    "--ref",
                    ref,
                    "--destination",
                    str(self.root / "cli-out"),
                    "--policy",
                    str(policy),
                ]
            )

        self.assertEqual(2, code)
        self.assertEqual("", stderr.getvalue())
        payload = json.loads(stdout.getvalue())
        self.assertEqual({"categories", "counts", "hashes"}, set(payload))
        self.assertEqual("blocked", payload["categories"]["result"])
        self.assertEqual(
            "replacement_count_mismatch", payload["categories"]["failure"]
        )
        rendered = stdout.getvalue()
        for forbidden in (raw_value, str(self.repo), str(policy), str(self.root / "cli-out")):
            self.assertNotIn(forbidden, rendered)

    def test_schema_closes_policy_and_replacement_objects(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "public_export_policy.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(schema["additionalProperties"])
        replacements = schema["properties"]["literal_replacements"]
        self.assertLessEqual(replacements["maxItems"], 512)
        self.assertFalse(replacements["items"]["additionalProperties"])
        self.assertEqual(4096, replacements["items"]["properties"]["match"]["maxLength"])
        repository_path = schema["$defs"]["repository_path"]
        pattern = re.compile(repository_path["pattern"])
        self.assertIsNotNone(pattern.fullmatch("safe/path.txt"))
        for unsafe in (
            "/absolute",
            " leading.txt",
            "dir/ child.txt",
            "a//b",
            "a/../b",
            "bad?.txt",
            "bad:name",
        ):
            with self.subTest(schema_path=unsafe):
                self.assertIsNone(pattern.fullmatch(unsafe))
        self.assertIn("CONIN$", repository_path["description"])
        self.assertIn("CONOUT$", repository_path["description"])


if __name__ == "__main__":
    unittest.main()
