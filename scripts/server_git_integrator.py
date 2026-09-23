#!/usr/bin/env python3
"""Single-writer Git integrator for a server-resident project capsule.

The integrator is deliberately small and stdlib-only.  Workers may create
commits in isolated worktrees, but they never update the server project
branch directly.  A proposal records only digests and Git identities; raw
prompts, commands, credentials, environment variables, and private paths are
not persisted.  ``apply_local`` requires a passing validation/scrub receipt,
an explicit review decision, a clean target worktree, and an unchanged base
commit.  ``push`` is a separate, explicit approval gate.

The proposal spool and lock must live outside the Git worktree.  This keeps
runtime state out of the public export and makes the single-writer boundary
visible to operators instead of relying on a hidden process convention.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import pathlib
import re
import subprocess
from collections.abc import Iterator, Mapping
from datetime import datetime, timezone
from typing import Any

try:  # package import when invoked from the repository root
    from scripts.project_capsule import CapsuleError, _reject_sensitive
except ImportError:  # pragma: no cover - direct execution from scripts/
    from project_capsule import CapsuleError, _reject_sensitive


SCHEMA_VERSION = 1
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_PROPOSAL_ID = re.compile(r"^proposal-[0-9a-f]{32}$")
_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_SAFE_STATUS = {"proposed", "applied", "pushed"}
_PASS_VALUES = {"pass", "passed", "validated", "ok"}
_APPROVED_VALUES = {"approved", "allow", "allowed"}


class IntegratorError(ValueError):
    """Raised when a proposal or Git transition fails closed."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise IntegratorError("integrator payload is not JSON-serializable") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _require_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise IntegratorError(f"{field} must be a sha256:<64 lowercase hex> digest")
    return value


def _require_commit(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _HEX40.fullmatch(value):
        raise IntegratorError(f"{field} must be a 40-character lowercase Git commit")
    return value


def _git(repo: pathlib.Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=repo,
            check=check,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except FileNotFoundError as exc:
        raise IntegratorError("git executable is unavailable") from exc
    except subprocess.CalledProcessError as exc:
        # Do not propagate stderr: Git may include a credential-bearing remote
        # URL or a server-specific path.  Callers get a stable error class.
        raise IntegratorError(f"git {args[0] if args else 'command'} failed") from exc


def _is_ancestor(repo: pathlib.Path, base_commit: str, candidate_commit: str) -> bool:
    """Check ancestry using the Git 2.9-compatible merge-base form.

    The central PBS workers still ship Git 2.9.5, which does not implement
    ``git merge-base --is-ancestor``. The two-commit merge-base output is
    available on both old and new Git and is equivalent for this check.
    """

    result = _git(repo, "merge-base", base_commit, candidate_commit, check=False)
    return result.returncode == 0 and result.stdout.strip() == base_commit


def _safe_relative_dir(value: pathlib.Path, *, field: str) -> pathlib.Path:
    resolved = value.expanduser().resolve(strict=False)
    if resolved == pathlib.Path(resolved.anchor):
        raise IntegratorError(f"{field} must not be a filesystem root")
    return resolved


def _repo_root(value: pathlib.Path | str) -> pathlib.Path:
    candidate = pathlib.Path(value).expanduser().resolve()
    if not candidate.is_dir():
        raise IntegratorError("repository path is not a directory")
    result = _git(candidate, "rev-parse", "--show-toplevel")
    try:
        root = pathlib.Path(result.stdout.strip()).resolve()
    except (OSError, RuntimeError) as exc:
        raise IntegratorError("Git repository root cannot be resolved") from exc
    if root != candidate:
        raise IntegratorError("repository path must be the canonical Git root")
    return root


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _pass(receipt: Mapping[str, Any], field: str) -> bool:
    value = receipt.get(field)
    if isinstance(value, str) and value.strip().lower() in _PASS_VALUES:
        return True
    return False


def _review_decision(receipt: Mapping[str, Any]) -> str:
    value = receipt.get("review_decision")
    if isinstance(value, str):
        return value.strip().lower()
    review = receipt.get("review")
    if isinstance(review, Mapping):
        value = review.get("decision")
        if isinstance(value, str):
            return value.strip().lower()
    return "pending"


def _normalize_public_scrub_digest(receipt: Mapping[str, Any]) -> str:
    for key in ("scrub_digest", "report_digest", "report_sha256"):
        value = receipt.get(key)
        if isinstance(value, str):
            if _SHA256.fullmatch(value):
                return value
            if re.fullmatch(r"[0-9a-f]{64}", value):
                return "sha256:" + value
    raise IntegratorError("scrub receipt digest is missing or invalid")


def _capsule_summary(capsule: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(capsule, Mapping):
        raise IntegratorError("capsule must be an object")
    try:
        _reject_sensitive(capsule)
    except CapsuleError as exc:
        raise IntegratorError("capsule contains a sensitive field") from exc
    required = ("project_id", "workspace_id", "capsule_generation", "capsule_spec_digest")
    missing = [key for key in required if key not in capsule]
    if missing:
        raise IntegratorError("capsule missing: " + ",".join(missing))
    status = capsule.get("status")
    if status not in {None, "bound"}:
        raise IntegratorError("only a bound capsule can reach the integrator")
    project_id = capsule.get("project_id")
    workspace_id = capsule.get("workspace_id")
    if not isinstance(project_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._:-]{0,127}", project_id):
        raise IntegratorError("capsule project_id is invalid")
    if not isinstance(workspace_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._:-]{0,127}", workspace_id):
        raise IntegratorError("capsule workspace_id is invalid")
    generation = capsule.get("capsule_generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise IntegratorError("capsule_generation must be a positive integer")
    spec_digest = _require_sha256(capsule.get("capsule_spec_digest"), "capsule_spec_digest")
    raw_scopes = capsule.get("write_scopes")
    if raw_scopes is not None and not isinstance(raw_scopes, (list, tuple)):
        raise IntegratorError("capsule write_scopes must be a list")
    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id,
        "workspace_id": workspace_id,
        "capsule_generation": generation,
        "capsule_spec_digest": spec_digest,
        "write_scope_digest": _digest(sorted(str(item) for item in (raw_scopes or []))),
    }


def _receipt_summary(
    *,
    source_digest: str,
    validation_receipt: Mapping[str, Any],
    scrub_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(validation_receipt, Mapping):
        raise IntegratorError("validation_receipt must be an object")
    if not isinstance(scrub_receipt, Mapping):
        raise IntegratorError("scrub_receipt must be an object")
    _require_sha256(source_digest, "source_digest")
    if not _pass(validation_receipt, "gate") and not _pass(validation_receipt, "status"):
        raise IntegratorError("validation receipt is not passing")
    if validation_receipt.get("source_digest") != source_digest:
        raise IntegratorError("validation receipt source digest mismatch")
    if not _pass(scrub_receipt, "gate") and not _pass(scrub_receipt, "status"):
        raise IntegratorError("public scrub receipt is not passing")
    blocking = scrub_receipt.get("blocking_finding_count", 0)
    if isinstance(blocking, bool) or not isinstance(blocking, int) or blocking != 0:
        raise IntegratorError("public scrub has blocking findings")
    if scrub_receipt.get("matched_text_persisted") is True:
        raise IntegratorError("public scrub persisted matched text")
    artifact_digest = validation_receipt.get("artifact_digest")
    if artifact_digest is None:
        artifact_digest = validation_receipt.get("validated_artifact_digest")
    artifact_digest = _require_sha256(artifact_digest, "validation_receipt.artifact_digest")
    candidate = validation_receipt.get("candidate_commit") or validation_receipt.get("commit")
    base = validation_receipt.get("base_commit") or validation_receipt.get("parent_commit")
    candidate = _require_commit(candidate, "validation_receipt.candidate_commit")
    base = _require_commit(base, "validation_receipt.base_commit")
    scrub_digest = _normalize_public_scrub_digest(scrub_receipt)
    return {
        "validation_gate": "pass",
        "scrub_gate": "pass",
        "source_digest": source_digest,
        "artifact_digest": artifact_digest,
        "candidate_commit": candidate,
        "base_commit": base,
        "scrub_digest": scrub_digest,
        "review_decision": _review_decision(validation_receipt),
        "validation_receipt_digest": _digest(
            {
                "source_digest": source_digest,
                "artifact_digest": artifact_digest,
                "candidate_commit": candidate,
                "base_commit": base,
            }
        ),
    }


class ServerGitIntegrator:
    """Serialize proposal/apply/push transitions for one server project."""

    def __init__(
        self,
        repo: pathlib.Path | str,
        *,
        proposals_dir: pathlib.Path | str | None = None,
        target_branch: str = "main",
        lock_path: pathlib.Path | str | None = None,
    ) -> None:
        self.repo = _repo_root(repo)
        if not isinstance(target_branch, str) or not _BRANCH.fullmatch(target_branch):
            raise IntegratorError("target_branch is invalid")
        self.target_branch = target_branch
        proposal_value = (
            pathlib.Path(proposals_dir).expanduser()
            if proposals_dir is not None
            else self.repo.parent / f".{self.repo.name}-integrator-proposals"
        )
        self.proposals_dir = _safe_relative_dir(proposal_value, field="proposals_dir")
        if self.repo == self.proposals_dir or self.repo in self.proposals_dir.parents:
            raise IntegratorError("proposals_dir must be outside the Git worktree")
        lock_value = (
            pathlib.Path(lock_path).expanduser()
            if lock_path is not None
            else self.proposals_dir.parent / f".{self.proposals_dir.name}.lock"
        )
        self.lock_path = _safe_relative_dir(lock_value, field="lock_path")
        if self.repo == self.lock_path or self.repo in self.lock_path.parents:
            raise IntegratorError("lock_path must be outside the Git worktree")

    @contextlib.contextmanager
    def _lock(self) -> Iterator[None]:
        """Hold an OS-level lock for every proposal state transition."""

        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            handle = self.lock_path.open("a+")
        except OSError as exc:
            raise IntegratorError("single-writer lock cannot be opened") from exc
        try:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            except OSError as exc:
                raise IntegratorError("single-writer lock is unavailable") from exc
            yield
        finally:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()

    def _proposal_path(self, proposal_id: str) -> pathlib.Path:
        if not isinstance(proposal_id, str) or not _PROPOSAL_ID.fullmatch(proposal_id):
            raise IntegratorError("proposal_id is invalid")
        return self.proposals_dir / f"{proposal_id}.json"

    def _read_proposal(self, proposal_id: str) -> dict[str, Any]:
        path = self._proposal_path(proposal_id)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise IntegratorError("proposal does not exist") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise IntegratorError("proposal cannot be read") from exc
        if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
            raise IntegratorError("proposal schema is unsupported")
        if data.get("proposal_id") != proposal_id:
            raise IntegratorError("proposal identity mismatch")
        status = data.get("status")
        if status not in _SAFE_STATUS:
            raise IntegratorError("proposal status is invalid")
        proposal_digest = data.get("proposal_digest")
        if proposal_digest != _digest({key: value for key, value in data.items() if key != "proposal_digest"}):
            raise IntegratorError("proposal digest mismatch")
        return data

    def _write_proposal(self, proposal: Mapping[str, Any]) -> None:
        self.proposals_dir.mkdir(parents=True, exist_ok=True)
        proposal_id = str(proposal["proposal_id"])
        path = self._proposal_path(proposal_id)
        body = {key: value for key, value in proposal.items() if key != "proposal_digest"}
        payload = dict(body)
        payload["proposal_digest"] = _digest(body)
        encoded = (_canonical(payload) + b"\n")
        temporary = path.with_name(
            f".{path.name}.{os.getpid()}.{hashlib.sha256(encoded).hexdigest()[:12]}.tmp"
        )
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            try:
                directory_fd = os.open(self.proposals_dir, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                # The proposal itself is durable enough on filesystems that
                # do not allow fsync on a directory; never weaken validation.
                pass
        except FileExistsError:
            # A stale temporary from a crashed writer is never trusted as a
            # proposal.  The lock makes this cleanup safe; the final proposal
            # is only accepted after a complete read and digest check.
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()
            raise IntegratorError("proposal temporary path already exists")
        except OSError as exc:
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()
            raise IntegratorError("proposal cannot be durably written") from exc

    def _target_head(self) -> str:
        result = _git(self.repo, "rev-parse", "--verify", f"{self.target_branch}^{{commit}}")
        return _require_commit(result.stdout.strip(), "target_head")

    def _current_branch(self) -> str:
        # ``symbolic-ref --short`` is not available on the Git 2.9 binary
        # installed on the central PBS workers.  The full ref form is
        # stable across the supported Git range.
        result = _git(self.repo, "symbolic-ref", "HEAD")
        reference = result.stdout.strip()
        prefix = "refs/heads/"
        branch = reference[len(prefix):] if reference.startswith(prefix) else reference
        if branch != self.target_branch:
            raise IntegratorError("target branch is not checked out")
        return branch

    def propose(
        self,
        *,
        capsule: Mapping[str, Any],
        source_digest: str,
        validation_receipt: Mapping[str, Any],
        scrub_receipt: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Persist a safe proposal without changing the Git worktree."""

        capsule_safe = _capsule_summary(capsule)
        receipts = _receipt_summary(
            source_digest=source_digest,
            validation_receipt=validation_receipt,
            scrub_receipt=scrub_receipt,
        )
        # Check object existence, ancestry, and the proposal base without
        # checking out or modifying anything.
        _git(self.repo, "cat-file", "-e", f"{receipts['candidate_commit']}^{{commit}}")
        _git(self.repo, "cat-file", "-e", f"{receipts['base_commit']}^{{commit}}")
        current_head = self._target_head()
        if receipts["base_commit"] != current_head:
            raise IntegratorError("proposal base_commit is stale")
        if receipts["candidate_commit"] == receipts["base_commit"]:
            raise IntegratorError("candidate commit has no change")
        if not _is_ancestor(self.repo, receipts["base_commit"], receipts["candidate_commit"]):
            raise IntegratorError("candidate commit is not descended from base_commit")
        immutable = {
            "schema_version": SCHEMA_VERSION,
            "project_id": capsule_safe["project_id"],
            "workspace_id": capsule_safe["workspace_id"],
            "capsule_generation": capsule_safe["capsule_generation"],
            "capsule_spec_digest": capsule_safe["capsule_spec_digest"],
            "write_scope_digest": capsule_safe["write_scope_digest"],
            "target_branch": self.target_branch,
            "base_commit": receipts["base_commit"],
            "candidate_commit": receipts["candidate_commit"],
            "source_digest": receipts["source_digest"],
            "artifact_digest": receipts["artifact_digest"],
            "scrub_digest": receipts["scrub_digest"],
            "validation_receipt_digest": receipts["validation_receipt_digest"],
            # A review decision is part of the proposal identity.  Re-running
            # a worker after review must not silently turn a pending proposal
            # into an approved one under the same durable ID.
            "review_decision": receipts["review_decision"],
        }
        proposal_id = "proposal-" + hashlib.sha256(_canonical(immutable)).hexdigest()[:32]
        proposal = {
            **immutable,
            "proposal_id": proposal_id,
            "status": "proposed",
            "review_decision": receipts["review_decision"],
            "created_at_utc": _utc_now(),
            "read_only": True,
        }
        proposal["proposal_digest"] = _digest(proposal)
        with self._lock():
            path = self._proposal_path(proposal_id)
            if path.exists():
                existing = self._read_proposal(proposal_id)
                if all(existing.get(key) == immutable.get(key) for key in immutable):
                    # Re-proposing the same immutable candidate is idempotent;
                    # preserve the original creation time and review state.
                    return existing
            self._write_proposal(proposal)
        return dict(proposal)

    def apply_local(self, proposal_id: str) -> dict[str, Any]:
        """Fast-forward the server branch after all local gates pass."""

        with self._lock():
            proposal = self._read_proposal(proposal_id)
            if proposal["status"] in {"applied", "pushed"}:
                return {
                    "proposal_id": proposal_id,
                    "status": proposal["status"],
                    "commit": proposal.get("applied_commit"),
                    "idempotent": True,
                    "read_only": False,
                }
            if proposal.get("review_decision") not in _APPROVED_VALUES:
                raise IntegratorError("review approval is required before local apply")
            self._current_branch()
            dirty = _git(self.repo, "status", "--porcelain").stdout.strip()
            if dirty:
                raise IntegratorError("target worktree is dirty")
            current = self._target_head()
            if current != proposal["base_commit"]:
                raise IntegratorError("target branch moved after proposal")
            _git(self.repo, "cat-file", "-e", f"{proposal['candidate_commit']}^{{commit}}")
            if not _is_ancestor(self.repo, proposal["base_commit"], proposal["candidate_commit"]):
                raise IntegratorError("candidate commit is no longer descended from base_commit")
            _git(self.repo, "merge", "--ff-only", proposal["candidate_commit"])
            applied = self._target_head()
            if applied != proposal["candidate_commit"]:
                raise IntegratorError("Git apply did not reach candidate commit")
            proposal = dict(proposal)
            proposal.update(
                {
                    "status": "applied",
                    "applied_commit": applied,
                    "applied_at_utc": _utc_now(),
                    "read_only": False,
                }
            )
            self._write_proposal(proposal)
            return {
                "proposal_id": proposal_id,
                "status": "applied",
                "commit": applied,
                "target_branch": self.target_branch,
                "idempotent": False,
                "read_only": False,
            }

    def push(self, proposal_id: str, *, approved: bool) -> dict[str, Any]:
        """Push an applied proposal only after explicit approval."""

        if approved is not True:
            return {
                "proposal_id": proposal_id,
                "status": "blocked",
                "reason": "explicit_push_approval_required",
                "read_only": True,
            }
        with self._lock():
            proposal = self._read_proposal(proposal_id)
            if proposal["status"] == "pushed":
                return {
                    "proposal_id": proposal_id,
                    "status": "pushed",
                    "commit": proposal.get("applied_commit"),
                    "idempotent": True,
                    "read_only": False,
                }
            if proposal["status"] != "applied":
                raise IntegratorError("proposal must be locally applied before push")
            self._current_branch()
            current = self._target_head()
            if current != proposal.get("applied_commit"):
                raise IntegratorError("target branch moved after local apply")
            # ``git remote get-url`` is not available on Git 2.9; the
            # underlying config key is stable and keeps this explicit push
            # gate portable without exposing the remote value.
            remote = _git(self.repo, "config", "--get", "remote.origin.url", check=False)
            if remote.returncode != 0 or not remote.stdout.strip():
                raise IntegratorError("origin remote is unavailable")
            _git(self.repo, "push", "--porcelain", "origin", self.target_branch)
            proposal = dict(proposal)
            proposal.update({"status": "pushed", "pushed_at_utc": _utc_now()})
            self._write_proposal(proposal)
            return {
                "proposal_id": proposal_id,
                "status": "pushed",
                "commit": current,
                "target_branch": self.target_branch,
                "idempotent": False,
                "read_only": False,
            }


__all__ = ["IntegratorError", "ServerGitIntegrator"]
