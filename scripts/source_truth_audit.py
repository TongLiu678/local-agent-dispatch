#!/usr/bin/env python3
"""Build a deterministic, privacy-safe Git source-truth report.

The report is intentionally read-only.  It records repository-relative
candidate paths and hashes public candidates, while naming denied runtime or
credential-like candidates without inspecting their contents.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
from typing import Any, Iterable


DENIED_PREFIXES = (
    ".git/",
    ".hermes/",
    ".codebase-memory/",
    ".lad/",
    "runs/",
    "logs/",
    "artifacts/",
    "task-packets/",
    "server-home/",
    "remote-workspace/",
    "downloads/",
    ".lad-agent-results/",
    "build/",
    "dist/",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
    ".egg-info/",
)
DENIED_NAMES = {"AGENTS.md", "audit_report.txt", "hosts.json", "events.jsonl"}
DENIED_PATTERNS = (
    "runtime-state",
    "preflight-state",
    "model-state",
    "compute-state",
    ".env",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".db",
    ".db-wal",
    ".db-shm",
    ".egg-info",
    "snapshot.json",
    "report.json",
    "state.json",
    "task-prompt",
    "runner-summary",
    "._",
)


def _git(repo: pathlib.Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def _safe_relative(value: str) -> str:
    path = pathlib.PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"unsafe repository path: {value!r}")
    return path.as_posix()


def _denied(path: str) -> bool:
    lower = path.lower()
    return (
        path in DENIED_NAMES
        or any(
            path == prefix[:-1] or path.startswith(prefix)
            for prefix in DENIED_PREFIXES
        )
        or any(pattern in lower for pattern in DENIED_PATTERNS)
    )


def _status_rows(repo: pathlib.Path) -> dict[str, str]:
    # Expand untracked directories so a nested public file (for example the
    # current task map) is audited and hashed by its exact relative path.
    # Without this flag Git reports only the containing directory, which makes
    # source-truth checks silently miss files that are about to be published.
    # ``--porcelain`` is the stable machine-readable spelling supported by
    # both current Git and the older Git 2.9 installations on the cluster.
    raw = _git(repo, "status", "--porcelain", "-z", "--untracked-files=all")
    rows: dict[str, str] = {}
    parts = raw.split(b"\0")
    index = 0
    while index < len(parts):
        entry = parts[index]
        index += 1
        if not entry:
            continue
        code = entry[:2].decode("ascii", errors="replace")
        path = entry[3:].decode("utf-8", errors="surrogateescape")
        if code[0] in {"R", "C"} and index < len(parts):
            path = parts[index].decode("utf-8", errors="surrogateescape")
            index += 1
        if code == "??":
            status = "untracked"
        elif "D" in code:
            status = "deleted"
        elif "A" in code:
            status = "added"
        else:
            status = "modified"
        safe_path = _safe_relative(path)
        rows[safe_path] = status
        # Keep the denied directory itself visible as well as its nested
        # contents.  ``--untracked-files=all`` is required for public files,
        # but Git then omits the parent directory entry that the export policy
        # used to report.  Re-add only denied ancestors so ordinary source
        # directories are not fabricated as missing files in the report.
        for parent in pathlib.PurePosixPath(safe_path).parents:
            parent_path = parent.as_posix()
            if parent_path == "." or not _denied(parent_path):
                continue
            rows.setdefault(parent_path, "untracked")
    return rows


def _digest(path: pathlib.Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _is_ancestor(repo: pathlib.Path, ancestor: str, descendant: str) -> bool:
    """Return whether ``ancestor`` is reachable from ``descendant``.

    Git history can be reconciled without making the current checkout point at
    the public release commit (for example, a documented two-parent graft).
    Keep that distinction explicit instead of treating every non-equal SHA as
    an unreconciled fork.
    """
    try:
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return True
    except subprocess.CalledProcessError:
        # Git 1.7 on the shared compute nodes predates the convenience flag.
        # Comparing the merge-base identity is the equivalent read-only test.
        try:
            base = _git(repo, "merge-base", ancestor, descendant).decode().strip()
        except subprocess.CalledProcessError:
            return False
        return base == ancestor


def build_report(
    repo: pathlib.Path | str,
    *,
    public_ref: str | None = None,
    public_head: str | None = None,
    extra_candidates: Iterable[str] = (),
    require_public_ref: bool = False,
    require_reconciled: bool = False,
) -> dict[str, Any]:
    root = pathlib.Path(repo).expanduser().resolve()
    git_root = pathlib.Path(
        _git(root, "rev-parse", "--show-toplevel").decode().strip()
    ).resolve()
    if git_root != root:
        raise ValueError("repo must be the canonical Git root")

    if require_public_ref and not public_ref:
        raise ValueError("public_ref is required for a source-truth gate")

    candidates = _status_rows(root)
    for raw in extra_candidates:
        candidates.setdefault(_safe_relative(raw), "candidate")

    files: list[dict[str, Any]] = []
    denied: list[dict[str, str]] = []
    for relative, status in sorted(candidates.items()):
        if _denied(relative):
            denied.append({"path": relative, "reason": "public_export_policy"})
            continue
        path = root / relative
        if status == "deleted" or not path.is_file():
            files.append({"path": relative, "status": status, "exists": False})
            continue
        resolved = path.resolve()
        if root not in resolved.parents:
            raise ValueError(f"path escapes repository: {relative!r}")
        files.append(
            {
                "path": relative,
                "status": status,
                "exists": True,
                "bytes": path.stat().st_size,
                "sha256": _digest(path),
            }
        )
    local_head = _git(root, "rev-parse", "HEAD").decode().strip()
    dirty = bool(_git(root, "status", "--porcelain").strip())
    public_head_source = "operator_supplied" if public_head else None
    if public_head is None and public_ref:
        try:
            peeled = _git(
                root, "rev-parse", "--verify", f"{public_ref}^{{commit}}"
            ).decode().strip()
        except subprocess.CalledProcessError:
            peeled = None
        if peeled:
            public_head = peeled
            public_head_source = "ref_peeled"
    canonical_state = "public_ref_unresolved"
    public_head_relationship = "unresolved"
    if public_head:
        if public_head == local_head:
            canonical_state = "aligned"
            public_head_relationship = "same_commit"
        elif _is_ancestor(root, public_head, local_head):
            canonical_state = "ancestry_reconciled"
            public_head_relationship = "public_is_ancestor"
        elif _is_ancestor(root, local_head, public_head):
            canonical_state = "local_is_ancestor"
            public_head_relationship = "local_is_ancestor"
        else:
            canonical_state = "diverged_unreconciled"
            public_head_relationship = "unrelated_or_diverged"
    if require_public_ref and public_head is None:
        raise ValueError(f"public ref could not be resolved: {public_ref!r}")
    if require_reconciled and canonical_state not in {
        "aligned",
        "ancestry_reconciled",
    }:
        raise ValueError(
            "source-truth relationship is not reconciled: "
            f"{canonical_state} ({public_head_relationship})"
        )
    report = {
        "schema_version": 1,
        "report_type": "local-agent-dispatch.source_truth",
        "local_head": local_head,
        "public_ref": public_ref,
        "public_head": public_head,
        "public_head_source": public_head_source,
        "canonical_state": canonical_state,
        "public_head_relationship": public_head_relationship,
        "working_tree_dirty": dirty,
        "files": files,
        "denied_candidates": denied,
        "read_only": True,
    }
    # The digest covers the report payload before the digest field itself is
    # added.  This gives private evidence stores a stable integrity check
    # without introducing timestamps or machine-local paths.
    report["report_sha256"] = hashlib.sha256(_canonical(report)).hexdigest()
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--public-ref")
    parser.add_argument("--public-head")
    parser.add_argument(
        "--require-public-ref",
        action="store_true",
        help="fail if --public-ref is missing or cannot be resolved",
    )
    parser.add_argument(
        "--require-reconciled",
        action="store_true",
        help="fail unless the resolved public ref is aligned or an ancestor",
    )
    parser.add_argument("--output", default="-")
    args = parser.parse_args()
    report = build_report(
        args.repo,
        public_ref=args.public_ref,
        public_head=args.public_head,
        require_public_ref=args.require_public_ref,
        require_reconciled=args.require_reconciled,
    )
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output == "-":
        print(text, end="")
    else:
        output = pathlib.Path(args.output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
