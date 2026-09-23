#!/usr/bin/env python3
"""Read-only content and path scrubber for a public Git export.

The scrubber reads a Git ref (or an explicitly requested working tree) and
returns only finding categories, paths, and line numbers.  It never emits the
matched secret/path text.  Synthetic test fixtures may be allowlisted by path,
but remain visible in the report.  A clean report is necessary, not
sufficient, for publication.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import stat
import subprocess
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = 1
REPORT_TYPE = "local-agent-dispatch.public_scrub"
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_REF_BYTES = 1024
GIT_COMMAND_TIMEOUT_SECONDS = 120
MINIMUM_GIT_VERSION = (2, 27, 0)
REV_PARSE_END_OF_OPTIONS_GIT_VERSION = (2, 30, 0)
NO_LAZY_FETCH_GIT_VERSION = (2, 45, 0)
_NO_TRANSPORT_PROTOCOL = "__local_agent_dispatch_no_transport__"
_OBJECT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_GIT_VERSION = re.compile(rb"\Agit version ([0-9]+)\.([0-9]+)(?:\.([0-9]+))?")
_GIT_BASE_PREFIX = (
    "git",
    "--no-replace-objects",
    "--no-optional-locks",
    "-c",
    "protocol.allow=never",
    "-c",
    "core.fsmonitor=",
    "-c",
    "core.untrackedCache=false",
)

_DENIED_PATH = re.compile(
    r"(?:^|/)(?:AGENTS\.md|audit_report\.txt|hosts\.json|events\.jsonl|"
    r"server-home|remote-workspace|downloads|\.hermes|\.codebase-memory|"
    r"\.lad|runtime-state|preflight-state|model-state|compute-state|"
    r"provider-state|host-inventory|private-hosts|runtime-evidence|"
    r"dispatch-evidence|attempt-receipts?|controller-logs?)"
    r"(?:/|$)|(?:^|/)[^/]*\.(?:env|pem|key|p12|pfx|db|db-wal|db-shm|"
    r"sqlite|sqlite3|sqlite-wal|sqlite-shm|pid|log)$|"
    r"(?:^|/)[^/]*(?:receipt|preflight|runtime-evidence|host-inventory)"
    r"[^/]*\.(?:json|jsonl|log|txt)$",
    re.IGNORECASE,
)

# Content allowlists are deliberately path based, visible in the report, and
# limited to directories that are unambiguously synthetic inputs.  This keeps
# ``--allow-path docs`` (or another broad source-tree bypass) from turning a
# publication gate into a no-op.
_SYNTHETIC_ALLOWLIST_ROOTS = (
    pathlib.PurePosixPath("fixtures"),
    pathlib.PurePosixPath("tests/fixtures"),
    pathlib.PurePosixPath("research/fixtures"),
    pathlib.PurePosixPath("research/scenarios"),
)

_UNIX_HOME_PATH = re.compile(
    r"(?<![A-Za-z0-9])/(?:Users|home)/(?P<principal>[A-Za-z0-9._<>-]+)"
    r"(?=$|[/\s\"'`,;:)\]}])"
)
_ROOT_HOME_PATH = re.compile(
    r"(?<![A-Za-z0-9])/root/(?P<principal>[A-Za-z0-9._<>-]+)"
    r"(?=$|[/\s\"'`,;:)\]}])"
)
_WINDOWS_HOME_PATH = re.compile(
    r"(?i)(?<![A-Za-z0-9])[A-Z]:[\\/]Users[\\/]"
    r"(?P<principal>[A-Za-z0-9._<>-]+)(?=$|[\\/\s\"'`,;:)\]}])"
)
_CLUSTER_ABSOLUTE_PATH = re.compile(
    r"(?<![A-Za-z0-9])/(?P<root>data|srv|var/tmp)/"
    r"(?P<principal><[^/\s]+>|[A-Za-z0-9._-]+)(?:/|\b)"
)
_IPV4_CANDIDATE = re.compile(
    r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])"
)
_INTERNAL_DNS = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:local|internal|lan|corp|home|ts\.net)"
    r"(?=$|[\s\"'`,;:/)\]}])"
)

_GENERIC_PATH_PRINCIPALS = frozenset(
    {
        "...",
        "example",
        "fixture",
        "fixtures",
        "lad",
        "lad-controller",
        "lad-lanes",
        "local-agent-dispatch",
        "opencode",
        "opencode-account",
        "opencode-data",
        "opencode-server-home",
        "other",
        "placeholder",
        "project",
        "shared",
        "test",
        "tmp",
        "user",
        "work",
    }
)
_GENERIC_INTERNAL_HOSTS = frozenset(
    {
        "example.local",
        "fake.local",
        "fixture.local",
        "localhost.local",
        "synthetic.local",
        "test.local",
    }
)

# These principals are emitted by the public exporter when it replaces a
# private path component.  Keep this list exact and case-sensitive: accepting
# arbitrary ``example_*`` principals would let a real account with a similar
# name bypass the publication gate.  ``LAD_TEST_TMP`` is the fixed synthetic
# root used by the reproducibility harness.
_PUBLIC_EXPORT_PLACEHOLDER_PRINCIPALS = frozenset(
    {
        "EXAMPLE_001",
        "EXAMPLE_002",
        "EXAMPLE_003",
        "EXAMPLE_004",
        "LAD_TEST_TMP",
    }
)


def _private_network(parts: tuple[int, int, int, int], prefix: int) -> ipaddress.IPv4Network:
    """Build a network without embedding a scrub-triggering address literal."""

    address = ".".join(str(part) for part in parts)
    return ipaddress.ip_network(f"{address}/{prefix}")


_PRIVATE_IPV4_NETWORKS = (
    _private_network((10, 0, 0, 0), 8),
    _private_network((172, 16, 0, 0), 12),
    _private_network((192, 168, 0, 0), 16),
    # The shared-address block is used by CGNAT and by default Tailscale
    # assignments.  It is not RFC1918, but it is still private topology.
    _private_network((100, 64, 0, 0), 10),
)

_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_endpoint",
        re.compile(r"\bconnect\.[A-Za-z0-9-]+\.[A-Za-z0-9.-]+\b"),
    ),
    (
        "ssh_endpoint",
        re.compile(
            r"(?i)(?:\bssh://(?:[^@\s/]+@)?[^/\s]+|"
            r"\b(?:ssh|scp|sftp)\b"
            r"(?:\s+(?:-[A-Za-z0-9][A-Za-z0-9-]*(?:=\S+)?|"
            r"[A-Za-z0-9_=./:\\-]+)){0,12}\s+[^\s@]+@[^\s]+|"
            r"^\s*ssh(?:\s+-\S+(?:\s+\S+)?){0,8}\s+"
            r"(?![-<])[A-Za-z0-9][A-Za-z0-9._-]*\s*$)"
        ),
    ),
    ("private_proxy", re.compile(r"\b127\.0\.0\.1:(?:17897|7897)\b")),
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:[A-Z0-9][A-Z0-9 -]* )?PRIVATE KEY(?: BLOCK)?-----"
        ),
    ),
    (
        "credential_token",
        re.compile(
            r"\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|"
            r"github_pat_[A-Za-z0-9_]{8,}|xox[baprs]-[A-Za-z0-9_-]{8,}|"
            r"AKIA[A-Z0-9]{16})\b"
        ),
    ),
    (
        "bearer_token",
        re.compile(r"\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._-]{12,}", re.I),
    ),
    (
        "credential_assignment",
        re.compile(
            r"\b(?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]"
            r"\s*(?!(?:os\.(?:environ|getenv)|getenv|environ|None)\b)"
            r"(?![A-Za-z_][A-Za-z0-9_.]*\s*\()"
            r"[\"']?[^<>\s\"']{12,}",
            re.I,
        ),
    ),
)


def _is_placeholder_principal(value: str) -> bool:
    normalized = value.strip().strip("<>")
    if value.startswith("<") and value.endswith(">"):
        return True
    if normalized in _PUBLIC_EXPORT_PLACEHOLDER_PRINCIPALS:
        return True
    return normalized.casefold() in _GENERIC_PATH_PRINCIPALS


def _semantic_categories(line: str) -> set[str]:
    """Return privacy categories that require more than a single regex.

    The matched values are intentionally discarded.  Only category, file, and
    line number leave this function through the final report.
    """

    categories: set[str] = set()
    for pattern in (_UNIX_HOME_PATH, _ROOT_HOME_PATH, _WINDOWS_HOME_PATH):
        for match in pattern.finditer(line):
            if not _is_placeholder_principal(match.group("principal")):
                categories.add("private_home_path")
                break

    for match in _CLUSTER_ABSOLUTE_PATH.finditer(line):
        if not _is_placeholder_principal(match.group("principal")):
            categories.add("private_cluster_path")
            break

    for match in _IPV4_CANDIDATE.finditer(line):
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        if any(address in network for network in _PRIVATE_IPV4_NETWORKS):
            categories.add("private_ip")
            break

    for match in _INTERNAL_DNS.finditer(line):
        hostname = match.group(0).casefold()
        if hostname not in _GENERIC_INTERNAL_HOSTS:
            categories.add("internal_hostname")
            break
    return categories


def _git_executable() -> str:
    names = ("git.exe", "git.com") if os.name == "nt" else ("git",)
    for raw_directory in os.environ.get("PATH", "").split(os.pathsep):
        if not raw_directory:
            continue
        directory = pathlib.Path(raw_directory)
        if not directory.is_absolute():
            continue
        for name in names:
            candidate = directory / name
            try:
                if not candidate.is_file():
                    continue
                resolved = candidate.resolve(strict=True)
            except OSError:
                continue
            if not resolved.is_file() or (os.name != "nt" and not os.access(resolved, os.X_OK)):
                continue
            return os.fspath(resolved)
    raise ValueError("git_unavailable")


def _git_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    environment.update(
        {
            "HOME": os.devnull,
            "PATH": os.devnull,
            "XDG_CONFIG_HOME": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_EXEC_PATH": os.devnull,
            "GIT_ALLOW_PROTOCOL": _NO_TRANSPORT_PROTOCOL,
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
            "LC_ALL": "C",
        }
    )
    return environment


def _git_prefix(
    version: tuple[int, int, int], git_executable: str | None = None
) -> tuple[str, ...]:
    executable = git_executable or _git_executable()
    base_prefix = (executable, *_GIT_BASE_PREFIX[1:])
    if version >= NO_LAZY_FETCH_GIT_VERSION:
        return (base_prefix[0], "--no-lazy-fetch", *base_prefix[1:])
    return base_prefix


def _require_git_version(git_executable: str | None = None) -> tuple[int, int, int]:
    executable = git_executable or _git_executable()
    try:
        completed = subprocess.run(
            [executable, *_GIT_BASE_PREFIX[1:], "--version"],
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=GIT_COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError("git_command_timeout") from exc
    except OSError as exc:
        raise ValueError("git_unavailable") from exc
    if completed.returncode != 0:
        raise ValueError("unsupported_git_version")
    matched = _GIT_VERSION.match(completed.stdout)
    if matched is None:
        raise ValueError("unsupported_git_version")
    version = tuple(int(part or b"0") for part in matched.groups())
    if version < MINIMUM_GIT_VERSION:
        raise ValueError("unsupported_git_version")
    return version


def _git(
    repo: pathlib.Path,
    *args: str,
    category: str,
    git_prefix: Sequence[str],
) -> bytes:
    try:
        completed = subprocess.run(
            [*git_prefix, *args],
            cwd=repo,
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=GIT_COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError("git_command_timeout") from exc
    except OSError as exc:
        raise ValueError(category) from exc
    if completed.returncode != 0:
        raise ValueError(category)
    return completed.stdout


def _verify_offline_repository(
    repo: pathlib.Path,
    git_version: tuple[int, int, int],
    git_prefix: Sequence[str],
) -> None:
    if git_version >= NO_LAZY_FETCH_GIT_VERSION:
        return
    raw_names = _git(
        repo,
        "config",
        "--list",
        "--name-only",
        "-z",
        category="repository_config_read_failed",
        git_prefix=git_prefix,
    )
    try:
        names = tuple(
            raw_name.decode("utf-8", errors="strict").casefold()
            for raw_name in raw_names.split(b"\0")
            if raw_name
        )
    except UnicodeError as exc:
        raise ValueError("repository_config_read_failed") from exc
    for name in names:
        if name == "extensions.partialclone":
            raise ValueError("unsupported_promisor_repository")
        if name.startswith("remote.") and name.endswith(
            (".promisor", ".partialclonefilter")
        ):
            raise ValueError("unsupported_promisor_repository")


def _resolve_commit(
    repo: pathlib.Path,
    ref: str,
    git_version: tuple[int, int, int],
    git_prefix: Sequence[str],
) -> str:
    try:
        ref_size = len(ref.encode("utf-8", errors="strict")) if isinstance(ref, str) else 0
    except UnicodeError as exc:
        raise ValueError("invalid_ref") from exc
    if (
        not isinstance(ref, str)
        or not ref
        or ref_size > MAX_REF_BYTES
        or ref.startswith("-")
        or any(ord(character) < 32 or ord(character) == 127 for character in ref)
    ):
        raise ValueError("invalid_ref")
    arguments = ["rev-parse", "--verify"]
    if git_version >= REV_PARSE_END_OF_OPTIONS_GIT_VERSION:
        arguments.append("--end-of-options")
    raw = _git(
        repo,
        *arguments,
        f"{ref}^{{commit}}",
        category="invalid_ref",
        git_prefix=git_prefix,
    )
    try:
        commit = raw.decode("ascii", errors="strict").strip()
    except UnicodeError as exc:
        raise ValueError("invalid_ref") from exc
    if not _OBJECT_ID.fullmatch(commit):
        raise ValueError("invalid_ref")
    return commit


def _safe_relative(value: str) -> str:
    if (
        not value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("unsafe_repository_path")
    path = pathlib.PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or not path.parts
    ):
        raise ValueError("unsafe_repository_path")
    return path.as_posix()


def _allowlisted(path: str, prefixes: Iterable[str]) -> bool:
    normalized = path.rstrip("/") + "/"
    return any(
        normalized.startswith(_safe_relative(prefix).rstrip("/") + "/")
        or path == _safe_relative(prefix).rstrip("/")
        for prefix in prefixes
    )


def _validated_allowlist_prefixes(prefixes: Iterable[str]) -> tuple[str, ...]:
    validated: list[str] = []
    for raw in prefixes:
        prefix = pathlib.PurePosixPath(_safe_relative(raw).rstrip("/"))
        allowed = any(
            prefix == root or root in prefix.parents
            for root in _SYNTHETIC_ALLOWLIST_ROOTS
        )
        if not allowed:
            raise ValueError(
                "allowlisted content must be under an explicit synthetic fixture root"
            )
        validated.append(prefix.as_posix())
    return tuple(validated)


def _ref_entries(
    repo: pathlib.Path, commit: str, git_prefix: Sequence[str]
) -> dict[str, dict[str, object]]:
    raw = _git(
        repo,
        "ls-tree",
        "-r",
        "-z",
        "-l",
        "--full-tree",
        commit,
        category="tree_read_failed",
        git_prefix=git_prefix,
    )
    entries: dict[str, dict[str, object]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            mode_raw, kind_raw, oid_raw, size_raw = header.split()
            mode = mode_raw.decode("ascii", errors="strict")
            kind = kind_raw.decode("ascii", errors="strict")
            oid = oid_raw.decode("ascii", errors="strict")
            path = _safe_relative(raw_path.decode("utf-8", errors="strict"))
            size = int(size_raw) if size_raw != b"-" else None
        except (UnicodeError, ValueError) as exc:
            raise ValueError("invalid_tree_entry") from exc
        if path in entries or not _OBJECT_ID.fullmatch(oid) or size is not None and size < 0:
            raise ValueError("invalid_tree_entry")
        entries[path] = {"mode": mode, "kind": kind, "oid": oid, "size": size}
    return entries


def _decode_path_list(raw: bytes) -> list[str]:
    try:
        return sorted(
            _safe_relative(part.decode("utf-8", errors="strict"))
            for part in raw.split(b"\0")
            if part
        )
    except UnicodeError as exc:
        raise ValueError("unsafe_repository_path") from exc


def _worktree_paths(repo: pathlib.Path, git_prefix: Sequence[str]) -> list[str]:
    raw = _git(
        repo,
        "ls-files",
        "-co",
        "--exclude-standard",
        "-z",
        category="worktree_inventory_failed",
        git_prefix=git_prefix,
    )
    return _decode_path_list(raw)


def _ignored_worktree_paths(
    repo: pathlib.Path, git_prefix: Sequence[str]
) -> list[str]:
    """Return ignored untracked paths without reading their contents.

    ``git ls-files -co --exclude-standard`` intentionally omits ignored files.
    That is useful for ordinary source discovery but unsafe at a publication
    boundary: an ignored ``.env`` or runtime directory must be visible to the
    operator instead of silently disappearing from the report.  Keep this
    separate from :func:`_worktree_paths` so the normal tracked/untracked
    inventory remains compatible, and only add path metadata to the report.
    """

    raw = _git(
        repo,
        "ls-files",
        "-o",
        "-i",
        "--exclude-standard",
        "-z",
        category="ignored_inventory_failed",
        git_prefix=git_prefix,
    )
    return _decode_path_list(raw)


class _FileTooLarge(ValueError):
    def __init__(self, size: int):
        self.size = size
        super().__init__("file_too_large")


class _UnsupportedWorktreeEntry(ValueError):
    pass


def _is_at_or_below(path: pathlib.Path, root: pathlib.Path) -> bool:
    current = path
    while True:
        if current.samefile(root):
            return True
        if current.parent == current:
            return False
        current = current.parent


def _worktree_blob(repo: pathlib.Path, relative: str, limit: int) -> bytes:
    path = repo.joinpath(*pathlib.PurePosixPath(relative).parts)
    resolved = path.resolve(strict=True)
    if not _is_at_or_below(resolved, repo):
        raise ValueError("worktree_path_escape")
    before_open = path.lstat()
    if not stat.S_ISREG(before_open.st_mode):
        raise _UnsupportedWorktreeEntry("unsupported_worktree_entry")
    if before_open.st_size > limit:
        raise _FileTooLarge(before_open.st_size)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino)
            != (before_open.st_dev, before_open.st_ino)
        ):
            raise _UnsupportedWorktreeEntry("unsupported_worktree_entry")
        if opened.st_size > limit:
            raise _FileTooLarge(opened.st_size)
        content = handle.read(limit + 1)
        after_read = os.fstat(handle.fileno())
    if len(content) > limit:
        raise _FileTooLarge(len(content))
    if (
        len(content) != opened.st_size
        or after_read.st_size != opened.st_size
        or after_read.st_mtime_ns != opened.st_mtime_ns
        or after_read.st_ctime_ns != opened.st_ctime_ns
    ):
        raise OSError("worktree_file_changed")
    return content


def _ref_blob(
    repo: pathlib.Path, oid: str, expected_size: int, git_prefix: Sequence[str]
) -> bytes:
    content = _git(
        repo,
        "cat-file",
        "blob",
        oid,
        category="blob_read_failed",
        git_prefix=git_prefix,
    )
    if len(content) != expected_size:
        raise ValueError("blob_size_mismatch")
    return content


def build_report(
    repo: pathlib.Path | str,
    *,
    ref: str = "HEAD",
    include_worktree: bool = False,
    allow_path_prefixes: Iterable[str] = (),
    max_file_bytes: int = MAX_FILE_BYTES,
) -> dict[str, Any]:
    try:
        root = pathlib.Path(repo).expanduser().resolve(strict=True)
    except OSError as exc:
        raise ValueError("invalid_repository") from exc
    if not root.is_dir():
        raise ValueError("invalid_repository")
    git_executable = _git_executable()
    git_version = _require_git_version(git_executable)
    git_prefix = _git_prefix(git_version, git_executable)
    raw_git_root = _git(
        root,
        "rev-parse",
        "--show-toplevel",
        category="invalid_repository",
        git_prefix=git_prefix,
    )
    try:
        git_root = pathlib.Path(
            raw_git_root.decode("utf-8", errors="strict").strip()
        ).resolve(strict=True)
    except (OSError, UnicodeError) as exc:
        raise ValueError("invalid_repository") from exc
    if not git_root.samefile(root):
        raise ValueError("repo must be the canonical Git root")
    _verify_offline_repository(root, git_version, git_prefix)
    if max_file_bytes <= 0:
        raise ValueError("max_file_bytes must be positive")
    prefixes = _validated_allowlist_prefixes(allow_path_prefixes)
    ref_entries: dict[str, dict[str, object]] = {}
    commit: str | None = None
    if include_worktree:
        ignored_paths = set(_ignored_worktree_paths(root, git_prefix))
        paths = sorted(set(_worktree_paths(root, git_prefix)) | ignored_paths)
    else:
        ignored_paths = set()
        commit = _resolve_commit(root, ref, git_version, git_prefix)
        ref_entries = _ref_entries(root, commit, git_prefix)
        paths = sorted(ref_entries)
    findings: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for relative in paths:
        path_allowlisted = _allowlisted(relative, prefixes)
        if relative in ignored_paths:
            # An ignored path is outside the normal public candidate set.  It
            # must still be named and remain blocking; path allowlists are for
            # synthetic content fixtures, not for suppressing export policy.
            findings.append(
                {
                    "path": relative,
                    "line": None,
                    "category": "ignored_path",
                    "allowlisted": False,
                }
            )
        if _DENIED_PATH.search(relative):
            finding = {
                "path": relative,
                "line": None,
                "category": "denied_path",
                # Denied paths are never made safe by an allowlist.  The
                # allowlist is intentionally limited to visible synthetic
                # redaction fixtures.
                "allowlisted": False,
            }
            findings.append(finding)
            continue
        if relative in ignored_paths:
            continue
        if include_worktree:
            try:
                content = _worktree_blob(root, relative, max_file_bytes)
            except _FileTooLarge as exc:
                skipped.append(
                    {"path": relative, "reason": "file_too_large", "bytes": exc.size}
                )
                continue
            except _UnsupportedWorktreeEntry:
                skipped.append(
                    {"path": relative, "reason": "unsupported_worktree_entry"}
                )
                continue
            except (OSError, ValueError) as exc:
                skipped.append(
                    {
                        "path": relative,
                        "reason": "read_error",
                        "type": type(exc).__name__,
                    }
                )
                continue
        else:
            entry = ref_entries[relative]
            size = entry["size"]
            if (
                entry["mode"] not in {"100644", "100755"}
                or entry["kind"] != "blob"
                or type(size) is not int
            ):
                skipped.append({"path": relative, "reason": "unsupported_tree_entry"})
                continue
            if size > max_file_bytes:
                skipped.append(
                    {"path": relative, "reason": "file_too_large", "bytes": size}
                )
                continue
            try:
                content = _ref_blob(root, str(entry["oid"]), size, git_prefix)
            except (OSError, ValueError) as exc:
                skipped.append(
                    {
                        "path": relative,
                        "reason": "read_error",
                        "type": type(exc).__name__,
                    }
                )
                continue
        if b"\0" in content:
            skipped.append({"path": relative, "reason": "binary_file"})
            continue
        try:
            text = content.decode("utf-8", errors="strict")
        except UnicodeError:
            skipped.append({"path": relative, "reason": "invalid_utf8"})
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            categories = _semantic_categories(line)
            for category, pattern in _RULES:
                if pattern.search(line):
                    categories.add(category)
            for category in sorted(categories):
                findings.append(
                    {
                        "path": relative,
                        "line": line_number,
                        "category": category,
                        "allowlisted": path_allowlisted,
                    }
                )
    blocked = [row for row in findings if not row["allowlisted"]]
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "report_type": REPORT_TYPE,
        "ref": ref,
        "source_commit": commit,
        "source": "working_tree" if include_worktree else "git_ref",
        "files_scanned": len(paths),
        "findings": findings,
        "skipped": skipped,
        "allowlisted_finding_count": len(findings) - len(blocked),
        "blocking_finding_count": len(blocked),
        "gate": "pass" if not blocked and not skipped else "blocked",
        "read_only": True,
        "matched_text_persisted": False,
    }
    report["report_sha256"] = hashlib.sha256(
        json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--ref", default="HEAD")
    parser.add_argument("--include-worktree", action="store_true")
    parser.add_argument("--allow-path", action="append", default=[])
    parser.add_argument("--output", default="-")
    args = parser.parse_args(argv)
    try:
        report = build_report(
            args.repo,
            ref=args.ref,
            include_worktree=args.include_worktree,
            allow_path_prefixes=args.allow_path,
        )
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        parser.error(str(exc))
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output == "-":
        print(text, end="")
    else:
        output = pathlib.Path(args.output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    return 0 if report["gate"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
