#!/usr/bin/env python3
"""Create a deterministic, offline public source snapshot from one Git ref.

The exporter reads Git objects directly, never runs exported content, never
contacts a remote, and never writes Git state.  Its JSON result deliberately
contains only bounded categories, counts, and hashes.  A private policy may
contain literal values to redact, but those values are never copied into the
result or an exception message.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import unicodedata
from typing import Any, Iterable, Mapping, Sequence


POLICY_TYPE = "local-agent-dispatch.public_export_policy"
MAX_POLICY_BYTES = 1024 * 1024
MAX_POLICY_ITEMS = 512
MAX_PATH_BYTES = 1024
MAX_LITERAL_BYTES = 4096
MAX_EXPECTED_PER_RULE = 10_000
MAX_TOTAL_EXPECTED = 100_000
MAX_REPLACEMENT_FILE_BYTES = 64 * 1024 * 1024
GIT_COMMAND_TIMEOUT_SECONDS = 120
MINIMUM_GIT_VERSION = (2, 27, 0)
REV_PARSE_END_OF_OPTIONS_GIT_VERSION = (2, 30, 0)
NO_LAZY_FETCH_GIT_VERSION = (2, 45, 0)
_NO_TRANSPORT_PROTOCOL = "__local_agent_dispatch_no_transport__"

_SAFE_CATEGORY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_OBJECT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_GIT_VERSION = re.compile(rb"\Agit version ([0-9]+)\.([0-9]+)(?:\.([0-9]+))?")
_WINDOWS_FORBIDDEN = frozenset('<>:"\\|?*')
_WINDOWS_DEVICE_DIGIT_TRANSLATION = str.maketrans({"¹": "1", "²": "2", "³": "3"})
_WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul", "clock$", "conin$", "conout$"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)
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


class PublicExportError(ValueError):
    """A deliberately redacted, stable public-export failure."""

    def __init__(self, category: str):
        if not _SAFE_CATEGORY.fullmatch(category):
            category = "internal_error"
        self.category = category
        super().__init__(category)


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - exercised by argparse
        del message
        raise PublicExportError("invalid_arguments")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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
    raise PublicExportError("git_unavailable")


def _git_environment() -> dict[str, str]:
    # Git's repository-routing, config-injection, tracing, and Windows
    # redirection variables can silently change the repository being read or
    # create files outside the export.  Git itself is resolved to an absolute
    # path before this environment is used, so seal PATH and GIT_EXEC_PATH too:
    # even a repository-controlled foreign-VCS name cannot find a remote helper.
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    environment.update(
        {
            # Git 2.27 predates GIT_CONFIG_GLOBAL.  Point its HOME/XDG lookup
            # at the platform null device as well as setting the newer knobs.
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
        raise PublicExportError("git_command_timeout") from exc
    except OSError as exc:
        raise PublicExportError("git_unavailable") from exc
    if completed.returncode != 0:
        raise PublicExportError("unsupported_git_version")
    matched = _GIT_VERSION.match(completed.stdout)
    if matched is None:
        raise PublicExportError("unsupported_git_version")
    version = tuple(int(part or b"0") for part in matched.groups())
    if version < MINIMUM_GIT_VERSION:
        raise PublicExportError("unsupported_git_version")
    return version


def _git(
    repo: pathlib.Path,
    *arguments: str,
    category: str,
    git_prefix: Sequence[str],
) -> bytes:
    try:
        completed = subprocess.run(
            [*git_prefix, *arguments],
            cwd=repo,
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=GIT_COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise PublicExportError("git_command_timeout") from exc
    except OSError as exc:
        raise PublicExportError(category) from exc
    if completed.returncode != 0:
        raise PublicExportError(category)
    return completed.stdout


def _duplicate_rejecting_object(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PublicExportError("invalid_policy")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    del value
    raise PublicExportError("invalid_policy")


def _safe_repository_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise PublicExportError("invalid_policy")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise PublicExportError("invalid_policy") from exc
    if len(encoded) > MAX_PATH_BYTES:
        raise PublicExportError("invalid_policy")
    if value.startswith("/") or any(character in _WINDOWS_FORBIDDEN for character in value):
        raise PublicExportError("invalid_policy")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise PublicExportError("invalid_policy")
    pure = pathlib.PurePosixPath(value)
    if pure.is_absolute() or pure.as_posix() != value or not pure.parts:
        raise PublicExportError("invalid_policy")
    for component in pure.parts:
        if (
            component in {"", ".", ".."}
            or component.startswith(" ")
            or component.endswith((" ", "."))
        ):
            raise PublicExportError("invalid_policy")
        if len(component.encode("utf-8")) > 255:
            raise PublicExportError("invalid_policy")
        base = (
            component.split(".", 1)[0]
            .casefold()
            .translate(_WINDOWS_DEVICE_DIGIT_TRANSLATION)
        )
        if base in _WINDOWS_RESERVED or component.casefold() == ".git":
            raise PublicExportError("invalid_policy")
    return value


def _safe_tree_path(raw: bytes) -> str:
    try:
        value = raw.decode("utf-8", errors="strict")
        return _safe_repository_path(value)
    except (UnicodeError, PublicExportError) as exc:
        raise PublicExportError("unsafe_repository_path") from exc


def _literal(value: object, *, allow_empty: bool) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise PublicExportError("invalid_policy")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise PublicExportError("invalid_policy") from exc
    if len(encoded) > MAX_LITERAL_BYTES or "\x00" in value:
        raise PublicExportError("invalid_policy")
    return value


def _string_list(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > MAX_POLICY_ITEMS:
        raise PublicExportError("invalid_policy")
    paths = tuple(_safe_repository_path(item) for item in value)
    if len(set(paths)) != len(paths):
        raise PublicExportError("invalid_policy")
    return paths


def _is_at_or_below(path: pathlib.Path, root: pathlib.Path) -> bool:
    current = path
    while True:
        if current.samefile(root):
            return True
        if current.parent == current:
            return False
        current = current.parent


def _decode_git_directory(repo: pathlib.Path, raw: bytes) -> pathlib.Path:
    try:
        text = raw.decode("utf-8", errors="strict").strip()
    except UnicodeError as exc:
        raise PublicExportError("invalid_repository") from exc
    if not text or any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise PublicExportError("invalid_repository")
    candidate = pathlib.Path(text)
    if not candidate.is_absolute():
        candidate = repo / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise PublicExportError("invalid_repository") from exc
    if not resolved.is_dir():
        raise PublicExportError("invalid_repository")
    return resolved


def _repository_metadata_directories(
    repo: pathlib.Path, git_prefix: Sequence[str]
) -> tuple[pathlib.Path, ...]:
    git_dir = _decode_git_directory(
        repo,
        _git(
            repo,
            "rev-parse",
            "--absolute-git-dir",
            category="invalid_repository",
            git_prefix=git_prefix,
        ),
    )
    common_dir = _decode_git_directory(
        repo,
        _git(
            repo,
            "rev-parse",
            "--git-common-dir",
            category="invalid_repository",
            git_prefix=git_prefix,
        ),
    )
    return tuple(dict.fromkeys((git_dir, common_dir)))


def _canonical_policy_path(
    path: pathlib.Path | str,
    *,
    repo: pathlib.Path,
    repository_metadata: Sequence[pathlib.Path],
    destination: pathlib.Path,
) -> pathlib.Path:
    raw_path = pathlib.Path(path).expanduser()
    try:
        final_component_is_symlink = raw_path.is_symlink()
        resolved = raw_path.resolve(strict=True)
    except OSError as exc:
        raise PublicExportError("invalid_policy") from exc
    if any(_is_at_or_below(resolved, root) for root in repository_metadata):
        raise PublicExportError("policy_inside_git_metadata")
    if _is_at_or_below(resolved, repo):
        raise PublicExportError("policy_inside_source")
    if os.path.lexists(destination) and _is_at_or_below(resolved, destination):
        raise PublicExportError("policy_inside_destination")
    if final_component_is_symlink or not resolved.is_file():
        raise PublicExportError("invalid_policy")
    return resolved


def _load_policy(path: pathlib.Path | str) -> tuple[dict[str, Any], str]:
    raw_path = pathlib.Path(path).expanduser()
    try:
        before_open = raw_path.lstat()
        if not stat.S_ISREG(before_open.st_mode):
            raise PublicExportError("invalid_policy")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(raw_path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino)
                != (before_open.st_dev, before_open.st_ino)
                or opened.st_size <= 0
                or opened.st_size > MAX_POLICY_BYTES
            ):
                raise PublicExportError("invalid_policy")
            raw = handle.read(MAX_POLICY_BYTES + 1)
            after_read = os.fstat(handle.fileno())
        if (
            len(raw) != opened.st_size
            or after_read.st_size != opened.st_size
            or after_read.st_mtime_ns != opened.st_mtime_ns
            or after_read.st_ctime_ns != opened.st_ctime_ns
        ):
            raise PublicExportError("invalid_policy")
        text = raw.decode("utf-8", errors="strict")
        parsed = json.loads(
            text,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_json_constant,
        )
    except PublicExportError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PublicExportError("invalid_policy") from exc
    if not isinstance(parsed, dict):
        raise PublicExportError("invalid_policy")
    required = {
        "schema_version",
        "policy_type",
        "exclude_paths",
        "exclude_prefixes",
        "literal_replacements",
    }
    if set(parsed) != required:
        raise PublicExportError("invalid_policy")
    if type(parsed["schema_version"]) is not int or parsed["schema_version"] != 1:
        raise PublicExportError("invalid_policy")
    if parsed["policy_type"] != POLICY_TYPE:
        raise PublicExportError("invalid_policy")
    exclude_paths = _string_list(parsed["exclude_paths"])
    exclude_prefixes = _string_list(parsed["exclude_prefixes"])
    for left_index, left in enumerate(exclude_prefixes):
        for right in exclude_prefixes[left_index + 1 :]:
            if left.startswith(right + "/") or right.startswith(left + "/"):
                raise PublicExportError("invalid_policy")
    for path_value in exclude_paths:
        if any(path_value.startswith(prefix + "/") for prefix in exclude_prefixes):
            raise PublicExportError("invalid_policy")
    raw_replacements = parsed["literal_replacements"]
    if not isinstance(raw_replacements, list) or len(raw_replacements) > MAX_POLICY_ITEMS:
        raise PublicExportError("invalid_policy")
    replacements: list[dict[str, Any]] = []
    expected_total = 0
    for rule in raw_replacements:
        if not isinstance(rule, dict) or set(rule) != {
            "path",
            "match",
            "replacement",
            "expected_count",
        }:
            raise PublicExportError("invalid_policy")
        path_value = _safe_repository_path(rule["path"])
        match = _literal(rule["match"], allow_empty=False)
        replacement = _literal(rule["replacement"], allow_empty=True)
        expected = rule["expected_count"]
        if type(expected) is not int or not 1 <= expected <= MAX_EXPECTED_PER_RULE:
            raise PublicExportError("invalid_policy")
        if match == replacement:
            raise PublicExportError("invalid_policy")
        expected_total += expected
        if expected_total > MAX_TOTAL_EXPECTED:
            raise PublicExportError("invalid_policy")
        replacements.append(
            {
                "path": path_value,
                "match": match,
                "replacement": replacement,
                "expected_count": expected,
            }
        )
    normalized: dict[str, Any] = {
        "schema_version": 1,
        "policy_type": POLICY_TYPE,
        "exclude_paths": list(exclude_paths),
        "exclude_prefixes": list(exclude_prefixes),
        "literal_replacements": replacements,
    }
    return normalized, _sha256(_canonical_json(normalized))


def _canonical_repo(
    repo: pathlib.Path | str, git_prefix: Sequence[str]
) -> pathlib.Path:
    try:
        root = pathlib.Path(repo).expanduser().resolve(strict=True)
    except OSError as exc:
        raise PublicExportError("invalid_repository") from exc
    if not root.is_dir():
        raise PublicExportError("invalid_repository")
    raw_git_root = _git(
        root,
        "rev-parse",
        "--show-toplevel",
        category="invalid_repository",
        git_prefix=git_prefix,
    )
    try:
        git_root = pathlib.Path(raw_git_root.decode("utf-8", errors="strict").strip()).resolve(
            strict=True
        )
    except (OSError, UnicodeError) as exc:
        raise PublicExportError("invalid_repository") from exc
    if git_root != root:
        raise PublicExportError("repository_not_canonical_root")
    return root


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
        raise PublicExportError("repository_config_read_failed") from exc
    for name in names:
        if name == "extensions.partialclone":
            raise PublicExportError("unsupported_promisor_repository")
        if name.startswith("remote.") and name.endswith(
            (".promisor", ".partialclonefilter")
        ):
            raise PublicExportError("unsupported_promisor_repository")


def _resolve_commit(
    repo: pathlib.Path,
    ref: str,
    git_version: tuple[int, int, int],
    git_prefix: Sequence[str],
) -> tuple[str, str, int]:
    try:
        ref_size = len(ref.encode("utf-8", errors="strict")) if isinstance(ref, str) else 0
    except UnicodeError as exc:
        raise PublicExportError("invalid_ref") from exc
    if (
        not isinstance(ref, str)
        or not ref
        or ref_size > MAX_PATH_BYTES
        or ref.startswith("-")
        or any(ord(character) < 32 or ord(character) == 127 for character in ref)
    ):
        raise PublicExportError("invalid_ref")
    verify_arguments = ["--verify"]
    # Git 2.30 introduced rev-parse's explicit option terminator.  For the
    # supported 2.27-2.29 range the leading-dash rejection above provides the
    # equivalent option-injection boundary.
    if git_version >= REV_PARSE_END_OF_OPTIONS_GIT_VERSION:
        verify_arguments.append("--end-of-options")
    commit_raw = _git(
        repo,
        "rev-parse",
        *verify_arguments,
        f"{ref}^{{commit}}",
        category="invalid_ref",
        git_prefix=git_prefix,
    )
    try:
        commit = commit_raw.decode("ascii", errors="strict").strip()
    except UnicodeError as exc:
        raise PublicExportError("invalid_ref") from exc
    if not _OBJECT_ID.fullmatch(commit):
        raise PublicExportError("invalid_ref")
    tree_raw = _git(
        repo,
        "rev-parse",
        *verify_arguments,
        f"{commit}^{{tree}}",
        category="invalid_ref",
        git_prefix=git_prefix,
    )
    epoch_raw = _git(
        repo,
        "show",
        "-s",
        "--format=%ct",
        commit,
        category="invalid_ref",
        git_prefix=git_prefix,
    )
    try:
        tree = tree_raw.decode("ascii", errors="strict").strip()
        epoch_text = epoch_raw.decode("ascii", errors="strict").strip()
        epoch = int(epoch_text)
    except (UnicodeError, ValueError) as exc:
        raise PublicExportError("invalid_ref") from exc
    if not _OBJECT_ID.fullmatch(tree) or epoch < 0:
        raise PublicExportError("invalid_ref")
    return commit, tree, epoch


def _source_is_dirty(repo: pathlib.Path, git_prefix: Sequence[str]) -> bool:
    status_output = _git(
        repo,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignore-submodules=all",
        category="source_status_failed",
        git_prefix=git_prefix,
    )
    return bool(status_output)


def _tree_entries(
    repo: pathlib.Path, commit: str, git_prefix: Sequence[str]
) -> list[dict[str, str]]:
    raw = _git(
        repo,
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        commit,
        category="tree_read_failed",
        git_prefix=git_prefix,
    )
    entries: list[dict[str, str]] = []
    portable_paths: set[str] = set()
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            mode_raw, kind_raw, oid_raw = header.split(b" ", 2)
            mode = mode_raw.decode("ascii", errors="strict")
            kind = kind_raw.decode("ascii", errors="strict")
            oid = oid_raw.decode("ascii", errors="strict")
        except (ValueError, UnicodeError) as exc:
            raise PublicExportError("invalid_tree_entry") from exc
        if mode == "120000":
            raise PublicExportError("unsupported_symlink")
        if mode == "160000" or kind == "commit":
            raise PublicExportError("unsupported_submodule")
        if mode not in {"100644", "100755"} or kind != "blob" or not _OBJECT_ID.fullmatch(oid):
            raise PublicExportError("unsupported_tree_entry")
        path_value = _safe_tree_path(raw_path)
        portable = "/".join(
            unicodedata.normalize("NFC", component).casefold()
            for component in pathlib.PurePosixPath(path_value).parts
        )
        if portable in portable_paths:
            raise PublicExportError("portable_path_collision")
        portable_paths.add(portable)
        entries.append({"path": path_value, "mode": mode, "oid": oid})
    entries.sort(key=lambda row: row["path"].encode("utf-8"))
    return entries


def _select_entries(
    entries: Sequence[Mapping[str, str]], policy: Mapping[str, Any]
) -> tuple[list[dict[str, str]], int, int]:
    all_paths = {entry["path"] for entry in entries}
    exact = tuple(policy["exclude_paths"])
    prefixes = tuple(policy["exclude_prefixes"])
    for path_value in exact:
        if path_value not in all_paths:
            raise PublicExportError("stale_exclude_path")
    for prefix in prefixes:
        if not any(path.startswith(prefix + "/") for path in all_paths):
            raise PublicExportError("stale_exclude_prefix")
    selected: list[dict[str, str]] = []
    exact_count = 0
    prefix_count = 0
    for entry in entries:
        path_value = entry["path"]
        if path_value in exact:
            exact_count += 1
        elif any(path_value.startswith(prefix + "/") for prefix in prefixes):
            prefix_count += 1
        else:
            selected.append(dict(entry))
    if not selected:
        raise PublicExportError("empty_export")
    selected_paths = {entry["path"] for entry in selected}
    for rule in policy["literal_replacements"]:
        if rule["path"] not in selected_paths:
            raise PublicExportError("replacement_target_unavailable")
    return selected, exact_count, prefix_count


def _blob_size(repo: pathlib.Path, oid: str, git_prefix: Sequence[str]) -> int:
    raw = _git(
        repo,
        "cat-file",
        "-s",
        oid,
        category="blob_read_failed",
        git_prefix=git_prefix,
    )
    try:
        size = int(raw.decode("ascii", errors="strict").strip())
    except (UnicodeError, ValueError) as exc:
        raise PublicExportError("blob_read_failed") from exc
    if size < 0:
        raise PublicExportError("blob_read_failed")
    return size


def _blob(repo: pathlib.Path, oid: str, git_prefix: Sequence[str]) -> bytes:
    return _git(
        repo,
        "cat-file",
        "blob",
        oid,
        category="blob_read_failed",
        git_prefix=git_prefix,
    )


def _replacement_payloads(
    repo: pathlib.Path,
    selected: Sequence[Mapping[str, str]],
    policy: Mapping[str, Any],
    git_prefix: Sequence[str],
) -> tuple[dict[str, bytes], int]:
    by_path = {entry["path"]: entry for entry in selected}
    rules_by_path: dict[str, list[Mapping[str, Any]]] = {}
    for rule in policy["literal_replacements"]:
        rules_by_path.setdefault(rule["path"], []).append(rule)
    transformed: dict[str, bytes] = {}
    occurrence_count = 0
    for path_value, rules in rules_by_path.items():
        entry = by_path[path_value]
        if _blob_size(repo, entry["oid"], git_prefix) > MAX_REPLACEMENT_FILE_BYTES:
            raise PublicExportError("replacement_target_too_large")
        data = _blob(repo, entry["oid"], git_prefix)
        for rule in rules:
            match = rule["match"].encode("utf-8")
            replacement = rule["replacement"].encode("utf-8")
            observed = data.count(match)
            if observed != rule["expected_count"]:
                raise PublicExportError("replacement_count_mismatch")
            data = data.replace(match, replacement)
            occurrence_count += observed
        if any(rule["match"].encode("utf-8") in data for rule in rules):
            raise PublicExportError("replacement_residue")
        transformed[path_value] = data
    return transformed, occurrence_count


def _destination(repo: pathlib.Path, value: pathlib.Path | str) -> pathlib.Path:
    raw = pathlib.Path(value).expanduser()
    try:
        absolute = raw.absolute()
        try:
            _safe_repository_path(absolute.name)
        except PublicExportError as exc:
            raise PublicExportError("invalid_destination_name") from exc
        if os.path.lexists(absolute):
            raise PublicExportError("destination_exists")
        parent = absolute.parent.resolve(strict=True)
    except PublicExportError:
        raise
    except OSError as exc:
        raise PublicExportError("invalid_destination_parent") from exc
    if not parent.is_dir() or absolute.name in {"", ".", ".."}:
        raise PublicExportError("invalid_destination_parent")
    destination = parent / absolute.name
    if _is_at_or_below(parent, repo):
        raise PublicExportError("destination_inside_source")
    if os.path.lexists(destination):
        raise PublicExportError("destination_exists")
    return destination


def _write_raw_blob(
    repo: pathlib.Path,
    oid: str,
    target: pathlib.Path,
    git_prefix: Sequence[str],
) -> None:
    try:
        with target.open("xb") as handle:
            completed = subprocess.run(
                [*git_prefix, "cat-file", "blob", oid],
                cwd=repo,
                env=_git_environment(),
                stdin=subprocess.DEVNULL,
                stdout=handle,
                stderr=subprocess.PIPE,
                check=False,
                timeout=GIT_COMMAND_TIMEOUT_SECONDS,
            )
    except subprocess.TimeoutExpired as exc:
        raise PublicExportError("git_command_timeout") from exc
    except OSError as exc:
        raise PublicExportError("destination_write_failed") from exc
    if completed.returncode != 0:
        raise PublicExportError("blob_read_failed")


def _hash_export(destination: pathlib.Path, entries: Sequence[Mapping[str, str]]) -> str:
    digest = hashlib.sha256()
    digest.update(b"local-agent-dispatch.public-export.v1\0")
    for entry in entries:
        path_bytes = entry["path"].encode("utf-8")
        mode_bytes = entry["mode"].encode("ascii")
        target = destination.joinpath(*pathlib.PurePosixPath(entry["path"]).parts)
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(len(mode_bytes).to_bytes(2, "big"))
        digest.update(mode_bytes)
        size = target.stat().st_size
        digest.update(size.to_bytes(8, "big"))
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _materialize(
    repo: pathlib.Path,
    destination: pathlib.Path,
    entries: Sequence[Mapping[str, str]],
    transformed: Mapping[str, bytes],
    epoch: int,
    git_prefix: Sequence[str],
) -> str:
    created = False
    try:
        destination.mkdir(mode=0o700, exist_ok=False)
        created = True
        directories: set[pathlib.Path] = {destination}
        timestamp_ns = epoch * 1_000_000_000
        for entry in entries:
            relative = pathlib.PurePosixPath(entry["path"])
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            current = target.parent
            while current != destination:
                directories.add(current)
                current = current.parent
            data = transformed.get(entry["path"])
            if data is None:
                _write_raw_blob(repo, entry["oid"], target, git_prefix)
            else:
                try:
                    with target.open("xb") as handle:
                        handle.write(data)
                except OSError as exc:
                    raise PublicExportError("destination_write_failed") from exc
            mode = 0o755 if entry["mode"] == "100755" else 0o644
            os.chmod(target, mode)
            os.utime(target, ns=(timestamp_ns, timestamp_ns))
        export_hash = _hash_export(destination, entries)
        for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
            os.chmod(directory, 0o755)
            os.utime(directory, ns=(timestamp_ns, timestamp_ns))
        return export_hash
    except PublicExportError:
        if created:
            try:
                shutil.rmtree(destination)
            except OSError as exc:
                raise PublicExportError("destination_cleanup_failed") from exc
        raise
    except OSError as exc:
        if created:
            try:
                shutil.rmtree(destination)
            except OSError as cleanup_exc:
                raise PublicExportError("destination_cleanup_failed") from cleanup_exc
        raise PublicExportError("destination_write_failed") from exc


def _success_manifest(
    *,
    commit: str,
    tree: str,
    policy_hash: str,
    export_hash: str,
    dirty_allowed: bool,
    source_count: int,
    exported_count: int,
    exact_rule_count: int,
    prefix_rule_count: int,
    replacement_rule_count: int,
    exact_excluded_count: int,
    prefix_excluded_count: int,
    replacement_occurrence_count: int,
) -> dict[str, object]:
    manifest: dict[str, object] = {
        "categories": {
            "result": "exported",
            "source": "exact_git_commit",
            "source_worktree": "dirty_allowed" if dirty_allowed else "clean",
            "selection": "explicit_closed_policy",
            "transformation": "bounded_literal_replacement",
        },
        "counts": {
            "source_entry_count": source_count,
            "exported_file_count": exported_count,
            "excluded_file_count": exact_excluded_count + prefix_excluded_count,
            "exact_exclusion_rule_count": exact_rule_count,
            "prefix_exclusion_rule_count": prefix_rule_count,
            "exact_excluded_file_count": exact_excluded_count,
            "prefix_excluded_file_count": prefix_excluded_count,
            "replacement_rule_count": replacement_rule_count,
            "replacement_occurrence_count": replacement_occurrence_count,
        },
        "hashes": {
            "source_commit": commit,
            "source_tree": tree,
            "policy_sha256": policy_hash,
            "export_sha256": export_hash,
        },
    }
    manifest_hash = _sha256(_canonical_json(manifest))
    manifest["hashes"]["manifest_sha256"] = manifest_hash  # type: ignore[index]
    return manifest


def export_public_snapshot(
    *,
    repo: pathlib.Path | str,
    ref: str,
    destination: pathlib.Path | str,
    policy_path: pathlib.Path | str,
    allow_dirty_source: bool = False,
) -> dict[str, object]:
    """Export one immutable Git snapshot under a strict, literal-only policy."""

    git_executable = _git_executable()
    git_version = _require_git_version(git_executable)
    git_prefix = _git_prefix(git_version, git_executable)
    root = _canonical_repo(repo, git_prefix)
    repository_metadata = _repository_metadata_directories(root, git_prefix)
    _verify_offline_repository(root, git_version, git_prefix)
    output = _destination(root, destination)
    canonical_policy = _canonical_policy_path(
        policy_path,
        repo=root,
        repository_metadata=repository_metadata,
        destination=output,
    )
    policy, policy_hash = _load_policy(canonical_policy)
    dirty = _source_is_dirty(root, git_prefix)
    if dirty and not allow_dirty_source:
        raise PublicExportError("dirty_source")
    commit, tree, epoch = _resolve_commit(root, ref, git_version, git_prefix)
    entries = _tree_entries(root, commit, git_prefix)
    selected, exact_excluded, prefix_excluded = _select_entries(entries, policy)
    transformed, occurrence_count = _replacement_payloads(
        root, selected, policy, git_prefix
    )
    export_hash = _materialize(
        root, output, selected, transformed, epoch, git_prefix
    )
    return _success_manifest(
        commit=commit,
        tree=tree,
        policy_hash=policy_hash,
        export_hash=export_hash,
        dirty_allowed=dirty,
        source_count=len(entries),
        exported_count=len(selected),
        exact_rule_count=len(policy["exclude_paths"]),
        prefix_rule_count=len(policy["exclude_prefixes"]),
        replacement_rule_count=len(policy["literal_replacements"]),
        exact_excluded_count=exact_excluded,
        prefix_excluded_count=prefix_excluded,
        replacement_occurrence_count=occurrence_count,
    )


def _failure_manifest(category: str) -> dict[str, object]:
    return {
        "categories": {"result": "blocked", "failure": category},
        "counts": {},
        "hashes": {},
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = _SafeArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--allow-dirty-source", action="store_true")
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
        manifest = export_public_snapshot(
            repo=args.repo,
            ref=args.ref,
            destination=args.destination,
            policy_path=args.policy,
            allow_dirty_source=args.allow_dirty_source,
        )
        code = 0
    except PublicExportError as exc:
        manifest = _failure_manifest(exc.category)
        code = 2
    except (OSError, UnicodeError, subprocess.SubprocessError):
        manifest = _failure_manifest("internal_io_error")
        code = 2
    print(_canonical_json(manifest).decode("utf-8"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
