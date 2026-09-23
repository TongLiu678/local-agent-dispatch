#!/usr/bin/env python3
"""Project-scoped placement and non-interference contract.

``ProjectCapsule`` is the boundary between a project and a shared cluster.
It binds identity, controller-local SQLite, server data/artifact roots, a
node-local temporary root, scheduler ownership, write scopes and resource
limits.  This module only validates metadata; it never creates directories,
opens SQLite, starts a scheduler, or copies credentials.

The controller database is deliberately stricter than workload data: a
candidate must carry current evidence that it is persistent and known-local.
Unknown or shared storage is returned as ``controller_storage_unavailable``.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
from collections.abc import Mapping, Sequence
from typing import Any


SCHEMA_VERSION = 1
_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHARED_FS = {
    "9p",
    "afs",
    "ceph",
    "cifs",
    "fuse.sshfs",
    "glusterfs",
    "gpfs",
    "lustre",
    "nfs",
    "nfs4",
    "smb3",
    "sshfs",
    "virtiofs",
}
_LOCALITY_VALUES = {"known-local", "local", "local_candidate", "memory"}
_ROOT_FIELDS = ("controller_db_path", "data_root", "artifact_root", "tmp_root", "log_root")
_SENSITIVE_KEY = re.compile(
    r"(?:token|secret|password|api[_-]?key|credential|authorization|private[_-]?key|auth\.json)",
    re.IGNORECASE,
)
_PATH_KEYS = {"cwd", "workdir", "working_directory", "default_cwd"}


class CapsuleError(ValueError):
    """Raised when a capsule cannot be safely bound to a project."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    except (TypeError, ValueError) as exc:
        raise CapsuleError("capsule contains non-JSON data") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise CapsuleError(f"{field} is invalid")
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise CapsuleError(f"{field} must be a sha256:<64 lowercase hex> digest")
    return value


def _reject_sensitive(value: Any, path: str = "capsule") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            if _SENSITIVE_KEY.search(key_text):
                raise CapsuleError(f"{path}: sensitive field is not allowed: {key_text}")
            if key_text in _PATH_KEYS:
                if not isinstance(child, str) or child in {"", ".", "default", "<cwd>"}:
                    raise CapsuleError(f"{path}.{key_text}: default cwd is not allowed")
            if key_text.lower() in {"image_tag", "mutable_image_tag"}:
                raise CapsuleError(f"{path}.{key_text}: mutable image tag is not allowed")
            _reject_sensitive(child, f"{path}.{key_text}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_sensitive(child, f"{path}[{index}]")


def _absolute_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise CapsuleError(f"{field} must be a non-empty absolute path")
    path = pathlib.Path(value)
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise CapsuleError(f"{field} must be an absolute normalized path")
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise CapsuleError(f"{field} cannot be resolved") from exc
    if str(resolved) == str(pathlib.Path.cwd().resolve()):
        raise CapsuleError(f"{field} must not use the default cwd")
    if any(part.lower() == "auth.json" for part in resolved.parts):
        raise CapsuleError(f"{field} must not point into auth.json")
    return str(resolved)


def _scope(value: Any, field: str = "write_scope") -> str:
    if not isinstance(value, str) or not value.strip():
        raise CapsuleError(f"{field} must be a non-empty relative path")
    raw = value.replace("\\", "/")
    path = pathlib.PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise CapsuleError(f"{field} must be a normalized relative path")
    return path.as_posix()


def _prefix(left: pathlib.PurePosixPath, right: pathlib.PurePosixPath) -> bool:
    return len(left.parts) <= len(right.parts) and left.parts == right.parts[: len(left.parts)]


def write_scope_conflicts(scopes: Sequence[str]) -> list[tuple[str, str]]:
    """Return all duplicate/prefix-conflicting normalized write scopes."""

    normalized = sorted({_scope(scope) for scope in scopes})
    paths = [(scope, pathlib.PurePosixPath(scope)) for scope in normalized]
    conflicts: list[tuple[str, str]] = []
    for index, (left, left_path) in enumerate(paths):
        for right, right_path in paths[index + 1 :]:
            if _prefix(left_path, right_path) or _prefix(right_path, left_path):
                conflicts.append((left, right))
    return conflicts


def _mount_row(mount_report: Mapping[str, Any], field: str) -> Mapping[str, Any]:
    value = mount_report.get(field)
    if isinstance(value, Mapping):
        return value
    # A direct SQLite admission report is accepted for the controller field.
    if field == "controller_db_path" and any(
        key in mount_report for key in ("allowed", "locality", "fs_type", "shared")
    ):
        return mount_report
    return {}


def _is_known_local(row: Mapping[str, Any]) -> bool:
    if row.get("shared") is True:
        return False
    if row.get("allowed") is False:
        return False
    if row.get("known_local") is True:
        return True
    locality = str(row.get("locality") or row.get("storage_class") or "").lower()
    if locality in _LOCALITY_VALUES:
        return True
    fs_type = str(row.get("fs_type") or "").lower()
    if fs_type in _SHARED_FS:
        return False
    # The existing resource_admission report calls a known local Linux mount
    # ``local_candidate`` and marks it with complete mount evidence.
    return row.get("evidence") == "complete" and bool(fs_type)


def _is_node_local_tmp(path: str, row: Mapping[str, Any]) -> bool:
    if row.get("shared") is True or row.get("allowed") is False:
        return False
    if row.get("known_local") is True:
        return True
    locality = str(row.get("locality") or row.get("storage_class") or "").lower()
    if locality in _LOCALITY_VALUES:
        return True
    # A node-local tmp path is a safe convention only when no contradictory
    # mount evidence exists.  /data, /home and project roots are not inferred.
    return path == "/tmp" or path.startswith("/tmp/") or path == "/var/tmp" or path.startswith("/var/tmp/") or path == "/dev/shm" or path.startswith("/dev/shm/")


def _persistent(row: Mapping[str, Any]) -> bool:
    return row.get("persistent") is True or row.get("durable") is True or row.get("storage_class") in {"local", "known-local"}


def _is_project_scoped_shared(
    row: Mapping[str, Any], *, project_id: str, path: str
) -> bool:
    """Return whether a shared data path has an explicit project namespace.

    Shared data mounts are useful on a cluster (for example a large NFS
    ``/data`` volume), but a bare ``shared=true`` fact is not an isolation
    boundary.  The preflight must therefore attest both the namespace and the
    project identity.  The path check is intentionally segment-aware so a
    project named ``lad`` cannot accidentally match ``lad-other``.
    """

    if row.get("shared") is not True or row.get("project_scoped") is not True:
        return False
    scoped_project = row.get("project_id") or row.get("namespace_project_id")
    if scoped_project != project_id:
        return False
    try:
        return project_id in pathlib.PurePosixPath(path).parts
    except (TypeError, ValueError):
        return False


def build_capsule(*, project_id: str, workspace_id: str, generation: int) -> dict[str, Any]:
    """Build an identity-only capsule skeleton awaiting live path binding.

    Paths, source-tree and mount digests are intentionally omitted: they are
    environment facts and cannot be guessed from project identity.  The
    returned ``status=unbound`` object is useful for compiling a plan but is
    not admissible for a live controller until filled and validated.
    """

    project = _id(project_id, "project_id")
    workspace = _id(workspace_id, "workspace_id")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise CapsuleError("capsule_generation must be a positive integer")
    identity = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project,
        "workspace_id": workspace,
        "capsule_generation": generation,
        "status": "unbound",
    }
    return {
        **identity,
        "capsule_spec_digest": _digest(identity),
        "write_scopes": [],
        "resource_limits": {},
    }


def validate_capsule(
    capsule: Mapping[str, Any], *, mount_report: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate a fully bound capsule and return a flattened report.

    The report includes ``capsule`` for callers that want the normalized
    object and repeats its fields at the top level for compatibility with the
    repository's existing evidence validators.  Any missing or unsafe fact
    raises ``CapsuleError``; no live track should continue after such a gate.
    """

    if not isinstance(capsule, Mapping):
        raise CapsuleError("capsule must be an object")
    _reject_sensitive(capsule)
    required = (
        "schema_version",
        "project_id",
        "workspace_id",
        "capsule_generation",
        "capsule_spec_digest",
        "source_tree_digest",
        "controller_db_path",
        "controller_db_mount_digest",
        "data_root",
        "artifact_root",
        "tmp_root",
        "log_root",
        "scheduler_backend",
        "write_scopes",
        "resource_limits",
    )
    missing = [field for field in required if field not in capsule]
    if missing:
        raise CapsuleError("capsule missing: " + ",".join(missing))
    if capsule.get("schema_version") != SCHEMA_VERSION:
        raise CapsuleError("capsule schema_version is unsupported")
    project = _id(capsule.get("project_id"), "project_id")
    workspace = _id(capsule.get("workspace_id"), "workspace_id")
    generation = capsule.get("capsule_generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise CapsuleError("capsule_generation must be a positive integer")
    _sha256(capsule.get("capsule_spec_digest"), "capsule_spec_digest")
    _sha256(capsule.get("source_tree_digest"), "source_tree_digest")
    _sha256(capsule.get("controller_db_mount_digest"), "controller_db_mount_digest")
    normalized_paths = {field: _absolute_path(capsule.get(field), field) for field in _ROOT_FIELDS}

    controller_mount = _mount_row(mount_report, "controller_db_path")
    if not controller_mount or not _is_known_local(controller_mount) or not _persistent(controller_mount):
        raise CapsuleError("controller_storage_unavailable")
    tmp_mount = _mount_row(mount_report, "tmp_root")
    if not _is_node_local_tmp(normalized_paths["tmp_root"], tmp_mount):
        raise CapsuleError("tmp_root must be node-local")
    for field in ("data_root", "artifact_root", "log_root"):
        row = _mount_row(mount_report, field)
        if not row:
            raise CapsuleError(f"{field} mount evidence unknown")
        if row and row.get("allowed") is False:
            raise CapsuleError(f"{field} mount is not admissible")
        if row and row.get("shared") is True:
            if not _is_project_scoped_shared(
                row, project_id=project, path=normalized_paths[field]
            ):
                raise CapsuleError(f"{field} shared mount lacks project scope")

    backend = capsule.get("scheduler_backend")
    if not isinstance(backend, (str, Mapping)) or (isinstance(backend, str) and not backend.strip()):
        raise CapsuleError("scheduler_backend must be a non-empty string or object")
    if isinstance(backend, str) and backend.lower() in {"interactive", "default", "unknown"}:
        raise CapsuleError("scheduler_backend must be explicit")

    raw_scopes = capsule.get("write_scopes")
    if not isinstance(raw_scopes, (list, tuple)) or not raw_scopes:
        raise CapsuleError("write_scopes must be a non-empty list")
    scopes = [_scope(item, f"write_scopes[{index}]") for index, item in enumerate(raw_scopes)]
    conflicts = write_scope_conflicts(scopes)
    if conflicts:
        raise CapsuleError("write_scopes overlap: " + repr(conflicts))
    limits = capsule.get("resource_limits")
    if not isinstance(limits, Mapping):
        raise CapsuleError("resource_limits must be an object")
    for key, value in limits.items():
        if not isinstance(key, str) or not key or _SENSITIVE_KEY.search(key):
            raise CapsuleError("resource_limits contains a sensitive key")
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            raise CapsuleError(f"resource_limits.{key} must be scalar")
        if isinstance(value, (int, float)) and value < 0:
            raise CapsuleError(f"resource_limits.{key} must be non-negative")

    normalized: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project,
        "workspace_id": workspace,
        "capsule_generation": generation,
        "capsule_spec_digest": capsule["capsule_spec_digest"],
        "source_tree_digest": capsule["source_tree_digest"],
        **normalized_paths,
        "controller_db_mount_digest": capsule["controller_db_mount_digest"],
        "scheduler_backend": dict(backend) if isinstance(backend, Mapping) else backend,
        "write_scopes": sorted(set(scopes)),
        "resource_limits": dict(limits),
    }
    for optional in ("status", "host_id", "scheduler", "runtime", "metadata"):
        if optional in capsule:
            value = capsule[optional]
            if optional in {"scheduler", "runtime", "metadata"} and not isinstance(value, Mapping):
                raise CapsuleError(f"{optional} must be an object")
            normalized[optional] = dict(value) if isinstance(value, Mapping) else value
    result: dict[str, Any] = {
        "valid": True,
        "errors": [],
        "warnings": [],
        "capsule": normalized,
    }
    result.update(normalized)
    return result


def _capsule_path_values(capsule: Mapping[str, Any]) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for field in _ROOT_FIELDS:
        value = capsule.get(field)
        if isinstance(value, str) and value.startswith("/"):
            try:
                values.append((field, str(pathlib.Path(value).resolve(strict=False))))
            except (OSError, RuntimeError):
                continue
    return values


def validate_noninterference(left: Mapping[str, Any], right: Mapping[str, Any]) -> dict[str, Any]:
    """Compare two capsules without starting either project."""

    conflicts: list[dict[str, str]] = []
    if left.get("project_id") == right.get("project_id") or left.get("workspace_id") == right.get("workspace_id"):
        conflicts.append({"kind": "identity", "left": str(left.get("project_id")), "right": str(right.get("project_id"))})
    left_paths = _capsule_path_values(left)
    right_paths = _capsule_path_values(right)
    for left_field, left_value in left_paths:
        left_path = pathlib.Path(left_value)
        for right_field, right_value in right_paths:
            right_path = pathlib.Path(right_value)
            if left_path == right_path or left_path in right_path.parents or right_path in left_path.parents:
                conflicts.append({"kind": "path", "left": left_field, "right": right_field})
    left_scopes = left.get("write_scopes") if isinstance(left.get("write_scopes"), (list, tuple)) else []
    right_scopes = right.get("write_scopes") if isinstance(right.get("write_scopes"), (list, tuple)) else []
    for left_scope in left_scopes:
        for right_scope in right_scopes:
            try:
                left_path = pathlib.PurePosixPath(_scope(left_scope))
                right_path = pathlib.PurePosixPath(_scope(right_scope))
            except CapsuleError:
                conflicts.append({"kind": "invalid_write_scope", "left": str(left_scope), "right": str(right_scope)})
                continue
            if _prefix(left_path, right_path) or _prefix(right_path, left_path):
                conflicts.append({"kind": "write_scope", "left": left_path.as_posix(), "right": right_path.as_posix()})
    return {
        "valid": not conflicts,
        "left_project_id": left.get("project_id"),
        "right_project_id": right.get("project_id"),
        "conflicts": conflicts,
        "reasons": [] if not conflicts else ["project_noninterference_violation"],
    }


def select_controller_db_path(candidates: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
    """Select the best persistent, known-local controller DB candidate.

    No candidate is silently guessed.  A block report is returned so callers
    can show the exact ``controller_storage_unavailable`` reason in the
    cockpit without opening a database on the wrong filesystem.
    """

    eligible: list[tuple[int, str, dict[str, Any]]] = []
    rejected: list[dict[str, Any]] = []
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, Mapping):
            rejected.append({"index": index, "reason": "candidate_not_object"})
            continue
        path = candidate.get("path") or candidate.get("controller_db_path")
        try:
            normalized_path = _absolute_path(path, "controller_db_path")
        except CapsuleError as exc:
            rejected.append({"index": index, "reason": str(exc)})
            continue
        if not _is_known_local(candidate):
            rejected.append({"index": index, "path": normalized_path, "reason": "not_known_local"})
            continue
        if not _persistent(candidate):
            rejected.append({"index": index, "path": normalized_path, "reason": "not_persistent"})
            continue
        priority = candidate.get("priority", index)
        if isinstance(priority, bool) or not isinstance(priority, int):
            priority = index
        row = dict(candidate)
        row["path"] = normalized_path
        row["decision"] = "admit"
        row["storage_role"] = "controller-local"
        eligible.append((priority, normalized_path, row))
    if not eligible:
        return {
            "valid": False,
            "decision": "block",
            "error": "controller_storage_unavailable",
            "reasons": ["controller_storage_unavailable"],
            "rejected": rejected,
        }
    _, _, selected = sorted(eligible, key=lambda item: (item[0], item[1]))[0]
    selected["valid"] = True
    selected["rejected"] = rejected
    return selected


__all__ = [
    "CapsuleError",
    "build_capsule",
    "validate_capsule",
    "validate_noninterference",
    "write_scope_conflicts",
    "select_controller_db_path",
]
