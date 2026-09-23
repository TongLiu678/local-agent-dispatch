#!/usr/bin/env python3
"""A local-only durable worker contract for server-side continuation.

This module deliberately stops at the worker boundary.  It prepares and
persists a safe job manifest, leases a job, records heartbeats and artifact
observations, and recovers expired leases after a crash.  It never invokes a
provider, SSH, a shell, or a model.  A real server adapter can consume the
manifest later, but the default CLI is therefore safe to run in CI and while
the Codex conversation is unavailable.

The spool is a directory rather than a database so this contract can be
installed on a small remote host without additional services.  Writes use an
fsync + atomic replace and a process lock.  The packet itself is never copied
into the manifest: only a digest and allow-listed metadata are persisted, so
inline prompts, environment values, and raw command argv cannot leak through
worker logs or status output.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import hashlib
import json
import os
import pathlib
import re
import sys
import time
import uuid
from collections.abc import Mapping
from typing import Any, Iterator

try:  # direct script import
    from portable_file_lock import exclusive_file_lock
except ImportError:  # pragma: no cover - package-style fallback
    from .portable_file_lock import exclusive_file_lock  # type: ignore

try:  # direct script import
    from dispatch_schema import validate as validate_schema
except ImportError:  # pragma: no cover - package-style fallback
    from .dispatch_schema import validate as validate_schema  # type: ignore

try:  # direct script import
    from remote_envelope import EnvelopeError, EnvelopeStore
except ImportError:  # pragma: no cover - package-style fallback
    from .remote_envelope import EnvelopeError, EnvelopeStore  # type: ignore


SCHEMA_VERSION = 1
MANIFEST_VERSION = 1
_SECRET_KEY = re.compile(r"(?:secret|token|password|api[_-]?key|credential|authorization)", re.I)
_PROCESS_IDENTITY_FIELDS = ("pid", "start_time", "process_group", "run_id", "fence")
_PROCESS_LIVENESS_STATES = {"alive", "exited", "not_found", "unknown"}
_MAX_PROCESS_IDENTITY_TTL_SECONDS = 86400.0
_PATH_FIELDS = {
    "workspace",
    "project_path",
    "worktree_path",
    "prompt_file",
    "result_source_path",
    "output_path",
    "runtime_state_path",
    "watch_path",
    "require_path",
    "remote_workspace",
}
_SAFE_ATTEMPT_FIELDS = {
    "attempt_id",
    "adapter",
    "transport",
    "model",
    "variant",
    "pool_id",
    "provider",
    "host_id",
    "workload_host",
    "execution_host",
}


class WorkerError(ValueError):
    """Raised when a worker packet, lease, or path is unsafe or inconsistent."""


def _utc_at(epoch_seconds: float) -> str:
    """Serialize a timestamp without throwing away short lease intervals."""
    return _dt.datetime.fromtimestamp(float(epoch_seconds), _dt.timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _utc_now() -> str:
    return _utc_at(time.time())


def _parse_time(value: Any) -> float:
    if not isinstance(value, str):
        return 0.0
    try:
        return _dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _safe_key(key: Any) -> bool:
    return not _SECRET_KEY.search(str(key))


def _reject_secret_keys(value: Any, path: str = "packet") -> None:
    """Reject credential-bearing packet fields before any durable write."""
    if isinstance(value, dict):
        for key, child in value.items():
            if not _safe_key(key):
                raise WorkerError(f"{path}: secret-like field is not accepted: {key}")
            _reject_secret_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_keys(child, f"{path}[{index}]")


def _canonical_root(root: pathlib.Path) -> pathlib.Path:
    try:
        return root.expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise WorkerError("invalid filesystem root") from exc


def _confined_path(value: Any, root: pathlib.Path, field: str, *, base: pathlib.Path | None = None) -> pathlib.Path:
    if not isinstance(value, str) or not value.strip():
        raise WorkerError(f"{field} must be a non-empty path")
    raw = pathlib.Path(value).expanduser()
    candidate = raw if raw.is_absolute() else (base or root) / raw
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise WorkerError(f"{field} is not a valid path") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise WorkerError(f"{field} escapes project root") from exc
    return resolved


def _relative(path: pathlib.Path, root: pathlib.Path) -> str:
    try:
        return path.relative_to(root).as_posix() or "."
    except ValueError as exc:  # pragma: no cover - callers validate first
        raise WorkerError("path is outside project root") from exc


def _ensure_project_root(root: pathlib.Path) -> pathlib.Path:
    root = _canonical_root(root)
    if not root.exists() or not root.is_dir():
        raise WorkerError(f"project root must be an existing directory: {root}")
    return root


def validate_packet(packet: dict[str, Any], project_root: pathlib.Path) -> dict[str, Any]:
    """Validate a modern task packet and return a non-sensitive report.

    The report contains relative path names and a digest only.  It is safe to
    print as a CLI result.  No provider or transport is contacted.
    """
    if not isinstance(packet, dict):
        raise WorkerError("task packet must be an object")
    root = _ensure_project_root(project_root)
    # ``task_capture.py`` deliberately emits a review-only capture envelope,
    # not an executable worker packet.  Reject it before the generic
    # credential-key walk so planner metrics such as ``input_tokens`` are not
    # misreported as the reason for the boundary failure.  The secret-key
    # guard below remains unchanged for all executable packet shapes.
    if packet.get("capture") == "bounded-task-capture":
        raise WorkerError(
            "task capture envelope must pass through plan_packet_bridge before worker execution"
        )
    _reject_secret_keys(packet)
    try:
        validate_schema("task_packet", packet)
    except Exception as exc:
        raise WorkerError(f"task packet schema validation failed: {exc}") from exc
    if packet.get("schema_version") != SCHEMA_VERSION:
        raise WorkerError("unsupported task packet schema_version")
    for field in ("packet_id", "job_id", "write_scope"):
        if not isinstance(packet.get(field), str) or not packet[field].strip():
            raise WorkerError(f"task packet requires {field}")
    if packet.get("validation_required") is not True:
        raise WorkerError("task packet requires validation_required=true")
    if "prompt" in packet:
        raise WorkerError("inline prompt is not accepted; use prompt_file")
    workspace_value = packet.get("worktree_path") or packet.get("workspace") or packet.get("project_path")
    workspace = _confined_path(workspace_value, root, "worktree_path", base=root) if workspace_value else root
    # The schema intentionally permits provider-specific metadata, but every
    # top-level path still needs the same confinement as attempt paths.  The
    # previous implementation only checked paths nested under ``attempts``;
    # a malicious packet could therefore hide an escaping output or runtime
    # path at the packet level while passing validation.
    for field in _PATH_FIELDS:
        if field not in packet or packet[field] is None:
            continue
        base = root if field in {"workspace", "project_path", "worktree_path"} else workspace
        _confined_path(packet[field], root, field, base=base)
    write_scope_path = _confined_path(packet["write_scope"], workspace, "write_scope", base=workspace)
    artifacts = packet.get("required_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise WorkerError("required_artifacts must be a non-empty list")
    artifact_paths = [_confined_path(item, workspace, "required_artifact", base=workspace) for item in artifacts]
    attempts = packet.get("attempts")
    if not isinstance(attempts, list) or not attempts:
        raise WorkerError("attempts must be a non-empty list")
    attempt_report: list[dict[str, Any]] = []
    for index, attempt in enumerate(attempts):
        if not isinstance(attempt, dict):
            raise WorkerError(f"attempt {index} must be an object")
        for field in ("attempt_id", "adapter", "transport", "model"):
            if not isinstance(attempt.get(field), str) or not attempt[field].strip():
                raise WorkerError(f"attempt {index} requires {field}")
        if attempt["transport"] not in {"local", "ssh"}:
            raise WorkerError(f"attempt {index} has unsupported transport")
        if "prompt" in attempt:
            raise WorkerError("inline prompt is not accepted; use prompt_file")
        for field in _PATH_FIELDS:
            if field in attempt and attempt[field] is not None:
                _confined_path(attempt[field], workspace, f"attempt[{index}].{field}", base=workspace)
        # Keep only identifiers in the durable report; argv and environment
        # are intentionally neither copied nor logged.
        attempt_report.append({key: attempt[key] for key in _SAFE_ATTEMPT_FIELDS if key in attempt})
    return {
        "schema_version": SCHEMA_VERSION,
        "packet_digest": _digest(packet),
        "packet_id": packet["packet_id"],
        "job_id": packet["job_id"],
        "project_root": str(root),
        "worktree_path": _relative(workspace, root),
        "write_scope": _relative(write_scope_path, root),
        "required_artifacts": [_relative(path, root) for path in artifact_paths],
        "validation_required": True,
        "validation_spec_digest": (
            _digest(packet.get("validation_argv"))
            if packet.get("validation_argv") is not None
            else None
        ),
        "attempts": attempt_report,
    }


def _atomic_write(path: pathlib.Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        try:
            directory_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()


@contextlib.contextmanager
def _spool_lock(spool_root: pathlib.Path) -> Iterator[None]:
    spool_root.mkdir(parents=True, exist_ok=True)
    lock_path = spool_root / ".worker.lock"
    with exclusive_file_lock(lock_path):
        yield


def _job_dir(spool_root: pathlib.Path, job_id: str) -> pathlib.Path:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", job_id):
        raise WorkerError("job_id contains unsupported path characters")
    return spool_root / "jobs" / job_id


def _manifest_path(job_dir: pathlib.Path) -> pathlib.Path:
    return job_dir / "manifest.json"


def _load_manifest(job_dir: pathlib.Path) -> dict[str, Any]:
    if job_dir.is_symlink() or _manifest_path(job_dir).is_symlink():
        raise WorkerError("worker spool may not contain symlinked job manifests")
    try:
        payload = json.loads(_manifest_path(job_dir).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise WorkerError(f"invalid worker manifest: {job_dir}") from exc
    if not isinstance(payload, dict) or payload.get("manifest_version") != MANIFEST_VERSION:
        raise WorkerError("unsupported worker manifest")
    return payload


def _safe_lease(lease: Any) -> dict[str, Any] | None:
    if not isinstance(lease, dict):
        return None
    owner = str(lease.get("owner_id") or "")
    return {
        "owner_hash": hashlib.sha256(owner.encode("utf-8")).hexdigest()[:16] if owner else None,
        "expires_at": lease.get("expires_at"),
        "heartbeat_at": lease.get("heartbeat_at"),
    }


def _safe_process_identity(identity: Any) -> dict[str, Any] | None:
    """Expose liveness metadata without PID, fence, or other identity secrets."""

    if not isinstance(identity, dict):
        return None
    state = identity.get("liveness_state")
    observed = identity.get("observed_at_utc")
    ttl = identity.get("ttl_seconds")
    if state not in _PROCESS_LIVENESS_STATES or not isinstance(observed, str):
        return {"evidence_state": "invalid"}
    try:
        ttl_value = float(ttl)
    except (TypeError, ValueError):
        return {"evidence_state": "invalid"}
    return {
        "evidence_state": "present",
        "liveness_state": state,
        "observed_at_utc": observed,
        "ttl_seconds": ttl_value,
    }


def _public_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    result = dict(manifest)
    result["lease"] = _safe_lease(manifest.get("lease"))
    if "process_identity" in manifest:
        result["process_identity"] = _safe_process_identity(manifest.get("process_identity"))
    return result


def _append_event(job_dir: pathlib.Path, event_type: str, **fields: Any) -> None:
    # Events are allow-listed at the call sites and recursively checked here
    # as a final guard against accidental prompt/secret/argv logging.
    _reject_secret_keys(fields, "event")
    if any(key in fields for key in ("argv", "prompt", "environment", "env")):
        raise WorkerError("worker events may not contain prompt, argv, or environment")
    row = {"schema_version": SCHEMA_VERSION, "event_id": str(uuid.uuid4()), "event_type": event_type, "at": _utc_now()}
    row.update(fields)
    with (job_dir / "events.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _artifact_manifest(root: pathlib.Path, relative_paths: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for relative in relative_paths:
        path = _confined_path(relative, root, "artifact", base=root)
        row: dict[str, Any] = {"path": _relative(path, root)}
        try:
            stat = path.stat()
        except FileNotFoundError:
            row["status"] = "missing"
            rows.append(row)
            continue
        if not path.is_file():
            row["status"] = "not_regular_file"
            rows.append(row)
            continue
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        row.update({"status": "present", "size": stat.st_size, "mtime_ns": stat.st_mtime_ns, "sha256": digest.hexdigest()})
        rows.append(row)
    return rows


def _artifact_rows_complete(rows: Any) -> bool:
    """Return whether every declared artifact is present and hashable.

    A durable worker never promotes a job from ``running`` to ``completed``
    merely because its executor returned zero.  The artifact gate is kept
    here, next to the hash collector, so fake and future server runtimes share
    the same completion contract.
    """
    if not isinstance(rows, list) or not rows:
        return False
    for row in rows:
        if not isinstance(row, dict) or row.get("status") != "present":
            return False
        try:
            size = int(row.get("size") or 0)
        except (TypeError, ValueError):
            return False
        digest = row.get("sha256")
        if size <= 0 or not isinstance(digest, str) or len(digest) != 64:
            return False
    return True


def _artifact_rows_fresh(before: Any, after: Any) -> bool:
    """Require every current artifact to be new or hash-changed.

    ``prepare_job`` stores the initial manifest.  A resumed worker may call
    ``record_artifacts`` several times; freshness must therefore always be
    compared with that initial baseline rather than the previous observation.
    """
    if not _artifact_rows_complete(after):
        return False
    previous = {
        str(row.get("path")): row
        for row in (before if isinstance(before, list) else [])
        if isinstance(row, dict) and row.get("path")
    }
    for row in after:
        old = previous.get(str(row.get("path")))
        if old and old.get("status") == "present" and old.get("sha256") == row.get("sha256"):
            return False
    return True


def _require_lease(
    manifest: dict[str, Any],
    owner_id: str,
    lease_token: str,
    *,
    require_unexpired: bool = True,
) -> dict[str, Any]:
    """Check owner/token fencing for a mutating worker operation."""
    lease = manifest.get("lease")
    if (
        not isinstance(lease, dict)
        or lease.get("owner_id") != owner_id
        or lease.get("lease_token") != lease_token
    ):
        raise WorkerError("lease fence mismatch")
    if require_unexpired and _parse_time(lease.get("expires_at")) <= time.time():
        raise WorkerError("lease has expired")
    return lease


def _normalize_process_identity(
    value: Any,
    *,
    lease_token: str | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Return a bounded process identity and fixed validation reasons.

    The worker may receive a richer process probe, but only the identity and
    liveness fields below are eligible for durable persistence.  In
    particular, argv, prompts, environments, and credentials are ignored.
    ``fence`` must be the currently held lease token so a stale worker cannot
    publish an identity for a newer attempt.
    """

    reasons: list[str] = []
    if not isinstance(value, dict):
        return None, ["process_identity_missing"]
    pid = value.get("pid")
    process_group = value.get("process_group")
    try:
        pid = int(pid)
        process_group = int(process_group)
    except (TypeError, ValueError):
        reasons.append("process_identity_pid_invalid")
        pid = process_group = None
    if pid is None or pid <= 1:
        reasons.append("process_identity_pid_invalid")
    if process_group is None or process_group <= 0:
        reasons.append("process_identity_process_group_invalid")
    start_time = str(value.get("start_time") or "").strip()
    run_id = str(value.get("run_id") or "").strip()
    fence = str(value.get("fence") or "").strip()
    if not start_time or len(start_time) > 128:
        reasons.append("process_identity_start_time_invalid")
    if not run_id or len(run_id) > 256:
        reasons.append("process_identity_run_id_invalid")
    if not fence or len(fence) > 256:
        reasons.append("process_identity_fence_invalid")
    if lease_token is not None and fence != lease_token:
        reasons.append("process_identity_fence_mismatch")
    if value.get("owned_by_dispatch") is not True:
        reasons.append("process_identity_ownership_unproven")
    liveness_state = str(value.get("liveness_state") or value.get("state") or "").strip().lower()
    if liveness_state not in _PROCESS_LIVENESS_STATES:
        reasons.append("process_identity_liveness_invalid")
    observed_at = value.get("observed_at_utc") or value.get("observed_at")
    observed_epoch = _parse_time(observed_at)
    if observed_epoch <= 0:
        reasons.append("process_identity_observed_at_invalid")
    try:
        ttl_seconds = float(value.get("ttl_seconds"))
    except (TypeError, ValueError):
        ttl_seconds = 0.0
    if not 0 < ttl_seconds <= _MAX_PROCESS_IDENTITY_TTL_SECONDS:
        reasons.append("process_identity_ttl_invalid")
    if reasons:
        return None, list(dict.fromkeys(reasons))
    assert isinstance(pid, int) and isinstance(process_group, int)
    assert isinstance(observed_at, str)
    return (
        {
            "pid": pid,
            "start_time": start_time,
            "process_group": process_group,
            "run_id": run_id,
            "fence": fence,
            "owned_by_dispatch": True,
            "liveness_state": liveness_state,
            "observed_at_utc": observed_at,
            "ttl_seconds": ttl_seconds,
        },
        [],
    )


def record_process_identity(
    spool_root: pathlib.Path,
    job_id: str,
    owner_id: str,
    lease_token: str,
    identity: Mapping[str, Any],
) -> dict[str, Any]:
    """Persist a fenced PID/process-group liveness observation.

    A running server adapter calls this immediately after starting its child
    and refreshes the observation before attempting recovery.  The operation
    requires the current unexpired lease; an expired or stale worker cannot
    claim ownership of a later process attempt.
    """

    if not owner_id or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", owner_id):
        raise WorkerError("owner_id is invalid")
    if not lease_token:
        raise WorkerError("lease_token is required")
    spool = _canonical_root(spool_root)
    job_dir = _job_dir(spool, job_id)
    with _spool_lock(spool):
        manifest = _load_manifest(job_dir)
        lease = _require_lease(manifest, owner_id, lease_token)
        # The lease token is already carried in the authenticated command
        # arguments.  Keep it out of stdin (and therefore out of transport
        # captures) while still binding the observation to this exact fence.
        candidate = dict(identity)
        candidate.setdefault("fence", lease_token)
        normalized, reasons = _normalize_process_identity(candidate, lease_token=lease_token)
        if normalized is None:
            raise WorkerError("process identity is invalid: " + ",".join(reasons))
        manifest["process_identity"] = normalized
        manifest["updated_at"] = _utc_now()
        _atomic_write(_manifest_path(job_dir), manifest)
        _append_event(
            job_dir,
            "process_identity_observed",
            liveness_state=normalized["liveness_state"],
            observed_at_utc=normalized["observed_at_utc"],
        )
        return _public_manifest(manifest)


def _process_identity_recovery_gate(
    manifest: Mapping[str, Any], *, now: float
) -> dict[str, Any]:
    """Check whether stale-lease reclaim has fresh proof the process exited."""

    lease = manifest.get("lease")
    if not isinstance(lease, dict):
        return {"valid": False, "reasons": ["lease_missing"], "identity": None}
    identity = manifest.get("process_identity")
    normalized, reasons = _normalize_process_identity(
        identity, lease_token=str(lease.get("lease_token") or "")
    )
    if normalized is None:
        return {"valid": False, "reasons": reasons, "identity": None}
    observed_epoch = _parse_time(normalized["observed_at_utc"])
    age = float(now) - observed_epoch
    if age > float(normalized["ttl_seconds"]):
        reasons.append("process_identity_stale")
    if age < -60:
        reasons.append("process_identity_from_future")
    if normalized["liveness_state"] not in {"exited", "not_found"}:
        reasons.append("process_not_confirmed_exited")
    reasons = list(dict.fromkeys(reasons))
    return {
        "valid": not reasons,
        "reasons": reasons,
        "identity": normalized,
    }


def prepare_job(packet: dict[str, Any], spool_root: pathlib.Path, project_root: pathlib.Path) -> dict[str, Any]:
    """Validate and durably prepare a job; never start a provider."""
    report = validate_packet(packet, project_root)
    spool = _canonical_root(spool_root)
    job_dir = _job_dir(spool, str(report["job_id"]))
    with _spool_lock(spool):
        if job_dir.exists():
            if job_dir.is_symlink():
                raise WorkerError("worker spool may not contain a symlinked job directory")
            existing = _load_manifest(job_dir)
            if existing.get("packet_digest") != report["packet_digest"]:
                raise WorkerError("job already exists with a different packet digest")
            return _public_manifest(existing)
        job_dir.mkdir(parents=True, exist_ok=False)
        root = pathlib.Path(report["project_root"])
        # Hash once while holding the spool lock.  The same prepare-time
        # snapshot is used for both the public observation and the freshness
        # baseline; computing it twice could otherwise observe a concurrent
        # file mutation between the two reads.
        initial_artifact_manifest = _artifact_manifest(root, report["required_artifacts"])
        manifest = {
            "manifest_version": MANIFEST_VERSION,
            "schema_version": SCHEMA_VERSION,
            "packet_digest": report["packet_digest"],
            "packet_id": report["packet_id"],
            "job_id": report["job_id"],
            "status": "prepared",
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
            "project_root": report["project_root"],
            "worktree_path": report["worktree_path"],
            "write_scope": report["write_scope"],
            "required_artifacts": report["required_artifacts"],
            "validation_required": bool(report.get("validation_required")),
            "validation_spec_digest": report.get("validation_spec_digest"),
            "validation": None,
            "artifact_manifest": initial_artifact_manifest,
            # Keep the prepare-time baseline separate from later observations;
            # otherwise a resumed worker could overwrite the baseline before a
            # completion gate checks freshness.
            "initial_artifact_manifest": initial_artifact_manifest,
            "attempts": report["attempts"],
            "lease": None,
        }
        _atomic_write(_manifest_path(job_dir), manifest)
        _append_event(job_dir, "prepared", job_id=report["job_id"], packet_id=report["packet_id"])
        return _public_manifest(manifest)


def claim_job(spool_root: pathlib.Path, job_id: str, owner_id: str, *, lease_seconds: int = 90) -> dict[str, Any]:
    if not owner_id or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", owner_id):
        raise WorkerError("owner_id is invalid")
    if lease_seconds < 1 or lease_seconds > 86400:
        raise WorkerError("lease_seconds must be between 1 and 86400")
    spool = _canonical_root(spool_root)
    job_dir = _job_dir(spool, job_id)
    with _spool_lock(spool):
        manifest = _load_manifest(job_dir)
        now = time.time()
        current = manifest.get("lease")
        if isinstance(current, dict) and _parse_time(current.get("expires_at")) > now:
            raise WorkerError("job lease is held by another worker")
        if manifest.get("status") in {"completed", "failed", "recovery_review"}:
            raise WorkerError(f"job is not claimable in status {manifest.get('status')}")
        if current:
            manifest["status"] = "recoverable"
        lease_token = uuid.uuid4().hex
        expires = _utc_at(now + lease_seconds)
        manifest["lease"] = {"owner_id": owner_id, "lease_token": lease_token, "expires_at": expires, "heartbeat_at": _utc_now()}
        # A new fence invalidates the previous child identity.  The new
        # adapter must record its own PID/process-group witness before a
        # strict recovery can ever reclaim this attempt.
        manifest["process_identity"] = None
        manifest["status"] = "running"
        manifest["updated_at"] = _utc_now()
        _atomic_write(_manifest_path(job_dir), manifest)
        _append_event(job_dir, "lease_acquired", owner_hash=hashlib.sha256(owner_id.encode()).hexdigest()[:16], expires_at=expires)
        result = _public_manifest(manifest)
        result["lease_token"] = lease_token
        return result


def heartbeat(
    spool_root: pathlib.Path,
    job_id: str,
    owner_id: str,
    lease_token: str,
    *,
    lease_seconds: int = 90,
) -> dict[str, Any]:
    if not lease_token:
        raise WorkerError("lease_token is required")
    if lease_seconds < 1 or lease_seconds > 86400:
        raise WorkerError("lease_seconds must be between 1 and 86400")
    spool = _canonical_root(spool_root)
    job_dir = _job_dir(spool, job_id)
    with _spool_lock(spool):
        manifest = _load_manifest(job_dir)
        lease = _require_lease(manifest, owner_id, lease_token)
        expires = _utc_at(time.time() + lease_seconds)
        lease.update({"expires_at": expires, "heartbeat_at": _utc_now()})
        manifest["updated_at"] = _utc_now()
        _atomic_write(_manifest_path(job_dir), manifest)
        _append_event(job_dir, "heartbeat", expires_at=expires)
        return _public_manifest(manifest)


def observe_artifacts(spool_root: pathlib.Path, job_id: str) -> dict[str, Any]:
    """Read current artifact hashes without mutating the durable manifest."""
    spool = _canonical_root(spool_root)
    job_dir = _job_dir(spool, job_id)
    with _spool_lock(spool):
        manifest = _load_manifest(job_dir)
        root = _ensure_project_root(pathlib.Path(str(manifest["project_root"])))
        observed = _artifact_manifest(root, list(manifest.get("required_artifacts") or []))
        result = _public_manifest(manifest)
        result["observed_artifact_manifest"] = observed
        return result


def record_artifacts(
    spool_root: pathlib.Path,
    job_id: str,
    *,
    owner_id: str | None = None,
    lease_token: str | None = None,
) -> dict[str, Any]:
    """Persist a fresh artifact observation under the current lease fence.

    Unfenced callers must use :func:`observe_artifacts`; allowing a status
    reader to rewrite the manifest would let an expired worker publish a
    completion-looking artifact epoch after lease recovery.
    """
    if owner_id is None or lease_token is None:
        raise WorkerError("owner_id and lease_token are required to record artifacts")
    spool = _canonical_root(spool_root)
    job_dir = _job_dir(spool, job_id)
    with _spool_lock(spool):
        manifest = _load_manifest(job_dir)
        _require_lease(manifest, owner_id, lease_token)
        if "initial_artifact_manifest" not in manifest:
            # Manifests created before the baseline field was introduced are
            # migrated conservatively at their first observation.
            manifest["initial_artifact_manifest"] = list(manifest.get("artifact_manifest") or [])
        root = _ensure_project_root(pathlib.Path(str(manifest["project_root"])))
        observed = _artifact_manifest(root, list(manifest.get("required_artifacts") or []))
        manifest["artifact_manifest"] = observed
        manifest["updated_at"] = _utc_now()
        _atomic_write(_manifest_path(job_dir), manifest)
        _append_event(job_dir, "artifact_observed", artifact_count=len(observed))
        return _public_manifest(manifest)


def complete_job(
    spool_root: pathlib.Path,
    job_id: str,
    owner_id: str,
    lease_token: str,
    *,
    success: bool = True,
    error_code: str | None = None,
) -> dict[str, Any]:
    """Finalize one leased job behind an artifact/hash completion gate.

    This is intentionally a local durable seam, not a provider executor.  A
    caller must hold the current lease fence.  The final artifact observation
    is compared with the prepare-time baseline, so an old file cannot be
    promoted to ``completed`` merely because a worker exited successfully.
    Completion always releases the lease, allowing a later handoff/status read
    to be independent of the crashed/original worker process.
    """
    if not owner_id or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", owner_id):
        raise WorkerError("owner_id is invalid")
    if not lease_token:
        raise WorkerError("lease_token is required")
    spool = _canonical_root(spool_root)
    job_dir = _job_dir(spool, job_id)
    with _spool_lock(spool):
        manifest = _load_manifest(job_dir)
        _require_lease(manifest, owner_id, lease_token)
        if manifest.get("status") in {"completed", "failed"}:
            raise WorkerError(f"job is not completable in status {manifest.get('status')}")
        root = _ensure_project_root(pathlib.Path(str(manifest["project_root"])))
        observed = _artifact_manifest(root, list(manifest.get("required_artifacts") or []))
        baseline = manifest.get("initial_artifact_manifest")
        if baseline is None:
            # Conservative migration for manifests produced before the
            # baseline field existed: the current persisted observation is the
            # only safe baseline available, so a same-content file will fail
            # the freshness gate.
            baseline = manifest.get("artifact_manifest") or []
        fresh = _artifact_rows_fresh(baseline, observed)
        completion_error = None
        if success and not _artifact_rows_complete(observed):
            completion_error = "artifact_missing_or_unhashable"
        elif success and not fresh:
            completion_error = "artifact_not_fresh"
        if not success:
            completion_error = str(error_code or "executor_failed")
        if completion_error and not re.fullmatch(r"[a-z0-9_.-]{1,80}", completion_error):
            raise WorkerError("error_code is invalid")
        status = "completed" if completion_error is None else "failed"
        manifest["status"] = status
        manifest["artifact_manifest"] = observed
        manifest["artifact_freshness_verified"] = bool(fresh and completion_error is None)
        manifest["completion"] = {
            "status": status,
            "error_code": completion_error,
            "completed_at": _utc_now(),
        }
        manifest["lease"] = None
        manifest["updated_at"] = _utc_now()
        _atomic_write(_manifest_path(job_dir), manifest)
        _append_event(
            job_dir,
            "job_completed" if status == "completed" else "job_failed",
            artifact_count=len(observed),
            artifact_freshness_verified=bool(fresh and completion_error is None),
            error_code=completion_error,
        )
        return _public_manifest(manifest)


# ``finalize_job`` is a discoverable spelling for adapters that use
# finalize/complete terminology.  It intentionally has identical fencing and
# artifact semantics.
finalize_job = complete_job


def _safe_events(job_dir: pathlib.Path, *, limit: int = 64) -> list[dict[str, Any]]:
    """Read a bounded allow-listed event tail for a handoff report."""
    allowed = {
        "schema_version",
        "event_id",
        "event_type",
        "at",
        "job_id",
        "packet_id",
        "owner_hash",
        "expires_at",
        "artifact_count",
        "artifact_freshness_verified",
        "reason",
        "error_code",
        "liveness_state",
        "observed_at_utc",
    }
    path = job_dir / "events.jsonl"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return []
    rows: list[dict[str, Any]] = []
    for line in lines[-max(1, int(limit)) :]:
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(value, dict):
            continue
        rows.append({key: value[key] for key in allowed if key in value})
    return rows


def _recover_manifest_unlocked(
    job_dir: pathlib.Path,
    *,
    now: float | None = None,
    require_process_identity: bool = False,
) -> tuple[dict[str, Any], bool, str | None]:
    """Reconcile one job while the caller holds ``_spool_lock``.

    Keeping the reconciliation primitive separate lets ``recover`` and the
    SSH-facing ``resume`` operation share one lock.  Without this, a new
    controller could observe a handoff between ``recover`` and ``handoff``
    while another worker claimed the freshly recoverable lease.
    """
    manifest = _load_manifest(job_dir)
    current_time = time.time() if now is None else float(now)
    lease = manifest.get("lease")
    expired = isinstance(lease, dict) and _parse_time(lease.get("expires_at")) <= current_time
    crashed = manifest.get("status") == "running" and not lease
    if not (expired or crashed):
        return manifest, False, None
    if require_process_identity:
        gate = _process_identity_recovery_gate(manifest, now=current_time)
        if not gate["valid"]:
            # Clearing an expired lease prevents a stale owner from renewing
            # it, while ``recovery_review`` remains unclaimable until an
            # operator records stronger process-liveness evidence.
            manifest["status"] = "recovery_review"
            manifest["lease"] = None
            manifest["recovery_block"] = {
                "reason": "process_liveness_unverified",
                "reasons": list(gate["reasons"]),
                "observed_at_utc": _utc_now(),
            }
            manifest["updated_at"] = _utc_now()
            _atomic_write(_manifest_path(job_dir), manifest)
            identity = gate.get("identity")
            _append_event(
                job_dir,
                "recovery_blocked",
                reason="process_liveness_unverified",
                liveness_state=(identity or {}).get("liveness_state") if isinstance(identity, dict) else None,
                observed_at_utc=(identity or {}).get("observed_at_utc") if isinstance(identity, dict) else None,
            )
            return manifest, False, "process_liveness_unverified"
    reason = "expired" if expired else "missing_lease"
    manifest["status"] = "recoverable"
    manifest["lease"] = None
    manifest["updated_at"] = _utc_now()
    _atomic_write(_manifest_path(job_dir), manifest)
    _append_event(job_dir, "lease_recovered", reason=reason)
    return manifest, True, reason


def _resume_handoff_unlocked(
    manifest: dict[str, Any],
    job_dir: pathlib.Path,
    *,
    event_limit: int = 64,
    recovery_performed: bool = False,
    recovery_reason: str | None = None,
) -> dict[str, Any]:
    """Build a handoff while the caller holds ``_spool_lock``."""
    public = _public_manifest(manifest)
    lease = manifest.get("lease")
    lease_active = isinstance(lease, dict) and _parse_time(lease.get("expires_at")) > time.time()
    status = str(manifest.get("status") or "unknown")
    if status in {"completed", "failed"}:
        next_action = "review_artifacts" if status == "completed" else "review_failure"
        resume_allowed = False
    elif status == "recovery_review":
        next_action = "review_process_liveness"
        resume_allowed = False
    elif lease_active:
        next_action = "wait_for_active_lease_or_recover"
        resume_allowed = False
    else:
        next_action = "claim_with_new_owner"
        resume_allowed = True
    events = _safe_events(job_dir, limit=event_limit)
    handoff: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "handoff_version": 1,
        "handoff_type": "local-agent-dispatch.resume",
        "job_id": public.get("job_id"),
        "packet_id": public.get("packet_id"),
        "packet_digest": public.get("packet_digest"),
        "status": status,
        "resume_required": status not in {"completed", "failed"},
        "resume_allowed": resume_allowed,
        "next_action": next_action,
        "project_root": public.get("project_root"),
        "worktree_path": public.get("worktree_path"),
        "write_scope": public.get("write_scope"),
        "required_artifacts": public.get("required_artifacts") or [],
        "artifact_manifest": public.get("artifact_manifest") or [],
        "artifact_freshness_verified": public.get("artifact_freshness_verified"),
        "completion": public.get("completion"),
        "lease": _safe_lease(lease),
        "attempts": public.get("attempts") or [],
        "events": events,
        "events_digest": _digest(events),
        "recovery": {
            "performed": bool(recovery_performed),
            "reason": recovery_reason,
            "liveness": (
                "verified"
                if recovery_performed and recovery_reason == "expired" and isinstance(manifest.get("process_identity"), dict)
                else "unverified"
                if recovery_reason == "process_liveness_unverified"
                else None
            ),
        },
    }
    # Preserve the legacy handoff shape for callers that explicitly use the
    # lease-only compatibility path.  Strict recovery carries this field as
    # an auditable liveness result; legacy recovery has no such evidence.
    if handoff["recovery"]["liveness"] is None:
        handoff["recovery"].pop("liveness")
    handoff["handoff_digest"] = _digest(handoff)
    return handoff


def resume_handoff(
    spool_root: pathlib.Path,
    job_id: str,
    *,
    event_limit: int = 64,
) -> dict[str, Any]:
    """Build a prompt/argv-safe handoff artifact for a later controller.

    The handoff contains packet/artifact identity, lease state, validation
    evidence, and a bounded event tail.  It never contains the original packet
    (which may include prompt paths or adapter metadata) and it does not claim
    that an active lease is resumable until that lease is recovered/expired.
    """
    spool = _canonical_root(spool_root)
    job_dir = _job_dir(spool, job_id)
    with _spool_lock(spool):
        manifest = _load_manifest(job_dir)
        return _resume_handoff_unlocked(manifest, job_dir, event_limit=event_limit)


def recover_and_handoff(
    spool_root: pathlib.Path,
    job_id: str,
    *,
    event_limit: int = 64,
    require_process_identity: bool = False,
) -> dict[str, Any]:
    """Atomically reconcile an expired lease and emit its resume handoff.

    This is the durable SSH/chat-loss boundary: the later controller gets one
    report showing whether recovery happened and the resulting claim action,
    without a race between separate ``recover`` and ``handoff`` calls.
    """
    spool = _canonical_root(spool_root)
    job_dir = _job_dir(spool, job_id)
    with _spool_lock(spool):
        manifest, recovered, reason = _recover_manifest_unlocked(
            job_dir, require_process_identity=require_process_identity
        )
        return _resume_handoff_unlocked(
            manifest,
            job_dir,
            event_limit=event_limit,
            recovery_performed=recovered,
            recovery_reason=reason,
        )


# Alias used by supervisor/continuity terminology.
build_resume_handoff = resume_handoff


_FAKE_ARTIFACT_TEXT = "local-agent-dispatch fake executor artifact\n"


def run_fake_job(
    spool_root: pathlib.Path,
    job_id: str,
    owner_id: str,
    *,
    lease_token: str | None = None,
    lease_seconds: int = 90,
    artifact_text: str = _FAKE_ARTIFACT_TEXT,
) -> dict[str, Any]:
    """Run a deterministic, provider-free executor against a prepared job.

    This seam is intentionally not a generic command runner: it writes only
    the declared artifact paths with bounded fixture text, records SHA-256
    observations, and finalizes through the same lease/freshness gate as a
    future server runtime.  It exists for CI/recovery demonstrations and must
    never be used as a provider fallback.
    """
    if not isinstance(artifact_text, str) or not artifact_text or len(artifact_text) > 512:
        raise WorkerError("artifact_text must be a non-empty string of at most 512 characters")
    if "\x00" in artifact_text:
        raise WorkerError("artifact_text contains NUL")
    if lease_seconds < 1 or lease_seconds > 86400:
        raise WorkerError("lease_seconds must be between 1 and 86400")
    spool = _canonical_root(spool_root)
    heartbeat_snapshot: dict[str, Any]
    if lease_token is None:
        claim = claim_job(spool, job_id, owner_id, lease_seconds=lease_seconds)
        lease_token = str(claim.get("lease_token") or "")
        # Keep the fake seam representative of a long-running worker: claim
        # and heartbeat are separate durable events even for this bounded run.
        heartbeat_snapshot = heartbeat(spool, job_id, owner_id, lease_token, lease_seconds=lease_seconds)
    else:
        # A resumed fake worker must prove its current fence before writing.
        heartbeat_snapshot = heartbeat(spool, job_id, owner_id, lease_token, lease_seconds=lease_seconds)
    if not lease_token:
        raise WorkerError("claim did not return a lease token")
    job_dir = _job_dir(spool, job_id)
    manifest = _load_manifest(job_dir)
    root = _ensure_project_root(pathlib.Path(str(manifest["project_root"])))
    try:
        for relative in list(manifest.get("required_artifacts") or []):
            path = _confined_path(relative, root, "required_artifact", base=root)
            if path.exists() and not path.is_file():
                raise WorkerError("required artifact is not a regular file")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(artifact_text, encoding="utf-8")
        observed = record_artifacts(
            spool,
            job_id,
            owner_id=owner_id,
            lease_token=lease_token,
        )
        completed = complete_job(
            spool,
            job_id,
            owner_id,
            lease_token,
            success=True,
        )
    except Exception:
        # Release a known lease on a deterministic fake-executor failure.  If
        # the lease itself has expired/fenced, recovery remains the safe path.
        try:
            failed = complete_job(
                spool,
                job_id,
                owner_id,
                lease_token,
                success=False,
                error_code="executor_failed",
            )
        except Exception:
            raise
        return {
            "schema_version": SCHEMA_VERSION,
            "executor": "fake",
            "job_id": job_id,
            "status": failed.get("status"),
            "heartbeat": heartbeat_snapshot,
            "manifest": failed,
            "handoff": resume_handoff(spool, job_id),
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "executor": "fake",
        "job_id": job_id,
        "status": completed.get("status"),
        "heartbeat": heartbeat_snapshot,
        "artifact_manifest": observed.get("artifact_manifest") or completed.get("artifact_manifest") or [],
        "manifest": completed,
        "handoff": resume_handoff(spool, job_id),
    }


def run_fake_service(
    spool_root: pathlib.Path,
    job_id: str,
    owner_id: str,
    *,
    poll_seconds: float = 1.0,
    max_idle_rounds: int = 0,
    lease_seconds: int = 90,
) -> dict[str, Any]:
    """Run a bounded, provider-free service for one prepared job.

    This is the smallest process-level continuation seam: a caller may start
    it independently of the originating chat, then a later controller can
    inspect the spool/handoff after the process exits.  It is deliberately
    restricted to the deterministic ``run_fake_job`` fixture and one explicit
    ``job_id``.  It must never be presented as a provider or model fallback.

    ``max_idle_rounds=0`` means wait indefinitely for the named job or for an
    active lease to expire.  A positive value gives a service manager a
    bounded readiness timeout without mutating an absent job.
    """
    if not isinstance(poll_seconds, (int, float)) or isinstance(poll_seconds, bool):
        raise WorkerError("poll_seconds must be a number")
    if poll_seconds < 0.01 or poll_seconds > 3600:
        raise WorkerError("poll_seconds must be between 0.01 and 3600 seconds")
    if isinstance(max_idle_rounds, bool) or int(max_idle_rounds) < 0:
        raise WorkerError("max_idle_rounds must be zero or a positive integer")
    if not owner_id or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", owner_id):
        raise WorkerError("owner_id is invalid")
    if lease_seconds < 1 or lease_seconds > 86400:
        raise WorkerError("lease_seconds must be between 1 and 86400")

    spool = _canonical_root(spool_root)
    idle_rounds = 0
    while True:
        # Reconcile an expired lease before deciding whether this service may
        # claim the named job.  This is what lets a new process continue after
        # the original worker/chat disappeared.
        recover_jobs(spool, job_id)
        try:
            current = status(spool, job_id)["jobs"][0]
        except (IndexError, KeyError, WorkerError):
            current = None

        if current is not None:
            current_status = str(current.get("status") or "unknown")
            if current_status in {"completed", "failed"}:
                handoff = resume_handoff(spool, job_id)
                return {
                    "schema_version": SCHEMA_VERSION,
                    "service": "fake",
                    "provider_execution": False,
                    "job_id": job_id,
                    "status": current_status,
                    "idle_rounds": idle_rounds,
                    "handoff": handoff,
                }
            if current_status in {"prepared", "recoverable"}:
                # ``run_fake_job`` claims with a fresh fence and uses the
                # normal artifact/hash completion gate.
                result = run_fake_job(
                    spool,
                    job_id,
                    owner_id,
                    lease_seconds=lease_seconds,
                )
                result["service"] = "fake"
                result["provider_execution"] = False
                result["idle_rounds"] = idle_rounds
                return result
            if current_status not in {"running"}:
                handoff = resume_handoff(spool, job_id)
                return {
                    "schema_version": SCHEMA_VERSION,
                    "service": "fake",
                    "provider_execution": False,
                    "job_id": job_id,
                    "status": current_status,
                    "error": "unsupported_worker_status",
                    "idle_rounds": idle_rounds,
                    "handoff": handoff,
                }

        idle_rounds += 1
        if max_idle_rounds and idle_rounds >= int(max_idle_rounds):
            # Do not claim a missing or actively leased job just to make a
            # bounded service look successful.  The handoff tells the next
            # controller exactly why it must retry or wait.
            handoff = None
            if current is not None:
                handoff = resume_handoff(spool, job_id)
            return {
                "schema_version": SCHEMA_VERSION,
                "service": "fake",
                "provider_execution": False,
                "job_id": job_id,
                "status": "waiting",
                "resume_required": True,
                "resume_allowed": False,
                "next_action": "prepare_or_wait_for_lease_recovery",
                "idle_rounds": idle_rounds,
                "handoff": handoff,
            }
        time.sleep(float(poll_seconds))


def recover_jobs(
    spool_root: pathlib.Path,
    job_id: str | None = None,
    *,
    require_process_identity: bool = False,
) -> list[dict[str, Any]]:
    """Mark crashed/expired jobs recoverable without running or re-enqueuing them.

    ``require_process_identity`` is the server-safe mode.  Legacy callers may
    retain the historical lease-only behavior explicitly, but remote
    production recovery should always require a fresh exited/not-found child
    observation first.
    """
    return _recover_jobs(
        spool_root,
        job_id,
        require_process_identity=require_process_identity,
    )


def _recover_jobs(
    spool_root: pathlib.Path,
    job_id: str | None = None,
    *,
    require_process_identity: bool = False,
) -> list[dict[str, Any]]:
    """Internal recovery implementation shared by legacy and strict modes."""
    spool = _canonical_root(spool_root)
    with _spool_lock(spool):
        if job_id:
            directories = [_job_dir(spool, job_id)]
        else:
            directories = sorted((spool / "jobs").glob("*/")) if (spool / "jobs").is_dir() else []
        results: list[dict[str, Any]] = []
        now = time.time()
        for directory in directories:
            if directory.is_symlink() or not directory.is_dir() or not _manifest_path(directory).is_file():
                continue
            manifest, _recovered, _reason = _recover_manifest_unlocked(
                directory,
                now=now,
                require_process_identity=require_process_identity,
            )
            results.append(_public_manifest(manifest))
        return results


def recover_jobs_verified(
    spool_root: pathlib.Path, job_id: str | None = None
) -> list[dict[str, Any]]:
    """Strict server recovery requiring process-liveness evidence."""

    return _recover_jobs(spool_root, job_id, require_process_identity=True)


def recover_and_handoff_verified(
    spool_root: pathlib.Path,
    job_id: str,
    *,
    event_limit: int = 64,
) -> dict[str, Any]:
    """Strict atomic recovery/handoff for remote reconnects."""

    return recover_and_handoff(
        spool_root,
        job_id,
        event_limit=event_limit,
        require_process_identity=True,
    )


def status(spool_root: pathlib.Path, job_id: str | None = None) -> dict[str, Any]:
    spool = _canonical_root(spool_root)
    with _spool_lock(spool):
        if job_id:
            manifests = [_public_manifest(_load_manifest(_job_dir(spool, job_id)))]
        else:
            manifests = []
            jobs_dir = spool / "jobs"
            for directory in sorted(jobs_dir.glob("*/")) if jobs_dir.is_dir() else []:
                if not directory.is_symlink() and _manifest_path(directory).is_file():
                    manifests.append(_public_manifest(_load_manifest(directory)))
        return {"schema_version": SCHEMA_VERSION, "spool_root": str(spool), "jobs": manifests}


def _load_packet(path: pathlib.Path) -> dict[str, Any]:
    # ``-`` is the transport-safe spelling used by remote_worker_client.  The
    # packet is sent over the already-open SSH stdin stream instead of being
    # interpolated into a remote command or copied through a temporary file.
    if str(path) == "-":
        try:
            payload = json.load(sys.stdin)
        except (OSError, json.JSONDecodeError) as exc:
            raise WorkerError("packet on stdin is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise WorkerError("packet must be a JSON object")
        return payload
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkerError(f"packet is not valid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise WorkerError("packet must be a JSON object")
    return payload


def _envelope_store(spool_root: pathlib.Path) -> EnvelopeStore:
    """Return the envelope store beneath a worker spool.

    Keeping envelopes in a child directory avoids sharing the worker's
    manifest lock while still giving the SSH transport one explicit spool
    path. ``EnvelopeStore`` owns its atomic writes and lock.
    """

    return EnvelopeStore(_canonical_root(spool_root) / "envelopes")


def _load_envelope(path: pathlib.Path) -> dict[str, Any]:
    """Load one metadata-only envelope from a path or stdin."""

    if str(path) == "-":
        try:
            payload = json.load(sys.stdin)
        except (OSError, json.JSONDecodeError) as exc:
            raise WorkerError("envelope on stdin is not valid JSON") from exc
    else:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise WorkerError(f"envelope is not valid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise WorkerError("envelope must be a JSON object")
    return payload


def _envelope_identity(envelope: dict[str, Any]) -> dict[str, Any]:
    """Return only safe identity fields, including the exact model/variant.

    ``EnvelopeStore.receive`` performs the complete schema/allow-list check.
    This projection is deliberately tiny so CLI output cannot accidentally
    become a prompt, argv, credential, or provider-output channel.
    """

    summary = envelope.get("payload_summary")
    if not isinstance(summary, dict):
        raise WorkerError("envelope payload_summary must be an object")
    model = summary.get("model")
    variant = summary.get("variant")
    if envelope.get("operation") == "execute.prepared":
        # A prepared remote task must preserve the selected model contract;
        # no implicit provider/model/variant fallback is allowed here.
        if not isinstance(model, str) or not model.strip():
            raise WorkerError("prepared envelope requires an exact model")
        gemini_null_variant = (
            summary.get("provider") == "antigravity"
            and summary.get("pool_id") == "antigravity.gemini"
            and model == "gemini-3.6-flash-high"
            and variant is None
        )
        if (not isinstance(variant, str) or not variant.strip()) and not gemini_null_variant:
            raise WorkerError("prepared envelope requires an exact variant")
    return {
        "request_id": envelope.get("request_id"),
        "idempotency_key": envelope.get("idempotency_key"),
        "source_id": envelope.get("source_id"),
        "target_id": envelope.get("target_id"),
        "operation": envelope.get("operation"),
        "packet_digest": envelope.get("packet_digest"),
        "payload_digest": envelope.get("payload_digest"),
        "model": model,
        "variant": variant,
    }


def receive_envelope(spool_root: pathlib.Path, envelope: dict[str, Any]) -> dict[str, Any]:
    """Receive one idempotent envelope without executing a task/provider."""

    identity = _envelope_identity(envelope)
    try:
        result = _envelope_store(spool_root).receive(envelope)
    except EnvelopeError as exc:
        raise WorkerError(str(exc)) from exc
    result = dict(result)
    result["schema_version"] = SCHEMA_VERSION
    result["envelope"] = identity
    return result


def complete_envelope(
    spool_root: pathlib.Path,
    request_id: str,
    *,
    status: str = "completed",
    result_digest: str | None = None,
    error_code: str | None = None,
) -> dict[str, Any]:
    """Record a terminal envelope receipt; never run the referenced task."""

    try:
        result = _envelope_store(spool_root).complete(
            request_id,
            status=status,
            result_digest=result_digest,
            error_code=error_code,
        )
    except EnvelopeError as exc:
        raise WorkerError(str(exc)) from exc
    result = dict(result)
    result["schema_version"] = SCHEMA_VERSION
    return result


def envelope_status(spool_root: pathlib.Path, request_id: str) -> dict[str, Any]:
    """Read one metadata-only envelope receipt; never execute a provider."""

    try:
        result = _envelope_store(spool_root).status(request_id)
    except EnvelopeError as exc:
        raise WorkerError(str(exc)) from exc
    result = dict(result)
    result["schema_version"] = SCHEMA_VERSION
    result["provider_execution"] = False
    return result


def pending_envelopes(spool_root: pathlib.Path) -> dict[str, Any]:
    """List metadata-only outbox envelopes without terminal receipts."""

    try:
        rows = _envelope_store(spool_root).pending()
    except EnvelopeError as exc:
        raise WorkerError(str(exc)) from exc
    return {"schema_version": SCHEMA_VERSION, "envelopes": rows}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local-only durable server worker contract (no provider execution)")
    sub = parser.add_subparsers(dest="command", required=True)
    validate_cmd = sub.add_parser("validate", help="validate a packet without persisting or executing it")
    validate_cmd.add_argument("--packet", required=True)
    validate_cmd.add_argument("--project-root", required=True)
    prepare_cmd = sub.add_parser("prepare", help="persist a dry-run job manifest")
    prepare_cmd.add_argument("--packet", required=True)
    prepare_cmd.add_argument("--project-root", required=True)
    prepare_cmd.add_argument("--spool", required=True)
    envelope_receive_cmd = sub.add_parser(
        "envelope-receive",
        aliases=["receive-envelope"],
        help="receive one metadata-only idempotent envelope (never execute it)",
    )
    envelope_receive_cmd.add_argument("--spool", required=True)
    envelope_receive_cmd.add_argument("--envelope", required=True)
    envelope_complete_cmd = sub.add_parser(
        "envelope-complete",
        aliases=["complete-envelope"],
        help="record a terminal metadata-only envelope receipt",
    )
    envelope_complete_cmd.add_argument("--spool", required=True)
    envelope_complete_cmd.add_argument("--request-id", required=True)
    envelope_complete_cmd.add_argument("--status", choices=("completed", "failed"), default="completed")
    envelope_complete_cmd.add_argument("--result-digest")
    envelope_complete_cmd.add_argument("--error-code")
    envelope_status_cmd = sub.add_parser(
        "envelope-status",
        aliases=["status-envelope"],
        help="read one metadata-only envelope receipt (never execute it)",
    )
    envelope_status_cmd.add_argument("--spool", required=True)
    envelope_status_cmd.add_argument("--request-id", required=True)
    envelope_pending_cmd = sub.add_parser(
        "envelope-pending",
        aliases=["pending-envelopes"],
        help="list pending metadata-only outbox envelopes",
    )
    envelope_pending_cmd.add_argument("--spool", required=True)
    status_cmd = sub.add_parser("status", help="show redacted job manifests")
    status_cmd.add_argument("--spool", required=True)
    status_cmd.add_argument("--job-id")
    recover_cmd = sub.add_parser("recover", help="mark expired leases recoverable")
    recover_cmd.add_argument("--spool", required=True)
    recover_cmd.add_argument("--job-id")
    recover_cmd.add_argument(
        "--require-process-identity",
        action="store_true",
        help="require fresh exited/not-found process evidence before reclaim",
    )
    identity_cmd = sub.add_parser(
        "process-identity",
        help="record a fenced PID/process-group liveness observation",
    )
    identity_cmd.add_argument("--spool", required=True)
    identity_cmd.add_argument("--job-id", required=True)
    identity_cmd.add_argument("--owner", required=True)
    identity_cmd.add_argument("--lease-token", required=True)
    identity_cmd.add_argument("--identity", required=True)
    heartbeat_cmd = sub.add_parser("heartbeat", help="renew one worker lease")
    heartbeat_cmd.add_argument("--spool", required=True)
    heartbeat_cmd.add_argument("--job-id", required=True)
    heartbeat_cmd.add_argument("--owner", required=True)
    heartbeat_cmd.add_argument("--lease-token", required=True)
    heartbeat_cmd.add_argument("--lease-seconds", type=int, default=90)
    complete_cmd = sub.add_parser("complete", aliases=["finalize"], help="finalize a leased job after artifact/hash validation")
    complete_cmd.add_argument("--spool", required=True)
    complete_cmd.add_argument("--job-id", required=True)
    complete_cmd.add_argument("--owner", required=True)
    complete_cmd.add_argument("--lease-token", required=True)
    complete_cmd.add_argument("--success", action=argparse.BooleanOptionalAction, default=True)
    complete_cmd.add_argument("--error-code")
    handoff_cmd = sub.add_parser("handoff", aliases=["resume-handoff"], help="emit a safe resume handoff report")
    handoff_cmd.add_argument("--spool", required=True)
    handoff_cmd.add_argument("--job-id", required=True)
    handoff_cmd.add_argument("--event-limit", type=int, default=64)
    handoff_cmd.add_argument("--output", default="-")
    resume_cmd = sub.add_parser(
        "resume",
        aliases=["recover-handoff"],
        help="atomically recover an expired lease and emit a safe resume handoff",
    )
    resume_cmd.add_argument("--spool", required=True)
    resume_cmd.add_argument("--job-id", required=True)
    resume_cmd.add_argument("--event-limit", type=int, default=64)
    resume_cmd.add_argument("--output", default="-")
    resume_cmd.add_argument(
        "--require-process-identity",
        action="store_true",
        help="require fresh exited/not-found process evidence before reclaim",
    )
    fake_cmd = sub.add_parser("fake-execute", aliases=["fake-run"], help="run the bounded provider-free fake executor")
    fake_cmd.add_argument("--spool", required=True)
    fake_cmd.add_argument("--job-id", required=True)
    fake_cmd.add_argument("--owner", required=True)
    fake_cmd.add_argument("--lease-token")
    fake_cmd.add_argument("--lease-seconds", type=int, default=90)
    service_cmd = sub.add_parser(
        "fake-service",
        aliases=["fake-daemon"],
        help="wait for and run one provider-free fake job (never a model fallback)",
    )
    service_cmd.add_argument("--spool", required=True)
    service_cmd.add_argument("--job-id", required=True)
    service_cmd.add_argument("--owner", required=True)
    service_cmd.add_argument("--poll-seconds", type=float, default=1.0)
    service_cmd.add_argument("--max-idle-rounds", type=int, default=0)
    service_cmd.add_argument("--lease-seconds", type=int, default=90)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            print(json.dumps(validate_packet(_load_packet(pathlib.Path(args.packet)), pathlib.Path(args.project_root)), ensure_ascii=False, sort_keys=True, indent=2))
        elif args.command == "prepare":
            print(json.dumps(prepare_job(_load_packet(pathlib.Path(args.packet)), pathlib.Path(args.spool), pathlib.Path(args.project_root)), ensure_ascii=False, sort_keys=True, indent=2))
        elif args.command in {"envelope-receive", "receive-envelope"}:
            print(json.dumps(receive_envelope(pathlib.Path(args.spool), _load_envelope(pathlib.Path(args.envelope))), ensure_ascii=False, sort_keys=True, indent=2))
        elif args.command in {"envelope-complete", "complete-envelope"}:
            print(json.dumps(complete_envelope(
                pathlib.Path(args.spool),
                args.request_id,
                status=args.status,
                result_digest=args.result_digest,
                error_code=args.error_code,
            ), ensure_ascii=False, sort_keys=True, indent=2))
        elif args.command in {"envelope-status", "status-envelope"}:
            print(json.dumps(envelope_status(
                pathlib.Path(args.spool), args.request_id
            ), ensure_ascii=False, sort_keys=True, indent=2))
        elif args.command in {"envelope-pending", "pending-envelopes"}:
            print(json.dumps(pending_envelopes(pathlib.Path(args.spool)), ensure_ascii=False, sort_keys=True, indent=2))
        elif args.command == "status":
            print(json.dumps(status(pathlib.Path(args.spool), args.job_id), ensure_ascii=False, sort_keys=True, indent=2))
        elif args.command == "recover":
            print(json.dumps({"schema_version": SCHEMA_VERSION, "jobs": recover_jobs(
                pathlib.Path(args.spool),
                args.job_id,
                require_process_identity=args.require_process_identity,
            )}, ensure_ascii=False, sort_keys=True, indent=2))
        elif args.command == "process-identity":
            print(json.dumps(record_process_identity(
                pathlib.Path(args.spool),
                args.job_id,
                args.owner,
                args.lease_token,
                _load_packet(pathlib.Path(args.identity)),
            ), ensure_ascii=False, sort_keys=True, indent=2))
        elif args.command == "heartbeat":
            print(json.dumps(heartbeat(pathlib.Path(args.spool), args.job_id, args.owner, args.lease_token, lease_seconds=args.lease_seconds), ensure_ascii=False, sort_keys=True, indent=2))
        elif args.command in {"complete", "finalize"}:
            print(json.dumps(complete_job(pathlib.Path(args.spool), args.job_id, args.owner, args.lease_token, success=args.success, error_code=args.error_code), ensure_ascii=False, sort_keys=True, indent=2))
        elif args.command in {"handoff", "resume-handoff"}:
            payload = resume_handoff(pathlib.Path(args.spool), args.job_id, event_limit=args.event_limit)
            text = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
            if args.output == "-":
                print(text, end="")
            else:
                _atomic_write(pathlib.Path(args.output).expanduser(), payload)
        elif args.command in {"resume", "recover-handoff"}:
            payload = recover_and_handoff(
                pathlib.Path(args.spool),
                args.job_id,
                event_limit=args.event_limit,
                require_process_identity=args.require_process_identity,
            )
            text = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
            if args.output == "-":
                print(text, end="")
            else:
                _atomic_write(pathlib.Path(args.output).expanduser(), payload)
        elif args.command in {"fake-service", "fake-daemon"}:
            print(json.dumps(
                run_fake_service(
                    pathlib.Path(args.spool),
                    args.job_id,
                    args.owner,
                    poll_seconds=args.poll_seconds,
                    max_idle_rounds=args.max_idle_rounds,
                    lease_seconds=args.lease_seconds,
                ),
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            ))
        else:
            print(json.dumps(run_fake_job(pathlib.Path(args.spool), args.job_id, args.owner, lease_token=args.lease_token, lease_seconds=args.lease_seconds), ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    except (OSError, WorkerError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
