#!/usr/bin/env python3
"""Export a strict, provider-free terminal receipt from SQLite evidence.

The exporter is deliberately read-only with respect to the controller.  It
does not complete jobs, release reservations, run validation commands, or
copy prompt/argv material.  It only joins already persisted terminal state,
the current controller fence, the packet binding, validation metadata and a
fresh artifact hash into the allow-listed receipt consumed by Foundry.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import sys
from typing import Any, Mapping


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX = re.compile(r"^[0-9a-f]{64}$")
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version", "kind", "run_id", "attempt_id", "state",
        "plan_digest", "packet_digest", "foundry_binding_digest",
        "agent_instance_digest", "resource_request_digest",
        "quota_snapshot_digest", "lane_profile_digest", "model_profile_digest",
        "execution_host_digest", "workload_host_digest", "worktree_lease_digest",
        "worktree_fence", "artifact_digest", "validation_command_digest",
        "validation_exit_code", "settlement_receipt_digest", "terminal_cause_kind",
        "terminal_cause_receipt_digest", "started_at", "completed_at",
        "receipt_digest",
    }
)
_PACKET_BODY_FIELDS = frozenset(
    {
        "schema_version", "kind", "job_id", "exact_model", "exact_effort",
        "execution_host_digest", "workload_host_digest", "resource_request",
        "quota_snapshot", "write_scope", "validation_command", "artifact_path",
        "result_path", "plan_digest", "assignment_digest", "foundry_binding",
    }
)
_BINDING_FIELDS = frozenset(
    {
        "schema_version", "kind", "task_profile_digest", "agent_instance_digest",
        "cps_recipe_digest", "route_manifest_digest", "lane_profile_digest",
        "resource_request_digest", "quota_snapshot_digest",
        "builder_backend_evidence_digest", "worktree_lease_digest", "worktree_fence",
        "plan_digest", "assignment_digest", "adapter_digest", "binding_digest",
    }
)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _file_digest(path: pathlib.Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return "sha256:" + hasher.hexdigest()


def _require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{label} must be a sha256 digest")
    return value


def _require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _timestamp(value: Any, label: str, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return value


def _expired(value: Any) -> bool:
    if not isinstance(value, str):
        return True
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return True
    if parsed.tzinfo is None:
        return True
    return parsed <= dt.datetime.now(tz=dt.timezone.utc)


def _safe_mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _packet_and_binding(job: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = _safe_mapping(job.get("payload"))
    candidate = payload.get("foundry_packet")
    candidate = _safe_mapping(candidate) if isinstance(candidate, Mapping) else payload
    packet_digest = candidate.get("packet_digest")
    binding = _safe_mapping(candidate.get("foundry_binding"))
    if not packet_digest or not binding:
        raise ValueError("terminal receipt requires a Foundry packet and binding")
    _require_digest(packet_digest, "packet_digest")
    binding_digest = _require_digest(binding.get("binding_digest"), "binding_digest")
    missing = _PACKET_BODY_FIELDS.difference(candidate)
    if missing:
        raise ValueError(f"packet is missing fields: {sorted(missing)}")
    # SQLite job payloads may carry controller-only metadata (workspace,
    # attempt plan, validation results).  It is not part of the Foundry
    # packet digest and must not silently change the packet identity.
    packet_body = {key: candidate[key] for key in _PACKET_BODY_FIELDS}
    if _digest(packet_body) != packet_digest:
        raise ValueError("packet digest mismatch")
    if set(binding) != _BINDING_FIELDS:
        raise ValueError("Foundry binding exact fields differ from schema")
    binding_body = dict(binding)
    binding_body.pop("binding_digest", None)
    if _digest(binding_body) != binding_digest:
        raise ValueError("Foundry binding digest mismatch")
    request = _safe_mapping(candidate.get("resource_request"))
    quota = _safe_mapping(candidate.get("quota_snapshot"))
    request_digest = _require_digest(request.get("request_digest"), "resource_request.request_digest")
    if request_digest != _digest({key: request[key] for key in request if key != "request_digest"}):
        raise ValueError("resource request self-digest mismatch")
    quota_digest = _require_digest(quota.get("snapshot_digest"), "quota_snapshot.snapshot_digest")
    if quota_digest != _digest({key: quota[key] for key in quota if key != "snapshot_digest"}):
        raise ValueError("quota snapshot self-digest mismatch")
    if binding.get("resource_request_digest") != request_digest:
        raise ValueError("resource request binding mismatch")
    if binding.get("quota_snapshot_digest") != quota_digest:
        raise ValueError("quota snapshot binding mismatch")
    if quota.get("exact_model") != candidate.get("exact_model"):
        raise ValueError("quota/model binding mismatch")
    return {**payload, **candidate}, binding


def _artifact_from_manifest(
    job: Mapping[str, Any], attempt: Mapping[str, Any], *, required: bool
) -> str | None:
    manifest = attempt.get("artifact_manifest")
    if manifest is None:
        if required:
            raise ValueError("completed terminal receipt requires an artifact manifest")
        return None
    if not isinstance(manifest, list) or not manifest:
        raise ValueError("artifact manifest must be a non-empty list")
    workspace_value = (
        job.get("workspace")
        or _safe_mapping(job.get("payload")).get("workspace")
        or _safe_mapping(job.get("payload")).get("project_root")
    )
    if not isinstance(workspace_value, str) or not workspace_value:
        raise ValueError("artifact manifest requires a workspace root")
    workspace = pathlib.Path(workspace_value).expanduser().resolve(strict=True)
    if workspace == pathlib.Path(workspace.anchor):
        raise ValueError("artifact workspace may not be filesystem root")
    digests: list[str] = []
    for item in manifest:
        if not isinstance(item, Mapping):
            raise ValueError("artifact manifest entries must be objects")
        raw_path = item.get("path")
        expected = item.get("sha256")
        if not isinstance(raw_path, str) or not raw_path or ".." in pathlib.PurePath(raw_path).parts:
            raise ValueError("artifact manifest path is unsafe")
        if not isinstance(expected, str) or not _HEX.fullmatch(expected):
            raise ValueError("artifact manifest sha256 is invalid")
        candidate = pathlib.Path(raw_path).expanduser()
        if not candidate.is_absolute():
            candidate = workspace / candidate
        if candidate.is_symlink():
            raise ValueError("artifact manifest path may not be a symlink")
        resolved = candidate.resolve(strict=True)
        try:
            resolved.relative_to(workspace)
        except ValueError as exc:
            raise ValueError("artifact manifest path escapes workspace") from exc
        if not resolved.is_file():
            raise ValueError("artifact manifest path is not a regular file")
        actual = _file_digest(resolved)
        if actual != "sha256:" + expected:
            raise ValueError("artifact hash changed after validation")
        digests.append(actual)
    # A single deterministic artifact is the current contract.  Multiple
    # artifacts are represented by a digest over their ordered manifest hashes.
    return digests[0] if len(digests) == 1 else _digest(digests)


def _validation_fields(attempt: Mapping[str, Any], *, required: bool) -> tuple[str | None, int | None]:
    validation = _safe_mapping(attempt.get("validation"))
    if required and not validation:
        raise ValueError("completed terminal receipt requires validation evidence")
    if required and validation.get("ok") is not True:
        raise ValueError("completed attempt validation did not pass")
    command = validation.get("command") or validation.get("argv")
    if command is None:
        command_digest = None
    else:
        if isinstance(command, str):
            command = [command]
        if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
            raise ValueError("validation command evidence is malformed")
        command_digest = _digest(command)
    exit_code = validation.get("returncode", validation.get("exit_code"))
    if exit_code is not None and (isinstance(exit_code, bool) or not isinstance(exit_code, int)):
        raise ValueError("validation exit code is malformed")
    if required and command_digest is None:
        raise ValueError("completed terminal receipt requires validation command evidence")
    if required and exit_code != 0:
        raise ValueError("completed attempt validation exit code is not zero")
    return command_digest, exit_code


def _settlement_digest(snapshot: Mapping[str, Any], job_id: str, attempt: Mapping[str, Any]) -> str:
    rows = [
        row for row in snapshot.get("reservations", [])
        if isinstance(row, Mapping) and str(row.get("job_id") or "") == job_id
    ]
    settled = [row for row in rows if str(row.get("status") or "") != "active"]
    if not settled:
        raise ValueError("terminal receipt requires a settled resource record")
    for row in settled:
        if str(row.get("owner_id") or "") != str(attempt.get("owner_id") or ""):
            raise ValueError("settlement receipt binding mismatch")
        if int(row.get("fence_token") or 0) != int(attempt.get("fence_token") or 0):
            raise ValueError("settlement receipt fence mismatch")
    safe_rows = []
    for row in settled:
        safe_rows.append(
            {
                key: row.get(key)
                for key in (
                    "reservation_id", "job_id", "scope", "status", "owner_id",
                    "fence_token", "created_at_utc", "updated_at_utc",
                    "lease_expires_at_utc", "resource_request", "admission",
                    "release_reason",
                )
            }
        )
    return _digest({"attempt_id": attempt.get("attempt_id"), "settled": safe_rows})


def _cause(state: str, attempt: Mapping[str, Any]) -> tuple[str | None, str | None]:
    if state == "completed":
        return None, None
    error_class = str(attempt.get("error_class") or "execution_failure")
    lowered = error_class.lower()
    if "timeout" in lowered or "timed_out" in lowered:
        kind = "timeout"
    elif state == "replanned" or "replan" in lowered:
        kind = "replan"
    else:
        kind = "execution_failure"
    safe = {
        "attempt_id": attempt.get("attempt_id"),
        "state": state,
        "error_class": error_class,
    }
    return kind, _digest(safe)


def _build_receipt(snapshot: Mapping[str, Any], job: Mapping[str, Any], attempt: Mapping[str, Any], *, owner_id: str, fence_token: int) -> dict[str, Any]:
    payload, binding = _packet_and_binding(job)
    attempt_id = _require_text(attempt.get("attempt_id"), "attempt_id")
    job_id = _require_text(job.get("job_id") or payload.get("job_id"), "job_id")
    if str(attempt.get("owner_id") or "") != owner_id or int(attempt.get("fence_token") or 0) != fence_token:
        raise ValueError("attempt owner or fence mismatch")
    raw_status = str(attempt.get("status") or job.get("status") or "")
    state = {
        "completed": "completed", "failed": "failed", "retry": "replanned",
        "timed_out": "timed_out", "denied": "denied", "blocked": "denied",
    }.get(raw_status)
    if state is None:
        raise ValueError("attempt is not terminal")
    required = state == "completed"
    if state == "denied":
        if attempt.get("started_at_utc") or attempt.get("artifact_manifest") or attempt.get("validation"):
            raise ValueError("denied terminal receipt cannot contain child artifacts")
        artifact_digest = None
        validation_command_digest, validation_exit_code = None, None
    else:
        artifact_digest = _artifact_from_manifest(job, attempt, required=required)
        validation_command_digest, validation_exit_code = _validation_fields(attempt, required=required)
    cause_kind, cause_digest = _cause(state, attempt)
    body: dict[str, Any] = {
        "schema_version": "0.1.0", "kind": "lad_attempt_receipt",
        "run_id": _require_text(job.get("run_id") or payload.get("run_id") or f"run:{job_id}", "run_id"),
        "attempt_id": attempt_id, "state": state,
        "plan_digest": _require_digest(binding.get("plan_digest"), "plan_digest"),
        "packet_digest": _require_digest(payload.get("packet_digest"), "packet_digest"),
        "foundry_binding_digest": _require_digest(binding.get("binding_digest"), "foundry_binding_digest"),
        "agent_instance_digest": _require_digest(binding.get("agent_instance_digest"), "agent_instance_digest"),
        "resource_request_digest": _require_digest(binding.get("resource_request_digest"), "resource_request_digest"),
        "quota_snapshot_digest": _require_digest(binding.get("quota_snapshot_digest"), "quota_snapshot_digest"),
        "lane_profile_digest": _require_digest(binding.get("lane_profile_digest"), "lane_profile_digest"),
        "model_profile_digest": _require_digest(payload.get("model_profile_digest") or binding.get("model_profile_digest") or _digest({"model": payload.get("exact_model"), "effort": payload.get("exact_effort")}), "model_profile_digest"),
        "execution_host_digest": _require_digest(payload.get("execution_host_digest"), "execution_host_digest"),
        "workload_host_digest": _require_digest(payload.get("workload_host_digest"), "workload_host_digest"),
        "worktree_lease_digest": _require_digest(binding.get("worktree_lease_digest"), "worktree_lease_digest"),
        "worktree_fence": binding.get("worktree_fence"),
        "artifact_digest": artifact_digest,
        "validation_command_digest": validation_command_digest,
        "validation_exit_code": validation_exit_code,
        "settlement_receipt_digest": _settlement_digest(snapshot, job_id, attempt),
        "terminal_cause_kind": cause_kind,
        "terminal_cause_receipt_digest": cause_digest,
        "started_at": _timestamp(attempt.get("started_at_utc"), "started_at", allow_none=True),
        "completed_at": _timestamp(attempt.get("finished_at_utc") or job.get("completed_at_utc"), "completed_at"),
    }
    if isinstance(body["worktree_fence"], bool) or not isinstance(body["worktree_fence"], int) or body["worktree_fence"] < 1:
        raise ValueError("worktree_fence must be positive")
    if body["worktree_fence"] != fence_token:
        raise ValueError("worktree fence binding mismatch")
    body["receipt_digest"] = _digest(body)
    if set(body) != _RECEIPT_FIELDS:
        raise ValueError("internal terminal receipt field error")
    return body


def export_terminal_receipt(
    db_path: str | pathlib.Path,
    attempt_id: str,
    *,
    owner_id: str,
    fence_token: int,
) -> dict[str, Any]:
    """Export one receipt without mutating SQLite or invoking a child."""
    script_dir = pathlib.Path(__file__).resolve().parent
    if str(script_dir) not in sys.path:
        sys.path.insert(0, str(script_dir))
    from sqlite_store import SQLiteStore

    with SQLiteStore(pathlib.Path(db_path).expanduser()) as store:
        lease = store.get_lease()
        if not isinstance(lease, Mapping):
            raise ValueError("controller lease is missing")
        if str(lease.get("status") or "") != "active" or str(lease.get("owner_id") or "") != str(owner_id):
            raise ValueError("controller lease owner mismatch")
        if int(lease.get("fence_token") or 0) != int(fence_token) or _expired(lease.get("lease_expires_at_utc")):
            raise ValueError("controller lease fence is stale or expired")
        attempt = store.get_attempt(str(attempt_id))
        if not isinstance(attempt, Mapping):
            raise ValueError("attempt does not exist")
        job = store.get_job(str(attempt.get("job_id") or ""))
        if not isinstance(job, Mapping):
            raise ValueError("parent job does not exist")
        snapshot = store.snapshot()
        return _build_receipt(snapshot, job, attempt, owner_id=str(owner_id), fence_token=int(fence_token))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--owner-id", required=True)
    parser.add_argument("--fence-token", required=True, type=int)
    parser.add_argument("--output", default="-")
    args = parser.parse_args(argv)
    try:
        receipt = export_terminal_receipt(
            args.db, args.attempt_id, owner_id=args.owner_id, fence_token=args.fence_token
        )
    except Exception as exc:  # CLI boundary is fail-closed and machine-readable.
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    text = json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    if args.output == "-":
        sys.stdout.write(text)
    else:
        pathlib.Path(args.output).expanduser().write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["export_terminal_receipt", "main"]
