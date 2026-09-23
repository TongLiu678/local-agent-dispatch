#!/usr/bin/env python3
"""Convert a planner assignment into a safe, durable controller packet.

The planner deliberately knows *where* work should run, not how a provider
CLI should be invoked.  This bridge is the explicit boundary: it copies only
placement/model fields from a plan, requires an adapter contract, validates
paths and artifacts, and defaults to a dry-run report.  It never starts a
provider or downloads data.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import pathlib
import shlex
from pathlib import PurePosixPath
from typing import Any

try:
    from continuity_controller import resolve_path
except ImportError:  # pragma: no cover - package/direct script fallback
    from .continuity_controller import resolve_path  # type: ignore

try:
    import dispatch_schema
except ImportError:  # pragma: no cover - package/direct script fallback
    from . import dispatch_schema  # type: ignore


SCHEMA_VERSION = 1
DESKTOP_ADAPTERS = {"codex", "cursor", "antigravity", "opencode"}


class BridgeError(ValueError):
    """Raised when a plan assignment cannot be made executable safely."""


def _canonical_digest(payload: Any) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def bridge_foundry_packet(packet: dict[str, Any], *, expected_job_id: str | None = None,
                          expected_plan_digest: str | None = None) -> dict[str, Any]:
    """Validate and pass through a strict Foundry packet without reinterpretation.

    Foundry owns the CPS/route/lane/resource/quota binding.  LAD only checks
    the repository-bound JSON contract and returns a copy; it must not rebuild
    the binding or copy prompt/skill content into a planner packet.
    """
    if not isinstance(packet, dict):
        raise BridgeError("Foundry packet must be an object")
    try:
        dispatch_schema.validate("task_packet", packet)
    except Exception as exc:
        raise BridgeError(f"Foundry packet validation failed: {exc}") from exc
    if expected_job_id is not None and packet.get("job_id") != expected_job_id:
        raise BridgeError("Foundry packet job_id does not match assignment")
    if expected_plan_digest is not None:
        binding = packet.get("foundry_binding") or {}
        if packet.get("plan_digest") != expected_plan_digest or binding.get("plan_digest") != expected_plan_digest:
            raise BridgeError("Foundry packet plan digest does not match bridged plan")
    # JSON round-tripping gives callers an independent value and prevents a
    # mutable planner object from changing the packet after its digest check.
    return json.loads(json.dumps(packet, ensure_ascii=False, sort_keys=True))


def _jobs_by_id(jobs: Any) -> dict[str, dict[str, Any]]:
    rows = jobs.get("jobs", []) if isinstance(jobs, dict) else jobs
    if not isinstance(rows, list):
        raise BridgeError("jobs must be a list or an object containing jobs")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not row.get("job_id"):
            raise BridgeError("every job must be an object with job_id")
        job_id = str(row["job_id"])
        if job_id in result:
            raise BridgeError(f"duplicate job_id: {job_id}")
        result[job_id] = row
    return result


def _host_rows(state: dict[str, Any]) -> dict[str, dict[str, Any]]:
    hosts = state.get("hosts") or state.get("compute_hosts") or {}
    if isinstance(hosts, list):
        return {str(row.get("host_id")): row for row in hosts if isinstance(row, dict) and row.get("host_id")}
    if isinstance(hosts, dict):
        return {str(key): dict(value or {}, host_id=key) for key, value in hosts.items()}
    return {}


_REMOTE_EVIDENCE_TOP_LEVEL = (
    "schema_version",
    "host_id",
    "observed_at_utc",
    "ttl_seconds",
    "cgroup",
    "psi",
    "storage",
    "route",
    "capacity",
    "write_scope_path",
)
_REMOTE_EVIDENCE_CHILDREN = {
    "cgroup": ("status", "max_bytes", "current_bytes", "available_bytes"),
    "psi": ("some_avg10",),
    "storage": ("mount_path", "workspace_path", "writable", "total_bytes", "free_bytes"),
    "route": ("kind", "status", "verified", "target_host_id"),
    "capacity": ("cpu_cores", "ram_gib", "gpu_count", "vram_gib_per_gpu", "vram_gib", "new_disk_gib", "disk_gib"),
}
_REMOTE_ROUTE_KINDS = {"control", "execution", "workload", "artifact", "bulk_data"}
_REMOTE_ROUTE_STATUSES = {"direct", "relay"}
_REMOTE_CAPACITY_RECEIPT_FIELDS = (
    "schema_version", "kind", "host_identity_digest", "project_path_digest",
    "output_path_digest", "runtime_digest", "resource_request_digest",
    "available_disk_bytes", "required_disk_bytes", "available_memory_bytes",
    "required_memory_bytes", "gpu_inventory_digest", "writable_probe_digest",
    "observed_at", "maximum_age_seconds", "receipt_digest",
)
_REMOTE_CAPACITY_RECEIPT_DIGEST_FIELDS = {
    "host_identity_digest", "project_path_digest", "output_path_digest",
    "runtime_digest", "resource_request_digest", "gpu_inventory_digest",
    "writable_probe_digest",
}
_REMOTE_CAPACITY_RECEIPT_INTEGER_FIELDS = {
    "available_disk_bytes", "required_disk_bytes", "available_memory_bytes",
    "required_memory_bytes", "maximum_age_seconds",
}


def _safe_remote_text(value: Any, *, max_length: int = 512) -> str | None:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        return None
    if any(char in value for char in "\0\r\n"):
        return None
    return value


def _safe_remote_timestamp(value: Any) -> str | None:
    text = _safe_remote_text(value, max_length=128)
    if text is None:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return text


def _safe_remote_path(value: Any, *, allow_root: bool = False) -> str | None:
    text = _safe_remote_text(value)
    if text is None:
        return None
    raw = PurePosixPath(text)
    if not raw.is_absolute() or (str(raw) == "/" and not allow_root):
        return None
    if any(part in {"", ".", ".."} for part in raw.parts if part != "/"):
        return None
    return str(raw)


def _safe_remote_number(value: Any) -> int | float | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (OverflowError, TypeError, ValueError):
        return None
    if not math.isfinite(parsed) or parsed < 0:
        return None
    # Preserve integral JSON values while rejecting non-finite values.  This
    # keeps the packet deterministic without carrying arbitrary producer text.
    return int(parsed) if parsed.is_integer() else parsed


def _bounded_remote_evidence_child(kind: str, value: Any) -> dict[str, Any]:
    """Project one evidence object without retaining malformed containers."""
    if not isinstance(value, dict):
        return {}
    result: dict[str, Any] = {}
    for key in _REMOTE_EVIDENCE_CHILDREN[kind]:
        if key not in value:
            continue
        item = value[key]
        if kind == "cgroup":
            if key == "status":
                if item == "complete":
                    result[key] = item
            else:
                number = _safe_remote_number(item)
                if number is not None:
                    result[key] = number
        elif kind == "psi":
            number = _safe_remote_number(item)
            if number is not None:
                result[key] = number
        elif kind == "storage":
            if key == "mount_path":
                path = _safe_remote_path(item, allow_root=True)
                if path is not None:
                    result[key] = path
            elif key == "workspace_path":
                path = _safe_remote_path(item)
                if path is not None:
                    result[key] = path
            elif key == "writable":
                if isinstance(item, bool):
                    result[key] = item
            else:
                number = _safe_remote_number(item)
                if number is not None:
                    result[key] = number
        elif kind == "route":
            if key == "kind" and item in _REMOTE_ROUTE_KINDS:
                result[key] = item
            elif key == "status" and item in _REMOTE_ROUTE_STATUSES:
                result[key] = item
            elif key == "verified" and isinstance(item, bool):
                result[key] = item
            elif key == "target_host_id":
                text = _safe_remote_text(item, max_length=128)
                if text is not None:
                    result[key] = text
        elif kind == "capacity":
            number = _safe_remote_number(item)
            if number is not None:
                result[key] = number
    if kind == "capacity":
        # Planner-facing inventories historically used ``vram_gib`` and
        # ``disk_gib`` while the remote admission contract uses the
        # canonical per-GPU/new-disk names.  Normalize aliases at this
        # boundary so valid capacity observations survive projection; the
        # downstream validator remains responsible for checking completeness
        # and request fit.  Canonical values win if both spellings exist.
        if "vram_gib_per_gpu" not in result and "vram_gib" in result:
            result["vram_gib_per_gpu"] = result["vram_gib"]
        result.pop("vram_gib", None)
        if "new_disk_gib" not in result and "disk_gib" in result:
            result["new_disk_gib"] = result["disk_gib"]
        result.pop("disk_gib", None)
    return result


def _bounded_remote_resource_evidence(value: Any) -> dict[str, Any]:
    """Project producer evidence to the admission contract's allow-list.

    Preflight snapshots may carry diagnostics from SSH and route discovery.
    The controller must receive only the fields understood by
    ``validate_remote_resource_evidence``; copying the raw snapshot would
    persist unrelated commands, credentials, or volatile process metadata.
    """
    if not isinstance(value, dict):
        raise BridgeError("remote_resource_evidence must be an object")
    projected: dict[str, Any] = {}
    for key in _REMOTE_EVIDENCE_TOP_LEVEL:
        if key not in value:
            continue
        child_keys = _REMOTE_EVIDENCE_CHILDREN.get(key)
        item = value[key]
        if child_keys is None:
            if key == "schema_version" and item == 1:
                projected[key] = item
            elif key == "host_id":
                text = _safe_remote_text(item)
                if text is not None:
                    projected[key] = text
            elif key == "observed_at_utc":
                timestamp = _safe_remote_timestamp(item)
                if timestamp is not None:
                    projected[key] = timestamp
            elif key == "ttl_seconds":
                number = _safe_remote_number(item)
                if number is not None and number > 0:
                    projected[key] = number
            elif key == "write_scope_path":
                path = _safe_remote_path(item)
                if path is not None:
                    projected[key] = path
        else:
            # Never preserve malformed containers: a producer can otherwise
            # smuggle command/argv/token-shaped values through an allowlisted
            # key.  An empty child remains fail-closed at controller claim.
            projected[key] = _bounded_remote_evidence_child(key, item)
    return projected


def _bounded_capacity_receipt(value: Any) -> dict[str, Any]:
    """Copy only the digest/count/timestamp capacity receipt contract."""
    if not isinstance(value, dict):
        return {}
    projected: dict[str, Any] = {}
    for key in _REMOTE_CAPACITY_RECEIPT_FIELDS:
        if key not in value:
            continue
        item = value[key]
        if key in _REMOTE_CAPACITY_RECEIPT_DIGEST_FIELDS or key == "receipt_digest":
            text = _safe_remote_text(item, max_length=71)
            if text is not None and len(text) == 71 and text.startswith("sha256:"):
                projected[key] = text
        elif key in _REMOTE_CAPACITY_RECEIPT_INTEGER_FIELDS:
            if isinstance(item, int) and not isinstance(item, bool) and item >= 0:
                projected[key] = item
        elif key == "schema_version" and item == "0.1.0":
            projected[key] = item
        elif key == "kind" and item == "server_capacity_receipt":
            projected[key] = item
        elif key == "observed_at":
            timestamp = _safe_remote_timestamp(item)
            if timestamp is not None:
                projected[key] = timestamp
    return projected


def _remote_resource_evidence(
    assignment: dict[str, Any],
    job: dict[str, Any],
    host_row: dict[str, Any],
    *,
    remote_workspace: str | None = None,
) -> dict[str, Any] | None:
    """Select or derive bounded evidence without copying a full preflight state."""
    for source in (assignment, job, host_row):
        if "remote_resource_evidence" in source:
            return _bounded_remote_resource_evidence(source["remote_resource_evidence"])
    # A fresh preflight may expose all raw facts needed for admission but not
    # yet carry the nested packet contract.  Derive it only when the host has
    # an explicit verified route and complete cgroup/storage/PSI observations;
    # otherwise leave the field absent so SQLite blocks rather than guessing.
    if remote_workspace:
        try:
            from remote_resource_evidence import derive_remote_resource_evidence
        except ImportError:  # pragma: no cover - package-style fallback
            from .remote_resource_evidence import derive_remote_resource_evidence  # type: ignore
        write_scope = assignment.get("write_scope") or job.get("write_scope")
        derived = derive_remote_resource_evidence(
            host_row,
            workspace_path=remote_workspace,
            write_scope=str(write_scope or ""),
        )
        if derived is not None:
            return _bounded_remote_resource_evidence(derived)
    return None


def _assignment_capacity_metadata(
    assignment: dict[str, Any], job: dict[str, Any], host_row: dict[str, Any]
) -> dict[str, Any]:
    """Carry strict capacity metadata without copying planner diagnostics."""
    result: dict[str, Any] = {}
    for source in (assignment, job, host_row):
        if "capacity_receipt" in source:
            result["capacity_receipt"] = _bounded_capacity_receipt(source["capacity_receipt"])
            break
    for key in ("resource_request_digest", "remote_resource_evidence_verified"):
        for source in (assignment, job):
            if key not in source:
                continue
            value = source[key]
            if key == "resource_request_digest":
                text = _safe_remote_text(value, max_length=71)
                if text is not None and len(text) == 71 and text.startswith("sha256:"):
                    result[key] = text
            elif isinstance(value, bool):
                result[key] = value
            break
    return result


def _validate_remote_cli_packet(packet: dict[str, Any]) -> None:
    """Run the same fail-closed placement gate before SQLite enqueue."""
    if not (
        "remote_cli_placement" in packet
        or any(
            isinstance(attempt, dict) and attempt.get("adapter") == "remote_cli"
            for attempt in (packet.get("attempts") or [])
        )
    ):
        return
    try:
        from sqlite_controller import validate_remote_cli_placement_packet
    except ImportError:  # pragma: no cover - package-style fallback
        from .sqlite_controller import validate_remote_cli_placement_packet  # type: ignore
    try:
        validate_remote_cli_placement_packet(packet)
    except ValueError as exc:
        raise BridgeError(str(exc)) from exc


def _require_path(value: Any, workspace: pathlib.Path, field: str) -> str:
    if not value:
        raise BridgeError(f"missing {field}")
    try:
        return str(resolve_path(str(value), workspace))
    except ValueError as exc:
        raise BridgeError(f"{field}: {exc}") from exc


def _require_remote_path(value: Any, remote_root: str, field: str) -> str:
    """Resolve a remote POSIX path below the declared host project root."""
    if not isinstance(value, str) or not value.strip():
        raise BridgeError(f"missing {field}")
    root = PurePosixPath(remote_root)
    raw = PurePosixPath(value)
    if not root.is_absolute():
        raise BridgeError("remote_workspace must be an absolute POSIX path")
    if any(part in {"", ".", ".."} for part in raw.parts if part != "/"):
        raise BridgeError(f"{field}: unsafe remote path component")
    candidate = raw if raw.is_absolute() else root / raw
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise BridgeError(f"{field}: path escapes remote workspace") from exc
    return str(candidate)


def _artifact_list(job: dict[str, Any], assignment: dict[str, Any]) -> list[Any]:
    values = job.get("required_artifacts")
    if values is None:
        values = job.get("required_artifact")
    if values is None:
        values = assignment.get("required_artifact")
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list) or not values or not all(values):
        raise BridgeError("required_artifacts must be a non-empty list")
    return list(values)


def _coerce_validation(job: dict[str, Any], spec: dict[str, Any]) -> list[str]:
    raw = job.get("validation_argv")
    if raw is None:
        raw = job.get("validation_command")
    if raw is None:
        raw = spec.get("validation_argv") or spec.get("validation_command")
    if isinstance(raw, str):
        argv = shlex.split(raw)
    elif isinstance(raw, list) and all(isinstance(item, str) for item in raw):
        argv = list(raw)
    else:
        raise BridgeError("validation command is required and must be argv or a shell-free string")
    if not argv:
        raise BridgeError("validation command must not be empty")
    executable = pathlib.Path(argv[0]).name.lower()
    if executable in {"sh", "bash", "zsh", "fish", "cmd", "powershell", "pwsh"} and any(
        item in {"-c", "/c", "-command"} for item in argv[1:]
    ):
        raise BridgeError("shell validation is not allowed; use an explicit argv executable")
    return argv


def _expand_argv(raw: Any, assignment: dict[str, Any], workspace: pathlib.Path) -> list[str]:
    if not isinstance(raw, list) or not raw or not all(isinstance(item, str) for item in raw):
        raise BridgeError("command adapter requires an explicit non-empty argv list")
    values = {
        "model": str(assignment.get("model") or ""),
        "variant": str(assignment.get("variant") or ""),
        "workspace": str(workspace),
    }
    result: list[str] = []
    for item in raw:
        if "{prompt}" in item or "{task}" in item:
            raise BridgeError("argv templates may not interpolate prompt/task text")
        try:
            result.append(item.format_map(values))
        except (KeyError, ValueError) as exc:
            raise BridgeError(f"invalid argv template: {item}") from exc
    return result


def assignment_to_packet(
    assignment: dict[str, Any],
    job: dict[str, Any],
    state: dict[str, Any],
    adapter_registry: dict[str, Any],
    *,
    plan_digest: str,
    model_policy: str | None = None,
) -> dict[str, Any]:
    """Build one deterministic packet or raise :class:`BridgeError`."""
    job_id = str(assignment.get("job_id") or job.get("job_id") or "")
    if not job_id:
        raise BridgeError("assignment is missing job_id")
    supplied_foundry_packet = assignment.get("foundry_packet")
    if supplied_foundry_packet is None:
        supplied_foundry_packet = job.get("foundry_packet")
    if supplied_foundry_packet is not None:
        return bridge_foundry_packet(
            supplied_foundry_packet,
            expected_job_id=job_id,
            expected_plan_digest=plan_digest,
        )
    model = str(assignment.get("model") or "")
    if not model:
        raise BridgeError(f"{job_id}: planner assignment must contain exact model")
    pool_id = str(assignment.get("pool_id") or "")
    if not pool_id:
        raise BridgeError(f"{job_id}: planner assignment must contain pool_id")
    spec = adapter_registry.get(pool_id) or adapter_registry.get(pool_id.split(".", 1)[0])
    if not isinstance(spec, dict):
        raise BridgeError(f"{job_id}: missing adapter contract for {pool_id}")
    adapter = str(spec.get("adapter") or "")
    if not adapter:
        raise BridgeError(f"{job_id}: adapter contract has no adapter")
    provider = str(spec.get("provider") or pool_id.split(".", 1)[0])

    execution_host = str(assignment.get("execution_host") or "")
    workload_host = str(assignment.get("workload_host") or execution_host)
    execution_transport = str(assignment.get("execution_transport") or spec.get("transport") or "local")
    workload_transport = str(assignment.get("workload_transport") or execution_transport)
    hosts = _host_rows(state)
    if execution_host and execution_host not in hosts:
        raise BridgeError(f"{job_id}: unknown execution_host {execution_host}")
    if workload_host and workload_host not in hosts:
        raise BridgeError(f"{job_id}: unknown workload_host {workload_host}")

    desktop_model_route = pool_id in {"codex.spark", "antigravity.gemini"}
    remote_cli_contract = assignment.get("remote_cli_placement")
    if remote_cli_contract is None:
        remote_cli_contract = job.get("remote_cli_placement")
    remote_cli_route = adapter == "remote_cli"
    if remote_cli_route:
        if not isinstance(remote_cli_contract, dict):
            raise BridgeError(f"{job_id}: remote_cli placement contract is required")
        if execution_transport != "ssh":
            raise BridgeError(f"{job_id}: remote_cli requires SSH execution")
    desktop_split = (
        desktop_model_route
        and execution_transport == "local"
        and workload_host != execution_host
    )
    desktop_split_contract = assignment.get("desktop_split_contract")
    if desktop_split_contract is None:
        desktop_split_contract = job.get("desktop_split_contract")

    if not remote_cli_route and (
        adapter in DESKTOP_ADAPTERS
        or provider in DESKTOP_ADAPTERS
        or desktop_model_route
    ):
        if execution_transport != "local":
            raise BridgeError(f"{job_id}: desktop adapter cannot execute over SSH")
        if workload_host != execution_host:
            if not (spec.get("supports_split_placement") and job.get("workload_wrapper")):
                raise BridgeError(f"{job_id}: split_placement_requires_remote_wrapper")
            if desktop_split_contract is None:
                raise BridgeError(f"{job_id}: desktop_split_contract_required")
    if adapter == "server_local":
        if workload_host != execution_host or workload_transport != "ssh":
            raise BridgeError(f"{job_id}: server_local requires one SSH execution/workload host")
    if adapter == "server_openai":
        base_url = str(spec.get("base_url") or job.get("base_url") or "")
        if not base_url or not any(token in base_url for token in ("127.0.0.1", "localhost", "::1")):
            raise BridgeError(f"{job_id}: server_openai requires a loopback base_url")
    if adapter == "cursor" and spec.get("cursor_prompt_argv_authorized") is not True:
        raise BridgeError(
            f"{job_id}: cursor adapter requires explicit "
            "cursor_prompt_argv_authorized=true"
        )

    workspace_value = job.get("workspace") or state.get("workspace")
    if not workspace_value:
        raise BridgeError(f"{job_id}: missing workspace")
    workspace = pathlib.Path(str(workspace_value)).expanduser().resolve()
    remote_server = execution_transport == "ssh" and adapter in {
        "server_local", "server_openai", "remote_cli"
    }
    remote_workload = remote_server or desktop_split
    remote_workspace: str | None = None
    prompt_file: str | None
    split_contract_body: dict[str, Any] = {}
    if desktop_split_contract is not None:
        if not isinstance(desktop_split_contract, dict):
            raise BridgeError(f"{job_id}: desktop_split_contract must be an object")
        raw_body = desktop_split_contract.get("contract")
        split_contract_body = dict(raw_body if isinstance(raw_body, dict) else desktop_split_contract)
    if remote_workload:
        # Resource evidence belongs to the workload mount.  Keep the
        # execution host as a fallback for legacy packets that do not carry a
        # distinct workload host, but never bind a split placement to the
        # controller/CLI host's capacity by accident.
        host_row = hosts.get(workload_host) or hosts.get(execution_host) or {}
        remote_root = str(host_row.get("project_path") or "")
        remote_workspace = _require_remote_path(
            str(
                split_contract_body.get("remote_workspace")
                or assignment.get("remote_workspace")
                or job.get("remote_workspace")
                or spec.get("remote_workspace")
                or remote_root
            ),
            remote_root,
            "remote_workspace",
        )
        if desktop_split:
            # The desktop CLI reads its prompt locally.  Only the workload
            # paths and validator belong to the SSH host.
            prompt_file = _require_path(
                job.get("prompt_file") or spec.get("prompt_file"), workspace, "prompt_file"
            )
        elif adapter in {"server_local", "remote_cli"}:
            remote_prompt = job.get("remote_prompt_file") or spec.get("remote_prompt_file")
            prompt_file = (
                _require_remote_path(remote_prompt, remote_workspace, "remote_prompt_file")
                if remote_prompt
                else None
            )
        else:
            # server_openai sends a small prompt payload over the authenticated
            # SSH stdin, so its source remains on the controller workspace.
            prompt_file = _require_path(
                job.get("prompt_file") or spec.get("prompt_file"), workspace, "prompt_file"
            )
        raw_artifacts = (
            split_contract_body.get("remote_required_artifacts")
            or job.get("remote_required_artifacts")
            or _artifact_list(job, assignment)
        )
        artifacts = [_require_remote_path(value, remote_workspace, "remote_required_artifact") for value in raw_artifacts]
        remote_result = (
            split_contract_body.get("remote_result_source_path")
            or assignment.get("remote_result_source_path")
            or job.get("remote_result_source_path")
            or spec.get("remote_result_source_path")
            or job.get("result_source_path")
            or spec.get("result_source_path")
        )
        result_source = _require_remote_path(remote_result, remote_workspace, "remote_result_source_path")
        # A generic SSH command is expected to create the remote artifact.  A
        # local controller must never try to publish stdout to that path.
        output_path = None
    else:
        prompt_file = _require_path(job.get("prompt_file") or spec.get("prompt_file"), workspace, "prompt_file")
        artifacts = [_require_path(value, workspace, "required_artifact") for value in _artifact_list(job, assignment)]
        result_source = _require_path(
            job.get("result_source_path") or spec.get("result_source_path"), workspace, "result_source_path"
        )
        output_path = _require_path(
            job.get("output_path") or spec.get("output_path") or result_source, workspace, "output_path"
        )
    validation_source = job
    if desktop_split:
        validation_source = dict(job)
        remote_validator = split_contract_body.get("remote_validator")
        if isinstance(remote_validator, dict) and remote_validator.get("argv"):
            validation_source["validation_argv"] = remote_validator["argv"]
        elif assignment.get("remote_validation_argv"):
            validation_source["validation_argv"] = assignment["remote_validation_argv"]
    validation_argv = _coerce_validation(validation_source, spec)
    if remote_workload and pathlib.Path(validation_argv[0]).is_absolute():
        raise BridgeError(
            f"{job_id}: remote validation must use a host-resolved executable name or remote absolute path"
        )

    # Carry only an explicitly supplied, bounded observation into a remote
    # packet.  SQLite will re-check freshness, host binding, route, mount,
    # cgroup/PSI, and capacity at claim time; absence therefore remains a
    # deliberate fail-closed outcome rather than an implicit verification.
    remote_evidence = (
        _remote_resource_evidence(
            assignment,
            job,
            hosts.get(workload_host) or hosts.get(execution_host) or {},
            remote_workspace=remote_workspace,
        )
        if remote_server
        else None
    )
    capacity_metadata = (
        _assignment_capacity_metadata(
            assignment,
            job,
            hosts.get(workload_host) or hosts.get(execution_host) or {},
        )
        if remote_server
        else {}
    )

    attempt_id = str(
        assignment.get("attempt_id")
        or "attempt-"
        + _canonical_digest(
            {"plan": plan_digest, "job_id": job_id, "pool_id": pool_id, "model": model, "variant": assignment.get("variant")}
        )[:16]
    )
    attempt: dict[str, Any] = {
        "attempt_id": attempt_id,
        "adapter": adapter,
        "transport": execution_transport,
        "host_id": execution_host or None,
        "pool_id": pool_id,
        "provider": provider,
        "model": model,
        "variant": assignment.get("variant"),
        "prompt_file": prompt_file,
        "result_source_path": result_source,
        "output_path": output_path,
        "timeout_seconds": min(int(job.get("timeout_seconds", spec.get("timeout_seconds", 3600))), 86400),
        "validation_argv": validation_argv,
    }
    if remote_workspace and (adapter == "server_local" or desktop_split):
        if desktop_split:
            # Keep the desktop CLI's local workspace in ``workspace`` while
            # binding the remote workload paths separately.
            attempt["remote_workspace"] = remote_workspace
            attempt["remote_result_source_path"] = result_source
            attempt["workload_host"] = workload_host
            attempt["workload_transport"] = workload_transport
        else:
            attempt["workspace"] = remote_workspace
            attempt["remote_workspace"] = remote_workspace
            attempt["remote_result_source_path"] = result_source
    elif remote_workspace:
        attempt["remote_workspace"] = remote_workspace
        attempt["remote_result_source_path"] = result_source
    if desktop_split:
        wrapper_body = split_contract_body.get("workload_wrapper")
        if isinstance(wrapper_body, dict):
            attempt["workload_wrapper"] = str(wrapper_body.get("name") or "")
        attempt["remote_required_artifacts"] = list(artifacts)
        if isinstance(split_contract_body.get("remote_validator"), dict):
            attempt["remote_validator"] = split_contract_body["remote_validator"]
    if remote_workspace and adapter == "server_local" and not desktop_split:
        attempt["workspace"] = remote_workspace
        attempt["remote_workspace"] = remote_workspace
        attempt["remote_result_source_path"] = result_source
    if adapter in {"command", "server_local"}:
        attempt["argv"] = _expand_argv(
            spec.get("argv"), assignment, pathlib.Path(workspace if desktop_split else (remote_workspace or workspace))
        )
    if adapter == "cursor":
        attempt["prompt_transport"] = "argv_insecure"
    for key in (
        "base_url",
        "temperature",
        "auto_approve",
        "pure",
        "print_timeout",
        "idle_timeout",
        "cursor_prompt_argv_authorized",
        "cursor_trust_workspace",
        "cursor_force_commands",
        "cursor_mode",
        "cursor_sandbox",
        "cursor_executable",
    ):
        if key in spec:
            attempt[key] = spec[key]

    packet = {
        "schema_version": SCHEMA_VERSION,
        "packet_id": "packet-" + _canonical_digest({"plan": plan_digest, "job_id": job_id})[:16],
        "job_id": job_id,
        "pool_id": pool_id,
        "model": model,
        "variant": assignment.get("variant"),
        "plan_digest": plan_digest,
        "assignment_digest": _canonical_digest(assignment),
        "workspace": (
            remote_workspace
            if remote_server and adapter in {"server_local", "remote_cli"}
            else str(workspace)
        ),
        "write_scope": str(assignment.get("write_scope") or job.get("write_scope") or ""),
        "required_artifacts": artifacts,
        "validation_argv": validation_argv,
        "validation_required": True,
        "execution_host": execution_host,
        "workload_host": workload_host,
        "execution_transport": execution_transport,
        "workload_transport": workload_transport,
        "data_route": assignment.get("data_route"),
        "resource_request": assignment.get("resource_request") or {},
        "attempts": [attempt],
    }
    if model_policy:
        packet["model_policy"] = str(model_policy)
    if remote_workspace and adapter in {"server_openai", "remote_cli"}:
        packet["remote_workspace"] = remote_workspace
    if remote_evidence is not None:
        packet["remote_resource_evidence"] = remote_evidence
    packet.update(capacity_metadata)
    if not packet["write_scope"]:
        raise BridgeError(f"{job_id}: write_scope is required")
    if desktop_split:
        try:
            from desktop_split_placement import attach_desktop_split_contract
        except ImportError:  # pragma: no cover - package-style fallback
            from .desktop_split_placement import attach_desktop_split_contract  # type: ignore
        try:
            packet = attach_desktop_split_contract(packet, desktop_split_contract)
        except ValueError as exc:
            raise BridgeError(str(exc)) from exc
    if remote_cli_route:
        try:
            from remote_cli_placement import attach_remote_cli_contract
        except ImportError:  # pragma: no cover - package-style fallback
            from .remote_cli_placement import attach_remote_cli_contract  # type: ignore
        try:
            packet = attach_remote_cli_contract(packet, remote_cli_contract)
        except ValueError as exc:
            raise BridgeError(str(exc)) from exc
    _validate_remote_cli_packet(packet)
    return packet


def bridge_plan(
    plan: dict[str, Any],
    jobs: Any,
    state: dict[str, Any],
    adapter_registry: dict[str, Any],
    *,
    mode: str = "dry-run",
) -> dict[str, Any]:
    """Return packets for dispatch assignments without executing them."""
    if mode not in {"dry-run", "enqueue-ready"}:
        raise BridgeError("mode must be dry-run or enqueue-ready")
    if not isinstance(plan, dict) or plan.get("schema_version", SCHEMA_VERSION) != SCHEMA_VERSION:
        raise BridgeError("plan schema_version must be 1")
    if not plan.get("ok") or plan.get("decision") != "dispatch":
        raise BridgeError("only an ok dispatch plan can be bridged")
    assignments = plan.get("assignments")
    if not isinstance(assignments, list):
        raise BridgeError("plan assignments must be a list")
    by_id = _jobs_by_id(jobs)
    plan_digest = _canonical_digest(plan)
    model_policy = plan.get("model_policy")
    if model_policy is not None and not isinstance(model_policy, str):
        raise BridgeError("plan model_policy must be a string when present")
    packets: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for assignment in assignments:
        if not isinstance(assignment, dict):
            errors.append({"job_id": "", "error": "assignment must be an object"})
            continue
        job_id = str(assignment.get("job_id") or "")
        job = by_id.get(job_id)
        if job is None:
            errors.append({"job_id": job_id, "error": "assignment references unknown job"})
            continue
        if str(job.get("status") or "") in {"active", "running", "completed", "blocked"}:
            errors.append({"job_id": job_id, "error": "job is not enqueueable in its current status"})
            continue
        try:
            packets.append(
                assignment_to_packet(
                    assignment,
                    job,
                    state,
                    adapter_registry,
                    plan_digest=plan_digest,
                    model_policy=model_policy,
                )
            )
        except BridgeError as exc:
            errors.append({"job_id": job_id, "error": str(exc)})
    return {
        "schema_version": SCHEMA_VERSION,
        "bridge_version": "0.1.0",
        "mode": mode,
        "read_only": True,
        "ok": not errors and bool(packets),
        "plan_digest": plan_digest,
        "packets": packets,
        "errors": errors,
        "deferred": plan.get("deferred") or [],
    }


def enqueue_packets(report: dict[str, Any], db_path: pathlib.Path) -> dict[str, Any]:
    """Explicitly enqueue bridged packets into the local SQLite controller.

    Bridging remains read-only by default.  This function is the deliberately
    narrow mutation boundary used only by the ``--enqueue``/``--execute`` CLI
    flags: it validates that the report was built in ``enqueue-ready`` mode,
    delegates packet validation to :class:`SQLiteController`, and returns only
    redacted job summaries.  It never claims to execute a provider, starts no
    worker, and opens no network or SSH connection.
    """
    if not isinstance(report, dict):
        raise BridgeError("bridge report must be an object")
    if report.get("mode") != "enqueue-ready":
        raise BridgeError("SQLite enqueue requires bridge mode enqueue-ready")
    if not report.get("ok"):
        raise BridgeError("cannot enqueue a bridge report with validation errors")
    packets = report.get("packets")
    if not isinstance(packets, list) or not packets:
        raise BridgeError("bridge report has no enqueueable packets")
    path = pathlib.Path(db_path).expanduser().resolve()
    try:
        from sqlite_controller import SQLiteController
    except ImportError:  # pragma: no cover - package-style fallback
        from .sqlite_controller import SQLiteController  # type: ignore

    controller = SQLiteController(path)
    jobs: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for packet in packets:
        job_id = str(packet.get("job_id") or "") if isinstance(packet, dict) else ""
        if not job_id:
            errors.append({"job_id": "", "error": "packet is missing job_id"})
            continue
        try:
            if isinstance(packet, dict) and packet.get("schema_version") == "lad_task_packet/2.0.0":
                raise BridgeError(
                    "strict Foundry packets are bridge-only until the LAD v2 claim adapter is enabled"
                )
            _validate_remote_cli_packet(packet)
            attempts = packet.get("attempts") if isinstance(packet, dict) else None
            split_remote = bool(
                isinstance(packet, dict)
                and isinstance(packet.get("desktop_split_placement"), dict)
                and packet.get("execution_transport") == "local"
                and packet.get("workload_transport") == "ssh"
            )
            remote = bool(
                isinstance(attempts, list)
                and attempts
                and isinstance(attempts[0], dict)
                and attempts[0].get("transport") == "ssh"
            ) or split_remote
            row = controller.enqueue_remote(packet) if remote else controller.enqueue(packet)
            jobs.append(
                {
                    "job_id": row.get("job_id", job_id),
                    "status": row.get("status", "queued"),
                    "state_revision": row.get("state_revision"),
                    "transport_outbox": remote,
                }
            )
        except Exception as exc:
            # Keep provider/argv/prompt payloads out of the audit response.
            errors.append({"job_id": job_id, "error": f"{type(exc).__name__}: {exc}"})
    return {
        "schema_version": SCHEMA_VERSION,
        "backend": "sqlite",
        "db_path": str(path),
        "enqueue_requested": True,
        "enqueue_performed": bool(jobs),
        "ok": not errors and bool(jobs),
        "jobs": jobs,
        "errors": errors,
        "provider_execution": False,
        "model_prompts_sent": False,
    }


def load_json(path: pathlib.Path) -> Any:
    return json.loads(path.expanduser().read_text(encoding="utf-8"))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--jobs", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--adapters", required=True)
    parser.add_argument("--output")
    parser.add_argument("--mode", choices=("dry-run", "enqueue-ready"), default="dry-run")
    parser.add_argument(
        "--enqueue", "--execute", dest="enqueue", action="store_true",
        help="explicitly enqueue the validated packets into SQLite; never executes a provider",
    )
    parser.add_argument("--db", help="SQLite database path required with --enqueue/--execute")
    args = parser.parse_args(argv)
    try:
        if args.enqueue and not args.db:
            raise BridgeError("--enqueue/--execute requires --db")
        mode = "enqueue-ready" if args.enqueue else args.mode
        report = bridge_plan(
            load_json(pathlib.Path(args.plan)),
            load_json(pathlib.Path(args.jobs)),
            load_json(pathlib.Path(args.state)),
            load_json(pathlib.Path(args.adapters)),
            mode=mode,
        )
        if args.enqueue:
            enqueue_report = enqueue_packets(report, pathlib.Path(args.db))
            report = dict(report)
            report["read_only"] = False
            report["enqueue"] = enqueue_report
            report["enqueue_requested"] = True
            report["enqueue_performed"] = bool(enqueue_report.get("enqueue_performed"))
            report["provider_execution"] = False
            report["ok"] = bool(report.get("ok") and enqueue_report.get("ok"))
    except Exception as exc:
        report = {
            "schema_version": SCHEMA_VERSION,
            "read_only": not bool(getattr(args, "enqueue", False)),
            "enqueue_requested": bool(getattr(args, "enqueue", False)),
            "enqueue_performed": False,
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    if args.output:
        pathlib.Path(args.output).expanduser().write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))
