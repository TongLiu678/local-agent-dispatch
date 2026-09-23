#!/usr/bin/env python3
"""Transactional SQLite controller for explicit, prepared task packets.

This is the first SQLite-backed execution path.  It reuses the existing
provider adapter/build/validation helpers, while queue claim, lease fencing,
attempt transitions, and event records are committed by ``SQLiteStore`` in
short WAL transactions.  It is intentionally opt-in; the legacy JSON
controller remains available during migration.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
import pathlib
import sys
import threading
import time
import uuid
from collections.abc import Mapping
from typing import Any, Callable

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import continuity_controller as continuity  # noqa: E402
from sqlite_store import (  # noqa: E402
    FencingError,
    JobConflict,
    ReservationAdmissionError,
    SQLiteStore,
)
import resource_governor as governor  # noqa: E402
import resource_admission as local_resource_admission  # noqa: E402
from remote_envelope import build_envelope  # noqa: E402
from remote_resource_evidence import validate_remote_resource_evidence  # noqa: E402
from desktop_split_placement import validate_desktop_split_placement_packet  # noqa: E402
import replan_controller as replan  # noqa: E402


def load_json(path: pathlib.Path) -> Any:
    return json.loads(path.expanduser().read_text(encoding="utf-8"))


def write_json(payload: Any) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def priority_value(job: dict[str, Any]) -> int:
    value = job.get("priority", 0)
    if isinstance(value, int):
        return int(value)
    return {"low": 1, "normal": 2, "high": 3, "critical": 4}.get(str(value).lower(), 2)


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _replan_feedback_payload(value: Any) -> Mapping[str, Any] | None:
    """Extract the planner feedback portion of a saved replan artifact.

    The controller accepts either the small ``replan_feedback`` object or a
    complete read-only ``dispatch_closed_loop`` report.  It deliberately
    ignores prompts, commands, and arbitrary planner fields: only the
    timestamp/reset metadata needed for a bounded wake can cross this seam.
    """

    if not isinstance(value, Mapping):
        return None
    direct = value.get("replan_feedback")
    if isinstance(direct, Mapping):
        return dict(direct)
    quota_watch = value.get("quota_window_watch")
    if isinstance(quota_watch, Mapping):
        watched = quota_watch.get("replan_feedback")
        if isinstance(watched, Mapping):
            return dict(watched)
    if "replan_at_utc" in value:
        return {
            key: value[key]
            for key in (
                "replan_at_utc",
                "replan_reason",
                "quota_reset_at_utc",
                "quota_reset_pool_id",
            )
            if key in value
        }
    # A previously compiled schedule is sufficient to preserve its target,
    # but never treat an arbitrary ``wake_at_utc`` as a reset target.
    for key in ("quota_replan_schedule", "replan_schedule"):
        schedule = value.get(key)
        if isinstance(schedule, Mapping) and schedule.get("target_replan_at_utc"):
            return {
                "replan_at_utc": schedule.get("target_replan_at_utc"),
                "replan_reason": schedule.get("replan_reason"),
                "quota_reset_at_utc": schedule.get("quota_reset_at_utc"),
                "quota_reset_pool_id": schedule.get("quota_reset_pool_id"),
            }
    return None


def _replan_event_payload(
    schedule: Mapping[str, Any],
    feedback: Mapping[str, Any] | None,
    *,
    loader_error: str | None = None,
    observation_mode: str = "idle",
    active_job_ids: list[str] | None = None,
    active_attempt_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Keep durable replan events metadata-only and secret-safe."""

    reason_text = str(schedule.get("replan_reason") or "").lower()
    if schedule.get("quota_reset_at_utc") or schedule.get("quota_reset_pool_id"):
        trigger_source = "quota_reset"
    elif "quota" in reason_text or "window" in reason_text:
        trigger_source = "quota_window"
    elif any(token in reason_text for token in ("resource", "memory", "disk", "pressure", "host")):
        trigger_source = "resource_pressure"
    else:
        trigger_source = "external"

    payload: dict[str, Any] = {
        "schema_version": 1,
        "source": "sqlite_controller",
        "trigger_source": trigger_source,
        "observation_mode": observation_mode,
        "feedback_digest": _digest(feedback or {}),
        "decision": schedule.get("decision"),
        "reason": schedule.get("reason"),
        "replan_reason": schedule.get("replan_reason"),
        "target_replan_at_utc": schedule.get("target_replan_at_utc"),
        "wake_at_utc": schedule.get("wake_at_utc"),
        "quota_reset_at_utc": schedule.get("quota_reset_at_utc"),
        "quota_reset_pool_id": schedule.get("quota_reset_pool_id"),
        "invalid_fields": list(schedule.get("invalid_fields") or []),
    }
    if active_job_ids:
        payload["active_job_ids"] = list(active_job_ids)
    if active_attempt_ids:
        payload["active_attempt_ids"] = list(active_attempt_ids)
    if loader_error:
        payload["loader_error"] = loader_error
    return payload


_CAPACITY_RECEIPT_FIELDS = frozenset({
    "schema_version", "kind", "host_identity_digest", "project_path_digest",
    "output_path_digest", "runtime_digest", "resource_request_digest",
    "available_disk_bytes", "required_disk_bytes", "available_memory_bytes",
    "required_memory_bytes", "gpu_inventory_digest", "writable_probe_digest",
    "observed_at", "maximum_age_seconds", "receipt_digest",
})


def validate_capacity_receipt(
    receipt: Any, *, request: dict[str, Any], expected_resource_request_digest: str | None = None,
    now_utc: str | None = None,
) -> dict[str, Any]:
    """Validate an explicit capacity receipt; boolean evidence is never enough."""
    if isinstance(receipt, bool) or not isinstance(receipt, dict):
        raise ValueError("capacity receipt is required; boolean evidence is not admissible")
    if set(receipt) != _CAPACITY_RECEIPT_FIELDS:
        raise ValueError("capacity receipt exact fields differ from schema")
    if receipt.get("schema_version") != "0.1.0" or receipt.get("kind") != "server_capacity_receipt":
        raise ValueError("capacity receipt schema or kind is invalid")
    for field in ("host_identity_digest", "project_path_digest", "output_path_digest", "runtime_digest", "resource_request_digest", "gpu_inventory_digest", "writable_probe_digest", "receipt_digest"):
        value = receipt.get(field)
        if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
            raise ValueError(f"capacity receipt {field} is invalid")
    body = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    if receipt["receipt_digest"] != "sha256:" + hashlib.sha256(json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest():
        raise ValueError("capacity receipt self-digest mismatch")
    request_digest = expected_resource_request_digest or request.get("resource_request_digest")
    if request_digest is not None and receipt["resource_request_digest"] != request_digest:
        raise ValueError("capacity receipt resource request binding mismatch")
    for field in ("available_disk_bytes", "required_disk_bytes", "available_memory_bytes", "required_memory_bytes", "maximum_age_seconds"):
        value = receipt.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"capacity receipt {field} is invalid")
    try:
        observed = dt.datetime.fromisoformat(str(receipt["observed_at"]).replace("Z", "+00:00"))
        current = dt.datetime.fromisoformat((now_utc or dt.datetime.now(dt.timezone.utc).isoformat()).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("capacity receipt observed_at is invalid") from exc
    if observed.tzinfo is None or current.tzinfo is None:
        raise ValueError("capacity receipt timestamps require timezone")
    age = (current - observed).total_seconds()
    if age < 0 or age > receipt["maximum_age_seconds"]:
        raise ValueError("capacity receipt is stale")
    if receipt["available_disk_bytes"] < receipt["required_disk_bytes"] or receipt["available_memory_bytes"] < receipt["required_memory_bytes"]:
        raise ValueError("capacity receipt capacity is insufficient")
    return {"valid": True, "receipt_digest": receipt["receipt_digest"], "observed_at": receipt["observed_at"]}


_QUOTA_SNAPSHOT_RECEIPT_FIELDS = frozenset({
    "schema_version", "kind", "snapshot_id", "project_id", "provider",
    "exact_model", "quota_kind", "pool_id", "remaining_units",
    "reserved_units", "reset_at", "observed_at", "maximum_age_seconds",
    "source_reference", "source_receipt_digest", "snapshot_digest",
})


def _quota_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _quota_timestamp(value: Any, field: str, *, allow_none: bool = False) -> dt.datetime | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"quota snapshot {field} is invalid")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"quota snapshot {field} is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"quota snapshot {field} requires timezone")
    return parsed


def validate_quota_snapshot_receipt(
    receipt: Any,
    *,
    expected_digest: str | None = None,
    expected_provider: str | None = None,
    expected_model: str | None = None,
    expected_pool_id: str | None = None,
    now_utc: str | None = None,
) -> dict[str, Any]:
    """Validate the exact, bounded quota snapshot carried by a task packet.

    A quota snapshot is an observation, not a balance oracle.  Its source is
    represented only by an opaque reference and digest; unknown or malformed
    counters never become schedulable capacity.  The controller calls this
    validator at reservation and child-launch boundaries.
    """
    if not isinstance(receipt, Mapping) or isinstance(receipt, bool):
        raise ValueError("quota snapshot receipt is required")
    if set(receipt) != _QUOTA_SNAPSHOT_RECEIPT_FIELDS:
        raise ValueError("quota snapshot receipt exact fields differ from schema")
    if receipt.get("schema_version") != "0.1.0" or receipt.get("kind") != "quota_snapshot_receipt":
        raise ValueError("quota snapshot receipt schema or kind is invalid")
    for field in (
        "snapshot_id", "project_id", "provider", "exact_model", "quota_kind",
        "pool_id", "source_reference",
    ):
        value = receipt.get(field)
        if not isinstance(value, str) or not value or any(char in value for char in "\0\r\n"):
            raise ValueError(f"quota snapshot {field} is invalid")
    for field in ("source_receipt_digest", "snapshot_digest"):
        value = receipt.get(field)
        if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
            raise ValueError(f"quota snapshot {field} is invalid")
        try:
            int(value[7:], 16)
        except ValueError as exc:
            raise ValueError(f"quota snapshot {field} is invalid") from exc
    body = {key: receipt[key] for key in receipt if key != "snapshot_digest"}
    if receipt["snapshot_digest"] != _quota_digest(body):
        raise ValueError("quota snapshot self-digest mismatch")
    if expected_digest is not None and receipt["snapshot_digest"] != expected_digest:
        raise ValueError("quota snapshot digest binding mismatch")
    for field in ("remaining_units", "reserved_units", "maximum_age_seconds"):
        value = receipt.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"quota snapshot {field} is invalid")
    if receipt["remaining_units"] < receipt["reserved_units"]:
        raise ValueError("quota snapshot remaining units are below reserved units")
    observed = _quota_timestamp(receipt.get("observed_at"), "observed_at")
    reset = _quota_timestamp(receipt.get("reset_at"), "reset_at", allow_none=True)
    current = _quota_timestamp(
        now_utc or dt.datetime.now(dt.timezone.utc).isoformat(), "now_utc"
    )
    assert observed is not None and current is not None
    age = (current - observed).total_seconds()
    if age < 0 or age > receipt["maximum_age_seconds"]:
        raise ValueError("quota snapshot is stale")
    if reset is not None and reset < observed:
        raise ValueError("quota snapshot reset_at precedes observed_at")
    for label, expected, field in (
        ("provider binding", expected_provider, "provider"),
        ("model binding", expected_model, "exact_model"),
        ("pool binding", expected_pool_id, "pool_id"),
    ):
        if expected is not None and receipt[field] != expected:
            raise ValueError(f"quota snapshot {label} mismatch")
    return {
        "valid": True,
        "snapshot_digest": receipt["snapshot_digest"],
        "observed_at": receipt["observed_at"],
        "remaining_units": receipt["remaining_units"],
        "reserved_units": receipt["reserved_units"],
    }


def _packet_quota_snapshot(
    packet: Mapping[str, Any], attempt: Mapping[str, Any] | None = None, *, now_utc: str | None = None
) -> dict[str, Any] | None:
    """Validate a packet quota observation using the exact attempt identity."""
    attempt = attempt or {}
    receipt = packet.get("quota_snapshot")
    binding = packet.get("foundry_binding")
    expected_digest = packet.get("quota_snapshot_digest")
    if expected_digest is None and isinstance(binding, Mapping):
        expected_digest = binding.get("quota_snapshot_digest")
    strict_packet = (
        packet.get("schema_version") == "lad_task_packet/2.0.0"
        or isinstance(binding, Mapping)
        or packet.get("remote_resource_evidence_verified") is True
        or expected_digest is not None
    )
    if receipt is None:
        if strict_packet:
            raise ValueError("quota snapshot receipt is required")
        return None
    return validate_quota_snapshot_receipt(
        receipt,
        expected_digest=expected_digest if isinstance(expected_digest, str) else None,
        expected_provider=(attempt.get("provider") or packet.get("provider")),
        expected_model=(attempt.get("model") or packet.get("model") or packet.get("exact_model")),
        expected_pool_id=(attempt.get("pool_id") or packet.get("pool_id")),
        now_utc=now_utc,
    )


_REMOTE_CLI_EXACT_ROUTES: dict[tuple[str, str], tuple[str, str, Any]] = {
    ("codex.luna", "codex"): ("codex", "gpt-5.6-sol", "max"),
    ("codex.spark", "codex"): ("codex", "gpt-5.3-codex-spark", "xhigh"),
    ("antigravity.gemini", "antigravity"): (
        "agy",
        "gemini-3.6-flash-high",
        None,
    ),
}


def _remote_cli_path(value: Any, field: str) -> str:
    """Validate a lexical absolute POSIX path from a remote contract."""
    if not isinstance(value, str) or not value.strip() or not value.startswith("/"):
        raise ValueError(f"remote_cli_placement {field} must be an absolute path")
    if value == "/" or any(part in {"", ".", ".."} for part in value.split("/")[1:]):
        raise ValueError(f"remote_cli_placement {field} contains an unsafe path")
    return str(pathlib.PurePosixPath(value))


def _remote_cli_below(path: Any, root: str, field: str, *, allow_root: bool = False) -> str:
    candidate = _remote_cli_path(path, field)
    try:
        relative = pathlib.PurePosixPath(candidate).relative_to(pathlib.PurePosixPath(root))
    except ValueError as exc:
        raise ValueError(f"remote_cli_placement {field} escapes {root}") from exc
    result = str(relative)
    if not allow_root and result in {"", "."}:
        raise ValueError(f"remote_cli_placement {field} may not equal {root}")
    return result


def _remote_cli_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"remote_cli_placement {field} is required")
    return value.strip()


def _remote_cli_hex(value: Any, field: str) -> str:
    text = _remote_cli_text(value, field).lower()
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise ValueError(f"remote_cli_placement {field} must be a lowercase SHA-256")
    return text


def validate_remote_cli_placement_packet(packet: dict[str, Any]) -> None:
    """Fail closed when a prepared remote CLI packet is missing or mutates its contract.

    The placement sidecar is intentionally provider-free, so this ingress check
    validates the persisted projection rather than executing or re-probing a
    CLI.  It binds the contract digest, exact route, host/path confinement,
    receipt, wrapper, and packet attempt fields together before SQLite writes.
    """
    if not isinstance(packet, dict):
        raise ValueError("remote_cli_placement packet must be an object")
    attempts = packet.get("attempts")
    if not isinstance(attempts, list) or not attempts or not isinstance(attempts[0], dict):
        raise ValueError("remote_cli_placement packet requires a prepared attempt")
    remote_attempts = [
        row for row in attempts
        if isinstance(row, dict) and row.get("adapter") == "remote_cli"
    ]
    placement_value = packet.get("remote_cli_placement")
    if not remote_attempts and placement_value is None:
        return
    if len(remote_attempts) != 1 or attempts[0].get("adapter") != "remote_cli":
        raise ValueError("remote_cli_placement must bind exactly the first remote_cli attempt")
    if not isinstance(placement_value, dict):
        raise ValueError("remote_cli_placement contract is required for adapter=remote_cli")
    contract = placement_value
    digest = _remote_cli_hex(contract.get("contract_digest"), "contract_digest")
    unsigned = {key: value for key, value in contract.items() if key != "contract_digest"}
    if _digest(unsigned) != digest:
        raise ValueError("remote_cli_placement contract digest mismatch")

    job_id = _remote_cli_text(packet.get("job_id"), "packet.job_id")
    if _remote_cli_text(contract.get("job_id"), "contract.job_id") != job_id:
        raise ValueError("remote_cli_placement job_id does not match packet")
    attempt = attempts[0]
    if _remote_cli_text(contract.get("attempt_id"), "contract.attempt_id") != _remote_cli_text(
        attempt.get("attempt_id"), "attempt.attempt_id"
    ):
        raise ValueError("remote_cli_placement attempt_id does not match attempt")

    provider = _remote_cli_text(contract.get("provider"), "contract.provider")
    pool_id = _remote_cli_text(contract.get("pool_id"), "contract.pool_id")
    expected = _REMOTE_CLI_EXACT_ROUTES.get((pool_id, provider))
    if expected is None:
        raise ValueError("remote_cli_placement has an unsupported pool/provider route")
    expected_cli, expected_model, expected_variant = expected
    if contract.get("model") != expected_model or contract.get("variant") != expected_variant:
        raise ValueError("remote_cli_placement exact model/variant validation failed")

    host = contract.get("host")
    if not isinstance(host, dict):
        raise ValueError("remote_cli_placement host evidence is required")
    execution_host = _remote_cli_text(contract.get("execution_host"), "contract.execution_host")
    if host.get("host_id") != execution_host or host.get("transport") != "ssh":
        raise ValueError("remote_cli_placement host binding is invalid")
    if contract.get("execution_transport") != "ssh" or contract.get("workload_transport") != "ssh":
        raise ValueError("remote_cli_placement requires SSH transports")
    project_path = _remote_cli_path(contract.get("project_path"), "project_path")
    if host.get("project_path") != project_path:
        raise ValueError("remote_cli_placement project_path does not match host")
    remote_workspace = _remote_cli_path(contract.get("remote_workspace"), "remote_workspace")
    _remote_cli_below(remote_workspace, project_path, "remote_workspace")

    write_scope = _remote_cli_text(contract.get("write_scope"), "write_scope")
    if write_scope.startswith("/") or any(part in {"", ".", ".."} for part in write_scope.split("/")):
        raise ValueError("remote_cli_placement write_scope is unsafe")
    write_scope_path = _remote_cli_path(contract.get("write_scope_path"), "write_scope_path")
    if _remote_cli_below(write_scope_path, remote_workspace, "write_scope_path") != write_scope:
        raise ValueError("remote_cli_placement write_scope path mismatch")

    receipt = contract.get("receipt")
    if not isinstance(receipt, dict):
        raise ValueError("remote_cli_placement receipt is required")
    receipt_path = _remote_cli_path(receipt.get("path"), "receipt.path")
    receipt_relative = _remote_cli_below(receipt_path, remote_workspace, "receipt.path")
    if receipt.get("relative_path") != receipt_relative:
        raise ValueError("remote_cli_placement receipt relative path mismatch")
    receipt_parts = pathlib.PurePosixPath(receipt_relative).parts
    if len(receipt_parts) < 3 or receipt_parts[:2] != (".lad", "receipts"):
        raise ValueError("remote_cli_placement receipt must be below .lad/receipts")
    if receipt.get("format") != "json" or receipt.get("status") != "required_pending":
        raise ValueError("remote_cli_placement receipt status/format is invalid")

    cli = contract.get("cli")
    if not isinstance(cli, dict) or cli.get("name") != expected_cli:
        raise ValueError("remote_cli_placement CLI does not match exact route")
    _remote_cli_path(cli.get("path"), "cli.path")
    _remote_cli_text(cli.get("version"), "cli.version")
    if cli.get("install_state") != "installed":
        raise ValueError("remote_cli_placement CLI is not installed")
    auth = cli.get("auth")
    if not isinstance(auth, dict) or auth.get("state") != "authenticated" or auth.get("scope") != "remote_host":
        raise ValueError("remote_cli_placement remote authentication evidence is invalid")
    if auth.get("host_id") != execution_host:
        raise ValueError("remote_cli_placement authentication host binding is invalid")

    route = contract.get("route_evidence")
    if not isinstance(route, dict) or route.get("provider") != "racknerd" or route.get("status") != "verified" or route.get("verified") is not True or route.get("target_host_id") != execution_host:
        raise ValueError("remote_cli_placement RackNerd route evidence is invalid")
    wrapper = contract.get("wrapper")
    if not isinstance(wrapper, dict) or wrapper.get("mode") != "dry-run":
        raise ValueError("remote_cli_placement wrapper must remain dry-run")
    _remote_cli_text(wrapper.get("name"), "wrapper.name")
    _remote_cli_text(wrapper.get("version"), "wrapper.version")
    _remote_cli_hex(wrapper.get("sha256"), "wrapper.sha256")

    for field in ("provider", "pool_id", "model", "variant", "execution_host", "workload_host"):
        if packet.get(field) != contract.get(field):
            raise ValueError(f"remote_cli_placement packet.{field} mismatch")
    if packet.get("execution_transport") != "ssh" or packet.get("workload_transport") != "ssh":
        raise ValueError("remote_cli_placement packet transport mismatch")
    if packet.get("workspace") != remote_workspace or packet.get("remote_workspace") != remote_workspace:
        raise ValueError("remote_cli_placement packet workspace mismatch")
    if packet.get("write_scope") != write_scope:
        raise ValueError("remote_cli_placement packet write_scope mismatch")
    for field in ("provider_execution", "model_prompts_sent", "ssh_prompt_sent"):
        if packet.get(field) is not False:
            raise ValueError(f"remote_cli_placement requires packet.{field}=false")

    attempt_fields = {
        "provider": provider,
        "pool_id": pool_id,
        "model": expected_model,
        "variant": expected_variant,
        "host_id": execution_host,
        "workspace": remote_workspace,
        "remote_workspace": remote_workspace,
        "write_scope": write_scope,
        "receipt_path": receipt_path,
    }
    for field, expected_value in attempt_fields.items():
        if attempt.get(field) != expected_value:
            raise ValueError(f"remote_cli_placement attempt.{field} mismatch")
    if attempt.get("transport") != "ssh" or attempt.get("adapter") != "remote_cli":
        raise ValueError("remote_cli_placement attempt marker mismatch")
    if attempt.get("remote_cli_wrapper") != wrapper:
        raise ValueError("remote_cli_placement attempt wrapper mismatch")


def build_transport_envelope(packet: dict[str, Any], *, source_id: str = "controller") -> dict[str, Any]:
    """Build the metadata-only envelope for an explicitly remote packet."""
    attempts = packet.get("attempts")
    if not isinstance(attempts, list) or not attempts or not isinstance(attempts[0], dict):
        raise ValueError("remote packet must contain one prepared attempt")
    attempt = attempts[0]
    desktop_split = isinstance(packet.get("desktop_split_placement"), Mapping)
    split_remote = bool(
        desktop_split
        and packet.get("execution_transport") == "local"
        and packet.get("workload_transport") == "ssh"
    )
    attempt_transport = str(attempt.get("transport") or packet.get("execution_transport") or "local")
    if attempt_transport != "ssh" and not split_remote:
        raise ValueError("transport envelope requires an SSH attempt")
    job_id = str(packet.get("job_id") or "")
    attempt_id = str(attempt.get("attempt_id") or "")
    target_id = str(
        packet.get("workload_host")
        if split_remote
        else (attempt.get("host_id") or packet.get("execution_host") or packet.get("workload_host") or "")
    )
    model = str(attempt.get("model") or packet.get("model") or "")
    provider = attempt.get("provider") or packet.get("provider")
    pool_id = attempt.get("pool_id") or packet.get("pool_id")
    raw_variant = (
        attempt["variant"]
        if "variant" in attempt
        else packet.get("variant")
    )
    # Gemini's effort is encoded in the exact model slug.  Preserve an
    # explicit JSON null in the metadata-only envelope instead of converting
    # it to an empty string (which would make the remote dual-route contract
    # impossible to enqueue).  Every other route still requires a non-empty
    # exact variant.
    gemini_null_variant = (
        provider == "antigravity"
        and pool_id == "antigravity.gemini"
        and model == "gemini-3.6-flash-high"
        and raw_variant is None
    )
    if raw_variant is None and not gemini_null_variant:
        variant: str | None = ""
    elif isinstance(raw_variant, str) and raw_variant:
        variant = raw_variant
    elif gemini_null_variant:
        variant = None
    else:
        variant = ""
    if not job_id or not attempt_id or not target_id or not model or (variant == ""):
        raise ValueError("remote packet requires job, attempt, target, exact model, and exact variant")
    request_id = f"{job_id}:{attempt_id}"
    placement = {
        "execution_host": packet.get("execution_host"),
        "workload_host": packet.get("workload_host"),
        "execution_transport": packet.get("execution_transport"),
        "workload_transport": packet.get("workload_transport"),
    }
    summary = {
        "job_id": job_id,
        "packet_id": packet.get("packet_id"),
        "attempt_id": attempt_id,
        "model": model,
        "variant": variant,
        "provider": provider,
        "pool_id": pool_id,
        "host_id": target_id,
        "execution_host": packet.get("execution_host") or target_id,
        "workload_host": packet.get("workload_host") or target_id,
        "write_scope": packet.get("write_scope"),
        "required_artifact_count": len(packet.get("required_artifacts") or []),
        "validation_required": bool(packet.get("validation_required")),
        "resource_digest": _digest(packet.get("resource_request") or {}),
        "placement_digest": _digest(placement),
    }
    return build_envelope(
        request_id=request_id,
        source_id=source_id,
        target_id=target_id,
        operation="execute.prepared",
        packet_digest=_digest(packet),
        payload_summary=summary,
    )


def _sha_fresh(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> bool | None:
    if not after:
        return None
    by_path = {str(row.get("path")): row for row in before}
    if any(row.get("error") for row in before):
        return False
    for row in after:
        if not row.get("exists") or not row.get("sha256"):
            return False
        old = by_path.get(str(row.get("path")), {})
        if old.get("exists"):
            if old.get("sha256") and old.get("sha256") == row.get("sha256"):
                return False
            if not old.get("sha256") and old.get("size") == row.get("size") and old.get("mtime") == row.get("mtime"):
                return False
    return True


class SQLiteController:
    def __init__(
        self,
        db_path: pathlib.Path,
        *,
        workspace: pathlib.Path | None = None,
        inventory: pathlib.Path | None = None,
        runtime_state: pathlib.Path | None = None,
        lease_ttl_seconds: int = 90,
        heartbeat_interval_seconds: float | None = None,
        enforce_reservations: bool = True,
    ) -> None:
        self.db_path = db_path.expanduser().resolve()
        self.sqlite_storage_admission = local_resource_admission.check_sqlite_storage(
            self.db_path
        )
        if not self.sqlite_storage_admission.get("allowed"):
            raise local_resource_admission.SQLiteStorageAdmissionError(
                self.sqlite_storage_admission
            )
        self.workspace = (workspace or pathlib.Path.cwd()).expanduser().resolve()
        self.inventory_path = inventory.expanduser().resolve() if inventory else None
        self.runtime_state = runtime_state.expanduser().resolve() if runtime_state else None
        self.lease_ttl_seconds = max(30, int(lease_ttl_seconds))
        if heartbeat_interval_seconds is not None and float(heartbeat_interval_seconds) <= 0:
            raise ValueError("heartbeat_interval_seconds must be positive")
        self.heartbeat_interval_seconds = (
            float(heartbeat_interval_seconds) if heartbeat_interval_seconds is not None else None
        )
        self.enforce_reservations = bool(enforce_reservations)

    def _state(self) -> dict[str, Any]:
        state: dict[str, Any] = {
            "workspace": str(self.workspace),
        }
        if self.inventory_path:
            state["inventory"] = str(self.inventory_path)
        if self.runtime_state:
            state["runtime_state"] = str(self.runtime_state)
        return state

    def _hosts(self) -> dict[str, dict[str, Any]]:
        if not self.inventory_path or not self.inventory_path.exists():
            return {}
        try:
            return continuity.load_inventory({"inventory": str(self.inventory_path)})
        except (OSError, ValueError, KeyError):
            return {}

    @staticmethod
    def _pid_liveness(pid: Any) -> str:
        """Return conservative local process evidence for stale recovery."""

        if pid in (None, ""):
            return "unknown"
        try:
            value = int(pid)
        except (TypeError, ValueError):
            return "unknown"
        if value <= 1:
            return "unknown"
        try:
            os.kill(value, 0)
        except ProcessLookupError:
            return "dead"
        except (PermissionError, OSError):
            return "unknown"
        return "alive"

    def _recovery_liveness(self, store: SQLiteStore) -> dict[str, str]:
        """Collect local PID evidence before SQLite stale-row recovery.

        SSH/remote attempts and packets without an explicit PID breadcrumb are
        intentionally ``unknown``.  The durable store then blocks them rather
        than risking duplicate writes; a human or remote worker must provide a
        stronger handoff before retrying.
        """

        evidence: dict[str, str] = {}
        for record in store.expired_running_jobs():
            job_row = dict(record.get("job") or {})
            # `expired_running_jobs` returns a durable row with the packet
            # nested under `payload`; `_attempt_spec` consumes packet shape.
            job = dict(job_row.get("payload") or {})
            job_id = str(job_row.get("job_id") or job.get("job_id") or "")
            job.setdefault("job_id", job_id)
            attempt_row = dict(record.get("attempt") or {})
            if not job_id or not attempt_row:
                if job_id:
                    evidence[job_id] = "unknown"
                continue
            try:
                attempt = self._attempt_spec(job, attempt_row)
            except (TypeError, ValueError, KeyError):
                evidence[job_id] = "unknown"
                continue
            if str(attempt.get("transport") or "local") != "local":
                evidence[job_id] = "unknown"
                continue
            pid = attempt.get("pid") or job.get("pid")
            pid_path = attempt.get("pid_path") or job.get("pid_path")
            if pid_path:
                try:
                    workspace = pathlib.Path(
                        str(job.get("workspace") or self.workspace)
                    ).expanduser().resolve()
                    path = continuity.resolve_path(str(pid_path), workspace)
                    pid = path.read_text(encoding="utf-8").strip()
                except (OSError, ValueError):
                    evidence[job_id] = "unknown"
                    continue
            evidence[job_id] = self._pid_liveness(pid)
        return evidence

    @staticmethod
    def _resource_request(packet: dict[str, Any]) -> dict[str, Any]:
        request = packet.get("resource_request")
        if isinstance(request, dict) and request:
            return dict(request)
        estimate = packet.get("resource_estimate")
        if not isinstance(estimate, dict):
            return {}
        # Planner estimates use the same names as resource requests for the
        # core dimensions.  Keep this compatibility mapping deliberately
        # small; unknown values must not be invented at claim time.
        mapped: dict[str, Any] = {}
        for key in (
            "cpu_cores", "ram_gib", "gpu_count", "vram_gib",
            "ram_gib_p90", "p90_ram_gib", "new_disk_gib", "compute_minutes", "network_gib",
        ):
            if key in estimate:
                mapped[key] = estimate[key]
        if "vram_gib" in mapped and "vram_gib_per_gpu" not in mapped:
            mapped["vram_gib_per_gpu"] = mapped.pop("vram_gib")
        return mapped

    @staticmethod
    def _first_attempt(packet: dict[str, Any]) -> dict[str, Any]:
        attempts = packet.get("attempts")
        return dict(attempts[0]) if isinstance(attempts, list) and attempts and isinstance(attempts[0], dict) else {}

    @staticmethod
    def _resource_capacity(packet: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
        """Extract bounded host/pool capacity evidence from a task packet.

        Capacity is observed world-state evidence, not a planner estimate.
        Keep this bridge explicit and mapping-only: arbitrary packet fields
        (commands, prompts, or credentials) must never reach the reservation
        transaction.  ``resource_capacity`` may use the compact nested shape
        accepted by ``SQLiteStore.reserve_resources``; the host/pool aliases
        support packets produced by the resource topology adapters.
        """
        resource = packet.get("resource_capacity")
        host = packet.get("host_capacity")
        pool = packet.get("pool_capacity")
        return (
            dict(resource) if isinstance(resource, dict) else None,
            dict(host) if isinstance(host, dict) else None,
            dict(pool) if isinstance(pool, dict) else None,
        )

    def _local_disk_evidence(
        self,
        packet: dict[str, Any],
        request: dict[str, Any],
        workspace: pathlib.Path,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Read local disk headroom for packets that reserve disk explicitly.

        The final pre-Popen gate protects startup, but a resource-bearing queue
        also needs a transactional capacity value before claim.  Only packets
        with an explicit ``new_disk_gib``/``disk_gib`` request enter this path;
        legacy packets remain migration-compatible.  The returned host capacity
        is an observed lower bound after a small controller guard, never a
        promise about untracked paths or future cleanup.
        """
        raw = request.get("new_disk_gib", request.get("disk_gib"))
        try:
            requested_gib = float(raw) if raw is not None else 0.0
        except (TypeError, ValueError):
            requested_gib = 0.0
        if requested_gib <= 0:
            return None, None
        paths: list[str] = [str(self.db_path)]
        for key in (
            "output_path", "result_source_path", "log_path", "pid_path",
            "artifact_path", "workload_storage_path",
        ):
            value = packet.get(key)
            if isinstance(value, str) and value.strip():
                paths.append(value)
        report = local_resource_admission.check_local_launch(
            workspace,
            additional_paths=tuple(paths),
            minimum_free_bytes=0,
            minimum_free_percent=0.0,
            label="local_disk_reservation",
        )
        rows = report.get("filesystems") or []
        complete = [row for row in rows if row.get("evidence") == "complete"]
        free_values = [int(row["free_bytes"]) for row in complete if row.get("free_bytes") is not None]
        guard_gib = 0.25
        if not report.get("allowed") or not free_values:
            return {
                "allowed": False,
                "decision": "block",
                "reason": "local_disk_evidence_unknown",
                "source": "resource_admission",
                "report": report,
            }, None
        free_gib = min(free_values) / float(governor.GIB)
        usable_gib = max(0.0, free_gib - guard_gib)
        disk_capacity = {
            "new_disk_gib": usable_gib,
            "disk_capacity_source": "local_statvfs_lower_bound",
            "disk_guard_gib": guard_gib,
        }
        allowed = requested_gib <= usable_gib
        return {
            "allowed": allowed,
            "decision": "admit" if allowed else "block",
            "reason": "local_disk_capacity_available" if allowed else "local_disk_capacity_exceeded",
            "source": "resource_admission",
            "requested_disk_gib": requested_gib,
            "usable_disk_gib": usable_gib,
            "report": report,
        }, disk_capacity

    def _ensure_reservations(
        self,
        store: SQLiteStore,
        owner_id: str,
        fence_token: int,
        *,
        max_lanes: int,
        hysteresis_state: dict[str, Any] | None = None,
        claim: bool = False,
    ) -> list[dict[str, Any]] | tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Reserve the next resource-bearing jobs before atomic claim.

        Legacy packets without a resource request remain compatible.  New
        planner packets are strict: local work needs a live governor admission;
        remote work needs a fresh, host-bound resource-evidence contract in the
        packet.  When ``claim=True``, each newly admitted lane uses the atomic
        ``reserve_and_claim_job`` store primitive so a crash cannot leave a
        reservation committed without its corresponding attempt.

        The default remains the list-only reservation API for migration and
        diagnostics callers.  The controller run loop opts into the tuple form
        to execute newly claimed resource-bearing lanes immediately.
        """
        if not self.enforce_reservations:
            return ([], []) if claim else []
        active = {
            str(row.get("job_id")): row
            for row in store.list_reservations(statuses=("active",))
        }
        # Reservations are promises, not RSS samples.  Subtract the RAM
        # already promised to local lanes before admitting another candidate;
        # otherwise every candidate would observe the same free-memory snapshot
        # and a multi-lane claim could exceed the aggregate P90 budget.
        reserved_local_ram_gib = 0.0
        for reservation in active.values():
            request_obj = reservation.get("resource_request") or {}
            host_id = str(request_obj.get("host_id") or "")
            if host_id and not (host_id == "local" or host_id.startswith("local_")):
                continue
            try:
                reserved_local_ram_gib += max(0.0, float(request_obj.get("ram_gib") or 0.0))
            except (TypeError, ValueError):
                continue
        pending_local_ram_gib = 0.0
        diagnostics: list[dict[str, Any]] = []
        preclaimed: list[dict[str, Any]] = []
        candidates = store.list_jobs(statuses=("queued", "retry"))[: max(1, int(max_lanes) * 8)]
        local_observation: tuple[dict[str, Any], list[dict[str, Any]]] | None = None
        for row in candidates:
            if claim and len(preclaimed) >= max(1, int(max_lanes)):
                break
            job_id = str(row.get("job_id") or "")
            packet = dict(row.get("payload") or {})
            request = self._resource_request(packet)
            required = bool(packet.get("resource_reservation_required") or request)
            if not required or not job_id or job_id in active:
                continue
            attempt = self._first_attempt(packet)
            transport = str(attempt.get("transport") or packet.get("execution_transport") or "local")
            remote_placement = transport == "ssh" or any(
                str(packet.get(key) or "") == "ssh"
                for key in ("execution_transport", "workload_transport")
            )
            resource_capacity, host_capacity, pool_capacity = self._resource_capacity(packet)
            admission: dict[str, Any]
            ram_gib = 0.0
            if remote_placement:
                # Bind the reservation identity to the workload host and
                # declared write scope before validating the observation.  The
                # planner historically omitted these identifiers from the
                # numeric resource request; filling them from the packet is
                # deterministic and keeps capacity totals host-specific.
                expected_host = (
                    packet.get("workload_host")
                    or packet.get("execution_host")
                    or attempt.get("host_id")
                )
                if expected_host and not request.get("host_id"):
                    request["host_id"] = str(expected_host)
                if not request.get("pool_id"):
                    pool_id = packet.get("pool_id") or attempt.get("pool_id")
                    if pool_id:
                        request["pool_id"] = str(pool_id)
                if packet.get("write_scope") and not request.get("write_scope"):
                    request["write_scope"] = str(packet["write_scope"])
                quota_report: dict[str, Any] | None = None
                try:
                    quota_report = _packet_quota_snapshot(packet, attempt)
                except ValueError as exc:
                    evidence_report = {
                        "valid": False,
                        "decision": "block",
                        "reason": str(exc),
                        "reasons": ["quota_snapshot_invalid"],
                        "summary": {},
                        "capacity": {"host": {}},
                    }
                else:
                    evidence_report = None
                capacity_receipt = packet.get("capacity_receipt")
                if evidence_report is not None:
                    pass
                elif packet.get("remote_resource_evidence_verified") is True and capacity_receipt is None:
                    evidence_report = {
                        "valid": False,
                        "decision": "block",
                        "reason": "capacity receipt required",
                        "reasons": ["capacity_receipt_required"],
                        "summary": {},
                        "capacity": {"host": {}},
                    }
                else:
                    if capacity_receipt is not None:
                        try:
                            validate_capacity_receipt(
                                capacity_receipt,
                                request=request,
                                expected_resource_request_digest=packet.get("resource_request_digest"),
                            )
                        except ValueError as exc:
                            evidence_report = {
                                "valid": False,
                                "decision": "block",
                                "reason": str(exc),
                                "reasons": ["capacity_receipt_invalid"],
                                "summary": {},
                                "capacity": {"host": {}},
                            }
                        else:
                            evidence_report = validate_remote_resource_evidence(
                                packet.get("remote_resource_evidence"),
                                packet=packet,
                                request=request,
                            )
                    else:
                        evidence_report = validate_remote_resource_evidence(
                            packet.get("remote_resource_evidence"),
                            packet=packet,
                            request=request,
                        )
                admission = {
                    "allowed": bool(evidence_report.get("valid")),
                    "decision": evidence_report.get("decision", "block"),
                    "reason": evidence_report.get("reason", "remote_resource_evidence_missing"),
                    "source": "remote_resource_evidence",
                    "evidence_block_reasons": evidence_report.get("reasons") or [],
                    "evidence_digest": evidence_report.get("evidence_digest"),
                    "evidence_summary": evidence_report.get("summary") or {},
                    "capacity_evidence_supplied": bool(evidence_report.get("valid")),
                    "quota_evidence_supplied": quota_report is not None,
                    "quota_snapshot_digest": (
                        quota_report.get("snapshot_digest") if quota_report else None
                    ),
                }
                if evidence_report.get("valid"):
                    # The live observation is authoritative for RAM/disk;
                    # packet-supplied capacity may retain other bounded
                    # dimensions, but never override fresh lower bounds.
                    observed_host = dict((evidence_report.get("capacity") or {}).get("host") or {})
                    host_capacity = {**dict(host_capacity or {}), **observed_host}
            else:
                disk_admission, local_disk_capacity = self._local_disk_evidence(
                    packet, request, pathlib.Path(str(packet.get("workspace") or self.workspace)).expanduser().resolve()
                )
                if local_disk_capacity is not None and host_capacity is None and resource_capacity is None:
                    host_capacity = local_disk_capacity
                ram_value = request.get("ram_gib")
                p90_ram_value = (
                    request.get("ram_gib_p90")
                    or request.get("p90_ram_gib")
                    or ram_value
                )
                try:
                    ram_gib = float(ram_value)
                except (TypeError, ValueError):
                    ram_gib = 0.0
                try:
                    p90_ram_gib = max(0.0, float(p90_ram_value))
                except (TypeError, ValueError):
                    p90_ram_gib = 0.0
                p90_ram_gib = max(p90_ram_gib, ram_gib)
                if ram_gib <= 0:
                    admission = {
                        "allowed": False,
                        "decision": "block",
                        "reason": "unknown_local_ram_request",
                        "source": "resource_request",
                    }
                else:
                    if local_observation is None:
                        local_observation = governor.observe_local()
                    ram, processes = local_observation
                    report = governor.build_report(
                        ram=ram,
                        processes=processes,
                        requested_lanes=1,
                        per_lane_peak_bytes=max(256 * governor.MIB, int(ram_gib * governor.GIB)),
                        p90_peak_bytes=(
                            max(256 * governor.MIB, int(p90_ram_gib * governor.GIB))
                            if p90_ram_gib > 0 else None
                        ),
                        max_local_lanes=1,
                        reserved_bytes=int(
                            (reserved_local_ram_gib + pending_local_ram_gib)
                            * governor.GIB
                        ),
                        hysteresis_state=hysteresis_state,
                    )
                    if hysteresis_state is not None:
                        hysteresis_state.clear()
                        hysteresis_state.update(report["ram"].get("hysteresis") or {})
                    admission = {
                        "allowed": bool(report["admission"].get("local_agent_launch_allowed")),
                        "decision": report["admission"].get("decision"),
                        "reason": report["ram"].get("pressure_tier"),
                        "source": "resource_governor",
                        "observed_at_utc": report.get("observed_at_utc"),
                        "pressure_tier": report["ram"].get("pressure_tier"),
                        "max_new_local_lanes": report["admission"].get("max_new_local_lanes"),
                        "already_reserved_bytes": report["ram"].get("already_reserved_bytes"),
                        "evidence_complete": report["admission"].get("evidence_complete"),
                        "evidence_block_reasons": report["admission"].get("evidence_block_reasons") or [],
                        "cgroup_memory_evidence_status": report["ram"].get("cgroup_memory_evidence_status"),
                        "cgroup_memory_max_bytes": report["ram"].get("cgroup_memory_max_bytes"),
                        "cgroup_memory_current_bytes": report["ram"].get("cgroup_memory_current_bytes"),
                        "cgroup_memory_available_bytes": report["ram"].get("cgroup_memory_available_bytes"),
                        "psi_some_avg10": report["ram"].get("psi_some_avg10"),
                        "p90_evidence": report["request"].get("p90_evidence"),
                    }
                if disk_admission is not None:
                    admission["disk_admission"] = disk_admission
                    if not disk_admission.get("allowed"):
                        admission["allowed"] = False
                        admission["decision"] = "block"
                        admission["reason"] = disk_admission.get("reason")
            try:
                if claim:
                    outcome = store.reserve_and_claim_job(
                        job_id,
                        owner_id,
                        fence_token,
                        request,
                        admission=admission,
                        capacity=resource_capacity,
                        host_capacity=host_capacity,
                        pool_capacity=pool_capacity,
                        lease_ttl_seconds=self.lease_ttl_seconds,
                        governor_state=hysteresis_state,
                    )
                    if outcome is None:
                        continue
                    reservation = dict(outcome.get("reservation") or {})
                    claim_result = outcome.get("claim")
                    if not isinstance(claim_result, dict):
                        raise ReservationAdmissionError("atomic reservation claim returned no claim")
                    preclaimed.append(claim_result)
                    diagnostics.append({"job_id": job_id, "status": "claimed", "reservation_id": reservation.get("reservation_id"), "admission": reservation.get("admission") or admission})
                else:
                    reservation = store.reserve_resources(
                        job_id,
                        owner_id,
                        fence_token,
                        request,
                        admission=admission,
                        capacity=resource_capacity,
                        host_capacity=host_capacity,
                        pool_capacity=pool_capacity,
                        ttl_seconds=self.lease_ttl_seconds,
                    )
                    diagnostics.append({"job_id": job_id, "status": "reserved", "reservation_id": reservation.get("reservation_id"), "admission": reservation.get("admission") or admission})
                if not remote_placement:
                    pending_local_ram_gib += ram_gib
            except ReservationAdmissionError as exc:
                blocked_admission = dict(admission)
                blocked_admission.update({
                    "allowed": False,
                    "decision": "block",
                    "reason": str(exc),
                    "source": "reservation_store",
                })
                diagnostics.append({"job_id": job_id, "status": "blocked", "admission": blocked_admission})
        return (diagnostics, preclaimed) if claim else diagnostics

    def enqueue(
        self,
        packet: dict[str, Any],
        *,
        transport_envelope: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        # Keep both controller backends behind the same ingress contract.
        # SQLite is opt-in, but it must not become an unvalidated escape hatch.
        packet = dict(packet)
        packet.setdefault("schema_version", 1)
        continuity.validate_task_packet(packet)
        validate_remote_cli_placement_packet(packet)
        validate_desktop_split_placement_packet(packet)
        self._validate_model_policy(packet)
        job_id = str(packet.get("job_id") or "")
        packet["packet_validation"] = {"mode": "strict", "backend": "sqlite"}
        with SQLiteStore(self.db_path) as store:
            owner_id = f"sqlite-enqueue-{uuid.uuid4().hex[:12]}"
            with store.controller_lease(owner_id, ttl_seconds=self.lease_ttl_seconds) as lease:
                fence_token = int(lease["fence_token"])
                existing = store.get_job(job_id)
                if existing is not None:
                    status = str(existing.get("status") or "")
                    if status in {"failed", "blocked", "pending"}:
                        return store.requeue_job(
                            job_id,
                            owner_id,
                            fence_token,
                            payload=packet,
                            priority=priority_value(packet),
                            reason="approved_replan",
                        )
                try:
                    return store.create_job(
                        job_id,
                        packet,
                        priority=priority_value(packet),
                        owner_id=owner_id,
                        fence_token=fence_token,
                        transport_envelope=transport_envelope,
                    )
                except JobConflict:
                    # Preserve the original conflict contract for queued,
                    # running, retry, or completed rows.  Only the explicit
                    # terminal-state transition above may replace a packet.
                    raise

    @staticmethod
    def _validate_model_policy(packet: dict[str, Any]) -> None:
        """Enforce any explicit task-local model route at durable ingress."""
        policy = packet.get("model_policy")
        if policy in (None, "", "auto"):
            return
        if policy not in {
            "codex-luna-max",
            "codex-sol-max",
            "codex-spark-antigravity-gemini",
        }:
            raise ValueError(f"unsupported model_policy: {policy!r}")
        attempts = packet.get("attempts") or []
        if not isinstance(attempts, list) or not attempts:
            raise ValueError(f"{policy} requires an attempt contract")
        allowed = {
            "codex-luna-max": {
                ("codex.luna", "codex", "gpt-5.6-luna", "max")
            },
            "codex-sol-max": {
                ("codex.luna", "codex", "gpt-5.6-sol", "max")
            },
            "codex-spark-antigravity-gemini": {
                ("codex.spark", "codex", "gpt-5.3-codex-spark", "xhigh"),
                (
                    "antigravity.gemini",
                    "antigravity",
                    "gemini-3.6-flash-high",
                    "",
                ),
            },
        }[str(policy)]
        for index, attempt in enumerate(attempts):
            if not isinstance(attempt, dict):
                raise ValueError(f"{policy} attempt {index} is invalid")
            pool = str(attempt.get("pool_id") or packet.get("pool_id") or "")
            provider = str(attempt.get("provider") or packet.get("provider") or "")
            model = str(attempt.get("model") or packet.get("model") or "")
            variant = str(attempt.get("variant") or packet.get("variant") or "")
            if (pool, provider, model, variant) not in allowed:
                raise ValueError(
                    f"{policy} attempt does not match its exact model allow-list"
                )

    def enqueue_remote(self, packet: dict[str, Any]) -> dict[str, Any]:
        """Enqueue a remote packet and its outbox envelope atomically.

        This method only persists the approved metadata envelope.  Delivery is
        still an explicit remote-worker/client operation; it never opens SSH
        or starts a provider.
        """
        envelope = build_transport_envelope(packet)
        return self.enqueue(packet, transport_envelope=envelope)

    def _attempt_spec(self, job: dict[str, Any], attempt_row: dict[str, Any]) -> dict[str, Any]:
        attempts = job.get("attempts") or []
        attempt_no = max(1, int(attempt_row.get("attempt_no") or 1))
        replan_base = max(0, int(job.get("_lad_replan_base_attempt_count") or 0))
        packet_index = attempt_no - replan_base - 1
        if packet_index < 0:
            packet_index = 0
        if packet_index >= len(attempts):
            raise ValueError(f"job {job.get('job_id')} has no packet attempt {packet_index + 1}")
        attempt = dict(attempts[packet_index])
        attempt["attempt_id"] = str(attempt_row.get("attempt_id") or attempt.get("attempt_id") or "")
        if not attempt["attempt_id"]:
            raise ValueError("claimed attempt has no attempt_id")
        return attempt

    def _execute_claim(
        self,
        store: SQLiteStore,
        claim: dict[str, Any],
        owner_id: str,
        fence_token: int,
    ) -> dict[str, Any]:
        row = claim.get("job") or {}
        job = dict(row.get("payload") or {})
        job["job_id"] = str(row.get("job_id") or job.get("job_id") or "")
        attempt_row = dict(claim.get("attempt") or {})
        attempt = self._attempt_spec(job, attempt_row)
        state = self._state()
        hosts = self._hosts()
        workspace = pathlib.Path(str(job.get("workspace") or self.workspace)).expanduser().resolve()
        artifact_host = None
        if str(attempt.get("transport") or "local") == "ssh":
            artifact_host = hosts.get(str(attempt.get("host_id") or ""))
        before = (
            continuity.remote_artifact_facts(job, attempt, artifact_host)
            if artifact_host
            else continuity.artifact_facts(job, workspace)
        )
        result_source_before = None
        result_source = attempt.get("result_source_path") or job.get("result_source_path")
        if result_source and not artifact_host:
            result_source_before = continuity.file_fact(
                continuity.resolve_path(str(result_source), workspace)
            )

        output = ""
        returncode = 2
        timed_out = False
        output_path: str | None = None
        validation: dict[str, Any] | None = None
        try:
            argv, cwd, output_path, stdin_payload = continuity.build_attempt(job, attempt, state, hosts)
            timeout_seconds = max(30, int(attempt.get("timeout_seconds", job.get("timeout_seconds", 3600))))
            pid_path = None
            if attempt.get("pid_path") or job.get("pid_path"):
                pid_value = attempt.get("pid_path") or job.get("pid_path")
                pid_path = str(continuity.resolve_path(str(pid_value), workspace))
            # A capacity receipt is an observation with a bounded validity
            # window.  Re-derive it immediately before the child boundary so
            # a receipt that expired between reservation and launch cannot
            # start a process.  This is intentionally before run_in_process_group.
            if job.get("capacity_receipt") is not None:
                try:
                    validate_capacity_receipt(
                        job["capacity_receipt"],
                        request=self._resource_request(job),
                        expected_resource_request_digest=job.get("resource_request_digest"),
                    )
                except ValueError as exc:
                    raise ValueError(f"launch-time capacity drift: {exc}") from exc
            try:
                _packet_quota_snapshot(job, attempt)
            except ValueError as exc:
                raise ValueError(f"launch-time quota drift: {exc}") from exc
            result = continuity._load_process_group_run().run_in_process_group(
                argv,
                cwd=str(cwd) if cwd else None,
                stdin_data=stdin_payload,
                timeout_seconds=timeout_seconds,
                pid_path=pid_path,
                local_admission=(str(attempt.get("transport") or "local") == "local"),
                local_admission_label="local_agent",
                local_admission_paths=(str(self.db_path),),
            )
            output = result.stdout or ""
            returncode = int(result.returncode)
            timed_out = bool(result.timed_out)
            if timed_out:
                returncode = 124
                output += "\ncontinuity controller: attempt timed out\n"
                output_path = None
            if output_path and returncode == 0:
                continuity.publish_attempt_output(
                    output,
                    output_path,
                    str(result_source) if result_source else None,
                    workspace,
                    result_source_before,
                )
            if returncode == 0:
                validation = continuity.run_validation(job, attempt, state, hosts)
                if validation is None and job.get("validation_required") is True:
                    validation = {
                        "ok": False,
                        "returncode": 2,
                        "timed_out": False,
                        "error": "validation is required but no validator was configured",
                    }
                if validation is not None and not validation.get("ok"):
                    returncode = int(validation.get("returncode") or 2)
        except Exception as exc:
            output += f"\nsqlite controller: {type(exc).__name__}: {exc}\n"
            returncode = 2

        facts = (
            continuity.remote_artifact_facts(job, attempt, artifact_host)
            if artifact_host
            else continuity.artifact_facts(job, workspace)
        )
        freshness = _sha_fresh(before, facts)
        if facts and job.get("accept_existing_artifacts"):
            freshness = bool(validation and validation.get("ok"))
        artifacts_ok = (
            all(row.get("exists") and row.get("size", 0) > 0 and row.get("sha256") for row in facts)
            and freshness
            if facts
            else returncode == 0
        )
        success = bool(returncode == 0 and artifacts_ok)
        error_class = None if success else continuity.classify(output, timed_out)
        try:
            continuity.record_runtime_feedback(
                state, job, attempt, success=success, error_class=error_class, output=output
            )
        except (OSError, ValueError):
            # Runtime feedback is supplementary; SQLite completion evidence is
            # still authoritative and must not be lost because a sidecar is
            # unavailable.
            pass
        attempt_count = int(attempt_row.get("attempt_no") or 1)
        fallback = set(attempt.get("fallback_on") or ["quota", "auth", "network", "capability"])
        normal_retry = error_class in fallback
        remote_resource_retry = continuity.resource_fallback_available(
            error_class, max(0, attempt_count - 1), list(job.get("attempts") or [])
        )
        retryable = (
            (not success)
            and (normal_retry or remote_resource_retry)
            and attempt_count < len(job.get("attempts") or [])
        )
        retry_delay_seconds = None
        if retryable:
            # Keep transient quota/network failures from hot-looping.  A
            # packet may choose a bounded base delay for its own policy; the
            # controller applies exponential growth per attempt and caps it
            # so a durable worker remains observable rather than sleeping
            # indefinitely.  Replan is a separate explicit queue transition
            # and is intentionally not delayed here.
            try:
                base_delay = float(attempt.get("retry_backoff_seconds", 5.0))
            except (TypeError, ValueError):
                base_delay = 5.0
            base_delay = min(300.0, max(1.0, base_delay))
            retry_delay_seconds = min(
                900.0, base_delay * (2 ** max(0, attempt_count - 1))
            )
        completed = store.complete_job(
            job["job_id"],
            str(attempt_row["attempt_id"]),
            owner_id,
            fence_token,
            success=success,
            result={"output": output[-8000:], "returncode": returncode, "timed_out": timed_out},
            artifact_manifest=facts,
            validation=validation,
            error_class=error_class,
            error={"class": error_class, "output": output[-2000:]} if not success else None,
            retryable=retryable,
            retry_delay_seconds=retry_delay_seconds,
        )
        return {
            "job_id": job["job_id"],
            "attempt_id": attempt_row["attempt_id"],
            "status": completed.get("status"),
            "success": success,
            "retryable": retryable,
            "retry_delay_seconds": retry_delay_seconds,
            "error_class": error_class,
            "artifact_freshness_verified": freshness,
            "validation": validation,
        }

    def run(
        self,
        *,
        once: bool = False,
        max_idle_rounds: int = 0,
        poll_seconds: float = 1.0,
        idle_backoff_seconds: float = 30.0,
        replan_feedback: Mapping[str, Any] | None = None,
        replan_feedback_loader: Callable[[], Mapping[str, Any] | None] | None = None,
        replan_max_wait_seconds: float = 300.0,
        max_lanes: int = 1,
        owner_id: str | None = None,
        sleep_fn: Callable[[float], Any] | None = None,
    ) -> dict[str, Any]:
        if isinstance(max_lanes, bool) or int(max_lanes) < 1:
            raise ValueError("max_lanes must be a positive integer")
        if isinstance(max_idle_rounds, bool) or int(max_idle_rounds) < 0:
            raise ValueError("max_idle_rounds must be zero (infinite) or a positive integer")
        try:
            idle_backoff = float(idle_backoff_seconds)
        except (TypeError, ValueError) as exc:
            raise ValueError("idle_backoff_seconds must be positive") from exc
        if not (idle_backoff > 0) or idle_backoff > 3600:
            raise ValueError("idle_backoff_seconds must be between 0 and 3600")
        if replan_feedback_loader is not None and not callable(replan_feedback_loader):
            raise ValueError("replan_feedback_loader must be callable")
        lanes = min(int(max_lanes), 32)
        owner = owner_id or f"sqlite-controller-{uuid.uuid4().hex[:12]}"
        sleep = sleep_fn or time.sleep
        results: list[dict[str, Any]] = []
        reservation_diagnostics: list[dict[str, Any]] = []
        replan_diagnostics: list[dict[str, Any]] = []
        # A due feedback file may be observed on many idle ticks.  Stable
        # event IDs make the durable audit idempotent without suppressing a
        # genuinely new planner artifact.
        emitted_replan_events: set[str] = set()
        # Bound diagnostics for an indefinitely running durable worker.
        diagnostic_limit = 100
        idle = 0
        replan_state_lock = threading.Lock()
        with SQLiteStore(self.db_path) as store:
            # Make the fencing heartbeat explicit at the controller boundary.
            # SQLiteStore also has a safe default, but keeping the interval
            # here prevents a future backend/default change from allowing a
            # long provider call to outlive the controller lease.
            heartbeat_interval = self.heartbeat_interval_seconds
            if heartbeat_interval is None:
                heartbeat_interval = max(1.0, min(float(self.lease_ttl_seconds) / 3.0, 30.0))
            with store.controller_lease(
                owner,
                ttl_seconds=self.lease_ttl_seconds,
                heartbeat_interval_seconds=heartbeat_interval,
            ) as lease:
                fence = int(lease["fence_token"])
                governor_state = store.get_governor_state()
                recovery_liveness = self._recovery_liveness(store)
                store.recover_expired_jobs(
                    owner,
                    fence,
                    liveness_by_job=recovery_liveness,
                    strict_liveness=True,
                )

                def execute_claim_with_heartbeats(claim: dict[str, Any]) -> dict[str, Any]:
                    claim_job = claim.get("job") or {}
                    claim_attempt = claim.get("attempt") or {}
                    job_id = str(claim_job.get("job_id") or "")
                    attempt_id = str(claim_attempt.get("attempt_id") or "")
                    if not job_id or not attempt_id:
                        raise ValueError("claim is missing job_id or attempt_id")
                    # A controller lease protects the scheduler; this
                    # per-attempt heartbeat protects the actual work row
                    # while the provider runs outside SQLite transactions.
                    with store.job_lease_heartbeat(
                        job_id,
                        attempt_id,
                        owner,
                        fence,
                        ttl_seconds=self.lease_ttl_seconds,
                        heartbeat_interval_seconds=heartbeat_interval,
                    ):
                        return self._execute_claim(store, claim, owner, fence)

                def execute_claim_safely(claim: dict[str, Any]) -> dict[str, Any]:
                    """Contain one lane failure without cancelling sibling lanes.

                    Provider/adapter exceptions normally get converted by
                    ``_execute_claim`` into a fenced terminal result.  A
                    failure in the surrounding heartbeat, packet decoding, or
                    an overridden adapter can still escape that boundary.  A
                    thread-pool ``future.result()`` must not let such an
                    exception tear down the whole batch and strand the other
                    claims in ``running``.  We therefore make a best-effort
                    terminal controller failure while preserving a structured
                    result if the lease has already been fenced.
                    """
                    try:
                        return execute_claim_with_heartbeats(claim)
                    except Exception as exc:  # pragma: no cover - exercised by fake-lane test
                        claim_job = claim.get("job") or {}
                        claim_attempt = claim.get("attempt") or {}
                        job_id = str(claim_job.get("job_id") or "")
                        attempt_id = str(claim_attempt.get("attempt_id") or "")
                        # Persist only the exception class.  Adapter/provider
                        # output can contain prompt or credential material;
                        # detailed diagnostics stay in the provider boundary.
                        safe_output = f"sqlite controller lane exception: {type(exc).__name__}"
                        result: dict[str, Any] = {
                            "job_id": job_id,
                            "attempt_id": attempt_id,
                            "status": "failed",
                            "success": False,
                            "retryable": False,
                            "error_class": "controller",
                            "artifact_freshness_verified": False,
                            "validation": None,
                        }
                        if not job_id or not attempt_id:
                            result["completion_error"] = "claim is missing job_id or attempt_id"
                            return result
                        try:
                            completed = store.complete_job(
                                job_id,
                                attempt_id,
                                owner,
                                fence,
                                success=False,
                                result={"output": safe_output, "returncode": 2, "timed_out": False},
                                artifact_manifest=[],
                                validation=None,
                                error_class="controller",
                                error={"class": "controller", "output": safe_output},
                                retryable=False,
                            )
                            result["status"] = completed.get("status", "failed")
                        except Exception as completion_exc:
                            # A lost/fenced lease cannot safely mutate the
                            # row.  Leave it for durable recovery and expose
                            # that fact instead of hiding the sibling result.
                            result["completion_error"] = type(completion_exc).__name__
                        return result

                def observe_replan_feedback(
                    *,
                    observation_mode: str,
                    active_claims: list[dict[str, Any]] | None = None,
                    record_diagnostic: bool = True,
                ) -> dict[str, Any] | None:
                    """Read, bound, and durably audit one planner wake hint.

                    Replan feedback is deliberately an observation seam: a
                    due hint records an event and wakes the controller, but
                    never switches providers or invents a new task.  The
                    helper is also used by the active-lane watcher so a long
                    provider call cannot hide a quota-reset or resource
                    decision until the lane finishes.
                    """

                    if replan_feedback is None and replan_feedback_loader is None:
                        return None
                    feedback_value: Any = replan_feedback
                    loader_error: str | None = None
                    if replan_feedback_loader is not None:
                        try:
                            feedback_value = replan_feedback_loader()
                        except Exception as exc:  # pragma: no cover - defensive boundary
                            feedback_value = None
                            loader_error = type(exc).__name__
                    feedback_payload = _replan_feedback_payload(feedback_value)
                    try:
                        schedule = replan.build_replan_schedule(
                            feedback_payload,
                            max_wait_seconds=replan_max_wait_seconds,
                        )
                    except Exception as exc:  # fail closed; never sleep unbounded
                        schedule = replan.build_replan_schedule(None)
                        schedule.update({
                            "ok": False,
                            "reason": "controller_replan_schedule_error",
                            "invalid_fields": ["replan_feedback"],
                            "error_class": type(exc).__name__,
                        })
                        loader_error = loader_error or type(exc).__name__
                    if loader_error:
                        schedule = dict(schedule)
                        schedule["loader_error"] = loader_error

                    active_job_ids = sorted({
                        str((claim.get("job") or {}).get("job_id"))
                        for claim in (active_claims or [])
                        if (claim.get("job") or {}).get("job_id")
                    })
                    active_attempt_ids = sorted({
                        str((claim.get("attempt") or {}).get("attempt_id"))
                        for claim in (active_claims or [])
                        if (claim.get("attempt") or {}).get("attempt_id")
                    })
                    feedback_digest = _digest(feedback_payload or {})
                    event_id = f"replan-due-{feedback_digest[:48]}"
                    event_recorded = False
                    event_error: str | None = None
                    if schedule.get("due"):
                        with replan_state_lock:
                            already_emitted = event_id in emitted_replan_events
                        if not already_emitted:
                            event_payload = _replan_event_payload(
                                schedule,
                                feedback_payload,
                                loader_error=loader_error,
                                observation_mode=observation_mode,
                                active_job_ids=active_job_ids,
                                active_attempt_ids=active_attempt_ids,
                            )
                            try:
                                store.append_event(
                                    "replan_due",
                                    event_id=event_id,
                                    owner_id=owner,
                                    fence_token=fence,
                                    payload=event_payload,
                                )
                            except Exception as exc:  # pragma: no cover - lock loss/race boundary
                                event_error = type(exc).__name__
                            else:
                                with replan_state_lock:
                                    emitted_replan_events.add(event_id)
                                event_recorded = True
                    # Future hints are intentionally quiet.  Durable
                    # diagnostics are useful at the safety boundary (due or
                    # malformed feedback), not for every healthy poll of a
                    # distant reset window.
                    if record_diagnostic and (
                        schedule.get("due")
                        or not schedule.get("ok", True)
                        or loader_error
                        or event_error
                    ):
                        diagnostic = {
                            "event_id": event_id,
                            "schedule": dict(schedule),
                            "feedback_digest": feedback_digest,
                            "observation_mode": observation_mode,
                        }
                        if active_job_ids:
                            diagnostic["active_job_ids"] = active_job_ids
                        if active_attempt_ids:
                            diagnostic["active_attempt_ids"] = active_attempt_ids
                        if event_recorded:
                            diagnostic["event_recorded"] = True
                        if event_error:
                            diagnostic["event_error"] = event_error
                        with replan_state_lock:
                            replan_diagnostics.append(diagnostic)
                            if len(replan_diagnostics) > diagnostic_limit:
                                del replan_diagnostics[:-diagnostic_limit]
                    return schedule

                def start_replan_watcher(
                    active_claims: list[dict[str, Any]],
                ) -> tuple[threading.Event, threading.Thread] | None:
                    """Keep replan feedback observable while provider work runs."""

                    if replan_feedback is None and replan_feedback_loader is None:
                        return None
                    stop = threading.Event()

                    def watch() -> None:
                        try:
                            while not stop.is_set():
                                schedule = observe_replan_feedback(
                                    observation_mode="active",
                                    active_claims=active_claims,
                                    record_diagnostic=True,
                                )
                                if schedule is None:
                                    break
                                try:
                                    wait_seconds = float(schedule.get("sleep_seconds") or 0.0)
                                except (TypeError, ValueError):
                                    wait_seconds = 0.0
                                if wait_seconds <= 0:
                                    try:
                                        wait_seconds = max(0.1, float(poll_seconds))
                                    except (TypeError, ValueError):
                                        wait_seconds = 1.0
                                wait_seconds = max(0.1, min(wait_seconds, idle_backoff))
                                if stop.wait(wait_seconds):
                                    break
                        except Exception as exc:  # pragma: no cover - defensive boundary
                            with replan_state_lock:
                                replan_diagnostics.append({
                                    "observation_mode": "active",
                                    "watcher_error": type(exc).__name__,
                                })
                                if len(replan_diagnostics) > diagnostic_limit:
                                    del replan_diagnostics[:-diagnostic_limit]

                    thread = threading.Thread(
                        target=watch,
                        name="lad-sqlite-replan-watcher",
                        daemon=True,
                    )
                    thread.start()
                    return stop, thread

                def stop_replan_watcher(
                    watcher: tuple[threading.Event, threading.Thread] | None,
                ) -> None:
                    if watcher is None:
                        return
                    stop, thread = watcher
                    stop.set()
                    thread.join(timeout=max(1.0, idle_backoff + 0.5))
                    if thread.is_alive():  # pragma: no cover - a pathological loader only
                        with replan_state_lock:
                            replan_diagnostics.append({
                                "observation_mode": "active",
                                "watcher_error": "join_timeout",
                            })
                            if len(replan_diagnostics) > diagnostic_limit:
                                del replan_diagnostics[:-diagnostic_limit]

                while True:
                    governor_state_before = dict(governor_state)
                    reservation_result = self._ensure_reservations(
                        store,
                        owner,
                        fence,
                        max_lanes=lanes,
                        hysteresis_state=governor_state,
                        claim=True,
                    )
                    # ``claim=True`` is the controller's atomic path: newly
                    # admitted resource-bearing lanes arrive with their
                    # reservation and attempt already committed together.
                    # Keep the default list-only return for older diagnostic
                    # callers and make the shape explicit here.
                    if not isinstance(reservation_result, tuple):  # pragma: no cover - defensive
                        reservation_rows = reservation_result
                        preclaimed: list[dict[str, Any]] = []
                    else:
                        reservation_rows, preclaimed = reservation_result
                    reservation_diagnostics.extend(reservation_rows)
                    if governor_state != governor_state_before:
                        store.put_governor_state(
                            governor_state,
                            owner_id=owner,
                            fence_token=fence,
                        )
                    if len(reservation_diagnostics) > diagnostic_limit:
                        del reservation_diagnostics[:-diagnostic_limit]
                    claims = list(preclaimed)
                    remaining_lanes = max(0, lanes - len(claims))
                    if remaining_lanes:
                        claims.extend(
                            store.claim_jobs(
                                owner,
                                fence,
                                max_jobs=remaining_lanes,
                                lease_ttl_seconds=self.lease_ttl_seconds,
                                require_reservation=self.enforce_reservations,
                            )
                        )
                    if not claims:
                        idle += 1
                        # ``0`` is the durable-worker mode: stay alive while
                        # the queue is empty so a later enqueue can continue
                        # after the originating chat/session disappears.
                        if once or (max_idle_rounds and idle >= int(max_idle_rounds)):
                            break
                        sleep_seconds = max(0.1, float(poll_seconds))
                        # Planner/quota feedback is an advisory wake hint.  A
                        # loader is re-read on every empty-queue tick so a
                        # monitor can publish a new decision without
                        # restarting the 24h controller.  Missing or malformed
                        # feedback fails closed to a normal short poll.
                        schedule = observe_replan_feedback(
                            observation_mode="idle",
                            record_diagnostic=True,
                        )
                        try:
                            target_sleep = float((schedule or {}).get("sleep_seconds") or 0.0)
                        except (TypeError, ValueError):
                            target_sleep = 0.0
                        if target_sleep > 0:
                            # The controller must still observe leases, mounts,
                            # and Resource Governor at least once per bounded
                            # backoff interval; never sleep until a distant
                            # quota reset in one uninterruptible call.
                            sleep_seconds = max(
                                sleep_seconds,
                                min(target_sleep, idle_backoff),
                            )
                        retry_at = store.next_retry_at_utc()
                        if retry_at is not None:
                            try:
                                retry_time = dt.datetime.fromisoformat(
                                    str(retry_at).replace("Z", "+00:00")
                                )
                                if retry_time.tzinfo is not None:
                                    retry_wait = (
                                        retry_time.astimezone(dt.timezone.utc)
                                        - dt.datetime.now(dt.timezone.utc)
                                    ).total_seconds()
                                    if retry_wait > 0:
                                        # Keep the queue responsive to a new
                                        # enqueue and preserve periodic
                                        # resource/lease observation while
                                        # avoiding a tight retry scan.
                                        sleep_seconds = max(
                                            sleep_seconds,
                                            min(retry_wait, idle_backoff),
                                        )
                            except (TypeError, ValueError, OverflowError):
                                # Malformed retry timestamps are ignored here;
                                # claim eligibility remains fail-closed in the
                                # transactional store.
                                pass
                        sleep(sleep_seconds)
                        continue
                    idle = 0
                    observe_replan_feedback(
                        observation_mode="active",
                        active_claims=claims,
                        record_diagnostic=True,
                    )
                    watcher = start_replan_watcher(claims)
                    try:
                        if len(claims) == 1:
                            results.append(execute_claim_safely(claims[0]))
                        else:
                            # Claiming is atomic; provider work is outside the
                            # transaction and can use independent write scopes.
                            # SQLiteStore serializes the short completion/event
                            # transactions safely.
                            with concurrent.futures.ThreadPoolExecutor(max_workers=len(claims)) as pool:
                                futures = [pool.submit(execute_claim_safely, claim) for claim in claims]
                                results.extend(future.result() for future in futures)
                    finally:
                        stop_replan_watcher(watcher)
                    if once:
                        break
            snapshot = store.snapshot()
        return {
            "schema_version": 1,
            "ok": True,
            "backend": "sqlite",
            "results": results,
            "reservation_diagnostics": reservation_diagnostics,
            "replan_diagnostics": replan_diagnostics,
            "snapshot": snapshot,
        }

    def status(self) -> dict[str, Any]:
        with SQLiteStore(self.db_path) as store:
            return {"schema_version": 1, "ok": True, "backend": "sqlite", "snapshot": store.snapshot()}

    def resume(self, *, owner_id: str | None = None) -> dict[str, Any]:
        owner = owner_id or f"sqlite-resume-{uuid.uuid4().hex[:12]}"
        with SQLiteStore(self.db_path) as store:
            with store.controller_lease(owner, ttl_seconds=self.lease_ttl_seconds) as lease:
                recovery_liveness = self._recovery_liveness(store)
                recovered = store.recover_expired_jobs(
                    owner,
                    int(lease["fence_token"]),
                    liveness_by_job=recovery_liveness,
                    strict_liveness=True,
                )
            return {"schema_version": 1, "ok": True, "backend": "sqlite", "recovered": recovered, "snapshot": store.snapshot()}


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)

    enqueue = sub.add_parser("enqueue")
    enqueue.add_argument("--db", required=True)
    enqueue.add_argument("--job-file", required=True)

    run = sub.add_parser("run")
    run.add_argument("--db", required=True)
    run.add_argument("--workspace", default=".")
    run.add_argument("--inventory")
    run.add_argument("--runtime-state")
    run.add_argument("--once", action="store_true")
    run.add_argument(
        "--max-idle-rounds", type=int, default=0,
        help="empty-queue polls before exit; 0 keeps the durable worker alive",
    )
    run.add_argument("--poll-seconds", type=float, default=1.0)
    run.add_argument(
        "--idle-backoff-seconds", type=float, default=30.0,
        help="maximum bounded sleep while the queue is empty (default: 30)",
    )
    run.add_argument(
        "--replan-feedback",
        help="saved planner/closed-loop JSON; re-read on every empty-queue tick",
    )
    run.add_argument(
        "--replan-max-wait-seconds", type=float, default=300.0,
        help="maximum wait before a replan/resource health recheck (default: 300)",
    )
    run.add_argument("--max-lanes", type=int, default=1)
    run.add_argument("--owner-id")
    run.add_argument(
        "--enforce-reservations", action=argparse.BooleanOptionalAction, default=True,
        help="require planner resource packets to hold a live admission reservation",
    )

    status = sub.add_parser("status")
    status.add_argument("--db", required=True)

    resume = sub.add_parser("resume")
    resume.add_argument("--db", required=True)
    resume.add_argument("--owner-id")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "enqueue":
            packet = load_json(pathlib.Path(args.job_file))
            if not isinstance(packet, dict):
                raise ValueError("job file must contain an object")
            result = SQLiteController(pathlib.Path(args.db)).enqueue(packet)
            write_json({"schema_version": 1, "ok": True, "backend": "sqlite", "job": result})
            return 0
        controller = SQLiteController(
            pathlib.Path(args.db),
            workspace=pathlib.Path(getattr(args, "workspace", ".")),
            inventory=pathlib.Path(args.inventory) if getattr(args, "inventory", None) else None,
            runtime_state=pathlib.Path(args.runtime_state) if getattr(args, "runtime_state", None) else None,
        )
        if args.command == "run":
            controller.enforce_reservations = bool(args.enforce_reservations)
            feedback_loader = None
            if args.replan_feedback:
                feedback_path = pathlib.Path(args.replan_feedback).expanduser().resolve()

                def feedback_loader(path: pathlib.Path = feedback_path) -> Mapping[str, Any] | None:
                    payload = load_json(path)
                    return payload if isinstance(payload, Mapping) else None

            write_json(controller.run(
                once=args.once,
                max_idle_rounds=args.max_idle_rounds,
                poll_seconds=args.poll_seconds,
                idle_backoff_seconds=args.idle_backoff_seconds,
                replan_feedback_loader=feedback_loader,
                replan_max_wait_seconds=args.replan_max_wait_seconds,
                max_lanes=args.max_lanes,
                owner_id=args.owner_id,
            ))
        elif args.command == "status":
            write_json(controller.status())
        elif args.command == "resume":
            write_json(controller.resume(owner_id=args.owner_id))
        return 0
    except Exception as exc:
        write_json({"schema_version": 1, "ok": False, "backend": "sqlite", "error": f"{type(exc).__name__}: {exc}"})
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
