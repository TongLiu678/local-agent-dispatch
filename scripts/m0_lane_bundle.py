#!/usr/bin/env python3
"""Build a provider-free, deterministic M0 lane bundle.

This module is deliberately a small planning seam, not another executor.  It
accepts an already captured M0 plan and host inventory, pins one exact model
and variant, and emits lane records for review.  It never imports a provider
client, opens SSH, creates a worktree, or writes a run directory.  An output
file is written only when the CLI caller explicitly supplies ``--output``;
otherwise the report is printed to stdout.

The bundle is useful before the larger dynamic planner is involved: every lane
gets a unique relative ``write_scope`` and an explicit quota/resource
admission decision.  Unknown evidence is deferred rather than silently
converted into capacity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import PurePosixPath
from typing import Any


SCHEMA_VERSION = 1
REPORT_TYPE = "local-agent-dispatch.m0_lane_bundle"
DEFAULT_LANE_COUNT = 10
DEFAULT_WRITE_ROOT = ".lad/m0-lanes"
_SECRET_KEY_MARKERS = (
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "credential",
    "password",
    "private_key",
    "secret",
)
_SAFE_CREDENTIAL_ASSERTION_KEYS = frozenset(
    {
        "no_credentials",
        "credentials_copied_or_emitted",
        "credential_queries",
        "credential_values_emitted",
        "provider_auth_queries",
    }
)


class LaneBundleError(ValueError):
    """Raised when a lane bundle cannot be bounded from supplied evidence."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    """Return the stable SHA-256 digest used by the lane contract."""

    return hashlib.sha256(_canonical(value)).hexdigest()


def _reject_secret_keys(value: Any, path: str = "$") -> None:
    """Fail closed if a supplied planning document contains credential fields."""

    if isinstance(value, Mapping):
        for key, child in value.items():
            lowered = str(key).lower().replace("-", "_")
            if (
                lowered not in _SAFE_CREDENTIAL_ASSERTION_KEYS
                and any(marker in lowered for marker in _SECRET_KEY_MARKERS)
            ):
                raise LaneBundleError(f"secret-like field is not accepted: {path}.{key}")
            _reject_secret_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_keys(child, f"{path}[{index}]")


def _text(value: Any, field: str, *, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise LaneBundleError(f"{field} is required")
        return None
    if not isinstance(value, str) or not value.strip():
        raise LaneBundleError(f"{field} must be a non-empty string")
    if "\x00" in value:
        raise LaneBundleError(f"{field} contains NUL")
    return value.strip()


def _number(value: Any, field: str, *, default: float | None = None) -> float | None:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        raise LaneBundleError(f"{field} must be numeric")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        if isinstance(value, str) and value.strip().lower() in {"unknown", "n/a", "na"}:
            return None
        raise LaneBundleError(f"{field} must be numeric") from exc
    if parsed < 0:
        raise LaneBundleError(f"{field} must be non-negative")
    return parsed


def _first(mapping: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return None


def _relative_scope(value: Any, field: str) -> str:
    raw = _text(value, field, required=True)
    assert raw is not None
    path = PurePosixPath(raw.replace("\\", "/"))
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise LaneBundleError(f"{field} must be a relative path without '..'")
    # ``PurePosixPath`` collapses repeated separators and a trailing slash;
    # this gives all callers one stable spelling for the digest.
    normalized = path.as_posix()
    if normalized in {"", "."}:
        raise LaneBundleError(f"{field} must not be the repository root")
    return normalized


def _path_prefix(left: PurePosixPath, right: PurePosixPath) -> bool:
    if len(left.parts) > len(right.parts):
        return False
    return left.parts == right.parts[: len(left.parts)]


def scopes_are_disjoint(scopes: Sequence[str]) -> bool:
    """Check path-segment disjointness, not just string inequality."""

    normalized = sorted(PurePosixPath(_relative_scope(scope, "write_scope")) for scope in scopes)
    return all(
        not _path_prefix(left, right)
        for left, right in zip(normalized, normalized[1:])
    )


def _as_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise LaneBundleError(f"{field} must be an object")
    return value


def _extract_tasks(plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = plan.get("tasks")
    if raw is None:
        raw = plan.get("jobs")
    if raw is None:
        raw = plan.get("lane_templates")
    if raw is None:
        raw = [plan]
    if isinstance(raw, Mapping):
        raw = list(raw.values())
    if not isinstance(raw, list) or not raw:
        raise LaneBundleError("M0 plan tasks/jobs must be a non-empty list")
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise LaneBundleError(f"M0 plan task {index} must be an object")
        task = dict(item)
        task_id = _text(
            task.get("task_id") or task.get("job_id") or task.get("id"),
            f"tasks[{index}].task_id",
        )
        task["task_id"] = task_id or f"m0-task-{index + 1:02d}"
        rows.append(task)
    return rows


def _extract_hosts(inventory: Any) -> list[dict[str, Any]]:
    if not isinstance(inventory, Mapping):
        raise LaneBundleError("host inventory must be an object")
    raw = inventory.get("hosts")
    if raw is None:
        raw = inventory.get("compute_hosts")
    if raw is None:
        # Accept a direct ``{host_id: {...}}`` inventory while avoiding
        # accidentally treating metadata keys as hosts.
        raw = {
            key: value
            for key, value in inventory.items()
            if isinstance(value, Mapping) and key not in {"quota", "metadata"}
        }
    rows: list[dict[str, Any]] = []
    if isinstance(raw, Mapping):
        iterator: Iterable[tuple[Any, Any]] = raw.items()
    elif isinstance(raw, list):
        iterator = ((None, item) for item in raw)
    else:
        raise LaneBundleError("host inventory hosts/compute_hosts must be an object or list")
    for index, (key, item) in enumerate(iterator):
        if not isinstance(item, Mapping):
            raise LaneBundleError(f"host inventory entry {index} must be an object")
        row = dict(item)
        host_id = _text(row.get("host_id") or key, f"hosts[{index}].host_id", required=True)
        assert host_id is not None
        row["host_id"] = host_id
        rows.append(row)
    if not rows:
        raise LaneBundleError("host inventory must contain at least one host")
    return sorted(rows, key=lambda row: str(row["host_id"]))


def _resource_request(plan: Mapping[str, Any], task: Mapping[str, Any]) -> dict[str, float | None]:
    source = task.get("resource_request")
    if source is None:
        source = task.get("resources")
    if source is None:
        source = plan.get("resource_request")
    if source is None:
        source = plan.get("resources")
    source_map = source if isinstance(source, Mapping) else {}
    compute = source_map.get("compute") if isinstance(source_map.get("compute"), Mapping) else {}
    storage = source_map.get("storage") if isinstance(source_map.get("storage"), Mapping) else {}
    return {
        "cpu_cores": _number(_first(source_map, "cpu_cores", "cpu", "cores") or _first(compute, "cpu_cores", "cores"), "resource_request.cpu_cores", default=1.0),
        "ram_gib": _number(_first(source_map, "ram_gib", "memory_gib", "ram") or _first(compute, "ram_gib", "memory_gib", "ram"), "resource_request.ram_gib", default=1.0),
        "gpu_count": _number(_first(source_map, "gpu_count", "gpus") or _first(compute, "gpu_count", "gpus"), "resource_request.gpu_count", default=0.0),
        "vram_gib": _number(_first(source_map, "vram_gib", "vram_gib_per_gpu", "gpu_memory_gib") or _first(compute, "vram_gib", "vram_gib_per_gpu"), "resource_request.vram_gib", default=0.0),
        "disk_gib": _number(_first(source_map, "new_disk_gib", "disk_gib", "output_gib") or _first(storage, "new_disk_gib", "disk_gib", "output_gib"), "resource_request.disk_gib", default=0.0),
    }


def _quota_source(plan: Mapping[str, Any], inventory: Mapping[str, Any]) -> Mapping[str, Any]:
    for key in ("quota", "quota_state", "quota_admission"):
        value = plan.get(key)
        if isinstance(value, Mapping):
            return value
    for key in ("quota", "quota_state"):
        value = inventory.get(key)
        if isinstance(value, Mapping):
            return value
    return {}


def _external_pool_state(inventory: Mapping[str, Any], pool_id: str | None) -> str:
    """Return a conservative account/pool occupancy state from host evidence.

    External OpenCode processes are account-level consumers even when they run
    on only one SSH host.  Therefore a busy/unknown observation must constrain
    the shared pool globally, not merely remove that one host from placement.
    The inventory may carry the scan at top level or attach it to a host.
    """

    sources: list[Mapping[str, Any]] = []
    top = inventory.get("external_consumers")
    if isinstance(top, Mapping):
        sources.append(top)
    raw_hosts = inventory.get("hosts") or inventory.get("compute_hosts")
    rows = raw_hosts.values() if isinstance(raw_hosts, Mapping) else (raw_hosts or [])
    for row in rows:
        if isinstance(row, Mapping) and isinstance(row.get("external_consumers"), Mapping):
            sources.append(row["external_consumers"])
    for source in sources:
        if source.get("scan_ok") is False or source.get("unknown") is True:
            return "unknown"
        inflight = source.get("inflight_by_pool")
        if isinstance(inflight, Mapping):
            try:
                if float(inflight.get(pool_id, 0) or 0) > 0:
                    return "busy"
            except (TypeError, ValueError):
                return "unknown"
    # OpenCode Go is one account-level shared pool.  A host inventory that
    # predates the privacy-safe external-consumer scan must not be interpreted
    # as an empty account: another chat may be consuming the same allowance.
    # Other pools retain the legacy clear default because their occupancy
    # evidence is not represented by this bounded M0 bundle.
    if pool_id == "opencode.go" and not sources:
        return "unknown"
    return "clear"


def _safe_preflight_evidence(preflight: Mapping[str, Any]) -> dict[str, Any]:
    """Copy only occupancy/quota fields needed by this planning seam.

    A full preflight contains provider and process metadata that must not be
    copied into a lane bundle.  This allow-list also prevents a credential-like
    field in an unrelated preflight section from becoming bundle state.
    """

    raw_external = preflight.get("external_consumers")
    if not isinstance(raw_external, Mapping):
        raise LaneBundleError("preflight.external_consumers is required")
    evidence: dict[str, Any] = {}
    for key in ("scan_ok", "unknown", "attribution", "exclusive_pool_observation"):
        if key in raw_external:
            evidence[key] = raw_external[key]
    raw_inflight = raw_external.get("inflight_by_pool")
    if isinstance(raw_inflight, Mapping):
        inflight: dict[str, int] = {}
        for pool_id, value in raw_inflight.items():
            try:
                parsed = float(value)
            except (TypeError, ValueError) as exc:
                raise LaneBundleError("preflight external inflight must be numeric") from exc
            if parsed < 0 or not parsed.is_integer():
                raise LaneBundleError("preflight external inflight must be a non-negative integer")
            inflight[str(pool_id)] = int(parsed)
        evidence["inflight_by_pool"] = inflight
    else:
        evidence["scan_ok"] = False
    return evidence


def _merge_preflight_evidence(
    plan: Mapping[str, Any],
    host_inventory: Mapping[str, Any],
    preflight: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Bind fresh, redacted occupancy/quota evidence to a bundle input."""

    if not isinstance(preflight, Mapping):
        raise LaneBundleError("preflight must be an object")
    safe_external = _safe_preflight_evidence(preflight)
    merged_plan = dict(plan)
    merged_inventory = dict(host_inventory)
    merged_inventory["external_consumers"] = safe_external

    pools = preflight.get("pools")
    opencode_pool = pools.get("opencode.go") if isinstance(pools, Mapping) else None
    if isinstance(opencode_pool, Mapping):
        current = _number(
            _first(opencode_pool, "effective_remaining_percent", "remaining_percent"),
            "preflight.pools.opencode.go.remaining_percent",
            default=None,
        )
        if current is not None:
            quota = dict(merged_plan.get("quota") or {})
            quota["pool_id"] = "opencode.go"
            quota["remaining_percent"] = current
            quota["effective_remaining_percent"] = current
            merged_plan["quota"] = quota
    return merged_plan, merged_inventory, safe_external


def _quota_admission(plan: Mapping[str, Any], inventory: Mapping[str, Any], tasks: Sequence[Mapping[str, Any]], lane_count: int) -> dict[str, Any]:
    quota = _quota_source(plan, inventory)
    policy_maps = [
        quota,
        quota.get("policy") if isinstance(quota.get("policy"), Mapping) else {},
        quota.get("pilot") if isinstance(quota.get("pilot"), Mapping) else {},
        plan,
        plan.get("quota_policy") if isinstance(plan.get("quota_policy"), Mapping) else {},
    ]
    # A live usage reader may know only a bounded lane cap, not a trustworthy
    # per-lane percentage cost.  Preserve every cap and use the most
    # conservative one when more than one policy layer supplies it.
    explicit_caps: list[int] = []
    for source in policy_maps:
        for key in ("max_admitted_lanes", "pilot_lanes"):
            if key not in source or source.get(key) is None:
                continue
            raw_cap = _number(source.get(key), f"quota.{key}", default=None)
            if raw_cap is None or not float(raw_cap).is_integer():
                raise LaneBundleError(f"quota.{key} must be a non-negative integer")
            explicit_caps.append(max(0, int(raw_cap)))
    explicit_lane_cap = min(explicit_caps) if explicit_caps else None
    remaining_raw = _first(quota, "effective_remaining_percent", "remaining_percent", "remaining")
    reserve_raw = _first(quota, "reserve_percent", "reserve")
    cost_raw = _first(
        quota,
        "cost_percent_per_lane",
        "per_lane_cost_percent",
        "estimated_quota_cost_percent",
        "lane_cost_percent",
    )
    if cost_raw is None:
        cost_raw = _first(plan, "quota_cost_percent_per_lane", "estimated_quota_cost_percent", "lane_cost_percent")
    if cost_raw is None and tasks:
        cost_raw = _first(tasks[0], "quota_cost_percent", "estimated_quota_cost_percent")
    remaining = _number(remaining_raw, "quota.remaining_percent", default=None)
    reserve = _number(reserve_raw, "quota.reserve_percent", default=0.0)
    cost = _number(cost_raw, "quota.cost_percent_per_lane", default=None)
    pool_id = _text(_first(quota, "pool_id", "id") or plan.get("pool_id"), "quota.pool_id")
    unknown_policy = str(
        _first(quota, "unknown_policy", "unknown_quota_policy")
        or plan.get("unknown_quota_policy")
        or "defer"
    ).lower()
    allow_unknown = bool(plan.get("allow_unknown_quota")) or unknown_policy in {"pilot", "bounded_pilot"}
    pilot_lanes = int(_number(plan.get("unknown_quota_pilot_lanes"), "unknown_quota_pilot_lanes", default=1) or 1)
    if remaining is None:
        if allow_unknown and explicit_lane_cap is not None:
            allowed = min(lane_count, explicit_lane_cap)
            reason = "explicit_pilot_cap" if allowed else "quota_unknown"
        else:
            allowed = min(lane_count, pilot_lanes) if allow_unknown and cost is not None else 0
            reason = "unknown_quota_bounded_pilot" if allowed else "quota_unknown"
        return {
            "pool_id": pool_id,
            "state": "unknown",
            "remaining_percent": None,
            "reserve_percent": reserve,
            "cost_percent_per_lane": cost,
            "budget_percent": None,
            "max_admitted_lanes": allowed,
            "explicit_lane_cap": explicit_lane_cap,
            "decision": "bounded_pilot" if allowed else "defer",
            "reason": reason,
            "unknown_policy": unknown_policy,
        }
    budget = max(0.0, remaining - float(reserve or 0.0))
    if cost is None or cost <= 0:
        if explicit_lane_cap is not None:
            allowed = min(lane_count, explicit_lane_cap)
            reason = "explicit_pilot_cap"
        else:
            allowed = lane_count if cost == 0 else 0
            reason = "zero_cost_lane" if cost == 0 else "quota_cost_unknown"
        return {
            "pool_id": pool_id,
            "state": "known",
            "remaining_percent": remaining,
            "reserve_percent": reserve,
            "cost_percent_per_lane": cost,
            "budget_percent": round(budget, 6),
            "max_admitted_lanes": allowed,
            "explicit_lane_cap": explicit_lane_cap,
            "decision": "admit" if allowed else "defer",
            "reason": reason,
            "unknown_policy": unknown_policy,
        }
    quota_allowed = min(lane_count, int(budget // cost + 1e-12))
    allowed = min(quota_allowed, explicit_lane_cap) if explicit_lane_cap is not None else quota_allowed
    reason = (
        "explicit_pilot_cap"
        if explicit_lane_cap is not None and allowed < quota_allowed
        else ("within_reserve" if allowed else "quota_reserve_exceeded")
    )
    return {
        "pool_id": pool_id,
        "state": "known",
        "remaining_percent": remaining,
        "reserve_percent": reserve,
        "cost_percent_per_lane": cost,
        "budget_percent": round(budget, 6),
        "max_admitted_lanes": allowed,
        "explicit_lane_cap": explicit_lane_cap,
        "decision": "admit" if allowed else "defer",
        "reason": reason,
        "unknown_policy": unknown_policy,
    }


def _host_capacity(row: Mapping[str, Any]) -> dict[str, Any]:
    capacity = row.get("capacity")
    if not isinstance(capacity, Mapping):
        capacity = row.get("resources") if isinstance(row.get("resources"), Mapping) else {}
    gpus = row.get("gpus") if isinstance(row.get("gpus"), list) else []
    free_vram = sum(
        float(gpu.get("vram_free_gib"))
        for gpu in gpus
        if isinstance(gpu, Mapping) and _number(gpu.get("vram_free_gib"), "host.gpu.vram_free_gib", default=None) is not None
    )
    storage_paths = row.get("storage_paths") if isinstance(row.get("storage_paths"), list) else []
    writable_paths = [
        path
        for path in storage_paths
        if isinstance(path, Mapping) and path.get("writable") is True and path.get("disk_free_gib") is not None
    ]
    best_storage = max(writable_paths, key=lambda path: float(path.get("disk_free_gib", 0)), default=None)
    writable = _first(row, "project_path_writable", "writable", "workload_path_writable")
    if writable is None and storage_paths:
        writable = any(path.get("writable") is True for path in storage_paths if isinstance(path, Mapping))
    external = row.get("external_consumers")
    if not isinstance(external, Mapping):
        external = {}
    inflight_by_pool = external.get("inflight_by_pool")
    if not isinstance(inflight_by_pool, Mapping):
        inflight_by_pool = {}
    external_inflight = 0.0
    for value in inflight_by_pool.values():
        try:
            external_inflight += max(0.0, float(value))
        except (TypeError, ValueError):
            continue
    # A scheduler inventory may be produced from a privacy-safe process scan.
    # An active external consumer is a hard conflict; a failed/unknown scan is
    # also fail-closed.  A successful scan with no recognized consumers remains
    # usable, even though attribution is still not exclusive.
    if external.get("scan_ok") is False:
        external_state = "unknown"
    elif external_inflight > 0:
        external_state = "busy"
    elif row.get("external_consumers_unknown") is True:
        external_state = "unknown"
    else:
        external_state = "clear"
    return {
        "host_id": str(row.get("host_id")),
        "reachable": row.get("reachable", True) is not False,
        "reachable_evidence": "declared" if "reachable" in row else "inventory_default",
        "writable": writable is not False if writable is not None else None,
        "writable_evidence": "declared" if writable is not None else "unknown",
        "transport": str(row.get("transport") or "unknown"),
        "project_path": row.get("project_path"),
        "storage_path": (best_storage or {}).get("path") if best_storage else row.get("best_writable_storage_path"),
        "slots": _number(_first(row, "available_slots", "lane_slots", "max_concurrency") or _first(capacity, "available_slots", "lane_slots", "max_concurrency"), "host.slots", default=None),
        "inflight": _number(row.get("inflight"), "host.inflight", default=0.0),
        "cpu_cores": _number(_first(row, "estimated_idle_cpu_cores", "available_cpu_cores", "logical_cpu_cores") or _first(capacity, "cpu_cores", "available_cpu_cores"), "host.cpu_cores", default=None),
        "ram_gib": _number(_first(row, "memory_available_gib", "available_ram_gib", "ram_gib") or _first(capacity, "ram_gib", "memory_available_gib"), "host.ram_gib", default=None),
        "gpu_count": _number(_first(row, "gpu_count", "available_gpu_count") or _first(capacity, "gpu_count"), "host.gpu_count", default=float(len(gpus))),
        "vram_gib": _number(_first(row, "vram_free_gib", "available_vram_gib") or _first(capacity, "vram_gib"), "host.vram_gib", default=free_vram),
        "disk_gib": _number(_first(row, "disk_free_gib", "free_disk_gib") or _first(capacity, "disk_free_gib"), "host.disk_gib", default=(float(best_storage.get("disk_free_gib")) if best_storage else None)),
        "pressure": str(row.get("memory_pressure_state") or "normal").lower(),
        "local_agent_launch_allowed": row.get("local_agent_launch_allowed", True),
        "external_consumer_state": external_state,
        "external_inflight": external_inflight,
    }


def _host_reason(capacity: Mapping[str, Any], request: Mapping[str, float | None]) -> list[str]:
    reasons: list[str] = []
    if not capacity["reachable"]:
        reasons.append("host_unreachable")
    if capacity["writable"] is False:
        reasons.append("write_path_not_writable")
    elif capacity["writable"] is None:
        reasons.append("write_path_unknown")
    if capacity["slots"] is None:
        reasons.append("lane_capacity_unknown")
    elif capacity["slots"] - capacity["inflight"] < 1:
        reasons.append("lane_capacity_exhausted")
    if capacity["local_agent_launch_allowed"] is False:
        reasons.append("local_agent_launch_blocked")
    if capacity.get("external_consumer_state") == "busy":
        reasons.append("external_consumer_pool_busy")
    elif capacity.get("external_consumer_state") == "unknown":
        reasons.append("external_consumer_state_unknown")
    if capacity["pressure"] in {"critical", "emergency", "stop"}:
        reasons.append("memory_pressure_critical")
    for resource, label in (
        ("cpu_cores", "cpu_cores"),
        ("ram_gib", "ram_gib"),
        ("gpu_count", "gpu_count"),
        ("vram_gib", "vram_gib"),
        ("disk_gib", "disk_gib"),
    ):
        required = request.get(resource)
        available = capacity.get(resource)
        if required in (None, 0):
            continue
        if available is None:
            reasons.append(f"{label}_unknown")
        elif float(available) < float(required):
            reasons.append(f"insufficient_{label}")
    return reasons


def _resource_projection(capacity: Mapping[str, Any], request: Mapping[str, float | None], *, admitted: bool) -> dict[str, Any]:
    before = {
        key: capacity.get(key)
        for key in ("slots", "cpu_cores", "ram_gib", "gpu_count", "vram_gib", "disk_gib")
    }
    after = dict(before)
    if admitted:
        if after["slots"] is not None:
            after["slots"] = round(float(after["slots"]) - 1, 6)
        for key in ("cpu_cores", "ram_gib", "gpu_count", "vram_gib", "disk_gib"):
            if after[key] is not None and request.get(key) is not None:
                after[key] = round(float(after[key]) - float(request[key] or 0), 6)
    return {
        "decision": "admit" if admitted else "defer",
        "required": dict(request),
        "capacity_before": before,
        "capacity_after": after,
    }


def build_lane_bundle(
    plan: Mapping[str, Any],
    model: str,
    variant: str | None,
    host_inventory: Mapping[str, Any],
    *,
    lane_count: int = DEFAULT_LANE_COUNT,
    preflight: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a read-only M0 bundle from supplied plan and inventory facts.

    ``lane_count`` defaults to ten for the M0 bounded lane shape.  The exact
    model is mandatory and never selected or replaced by this helper.  A
    caller may explicitly opt into one unknown-quota pilot lane through the
    plan; the default remains fail-closed.
    """

    if not isinstance(plan, Mapping):
        raise LaneBundleError("M0 plan must be an object")
    if not isinstance(host_inventory, Mapping):
        raise LaneBundleError("host inventory must be an object")
    preflight_evidence: dict[str, Any] | None = None
    if preflight is not None:
        plan, host_inventory, preflight_evidence = _merge_preflight_evidence(
            plan, host_inventory, preflight
        )
    _reject_secret_keys(plan)
    _reject_secret_keys(host_inventory)
    if isinstance(lane_count, bool) or int(lane_count) < 1 or int(lane_count) > 100:
        raise LaneBundleError("lane_count must be between 1 and 100")
    lane_count = int(lane_count)
    exact_model = _text(model, "model", required=True)
    assert exact_model is not None
    plan_model = _text(plan.get("model") or plan.get("exact_model"), "plan.model")
    if plan_model and plan_model != exact_model:
        raise LaneBundleError(f"exact model mismatch: plan has {plan_model!r}, caller has {exact_model!r}")
    model_selection = plan.get("model_selection")
    if isinstance(model_selection, Mapping):
        declared = _text(model_selection.get("model"), "plan.model_selection.model")
        if declared and declared != exact_model:
            raise LaneBundleError("exact model mismatch in model_selection")
        declared_variant = _text(model_selection.get("variant"), "plan.model_selection.variant")
    else:
        declared_variant = None
    plan_variant = _text(plan.get("variant"), "plan.variant") or declared_variant
    exact_variant = _text(variant, "variant") if variant is not None else plan_variant
    if plan_variant and exact_variant and plan_variant != exact_variant:
        raise LaneBundleError(f"exact variant mismatch: plan has {plan_variant!r}, caller has {exact_variant!r}")

    tasks = _extract_tasks(plan)
    hosts = _extract_hosts(host_inventory)
    quota = _quota_admission(plan, host_inventory, tasks, lane_count)
    external_pool_state = _external_pool_state(
        host_inventory, str(quota.get("pool_id") or "") or None
    )
    if external_pool_state != "clear":
        quota = dict(quota)
        quota["max_admitted_lanes"] = 0
        quota["decision"] = "defer"
        quota["reason"] = (
            "external_consumer_pool_busy"
            if external_pool_state == "busy"
            else "external_consumer_state_unknown"
        )
        quota["external_consumer_state"] = external_pool_state
    scope_root = _relative_scope(
        plan.get("lane_write_root") or plan.get("write_scope_root") or DEFAULT_WRITE_ROOT,
        "lane_write_root",
    )
    host_states: list[dict[str, Any]] = []
    for row in hosts:
        state = _host_capacity(row)
        if state["slots"] is not None:
            state["slots"] = max(0.0, float(state["slots"]) - float(state["inflight"] or 0))
        host_states.append(state)

    lanes: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    cursor = 0
    for ordinal in range(1, lane_count + 1):
        task = tasks[(ordinal - 1) % len(tasks)]
        lane_id = f"m0-lane-{ordinal:02d}"
        write_scope = f"{scope_root}/lane-{ordinal:02d}"
        request = _resource_request(plan, task)
        reasons: list[str] = []
        quota_allowed = ordinal <= int(quota["max_admitted_lanes"])
        if not quota_allowed:
            # The aggregate quota decision describes the admitted prefix; a
            # deferred lane needs its own reason so a caller can distinguish
            # "within reserve" for earlier lanes from the reserve breach at
            # this ordinal.
            if str(quota.get("reason") or "").startswith("external_consumer_"):
                reasons.append(str(quota["reason"]))
            elif quota.get("state") == "known" and quota.get("cost_percent_per_lane") is not None:
                reasons.append(
                    "quota_reserve_exceeded"
                    if float(quota.get("budget_percent") or 0) > 0
                    else "quota_exhausted"
                )
            else:
                reasons.append(str(quota["reason"]))
        selected: dict[str, Any] | None = None
        host_attempts: list[dict[str, Any]] = []
        if quota_allowed:
            for offset in range(len(host_states)):
                index = (cursor + offset) % len(host_states)
                state = host_states[index]
                host_reasons = _host_reason(state, request)
                host_attempts.append({"host_id": state["host_id"], "reasons": host_reasons})
                if not host_reasons:
                    selected = state
                    cursor = (index + 1) % len(host_states)
                    break
            if selected is None:
                reasons.append("no_host_admission")
                for attempt in host_attempts:
                    for reason in attempt["reasons"]:
                        detail = f"{reason}:{attempt['host_id']}"
                        if detail not in reasons:
                            reasons.append(detail)
        host_id = selected["host_id"] if selected else None
        if selected:
            resource_admission = _resource_projection(selected, request, admitted=True)
            selected["slots"] = float(selected["slots"]) - 1 if selected["slots"] is not None else None
            for key in ("cpu_cores", "ram_gib", "gpu_count", "vram_gib", "disk_gib"):
                if selected[key] is not None and request.get(key) is not None:
                    selected[key] = float(selected[key]) - float(request[key] or 0)
        else:
            resource_admission = {
                "decision": "defer" if quota_allowed else "not_attempted",
                "required": dict(request),
                "capacity_before": None,
                "capacity_after": None,
                "host_attempts": host_attempts,
            }
        status = "admitted" if selected and quota_allowed else "deferred"
        lane: dict[str, Any] = {
            "lane_id": lane_id,
            "ordinal": ordinal,
            "task_id": str(task["task_id"]),
            "model": exact_model,
            "variant": exact_variant,
            "model_selection": "exact_caller_pin",
            "host_id": host_id,
            "transport": selected.get("transport") if selected else None,
            "project_path": selected.get("project_path") if selected else None,
            "storage_path": selected.get("storage_path") if selected else None,
            "write_scope": write_scope,
            "status": status,
            "deferred_reasons": reasons,
            "quota_admission": {
                "pool_id": quota.get("pool_id"),
                "decision": "admit" if quota_allowed else "defer",
                "cost_percent": quota.get("cost_percent_per_lane"),
                "max_admitted_lanes": quota.get("max_admitted_lanes"),
                "state": quota.get("state"),
            },
            "resource_admission": resource_admission,
        }
        lane["lane_digest"] = canonical_digest(lane)
        lanes.append(lane)
        if status != "admitted":
            deferred.append(
                {
                    "lane_id": lane_id,
                    "task_id": str(task["task_id"]),
                    "reasons": list(reasons) or ["admission_deferred"],
                }
            )

    scopes = [str(lane["write_scope"]) for lane in lanes]
    if not scopes_are_disjoint(scopes):
        raise LaneBundleError("generated write scopes are not disjoint")
    plan_digest = canonical_digest(dict(plan))
    inventory_digest = canonical_digest(dict(host_inventory))
    bundle: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "report_type": REPORT_TYPE,
        "plan_id": str(plan.get("plan_id") or plan.get("mission_id") or "m0-source-truth"),
        "lane_count": lane_count,
        "model": exact_model,
        "variant": exact_variant,
        "read_only": True,
        "provider_execution": False,
        "ssh_execution": False,
        "real_run_directory_written": False,
        "side_effects": [],
        "scope_root": scope_root,
        "external_consumer_evidence": preflight_evidence,
        "quota_admission": quota,
        "resource_admission": {
            "host_count": len(host_states),
            "admitted_lanes": sum(lane["status"] == "admitted" for lane in lanes),
            "deferred_lanes": len(deferred),
            "host_ids": [state["host_id"] for state in host_states],
        },
        "lanes": lanes,
        "deferred": deferred,
        "digests": {
            "algorithm": "sha256-json-c14n-v1",
            "plan": plan_digest,
            "host_inventory": inventory_digest,
            "lanes": [str(lane["lane_digest"]) for lane in lanes],
        },
    }
    bundle["digests"]["bundle"] = canonical_digest(bundle)
    return bundle


def build_bundle(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Compatibility alias for callers that use the shorter name."""

    return build_lane_bundle(*args, **kwargs)


def validate_bundle(bundle: Mapping[str, Any], *, expected_lane_count: int | None = None) -> None:
    """Validate the stable invariants of a generated bundle."""

    if bundle.get("schema_version") != SCHEMA_VERSION or bundle.get("report_type") != REPORT_TYPE:
        raise LaneBundleError("unsupported lane bundle schema")
    if bundle.get("read_only") is not True or bundle.get("provider_execution") is not False:
        raise LaneBundleError("lane bundle must be provider-free and read-only")
    lanes = bundle.get("lanes")
    if not isinstance(lanes, list):
        raise LaneBundleError("lane bundle lanes must be a list")
    lane_count = expected_lane_count if expected_lane_count is not None else int(bundle.get("lane_count") or 0)
    if len(lanes) != lane_count:
        raise LaneBundleError("lane_count does not match lanes")
    scopes = [str(row.get("write_scope") or "") for row in lanes if isinstance(row, Mapping)]
    if len(scopes) != len(lanes) or len(set(scopes)) != len(scopes) or not scopes_are_disjoint(scopes):
        raise LaneBundleError("lane write scopes must be unique and disjoint")
    for lane in lanes:
        if not isinstance(lane, Mapping) or not lane.get("lane_id") or lane.get("status") not in {"admitted", "deferred"}:
            raise LaneBundleError("malformed lane record")
        body = dict(lane)
        digest = body.pop("lane_digest", None)
        if digest != canonical_digest(body):
            raise LaneBundleError(f"lane digest mismatch: {lane.get('lane_id')}")
    digests = bundle.get("digests")
    if not isinstance(digests, Mapping) or digests.get("lanes") != [lane.get("lane_digest") for lane in lanes]:
        raise LaneBundleError("lane digest index mismatch")
    body = dict(bundle)
    body_digests = dict(body.get("digests") or {})
    bundle_digest = body_digests.pop("bundle", None)
    body["digests"] = body_digests
    if bundle_digest != canonical_digest(body):
        raise LaneBundleError("bundle digest mismatch")


def _load_json(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    return json.loads(pathlib.Path(path).expanduser().read_text(encoding="utf-8"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, help="M0 plan JSON, or '-' for stdin")
    parser.add_argument("--hosts", required=True, help="host inventory JSON")
    parser.add_argument(
        "--preflight",
        help="optional fresh preflight JSON; only redacted occupancy/quota evidence is copied",
    )
    parser.add_argument("--model", required=True, help="exact model identifier; never auto-selected")
    parser.add_argument("--variant", default=None, help="exact model variant")
    parser.add_argument("--lane-count", type=int, default=DEFAULT_LANE_COUNT)
    parser.add_argument("--output", help="optional explicit output path; default is stdout")
    args = parser.parse_args(argv)
    try:
        plan = _load_json(args.plan)
        hosts = _load_json(args.hosts)
        preflight = _load_json(args.preflight) if args.preflight else None
        bundle = build_lane_bundle(
            plan,
            args.model,
            args.variant,
            hosts,
            lane_count=args.lane_count,
            preflight=preflight,
        )
        validate_bundle(bundle)
        rendered = json.dumps(bundle, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.output:
            target = pathlib.Path(args.output).expanduser()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"m0-lane-bundle: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
