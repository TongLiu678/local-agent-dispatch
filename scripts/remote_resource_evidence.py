#!/usr/bin/env python3
"""Validate the bounded resource evidence required by a remote reservation.

The scheduler may decide that a workload belongs on an SSH host, but that
decision is not itself evidence that the host is still safe to write to.  This
module is a pure, provider-free contract validator for the small observation
packet that must accompany a remote resource-bearing task.  It deliberately
returns a redacted summary and a deterministic reason list; raw inventory,
commands, prompts, and credentials never enter the SQLite admission record.

The contract is intentionally stricter than the legacy boolean
``remote_resource_evidence_verified`` flag.  A valid observation binds the
host, cgroup/PSI sample, writable mount/workspace, route, write scope, and
capacity vector to the exact packet being claimed.  Missing, stale, or
inconsistent evidence fails closed.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
from pathlib import PurePosixPath
from typing import Any, Mapping


SCHEMA_VERSION = 1
GIB = 1024**3
DEFAULT_TTL_SECONDS = 1800.0
MAX_TTL_SECONDS = 86400.0
MAX_CLOCK_SKEW_SECONDS = 60.0
_CAPACITY_FIELDS = (
    "cpu_cores",
    "ram_gib",
    "gpu_count",
    "vram_gib_per_gpu",
    "new_disk_gib",
)
_ROUTE_KINDS = {"control", "execution", "workload", "artifact", "bulk_data"}
_ROUTE_STATUSES = {"direct", "relay"}


def _number(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(parsed) or parsed < 0:
        return None
    return parsed


def _parse_timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def _now(value: str | dt.datetime | None) -> dt.datetime:
    if value is None:
        return dt.datetime.now(tz=dt.timezone.utc)
    if isinstance(value, dt.datetime):
        parsed = value
    else:
        parsed = _parse_timestamp(value)
        if parsed is None:
            raise ValueError("now_utc must be an ISO-8601 timestamp")
    if parsed.tzinfo is None:
        raise ValueError("now_utc must be timezone-aware")
    return parsed.astimezone(dt.timezone.utc)


def _safe_path(value: Any, field: str, *, allow_root: bool = False) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not value.strip() or any(char in value for char in "\0\r\n"):
        return None, f"{field}_invalid"
    raw = PurePosixPath(value)
    if not raw.is_absolute() or (str(raw) == "/" and not allow_root):
        return None, f"{field}_invalid"
    # Do not let lexical normalization hide a traversal component.  Symlink
    # resolution is a separate remote observation responsibility.
    if any(part in {"", ".", ".."} for part in raw.parts if part != "/"):
        return None, f"{field}_unsafe_path"
    return str(raw), None


def _inside(child: str, parent: str) -> bool:
    try:
        PurePosixPath(child).relative_to(PurePosixPath(parent))
    except ValueError:
        return False
    return True


def _expected_host(packet: Mapping[str, Any], request: Mapping[str, Any]) -> str | None:
    direct = request.get("host_id")
    if direct:
        return str(direct)
    # Resource capacity belongs to the workload host.  An execution host is a
    # safe fallback for server-local packets where both roles are identical.
    for key in ("workload_host", "execution_host"):
        if packet.get(key):
            return str(packet[key])
    attempts = packet.get("attempts")
    if isinstance(attempts, list) and attempts and isinstance(attempts[0], Mapping):
        if attempts[0].get("host_id"):
            return str(attempts[0]["host_id"])
    return None


def _expected_workspace(packet: Mapping[str, Any]) -> str | None:
    attempts = packet.get("attempts")
    attempt = attempts[0] if isinstance(attempts, list) and attempts and isinstance(attempts[0], Mapping) else {}
    for source in (packet, attempt):
        # ``workspace`` on a controller packet is often a local staging path.
        # Remote admission must bind to an explicitly remote path (or to the
        # attempt's remote workspace), otherwise a local path can be mistaken
        # for proof that the SSH target has a writable project mount.
        for key in ("remote_workspace",):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value
    if str(attempt.get("transport") or packet.get("execution_transport") or "") == "ssh":
        value = attempt.get("workspace")
        if isinstance(value, str) and value.strip():
            return value
    return None


def _expected_write_scope_path(packet: Mapping[str, Any], workspace: str) -> tuple[str | None, str | None]:
    raw = packet.get("write_scope")
    if not isinstance(raw, str) or not raw.strip():
        return None, "remote_write_scope_missing"
    candidate = PurePosixPath(raw) if raw.startswith("/") else PurePosixPath(workspace) / PurePosixPath(raw)
    path = str(candidate)
    safe, error = _safe_path(path, "remote_write_scope_path")
    if error:
        return None, error
    if safe is None or not _inside(safe, workspace):
        return None, "remote_write_scope_path_escape"
    return safe, None


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def derive_remote_resource_evidence(
    host: Mapping[str, Any],
    *,
    workspace_path: str,
    write_scope: str,
    observed_at_utc: str | None = None,
    ttl_seconds: float = DEFAULT_TTL_SECONDS,
) -> dict[str, Any] | None:
    """Build the bounded evidence packet from an explicit host observation.

    This helper is intentionally conservative.  It does not infer a route
    from an SSH port, a helper binary, or a hostname.  A host must carry an
    explicit ``route_evidence``/``remote_route_evidence`` object whose
    ``verified`` bit and target host match.  Likewise, storage and cgroup
    values must come from the same probe; stale inventory or procfs-only RAM
    observations produce ``None`` and therefore remain a controller block.

    ``status=verified`` is accepted only when the route evidence also carries
    an explicit route ``kind``; it is normalized to the admission contract's
    ``status=direct``.  This supports the RackNerd verifier's terminology
    without treating RackNerd as a provider or a geography bypass.
    """
    if not isinstance(host, Mapping) or host.get("transport") != "ssh" or host.get("reachable") is not True:
        return None
    host_id = host.get("host_id")
    if not isinstance(host_id, str) or not host_id.strip():
        return None
    workspace, workspace_error = _safe_path(workspace_path, "remote_workspace")
    if workspace_error or workspace is None:
        return None
    project_root, project_error = _safe_path(host.get("project_path"), "remote_project_path")
    if project_error or project_root is None or not _inside(workspace, project_root):
        return None
    if not isinstance(write_scope, str) or not write_scope.strip():
        return None
    raw_scope = PurePosixPath(write_scope) if write_scope.startswith("/") else PurePosixPath(workspace) / write_scope
    scope_path, scope_error = _safe_path(str(raw_scope), "remote_write_scope_path")
    if scope_error or scope_path is None or not _inside(scope_path, workspace):
        return None

    observed = observed_at_utc or host.get("last_probed_at_utc") or host.get("observed_at_utc")
    if not isinstance(observed, str) or _parse_timestamp(observed) is None:
        return None
    try:
        ttl = float(ttl_seconds)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(ttl) or ttl <= 0 or ttl > MAX_TTL_SECONDS:
        return None

    def finite(value: Any) -> float | None:
        parsed = _number(value)
        return parsed if parsed is not None and math.isfinite(parsed) else None

    max_bytes = finite(host.get("cgroup_memory_max_bytes"))
    current_bytes = finite(host.get("cgroup_memory_current_bytes"))
    available_bytes = finite(host.get("cgroup_memory_available_bytes"))
    if host.get("cgroup_memory_evidence_status") != "complete":
        return None
    if max_bytes is None or max_bytes <= 0 or current_bytes is None or available_bytes is None:
        return None
    if current_bytes > max_bytes or available_bytes != max_bytes - current_bytes:
        return None
    psi = finite(host.get("psi_some_avg10"))
    if psi is None or psi > 100:
        return None

    storage_rows = host.get("storage_paths") or []
    if not isinstance(storage_rows, list):
        return None
    selected: Mapping[str, Any] | None = None
    selected_mount: str | None = None
    selected_free: float | None = None
    selected_total: float | None = None
    for row in storage_rows:
        if not isinstance(row, Mapping) or row.get("writable") is not True:
            continue
        # ``path`` is the probed directory; ``mount_path`` is emitted by the
        # read-only df probe.  Never treat an arbitrary candidate directory as
        # a filesystem mount when the latter is absent.
        path, path_error = _safe_path(row.get("mount_path"), "remote_mount_path", allow_root=True)
        if path_error or path is None or not _inside(workspace, path):
            continue
        total = finite(row.get("total_bytes"))
        free = finite(row.get("free_bytes"))
        if total is None:
            total_gib = finite(row.get("disk_total_gib"))
            total = total_gib * GIB if total_gib is not None else None
        if free is None:
            free_gib = finite(row.get("disk_free_gib"))
            free = free_gib * GIB if free_gib is not None else None
        if total is None or total <= 0 or free is None or free < 0 or free > total:
            continue
        # If several rows contain the workspace, bind the receipt to the
        # deepest mount first.  A parent mount such as ``/`` may report more
        # free space than the actual project mount, but using that larger
        # number would make a low-space project filesystem look healthy.
        # Equal-depth rows are duplicate observations of the same mount; use
        # the larger free value as the deterministic tie-breaker.
        candidate_depth = len(PurePosixPath(path).parts)
        selected_depth = (
            len(PurePosixPath(selected_mount).parts)
            if selected_mount is not None
            else -1
        )
        if (
            selected is None
            or candidate_depth > selected_depth
            or (
                candidate_depth == selected_depth
                and free > float(selected_free or -1)
            )
        ):
            selected = row
            selected_mount = path
            selected_total = total
            selected_free = free
    if selected is None or selected_mount is None or selected_total is None or selected_free is None:
        return None

    route = host.get("route_evidence") or host.get("remote_route_evidence")
    if not isinstance(route, Mapping) or route.get("verified") is not True:
        return None
    route_kind = route.get("kind") or route.get("route_kind")
    route_status = route.get("status")
    if route_status == "verified":
        route_status = "direct"
    if route_kind not in _ROUTE_KINDS or route_status not in _ROUTE_STATUSES:
        return None
    if route.get("target_host_id") != host_id:
        return None

    # Admission capacity is idle capacity, not the host's nameplate core
    # count.  Missing load-derived idle cores remains an unknown gate.
    cpu = finite(host.get("estimated_idle_cpu_cores"))
    ram_gib = available_bytes / GIB
    gpu_count = finite(host.get("gpu_count"))
    if cpu is None or cpu <= 0 or gpu_count is None or gpu_count < 0:
        return None
    gpus = host.get("gpus") or []
    free_vram: list[float] = []
    if int(gpu_count) > 0:
        if not isinstance(gpus, list):
            return None
        for gpu in gpus:
            if not isinstance(gpu, Mapping):
                continue
            value = finite(gpu.get("vram_free_gib"))
            if value is not None:
                free_vram.append(value)
        if len(free_vram) < int(gpu_count):
            return None
    vram_gib = min(free_vram) if free_vram else 0.0

    return {
        "schema_version": SCHEMA_VERSION,
        "host_id": host_id,
        "observed_at_utc": observed,
        "ttl_seconds": ttl,
        "cgroup": {
            "status": "complete",
            "max_bytes": int(max_bytes),
            "current_bytes": int(current_bytes),
            "available_bytes": int(available_bytes),
        },
        "psi": {"some_avg10": psi},
        "storage": {
            "mount_path": selected_mount,
            "workspace_path": workspace,
            "writable": True,
            "total_bytes": int(selected_total),
            "free_bytes": int(selected_free),
        },
        "route": {
            "kind": route_kind,
            "status": route_status,
            "verified": True,
            "target_host_id": host_id,
        },
        "capacity": {
            "cpu_cores": cpu,
            "ram_gib": ram_gib,
            "gpu_count": int(gpu_count),
            "vram_gib_per_gpu": vram_gib,
            "new_disk_gib": selected_free / GIB,
        },
        "write_scope_path": scope_path,
    }


def validate_remote_resource_evidence(
    evidence: Mapping[str, Any] | None,
    *,
    packet: Mapping[str, Any],
    request: Mapping[str, Any],
    now_utc: str | dt.datetime | None = None,
    max_clock_skew_seconds: float = MAX_CLOCK_SKEW_SECONDS,
) -> dict[str, Any]:
    """Return a redacted, fail-closed admission report for remote evidence.

    ``evidence`` is expected to have this bounded shape::

        {
          "schema_version": 1,
          "host_id": "westd",
          "observed_at_utc": "...+00:00",
          "ttl_seconds": 1800,
          "cgroup": {"status": "complete", "max_bytes": ..., ...},
          "psi": {"some_avg10": 0.0},
          "storage": {"mount_path": ..., "workspace_path": ..., ...},
          "route": {"kind": "workload", "status": "direct", ...},
          "capacity": {"cpu_cores": ..., "ram_gib": ..., ...},
          "write_scope_path": "/srv/project/job/out",
        }

    The validator never returns the input mapping.  Callers may persist the
    returned ``summary`` and ``capacity`` because those fields are allow-listed
    observation facts rather than arbitrary packet content.
    """
    reasons: list[str] = []
    if not isinstance(evidence, Mapping):
        return {
            "schema_version": SCHEMA_VERSION,
            "valid": False,
            "decision": "block",
            "reason": "remote_resource_evidence_missing",
            "reasons": ["remote_resource_evidence_missing"],
            "summary": {},
            "capacity": {"host": {}},
        }
    raw = dict(evidence)
    if raw.get("schema_version") != SCHEMA_VERSION:
        reasons.append("remote_resource_evidence_schema_unsupported")

    try:
        observed_now = _now(now_utc)
    except ValueError:
        observed_now = dt.datetime.now(tz=dt.timezone.utc)
        reasons.append("remote_resource_now_invalid")
    observed = _parse_timestamp(raw.get("observed_at_utc"))
    ttl = _number(raw.get("ttl_seconds"))
    if observed is None:
        reasons.append("remote_resource_evidence_observed_at_invalid")
    if ttl is None or ttl <= 0 or ttl > MAX_TTL_SECONDS:
        reasons.append("remote_resource_evidence_ttl_invalid")
    if observed is not None and ttl is not None and 0 < ttl <= MAX_TTL_SECONDS:
        age = (observed_now - observed).total_seconds()
        if age > ttl:
            reasons.append("remote_resource_evidence_stale")
        if age < -max(0.0, float(max_clock_skew_seconds)):
            reasons.append("remote_resource_evidence_future")

    expected_host = _expected_host(packet, request)
    host_id = raw.get("host_id")
    if not isinstance(host_id, str) or not host_id.strip():
        reasons.append("remote_resource_host_unknown")
        host_id = None
    elif expected_host and host_id != expected_host:
        reasons.append("remote_resource_host_mismatch")
    elif not expected_host:
        reasons.append("remote_resource_expected_host_unknown")

    cgroup = raw.get("cgroup")
    cgroup_summary: dict[str, Any] = {}
    available_bytes: int | None = None
    if not isinstance(cgroup, Mapping):
        reasons.append("remote_cgroup_evidence_incomplete")
    else:
        cgroup_status = cgroup.get("status")
        maximum = _number(cgroup.get("max_bytes"))
        current = _number(cgroup.get("current_bytes"))
        available = _number(cgroup.get("available_bytes"))
        if cgroup_status != "complete":
            reasons.append("remote_cgroup_evidence_incomplete")
        if maximum is None or maximum <= 0 or current is None or available is None:
            reasons.append("remote_cgroup_bounds_invalid")
        elif current > maximum or available != maximum - current:
            reasons.append("remote_cgroup_bounds_invalid")
        else:
            available_bytes = int(available)
            cgroup_summary = {
                "status": "complete",
                "max_bytes": int(maximum),
                "current_bytes": int(current),
                "available_bytes": int(available),
            }

    psi = raw.get("psi")
    psi_avg = None
    if not isinstance(psi, Mapping):
        reasons.append("remote_psi_evidence_missing")
    else:
        psi_avg = _number(psi.get("some_avg10"))
        if psi_avg is None or psi_avg > 100:
            reasons.append("remote_psi_invalid")

    workspace_expected = _expected_workspace(packet)
    workspace, workspace_error = _safe_path(workspace_expected, "remote_workspace") if workspace_expected else (None, "remote_workspace_missing")
    if workspace_error:
        reasons.append(workspace_error)
    storage = raw.get("storage")
    storage_summary: dict[str, Any] = {}
    free_bytes: int | None = None
    if not isinstance(storage, Mapping):
        reasons.append("remote_storage_evidence_missing")
    else:
        # A project may legitimately live on the root filesystem (for
        # example ``/root/project``).  The workspace itself must remain a
        # concrete non-root path, but the containing mount can be ``/``.
        mount_path, mount_error = _safe_path(
            storage.get("mount_path"), "remote_mount_path", allow_root=True
        )
        storage_workspace, storage_workspace_error = _safe_path(storage.get("workspace_path"), "remote_storage_workspace_path")
        writable = storage.get("writable")
        total = _number(storage.get("total_bytes"))
        free = _number(storage.get("free_bytes"))
        if mount_error:
            reasons.append(mount_error)
        if storage_workspace_error:
            reasons.append(storage_workspace_error)
        if workspace and storage_workspace and storage_workspace != workspace:
            reasons.append("remote_workspace_evidence_mismatch")
        if storage_workspace and mount_path and not _inside(storage_workspace, mount_path):
            reasons.append("remote_mount_not_parent")
        if writable is not True:
            reasons.append("remote_writable_path_not_writable")
        if total is None or total <= 0 or free is None or free < 0 or free > total:
            reasons.append("remote_storage_capacity_invalid")
        else:
            free_bytes = int(free)
            storage_summary = {
                "mount_path": mount_path,
                "workspace_path": storage_workspace,
                "writable": True,
                "total_bytes": int(total),
                "free_bytes": int(free),
            }

    expected_scope_path, scope_error = _expected_write_scope_path(packet, workspace) if workspace else (None, "remote_write_scope_missing")
    if scope_error:
        reasons.append(scope_error)
    supplied_scope_path, supplied_scope_error = _safe_path(raw.get("write_scope_path"), "remote_write_scope_path")
    if supplied_scope_error:
        reasons.append(supplied_scope_error)
    elif expected_scope_path and supplied_scope_path != expected_scope_path:
        reasons.append("remote_write_scope_mismatch")
    elif supplied_scope_path and workspace and not _inside(supplied_scope_path, workspace):
        reasons.append("remote_write_scope_path_escape")

    route = raw.get("route")
    route_summary: dict[str, Any] = {}
    if not isinstance(route, Mapping):
        reasons.append("remote_route_evidence_missing")
    else:
        kind = route.get("kind")
        status = route.get("status")
        verified = route.get("verified")
        target = route.get("target_host_id")
        if kind not in _ROUTE_KINDS or status not in _ROUTE_STATUSES:
            reasons.append("remote_route_invalid")
        if verified is not True:
            reasons.append("remote_route_unverified")
        if expected_host and target != expected_host:
            reasons.append("remote_route_target_mismatch")
        route_summary = {
            "kind": kind,
            "status": status,
            "verified": verified is True,
            "target_host_id": target,
        }

    capacity = raw.get("capacity")
    capacity_summary: dict[str, float] = {}
    if not isinstance(capacity, Mapping):
        reasons.append("remote_capacity_evidence_missing")
    else:
        for field in _CAPACITY_FIELDS:
            value = capacity.get(field)
            if field == "vram_gib_per_gpu" and value is None:
                value = capacity.get("vram_gib")
            parsed = _number(value)
            if parsed is None:
                reasons.append(f"remote_capacity_{field}_invalid")
            else:
                capacity_summary[field] = parsed
        if available_bytes is not None and "ram_gib" in capacity_summary:
            if capacity_summary["ram_gib"] > available_bytes / GIB + 1e-9:
                reasons.append("remote_ram_capacity_exceeds_cgroup_available")
        if free_bytes is not None and "new_disk_gib" in capacity_summary:
            if capacity_summary["new_disk_gib"] > free_bytes / GIB + 1e-9:
                reasons.append("remote_disk_capacity_exceeds_mount_free")

    # The request itself is checked against the observed capacity before it
    # reaches SQLite.  SQLite repeats the aggregate check against reservations.
    aliases = {"vram_gib": "vram_gib_per_gpu", "disk_gib": "new_disk_gib"}
    for raw_field, value in request.items():
        field = aliases.get(str(raw_field), str(raw_field))
        if field not in _CAPACITY_FIELDS or value is None or field not in capacity_summary:
            continue
        requested = _number(value)
        if requested is None:
            reasons.append(f"remote_request_{field}_invalid")
        elif requested > capacity_summary[field] + 1e-9:
            reasons.append(f"remote_request_{field}_exceeds_evidence")

    summary = {
        "schema_version": SCHEMA_VERSION,
        "host_id": host_id,
        "observed_at_utc": raw.get("observed_at_utc"),
        "ttl_seconds": ttl,
        "cgroup": cgroup_summary,
        "psi": {"some_avg10": psi_avg} if psi_avg is not None else {},
        "storage": storage_summary,
        "route": route_summary,
        "write_scope_path": supplied_scope_path,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "valid": not reasons,
        "decision": "admit" if not reasons else "block",
        "reason": "remote_resource_evidence_valid" if not reasons else reasons[0],
        "reasons": list(dict.fromkeys(reasons)),
        "host_id": host_id,
        "observed_at_utc": raw.get("observed_at_utc"),
        "expires_at_utc": (
            (observed + dt.timedelta(seconds=float(ttl))).isoformat()
            if observed is not None and ttl is not None and 0 < ttl <= MAX_TTL_SECONDS
            else None
        ),
        "summary": summary,
        "capacity": {"host": capacity_summary},
        "evidence_digest": _digest(summary),
    }


__all__ = ["SCHEMA_VERSION", "validate_remote_resource_evidence"]
