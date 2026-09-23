#!/usr/bin/env python3
"""Build one no-prompt preflight snapshot for dynamic local-agent dispatch."""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import os
import pathlib
import re
import subprocess
import sys
from collections.abc import Mapping
from typing import Any


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
DEFAULT_ROOT = pathlib.Path(
    os.environ.get(
        "LOCAL_AGENT_DISPATCH_HOME",
        str(pathlib.Path.home() / ".codex" / "local-agent-dispatch"),
    )
)
CURSOR_POLICY_EXCLUDED_PREFIXES = ("gpt-5.6-sol-", "gpt-5.6-terra-")
OPENCODE_POLICY_EXCLUDED_PREFIXES = (
    # Preserve the user's existing dispatch boundary: DeepSeek is not a
    # default worker even when it appears inside the OpenCode Go catalog.
    "opencode-go/deepseek-",
)
RUNTIME_EVIDENCE_TTL = dt.timedelta(minutes=30)
OFFICIAL_OPENCODE_GO_USAGE_ENDPOINT = "https://opencode.ai/zen/go/v1/usage"
ANTIGRAVITY_PROVIDER_IDS = frozenset({"antigravity", "antigravity-cli"})
_LOCATION_REJECTION_RE = re.compile(
    r"(?:failed[_\s-]*precondition\s*:?\s*)?"
    r"(?:user\s+)?location\s+is\s+not\s+supported|"
    r"(?:unsupported|unavailable)\s+(?:country|region|location)|"
    r"(?:country|region|location)\s+(?:is\s+)?not\s+supported|"
    r"location\s+restriction|"
    r"not\s+available\s+in\s+(?:your\s+)?location|"
    r"geographic(?:al)?\s+(?:restriction|block)",
    re.IGNORECASE,
)
_RUNTIME_ERROR_TEXT_FIELDS = (
    "error_message",
    "runtime_reason",
    "reason",
    "error",
    "message",
    "detail",
    "output",
    "last_failure",
)
_CURSOR_GROK_MODEL_RE = re.compile(
    r"^cursor-grok-(?P<version>\d+(?:\.\d+)*)"
    r"(?:-(?P<effort>none|minimal|low|medium|high|xhigh|max))?"
    r"(?P<fast>-fast)?$",
    re.IGNORECASE,
)
_CURSOR_COMPOSER_MODEL_RE = re.compile(
    r"^composer-(?P<version>\d+(?:\.\d+)*)(?P<fast>-fast)?$",
    re.IGNORECASE,
)
_CURSOR_EFFORT_RANK = {
    "none": 0,
    "minimal": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "xhigh": 5,
    "max": 6,
}
_CURSOR_KEYCHAIN_LOCKED_RE = re.compile(
    r"(?:login\s+)?keychain[^\n]{0,160}(?:is\s+)?locked|"
    r"user\s+interaction\s+is\s+not\s+allowed",
    re.IGNORECASE,
)


def now() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).isoformat()


def read_json(path: pathlib.Path, default: Any = None) -> Any:
    try:
        return json.loads(path.expanduser().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def atomic_write(path: pathlib.Path, payload: Any) -> None:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def run(argv: list[str], timeout: float, cwd: pathlib.Path) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            argv, cwd=str(cwd), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False,
        )
        return {
            "ok": completed.returncode == 0, "returncode": completed.returncode,
            "stdout": completed.stdout, "stderr": completed.stderr,
        }
    except subprocess.TimeoutExpired as exc:
        def partial_text(value: Any) -> str:
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")[-2000:]
            return str(value or "")[-2000:]

        partial_stderr = partial_text(exc.stderr)
        return {
            "ok": False,
            "timed_out": True,
            "returncode": 124,
            "stdout": partial_text(exc.stdout),
            "stderr": partial_stderr or "timeout",
        }
    except OSError as exc:
        return {"ok": False, "returncode": 127, "stdout": "", "stderr": str(exc)}


def skipped_result(reason: str) -> dict[str, Any]:
    return {
        "ok": False,
        "skipped": True,
        "returncode": None,
        "stdout": "",
        "stderr": reason,
    }


def as_json(result: dict[str, Any]) -> dict[str, Any]:
    try:
        payload = json.loads(result.get("stdout") or "")
        return payload if isinstance(payload, dict) else {"ok": False, "error": "JSON root is not an object"}
    except ValueError:
        return {
            "ok": False, "error": (result.get("stderr") or result.get("stdout") or "invalid JSON")[-1200:],
            "returncode": result.get("returncode"),
        }


def cursor_models(text: str) -> list[str]:
    models = []
    for line in text.splitlines():
        if " - " not in line:
            continue
        slug = line.split(" - ", 1)[0].strip()
        if slug and " " not in slug and slug != "auto":
            models.append(slug)
    return sorted(set(models))


def _cursor_version(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def cursor_model_family(model: str) -> str | None:
    """Classify an exact Cursor catalog slug with the ranking regexes.

    Keeping catalog partitioning and ranking on the same matcher prevents a
    case-only spelling difference from placing one exact slug in two pools.
    The original catalog spelling is still preserved for dispatch.
    """

    if _CURSOR_COMPOSER_MODEL_RE.fullmatch(model):
        return "composer"
    if _CURSOR_GROK_MODEL_RE.fullmatch(model):
        return "grok"
    return None


def rank_cursor_models(
    catalog: list[str], family: str, role: str, blocked: set[str] | None = None
) -> list[str]:
    """Rank only exact, live Cursor model IDs for a scheduling role.

    Catalog discovery remains authoritative: this function never constructs a
    model ID or revives a blocked one.  Version is ranked before presentation
    variants so a stale hard-coded preference cannot pin dispatch to an older
    model family when Cursor adds a newer exact slug.
    """

    blocked_models = blocked or set()
    pattern = {
        "composer": _CURSOR_COMPOSER_MODEL_RE,
        "grok": _CURSOR_GROK_MODEL_RE,
    }.get(family)
    if pattern is None:
        raise ValueError(f"unsupported Cursor model family: {family}")

    ranked: list[tuple[tuple[Any, ...], str]] = []
    for model in sorted(set(catalog) - blocked_models):
        match = pattern.fullmatch(model)
        if match is None:
            continue
        version = _cursor_version(match.group("version"))
        is_fast = bool(match.groupdict().get("fast"))
        if family == "grok":
            effort = _CURSOR_EFFORT_RANK.get(
                str(match.groupdict().get("effort") or "none").lower(), 0
            )
            if role == "hard":
                rank = (version, effort, not is_fast, model)
            else:
                rank = (version, is_fast, effort, model)
        else:
            # Composer has no explicit effort suffix.  Fast is preferred for
            # efficient/code work; the regular variant is the stronger
            # conservative fallback for hard work when no Grok model exists.
            rank = (version, (not is_fast) if role == "hard" else is_fast, model)
        ranked.append((rank, model))
    return [model for _, model in sorted(ranked, reverse=True)]


def cursor_auth_failure_class(*results: Mapping[str, Any]) -> str | None:
    """Return a privacy-safe class for a known Cursor auth-context failure."""

    text = " ".join(
        str(result.get(field) or "")[:2000]
        for result in results
        for field in ("stderr", "stdout", "error")
    )
    if _CURSOR_KEYCHAIN_LOCKED_RE.search(text):
        return "keychain_locked"
    if re.search(r"not\s+(?:logged|signed)\s+in|unauthenticated", text, re.IGNORECASE):
        return "unauthenticated"
    return None


def annotate_cursor_status(
    status: Mapping[str, Any], *probe_results: Mapping[str, Any]
) -> dict[str, Any]:
    """Attach actionable auth state without persisting raw auth diagnostics."""

    annotated = dict(status)
    if annotated.get("isAuthenticated") is True:
        annotated["auth_state"] = "authenticated"
        return annotated
    failure_class = cursor_auth_failure_class(*probe_results)
    if failure_class == "keychain_locked":
        annotated.pop("error", None)
        annotated.update(
            auth_state="unavailable",
            auth_error_class="keychain_locked",
            auth_error=(
                "macOS login keychain is locked for this execution context; "
                "unlock it on the execution host or run from a logged-in local session"
            ),
        )
    elif failure_class == "unauthenticated":
        annotated.pop("error", None)
        annotated.update(
            auth_state="unauthenticated",
            auth_error_class="unauthenticated",
            auth_error="Cursor Agent is not signed in for this execution context",
        )
    elif annotated.get("skipped"):
        annotated["auth_state"] = "unavailable"
    else:
        annotated["auth_state"] = "unknown"
    return annotated


def antigravity_models(text: str) -> list[str]:
    models = set()
    for line in text.splitlines():
        fields = line.strip().split(None, 1)
        if not fields:
            continue
        slug = fields[0]
        if "-" in slug and all(char.isalnum() or char in "-._" for char in slug):
            models.add(slug)
    return sorted(models)


def runtime_model_rejection_class(
    provider: Any, model_id: Any, row: dict[str, Any]
) -> str | None:
    """Classify a location-gated Antigravity Gemini model rejection.

    The provider and model checks are intentional: a generic
    ``FAILED_PRECONDITION`` is not enough to reject a model, and a location
    error from another provider must not change its normal quota/catalog path.
    The text fallback is bounded to explicit error fields so arbitrary runtime
    state (including credentials accidentally stored elsewhere) is not parsed.
    """
    provider_id = str(provider or "").strip().lower()
    model = str(model_id or "").strip().lower()
    if provider_id not in ANTIGRAVITY_PROVIDER_IDS or not model.startswith("gemini-"):
        return None
    if str(row.get("error_class") or "").strip().lower() == "location_restricted":
        return "location_restricted"
    text = " ".join(
        value[:2000]
        for key in _RUNTIME_ERROR_TEXT_FIELDS
        if isinstance(value := row.get(key), str)
    )
    return "location_restricted" if _LOCATION_REJECTION_RE.search(text) else None


def runtime_rejection_rows(runtime_state: Any) -> list[dict[str, Any]]:
    """Extract exact runtime model/variant rejections for preflight pools."""
    if not isinstance(runtime_state, dict):
        return []
    models = runtime_state.get("models") or {}
    if not isinstance(models, dict):
        return []
    blocked: list[dict[str, Any]] = []
    for provider, provider_rows in models.items():
        if not isinstance(provider_rows, dict):
            continue
        for model_id, row in provider_rows.items():
            if not isinstance(row, dict):
                continue
            if row.get("runtime_state") == "rejected":
                rejection_class = runtime_model_rejection_class(provider, model_id, row)
                if row.get("error_class") == "capability" or rejection_class == "location_restricted":
                    item = {"provider": provider, "model": model_id, **row}
                    if rejection_class is not None:
                        item["error_class"] = rejection_class
                    blocked.append(item)
            variants = row.get("variants") or {}
            if not isinstance(variants, dict):
                continue
            for variant, variant_row in variants.items():
                if not isinstance(variant_row, dict):
                    continue
                if variant_row.get("runtime_state") != "rejected":
                    continue
                rejection_class = runtime_model_rejection_class(provider, model_id, variant_row)
                if variant_row.get("error_class") != "capability" and rejection_class != "location_restricted":
                    continue
                item = {
                    "provider": provider,
                    "model": model_id,
                    "variant": str(variant),
                    **variant_row,
                }
                if rejection_class is not None:
                    item["error_class"] = rejection_class
                blocked.append(item)
    return blocked


def opencode_go_models(snapshot: dict[str, Any]) -> list[str]:
    catalog = snapshot.get("catalog") or {}
    return sorted(
        {
            str(row.get("model_id"))
            for row in (catalog.get("models") or [])
            if isinstance(row, dict) and str(row.get("model_id") or "").startswith("opencode-go/")
        }
    )


def local_system_host(snapshot: dict[str, Any], workspace: pathlib.Path) -> dict[str, Any] | None:
    """Translate the first-stage local scan into planner host fields."""
    if not snapshot.get("ok"):
        return None
    cpu = snapshot.get("cpu") or {}
    ram = snapshot.get("ram") or {}
    workspace_disk = ((snapshot.get("disks") or {}).get("workspace") or {})
    accelerators = snapshot.get("accelerators") or []
    clis = snapshot.get("clis") or {}
    commands = {
        str(name): str(row.get("executable") or name)
        for name, row in clis.items()
        if isinstance(row, dict) and row.get("present")
    }
    # Python is part of the hardware/runtime snapshot even though it is not an
    # agent CLI.  Expose it to planner command gates so a local Python task is
    # not rejected merely because the CLI inventory intentionally omits it.
    python_executable = (snapshot.get("python") or {}).get("executable")
    if python_executable:
        commands.setdefault("python3", str(python_executable))
    gpus: list[dict[str, Any]] = []
    for index, row in enumerate(accelerators):
        if not isinstance(row, dict) or row.get("type") != "gpu":
            continue
        gpu = dict(row)
        gpu.setdefault("index", index)
        if gpu.get("memory_total_bytes") is not None:
            gpu["vram_total_gib"] = round(float(gpu["memory_total_bytes"]) / (1024**3), 3)
        if gpu.get("memory_free_bytes") is not None:
            gpu["vram_free_gib"] = round(float(gpu["memory_free_bytes"]) / (1024**3), 3)
        gpus.append(gpu)
    process_snapshot = snapshot.get("agent_model_processes") or {}
    agent_rss_bytes = process_snapshot.get("rss_bytes_total")
    total_bytes = workspace_disk.get("total_bytes")
    free_bytes = workspace_disk.get("free_bytes")
    logical = int(cpu.get("logical_cores") or 1)
    load_1m = cpu.get("load_1m")
    try:
        load_1m = float(load_1m) if load_1m is not None else None
    except (TypeError, ValueError):
        load_1m = None
    # Load average is expressed in runnable-core equivalents.  Clamp the
    # result so a transient load spike cannot create negative capacity.  If
    # the platform cannot report load, leave capacity unknown and let the
    # planner's explicit unknown-resource gate decide whether a pilot is
    # allowed; never silently reuse a full-core estimate.
    if load_1m is not None:
        estimated_idle = max(0.0, float(logical) - load_1m)
        capacity_evidence = "live_load_average"
    elif "load_1m" not in cpu:
        # Pre-load-average snapshots are a versioned compatibility case.  The
        # current system-first workflow always refreshes the local snapshot,
        # but standalone hardware-fit consumers may still open an older file.
        # Preserve that file's historical behaviour while making the weaker
        # evidence explicit for callers and reports.
        estimated_idle = float(logical)
        capacity_evidence = "legacy_snapshot_without_load"
    else:
        estimated_idle = None
        capacity_evidence = "load_unknown"
    return {
        "host_id": "local_system",
        "transport": "local",
        "reachable": True,
        "project_path": str(workspace),
        "project_path_exists": bool(workspace_disk.get("exists")),
        "project_path_writable": bool(workspace_disk.get("writable")),
        "os": (snapshot.get("os") or {}).get("name"),
        "arch": snapshot.get("arch"),
        "logical_cpu_cores": logical,
        "physical_cpu_cores": cpu.get("physical_cores"),
        "estimated_idle_cpu_cores": estimated_idle,
        "load1": load_1m,
        "load_source": cpu.get("load_source"),
        "capacity_evidence": capacity_evidence,
        "memory_total_gib": ram.get("total_gib"),
        "memory_available_gib": ram.get("available_gib"),
        "memory_source": ram.get("source"),
        "memory_pressure_state": ram.get("pressure_state"),
        "pressure_free_percent": ram.get("pressure_free_percent"),
        "psi_some_avg10": ram.get("psi_some_avg10"),
        "cgroup_required": ram.get("cgroup_required"),
        "cgroup_memory_source": ram.get("cgroup_memory_source"),
        "cgroup_memory_evidence_status": ram.get("cgroup_memory_evidence_status"),
        "cgroup_memory_unbounded": ram.get("cgroup_memory_unbounded"),
        "cgroup_memory_max_bytes": ram.get("cgroup_memory_max_bytes"),
        "cgroup_memory_current_bytes": ram.get("cgroup_memory_current_bytes"),
        "cgroup_memory_available_bytes": ram.get("cgroup_memory_available_bytes"),
        "cgroup_memory_events_high": ram.get("cgroup_memory_events_high"),
        "cgroup_memory_events_oom": ram.get("cgroup_memory_events_oom"),
        "cgroup_memory_events_oom_kill": ram.get("cgroup_memory_events_oom_kill"),
        "swap_total_gib": (
            round(float(ram["swap_total_bytes"]) / (1024**3), 3)
            if ram.get("swap_total_bytes") is not None else None
        ),
        "swap_used_gib": (
            round(float(ram["swap_used_bytes"]) / (1024**3), 3)
            if ram.get("swap_used_bytes") is not None else None
        ),
        "swap_free_gib": (
            round(float(ram["swap_free_bytes"]) / (1024**3), 3)
            if ram.get("swap_free_bytes") is not None else None
        ),
        "local_agent_launch_allowed": (
            (snapshot.get("capacity_gates") or {}).get("local_agent_launch_allowed")
        ),
        "agent_process_count": len(process_snapshot.get("processes") or []),
        "agent_rss_gib": (
            round(float(agent_rss_bytes) / (1024**3), 3)
            if agent_rss_bytes is not None else None
        ),
        "disk_total_gib": round(float(total_bytes) / (1024**3), 3) if total_bytes is not None else None,
        "disk_free_gib": round(float(free_bytes) / (1024**3), 3) if free_bytes is not None else None,
        "best_storage_path": str(workspace),
        "best_writable_storage_path": str(workspace) if workspace_disk.get("writable") else None,
        "storage_paths": [
            {
                "path": str(workspace),
                "exists": workspace_disk.get("exists"),
                "writable": workspace_disk.get("writable"),
                "disk_total_gib": round(float(total_bytes) / (1024**3), 3) if total_bytes is not None else None,
                "disk_free_gib": round(float(free_bytes) / (1024**3), 3) if free_bytes is not None else None,
            }
        ],
        "gpu_count": len(gpus),
        "gpus": gpus,
        "commands": commands,
        "python": snapshot.get("python") or {},
        "tags": ["local", "apple"] if str(snapshot.get("os", {}).get("name")) == "Darwin" else ["local"],
        "resource_source": "local_system_scan",
    }


_INVENTORY_SNAPSHOT_FIELDS = frozenset(
    {
        "host_id",
        "transport",
        "hostname",
        "user",
        "port",
        "project_path",
        "role",
        "provider",
        "tags",
        "storage_paths",
        "storage_candidates",
        "discover_storage",
        "verify_racknerd_route",
        "verify_external_network",
    }
)


def load_inventory_compute_hosts(inventory_path: str | pathlib.Path) -> dict[str, dict[str, Any]]:
    """Load only non-secret host identity needed for an unavailable-host receipt."""

    if str(inventory_path) == "-":
        return {}
    payload = read_json(pathlib.Path(str(inventory_path)).expanduser(), {})
    if not isinstance(payload, dict):
        return {}
    raw_hosts = payload.get("hosts")
    if raw_hosts is None:
        raw_hosts = payload.get("compute_hosts")
    if raw_hosts is None:
        raw_hosts = payload.get("compute_hosts_list")
    if isinstance(raw_hosts, dict):
        entries = raw_hosts.items()
    elif isinstance(raw_hosts, list):
        entries = ((str(index), row) for index, row in enumerate(raw_hosts))
    else:
        return {}

    hosts: dict[str, dict[str, Any]] = {}
    for key, row in entries:
        if not isinstance(row, dict):
            continue
        host_id = str(row.get("host_id") or key).strip()
        if not host_id:
            continue
        snapshot = {
            field: row[field]
            for field in _INVENTORY_SNAPSHOT_FIELDS
            if field in row
        }
        snapshot["host_id"] = host_id
        snapshot.setdefault(
            "transport", "ssh" if snapshot.get("hostname") else "local"
        )
        snapshot.setdefault("project_path", ".")
        hosts[host_id] = snapshot
    return hosts


def compute_probe_failure_code(compute_result: Mapping[str, Any]) -> str:
    if compute_result.get("ok"):
        return "compute_probe_incomplete"
    error = str(compute_result.get("error") or "").lower()
    if any(
        marker in error
        for marker in (
            "user interaction is not allowed",
            "errsecinteractionnotallowed",
            "signing failed",
            "agent refused operation",
        )
    ) or ("keychain" in error and "locked" in error):
        return "compute_probe_auth_context_unavailable"
    if compute_result.get("returncode") == 124:
        return "compute_probe_timeout"
    if any(
        marker in error
        for marker in (
            "connection refused",
            "connection_refused",
            "connect refused",
        )
    ):
        return "compute_probe_connection_refused"
    if any(
        marker in error
        for marker in (
            "could not resolve",
            "name or service not known",
            "temporary failure in name resolution",
            "nodename nor servname",
            "unknown host",
        )
    ):
        return "compute_probe_dns_failure"
    if any(
        marker in error
        for marker in (
            "permission denied",
            "publickey",
            "authentication failed",
            "auth failed",
        )
    ):
        return "compute_probe_auth_failed"
    return "compute_probe_timeout" if "timeout" in error else "compute_probe_failed"


def unavailable_inventory_host(
    host: Mapping[str, Any], failure_code: str, observed_at: str
) -> dict[str, Any]:
    result = dict(host)
    declared_storage = result.get("storage_paths") or result.get("storage_candidates") or []
    failure_messages = {
        "compute_probe_timeout": "compute probe timed out before a per-host result was returned",
        "compute_probe_connection_refused": "compute probe connection was refused before a per-host result was returned",
        "compute_probe_dns_failure": "compute probe DNS resolution failed before a per-host result was returned",
        "compute_probe_auth_failed": "compute probe authentication failed before a per-host result was returned",
        "compute_probe_auth_context_unavailable": (
            "compute probe could not use the local keychain or SSH signing agent "
            "in this execution context"
        ),
    }
    result.update(
        reachable=False,
        project_path_exists=None,
        project_path_writable=None,
        probe_result_available=False,
        probe_failure_code=failure_code,
        probe_error=failure_messages.get(
            failure_code, "compute probe did not return a per-host result"
        ),
        inventory_observed_at_utc=observed_at,
        resource_source="inventory_unreachable_fallback",
        gpus=[],
        commands={},
        disks=[],
        gpu_count=0,
        storage_paths=[],
        declared_storage_paths=declared_storage,
    )
    return result


def merge_inventory_compute_hosts(
    compute_hosts: Mapping[str, Any] | None,
    inventory_hosts: Mapping[str, Any],
    compute_result: Mapping[str, Any],
    observed_at: str,
) -> dict[str, dict[str, Any]]:
    """Keep inventory hosts visible when the outer probe loses per-host output."""

    hosts = {
        str(host_id): dict(row)
        for host_id, row in (compute_hosts or {}).items()
        if isinstance(row, Mapping)
    }
    failure_code = compute_probe_failure_code(compute_result)
    for host_id, row in (inventory_hosts or {}).items():
        normalized_id = str(host_id)
        if normalized_id not in hosts and isinstance(row, Mapping):
            hosts[normalized_id] = unavailable_inventory_host(
                row, failure_code, observed_at
            )
    return dict(sorted(hosts.items()))


def merge_local_system_compute_host(
    compute_hosts: dict[str, Any], snapshot: dict[str, Any], workspace: pathlib.Path
) -> dict[str, Any]:
    hosts = {str(key): dict(value or {}) for key, value in (compute_hosts or {}).items()}
    observed = local_system_host(snapshot, workspace)
    if observed is None:
        return hosts
    local_id = next(
        (host_id for host_id, row in hosts.items() if str(row.get("transport", "local")) == "local"),
        None,
    )
    if local_id is None:
        hosts[observed["host_id"]] = observed
        return hosts
    current = hosts[local_id]
    # Keep private inventory identity/tags while making live system facts
    # authoritative for resources and installed commands.  Unknown live
    # values deliberately overwrite old values: stale capacity is more
    # dangerous than an explicit unknown that triggers a pilot/fail-closed
    # planner gate.
    live_fields = {
        "transport", "reachable", "project_path", "project_path_exists", "project_path_writable",
        "os", "arch", "logical_cpu_cores", "physical_cpu_cores", "estimated_idle_cpu_cores",
        "load1", "load_source", "capacity_evidence", "memory_total_gib", "memory_available_gib", "memory_source",
        "memory_pressure_state", "pressure_free_percent", "psi_some_avg10",
        "cgroup_required", "cgroup_memory_source", "cgroup_memory_evidence_status",
        "cgroup_memory_unbounded",
        "cgroup_memory_max_bytes", "cgroup_memory_current_bytes", "cgroup_memory_available_bytes",
        "cgroup_memory_events_high", "cgroup_memory_events_oom", "cgroup_memory_events_oom_kill",
        "swap_total_gib", "swap_used_gib",
        "swap_free_gib", "local_agent_launch_allowed", "agent_process_count", "agent_rss_gib",
        "disk_total_gib",
        "disk_free_gib", "gpu_count", "gpus", "commands", "python", "resource_source",
        "best_storage_path", "best_writable_storage_path", "storage_paths",
    }
    for key in live_fields:
        if key in observed:
            current[key] = observed[key]
    for key in (
        "probe_result_available",
        "probe_failure_code",
        "probe_error",
        "inventory_observed_at_utc",
        "declared_storage_paths",
    ):
        current.pop(key, None)
    current["resource_source"] = "local_system_scan"
    return hosts


def parse_utc(value: Any) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def apply_runtime_overrides(
    pools: dict[str, dict[str, Any]], runtime_state: Any, checked_at: str
) -> list[dict[str, Any]]:
    """Overlay fresh invocation evidence without reviving live-blocked pools.

    Catalog/auth/runtime discovery in the current preflight is authoritative
    for a hard ``blocked`` result.  A previous successful invocation may not
    turn an absent model or missing login back into ``ready``.  Quota
    cooldowns remain valid while their explicit expiry is in the future;
    timestamped non-quota failures expire after a short evidence TTL.
    """
    if not isinstance(runtime_state, dict):
        return []
    checked = parse_utc(checked_at) or dt.datetime.now(tz=dt.timezone.utc)
    applied: list[dict[str, Any]] = []
    for pool_id, raw in (runtime_state.get("pools") or {}).items():
        if not isinstance(raw, dict) or pool_id not in pools:
            continue
        until = parse_utc(raw.get("cooldown_until_utc"))
        if until is not None and until <= checked:
            continue
        health = str(raw.get("health") or "")
        if not health:
            continue
        pool = pools[pool_id]
        live_health = str(pool.get("health") or "unknown")
        observed_times = [
            parsed
            for key in ("last_checked_at", "last_runtime_failure", "last_runtime_success")
            if (parsed := parse_utc(raw.get(key))) is not None
        ]
        observed_at = max(observed_times, default=None)
        fresh = bool(
            observed_at is not None
            and (observed_at >= checked or checked - observed_at <= RUNTIME_EVIDENCE_TTL)
        )
        future_cooldown = until is not None and until > checked

        # A live catalog/auth block has stronger evidence than any old
        # success, and should never be overwritten by a runtime snapshot.
        if live_health == "blocked":
            continue
        if health == "ready" and live_health != "ready":
            continue
        if not future_cooldown and not fresh:
            continue
        for key in (
            "health",
            "runtime_state",
            "runtime_reason",
            "last_runtime_success",
            "last_runtime_failure",
            "last_checked_at",
            "error_class",
            "cooldown_until_utc",
        ):
            if key in raw:
                pool[key] = raw[key]
        applied.append(
            {
                "pool_id": str(pool_id),
                "health": health,
                "runtime_reason": raw.get("runtime_reason"),
                "cooldown_until_utc": raw.get("cooldown_until_utc"),
            }
        )
    return applied


def pool_for_process(command: str) -> tuple[str | None, str | None]:
    lowered = command.lower()
    model_match = re.search(r"(?:--model|-m)\s+([^\s]+)", command)
    model = _safe_process_model(model_match.group(1)) if model_match else None
    if re.search(r"(?:^|/)codex\s+exec(?:\s|$)", lowered):
        if model and "gpt-5.3-codex-spark" in model:
            return "codex.spark", model
        if model and "gpt-5.6-luna" in model:
            return "codex.luna", model
        return None, model
    if re.search(r"(?:^|/)cursor-agent\s+", lowered) and re.search(
        r"(?:^|\s)(?:-p|--print)(?:\s|$)", command
    ):
        if model and cursor_model_family(model) in {"composer", "grok"}:
            return "cursor.composer_grok", model
        return "cursor.other", model
    if re.search(r"(?:^|/)antigravity\s+-p(?:\s|$)", lowered):
        if model and model.startswith("gemini-"):
            return "antigravity.gemini", model
        return "antigravity.claude_gpt", model
    if re.search(r"(?:^|/)opencode\s+run(?:\s|$)", lowered):
        if model and model.startswith("opencode-go/"):
            return "opencode.go", model
        return None, model
    return None, model


_PROCESS_MODEL_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+\-]{0,127}$")
_PROCESS_MODEL_PREFIXES = (
    "opencode-go/",
    "gpt-",
    "composer-",
    "cursor-grok-",
    "gemini-",
    "claude-",
    "deepseek-",
    "kimi-",
    "qwen",
    "mimo-",
    "minimax-",
    "glm-",
    "grok-",
)


def _safe_process_model(value: str) -> str | None:
    """Return only an allow-listed model slug from transient argv.

    Process command lines can contain prompts, paths, or credentials.  The
    dispatch classifier may inspect them in memory, but persisted occupancy
    evidence must never echo arbitrary ``--model`` values.  Provider/model
    slugs exposed by the supported CLIs have a bounded token grammar and one
    of the prefixes below; everything else is omitted while pool-level
    occupancy can still be counted.
    """

    candidate = str(value or "").strip()
    if not _PROCESS_MODEL_TOKEN.fullmatch(candidate):
        return None
    lowered = candidate.lower()
    if any(marker in lowered for marker in ("sk-", "token", "secret", "prompt", "bearer", "api_key")):
        return None
    if not lowered.startswith(_PROCESS_MODEL_PREFIXES):
        return None
    return candidate


def local_agent_process_snapshot(text: str, current_pid: int) -> dict[str, Any]:
    processes: list[dict[str, Any]] = []
    inflight: dict[str, int] = {}
    for raw in text.splitlines():
        fields = raw.strip().split(None, 2)
        if len(fields) != 3 or not fields[0].isdigit() or not fields[1].isdigit():
            continue
        pid, ppid, command = int(fields[0]), int(fields[1]), fields[2]
        if pid == current_pid:
            continue
        pool_id, model = pool_for_process(command)
        if not pool_id:
            continue
        # The full command is used in-memory only to classify the pool. Never
        # persist prompt-bearing argv in the public preflight snapshot.
        processes.append(
            {
                "pid": pid,
                "ppid": ppid,
                "pool_id": pool_id,
                "model": model,
                "command_name": pool_id.split(".", 1)[0],
                "arguments_collected": False,
            }
        )
        inflight[pool_id] = inflight.get(pool_id, 0) + 1
    return {
        "scan_ok": True,
        "processes": processes,
        "inflight_by_pool": inflight,
        # A point-in-time process scan supports a conservative non-exclusive
        # claim; explicit run ownership is still required for rate attribution.
        "exclusive_pool_observation": False,
        "attribution": "pool_level_or_externally_confounded",
    }


def aggregate_external_consumers(
    local_snapshot: dict[str, Any], compute_hosts: dict[str, Any]
) -> dict[str, Any]:
    """Merge local and SSH-host occupancy into one privacy-safe view.

    OpenCode Go is an account-level shared pool: a process on bjb2 or westd
    must reduce the same ``opencode.go`` capacity used by a local CLI.  Host
    records already contain only the sanitized PID/command/model rows emitted
    by ``compute_resource_probe``.  This helper preserves those rows under a
    host key, aggregates pool counts for the planner, and fails closed when a
    remote process scan was unavailable.
    """

    local = dict(local_snapshot or {})
    merged = {
        "scan_ok": bool(local.get("scan_ok")),
        "processes": list(local.get("processes") or []),
        "inflight_by_pool": {},
        "exclusive_pool_observation": False,
        "attribution": "pool_level_or_externally_confounded",
        "remote_hosts": {},
    }
    for pool_id, value in (local.get("inflight_by_pool") or {}).items():
        try:
            merged["inflight_by_pool"][str(pool_id)] = max(0, int(value))
        except (TypeError, ValueError):
            merged["scan_ok"] = False
            merged["unknown"] = True
    for host_id, row in (compute_hosts or {}).items():
        if not isinstance(row, dict):
            continue
        external = row.get("external_consumers")
        if not isinstance(external, dict):
            # Older/hand-authored host inventories have no process evidence;
            # do not claim they are clear.  Live compute probes always emit
            # this field, so this path is an explicit compatibility warning.
            if str(row.get("transport") or "") == "ssh":
                merged["scan_ok"] = False
                merged["unknown"] = True
            continue
        merged["remote_hosts"][str(host_id)] = external
        if external.get("scan_ok") is not True:
            merged["scan_ok"] = False
            merged["unknown"] = True
        for pool_id, value in (external.get("inflight_by_pool") or {}).items():
            try:
                count = max(0, int(value))
            except (TypeError, ValueError):
                merged["scan_ok"] = False
                merged["unknown"] = True
                continue
            merged["inflight_by_pool"][str(pool_id)] = (
                int(merged["inflight_by_pool"].get(str(pool_id), 0)) + count
            )
    if merged.get("unknown"):
        merged["attribution"] = "unknown_process_state_nonexclusive"
    return merged


def merge_model_state(
    path: pathlib.Path,
    catalog: list[str],
    checked_at: str,
    catalog_valid: bool = True,
    additional_catalogs: dict[str, tuple[list[str], bool]] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    state = read_json(path, {"models": {}})
    if not isinstance(state, dict):
        state = {"models": {}}
    models = state.setdefault("models", {})
    catalogs = {"cursor": (catalog, catalog_valid), **(additional_catalogs or {})}
    blocked: list[dict[str, Any]] = []
    for provider, (provider_catalog, provider_catalog_valid) in catalogs.items():
        provider_models = models.setdefault(provider, {})
        visible = set(provider_catalog)
        for model_id in visible:
            provider_models.setdefault(model_id, {})
        for model_id, row in list(provider_models.items()):
            if not isinstance(row, dict):
                row = {}
                provider_models[model_id] = row
            if provider_catalog_valid:
                row["catalog_state"] = "visible" if model_id in visible else "absent"
                row.pop("catalog_error", None)
            else:
                row["catalog_error"] = "catalog scan failed or returned no model IDs"
            row["catalog_checked_at"] = checked_at
            if row.get("runtime_state") == "rejected":
                blocked.append({"provider": provider, "model": model_id, **row})
            for variant, variant_row in (row.get("variants") or {}).items():
                if isinstance(variant_row, dict) and variant_row.get("runtime_state") == "rejected":
                    blocked.append(
                        {
                            "provider": provider,
                            "model": model_id,
                            "variant": str(variant),
                            **variant_row,
                        }
                    )
    state["updated_at_utc"] = checked_at
    atomic_write(path, state)
    return state, blocked


def first_visible(catalog: list[str], preferences: list[str], blocked: set[str]) -> str | None:
    visible = set(catalog) - blocked
    for model in preferences:
        if model in visible:
            return model
    return next(iter(sorted(visible)), None)


def server_local_smoke_match(
    smoke: dict[str, Any], host_id: str, ready_api: dict[str, Any] | None,
    checked_at: str | None = None,
) -> tuple[bool, str | None]:
    """Check that a passed coding smoke belongs to the live local runtime.

    A status-only smoke record is not enough to establish that the current
    API is the one that was exercised.  Identity fields are optional for
    compatibility, but a freshness timestamp is mandatory: an old smoke can
    otherwise keep a rebuilt or broken runtime falsely marked ready.
    """
    if not ready_api:
        return False, "no healthy loopback local-model API with a loaded model"
    if str(smoke.get("status") or "") != "passed":
        return False, "agentic coding smoke has not passed"
    observed_at = parse_utc(
        smoke.get("completed_at_utc")
        or smoke.get("observed_at_utc")
        or smoke.get("updated_at_utc")
    )
    checked = parse_utc(checked_at) or dt.datetime.now(tz=dt.timezone.utc)
    if observed_at is None:
        return False, "agentic smoke freshness timestamp is missing"
    if observed_at < checked - RUNTIME_EVIDENCE_TTL:
        return False, "agentic smoke evidence is stale"

    observed_host = smoke.get("host_id")
    if observed_host not in (None, "") and str(observed_host) != str(host_id):
        return False, "agentic smoke host_id does not match live host"

    observed_model = smoke.get("model")
    live_models = {
        str(model)
        for model in (ready_api.get("models") or [])
        if model not in (None, "")
    }
    if observed_model not in (None, "") and str(observed_model) not in live_models:
        return False, "agentic smoke model does not match live API model"

    observed_endpoint = smoke.get("endpoint") or smoke.get("base_url")
    live_endpoint = ready_api.get("base_url")
    if observed_endpoint not in (None, ""):
        if live_endpoint in (None, ""):
            return False, "agentic smoke endpoint cannot be verified against live API"
        if str(observed_endpoint).rstrip("/") != str(live_endpoint).rstrip("/"):
            return False, "agentic smoke endpoint does not match live API endpoint"
    return True, None


def build_pools(
    codex_usage: dict[str, Any], cursor_status: dict[str, Any], cursor_catalog: list[str],
    antigravity_usage: dict[str, Any], antigravity_catalog: list[str],
    opencode_go: dict[str, Any], local_models: dict[str, Any],
    blocked_rows: list[dict[str, Any]],
    external_inflight: dict[str, int] | None = None,
    checked_at: str | None = None,
    opencode_go_quota: dict[str, Any] | None = None,
    codex_capabilities: Mapping[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    observed_inflight = external_inflight or {}
    pools: dict[str, dict[str, Any]] = {}
    for pool_id, defaults in {
        "codex.luna": {"model": "gpt-5.6-luna/max", "reserve_percent": 20},
        "codex.spark": {"model": "gpt-5.3-codex-spark/xhigh", "reserve_percent": 10},
    }.items():
        live = dict((codex_usage.get("pools") or {}).get(pool_id) or {})
        live.update(defaults, max_concurrency=1, inflight=int(observed_inflight.get(pool_id, 0)))
        # Rate-limit snapshots identify the pool but do not always carry the
        # scheduler's exact model/effort pair.  Preserve the preflight default
        # explicitly so readiness and downstream fit reports do not drop a
        # healthy Luna (or a blocked-but-known Spark) pool on a null field.
        if not live.get("default_model"):
            live["default_model"] = defaults["model"]
        live.setdefault("health", "unknown")
        if codex_usage.get("skipped"):
            live["health"] = "blocked"
            live["blocked_reason"] = "Codex CLI was not observed by the local system scan"
        codex_model, _, codex_variant = str(defaults["model"]).partition("/")
        codex_rejected = any(
            str(row.get("provider") or "") in {"codex", "codex-cli"}
            and str(row.get("model") or "") == codex_model
            and (not row.get("variant") or str(row.get("variant")) == codex_variant)
            for row in blocked_rows
        )
        live["rejected_models"] = [codex_model] if codex_rejected else []
        live["rejected_model_variants"] = {codex_model: [codex_variant]} if codex_rejected else {}
        if codex_rejected:
            live["health"] = "blocked"
            live["effective_remaining_percent"] = 0
            live["blocked_reason"] = "exact Codex model/effort rejected by runtime"
        capability_rows = (codex_capabilities or {}).get(pool_id)
        if capability_rows is not None:
            if isinstance(capability_rows, Mapping):
                capability_rows = [capability_rows]
            elif not isinstance(capability_rows, list):
                capability_rows = []
            exact_models: set[str] = set()
            exact_variants: dict[str, set[str]] = {}
            for capability in capability_rows:
                if not isinstance(capability, Mapping) or capability.get("ok") is not True:
                    continue
                capability_model = str(capability.get("model") or "")
                capability_effort = str(capability.get("effort") or "")
                if not capability_model or not capability_effort:
                    continue
                exact_models.add(capability_model)
                exact_variants.setdefault(capability_model, set()).add(capability_effort)
            # Codex model-cache capability is separate from account quota. It
            # must still be present before an exact model route is schedulable.
            live["catalog_models"] = sorted(exact_models)
            live["available_model_variants"] = {
                model: sorted(variants)
                for model, variants in sorted(exact_variants.items())
            }
            live["capability_state"] = "ready" if exact_models else "blocked"
            if not exact_models:
                live["health"] = "blocked"
                live["blocked_reason"] = "exact Codex model/effort preflight did not pass"
        pools[pool_id] = live

    blocked = {
        str(row.get("model"))
        for row in blocked_rows
        if str(row.get("provider") or "") == "cursor"
    }
    authenticated = bool(cursor_status.get("isAuthenticated"))
    composer_by_role = {
        role: rank_cursor_models(cursor_catalog, "composer", role, blocked)
        for role in ("efficient", "code", "hard")
    }
    grok_by_role = {
        role: rank_cursor_models(cursor_catalog, "grok", role, blocked)
        for role in ("efficient", "code", "hard")
    }
    cursor_role_candidates = {
        "efficient": list(
            dict.fromkeys(composer_by_role["efficient"] + grok_by_role["efficient"])
        ),
        "code": list(dict.fromkeys(composer_by_role["code"] + grok_by_role["code"])),
        "hard": list(dict.fromkeys(grok_by_role["hard"] + composer_by_role["hard"])),
    }
    cursor_role_models = {
        role: candidates[0]
        for role, candidates in cursor_role_candidates.items()
        if candidates
    }
    cursor_default = cursor_role_models.get("code") or cursor_role_models.get("hard")
    cursor_auth_state = str(
        cursor_status.get("auth_state")
        or ("authenticated" if authenticated else "unknown")
    )

    def cursor_blocked_reason(has_candidate: bool) -> str | None:
        if not authenticated:
            if cursor_status.get("auth_error_class") == "keychain_locked":
                return (
                    "Cursor authentication is unavailable because the macOS login "
                    "keychain is locked for this execution context"
                )
            if cursor_auth_state == "unauthenticated":
                return "Cursor Agent is not signed in for this execution context"
            return "Cursor Agent authentication is not verified"
        if not has_candidate:
            return "no policy-eligible exact model in the fresh Cursor catalog"
        return None

    composer_grok_catalog = [
        model for model in cursor_catalog
        if cursor_model_family(model) in {"composer", "grok"}
    ]
    policy_excluded = [
        model for model in cursor_catalog
        if model.lower().startswith(CURSOR_POLICY_EXCLUDED_PREFIXES)
    ]
    other_catalog = [
        model for model in cursor_catalog
        if cursor_model_family(model) is None
        and not model.lower().startswith(CURSOR_POLICY_EXCLUDED_PREFIXES)
    ]
    other = first_visible(
        other_catalog,
        ["gpt-5.3-codex", "gpt-5.3-codex-fast", "gpt-5.3-codex-low-fast", "gemini-3.6-flash-high"],
        blocked,
    )
    pools["cursor.composer_grok"] = {
        "provider": "cursor", "health": "ready" if authenticated and cursor_default else "blocked",
        "auth_state": cursor_auth_state,
        "auth_error_class": cursor_status.get("auth_error_class"),
        "effective_remaining_percent": None, "default_model": cursor_default,
        "catalog_models": composer_grok_catalog,
        "rejected_models": sorted(blocked),
        "role_models": cursor_role_models,
        "role_model_candidates": cursor_role_candidates,
        # Cursor exposes catalog/auth but no attributable numeric quota.  A
        # bounded pilot is therefore explicit evidence, not a planner default.
        "unknown_quota_policy": "pilot", "unknown_quota_pilot_percent": 5.0,
        "reserve_percent": 10, "max_concurrency": 1,
        "inflight": int(observed_inflight.get("cursor.composer_grok", 0)),
        "blocked_reason": cursor_blocked_reason(bool(cursor_default)),
    }
    pools["cursor.other"] = {
        "provider": "cursor", "health": "ready" if authenticated and other else "blocked",
        "auth_state": cursor_auth_state,
        "auth_error_class": cursor_status.get("auth_error_class"),
        "effective_remaining_percent": None, "default_model": other,
        "catalog_models": other_catalog, "rejected_models": sorted(blocked),
        "policy_excluded_models": sorted(policy_excluded),
        "role_models": {role: other for role in ("efficient", "code", "hard") if other},
        "role_model_candidates": {role: [other] for role in ("efficient", "code", "hard") if other},
        "unknown_quota_policy": "pilot", "unknown_quota_pilot_percent": 5.0,
        "reserve_percent": 10, "max_concurrency": 1,
        "inflight": int(observed_inflight.get("cursor.other", 0)),
        "blocked_reason": cursor_blocked_reason(bool(other)),
    }

    ag_live = antigravity_usage.get("pools") or {}
    for pool_id, preferences in {
        "antigravity.gemini": ["gemini-3.6-flash-high", "gemini-3.1-pro-high"],
        "antigravity.claude_gpt": ["claude-sonnet-4-6", "gpt-oss-120b-medium", "claude-opus-4-6-thinking"],
    }.items():
        live = dict(ag_live.get(pool_id) or {})
        ag_rejected: set[str] = set()
        ag_rejected_variants: dict[str, set[str]] = {}
        for row in blocked_rows:
            if str(row.get("provider") or "") not in {"antigravity", "antigravity-cli"}:
                continue
            model_id = str(row.get("model") or "")
            variant = str(row.get("variant") or "")
            # Antigravity sometimes serializes a model slug's effort suffix as
            # a synthetic variant row (for example model
            # ``gemini-3.1-pro-high`` with variant ``high``).  The planner
            # route for that exact slug carries variant=null because the
            # effort is already encoded in the model ID.  Keep the rejection
            # model-scoped in that case; otherwise a location/capability
            # failure would be mistaken for a healthy catalog candidate.
            if model_id and (
                not variant
                or model_id.lower().endswith("-" + variant.lower())
            ):
                ag_rejected.add(model_id)
            if model_id and variant:
                ag_rejected_variants.setdefault(model_id, set()).add(variant)
        candidate_catalog = [
            item for item in preferences
            if item in antigravity_catalog and item not in ag_rejected
        ]
        effective = live.get("effective_percent_displayed")
        live.update(
            provider="antigravity", default_model=candidate_catalog[0] if candidate_catalog else None,
            # Keep the current, rejection-filtered catalog under the same
            # field consumed by the planner and public dispatch report.
            catalog_models=sorted(candidate_catalog),
            effective_remaining_percent=effective, max_concurrency=1,
            inflight=int(observed_inflight.get(pool_id, 0)),
            reserve_percent=15 if pool_id.endswith("gemini") else 20,
            # Antigravity's /usage parser supplies a number when healthy; if
            # it is temporarily unreadable, keep only a small explicit pilot
            # allowance rather than treating unknown as full quota.
            unknown_quota_policy="pilot", unknown_quota_pilot_percent=5.0,
        )
        # The TUI parser intentionally reports ``health=unknown`` when the
        # five-hour window is disabled after a weekly exhaustion.  A displayed
        # zero weekly balance is nevertheless a hard quota block; leaving the
        # pool as ``unknown`` would make the final schedulable-pool summary
        # advertise a model that cannot run.  Keep the shared pool intact and
        # block every member until the next fresh usage snapshot clears it.
        weekly = live.get("weekly_percent_displayed")
        if weekly is not None:
            try:
                if float(weekly) <= 0.0:
                    live["health"] = "blocked"
                    live["effective_remaining_percent"] = 0.0
                    live["blocked_reason"] = "Antigravity /usage weekly quota exhausted"
            except (TypeError, ValueError):
                pass
        efficient = next((model for model in candidate_catalog if "flash" in model.lower() or "sonnet" in model.lower()), None)
        hard = next((model for model in candidate_catalog if "pro" in model.lower() or "opus" in model.lower()), None)
        alternate = next((model for model in candidate_catalog if "gpt-oss" in model.lower()), None)
        live["role_models"] = {
            "efficient": efficient or alternate or hard,
            "code": efficient or alternate or hard,
            "hard": hard or alternate or efficient,
        }
        live["role_model_candidates"] = {
            "efficient": [model for model in (efficient, alternate, hard) if model],
            "code": [model for model in (alternate, efficient, hard) if model],
            "hard": [model for model in (hard, alternate, efficient) if model],
        }
        live["rejected_models"] = sorted(ag_rejected)
        live["rejected_model_variants"] = {
            model: sorted(variants)
            for model, variants in sorted(ag_rejected_variants.items())
        }
        live.setdefault("health", "unknown")
        if not candidate_catalog:
            live["health"] = "blocked"
            live["blocked_reason"] = "no exact model slug in a fresh Antigravity catalog"
        pools[pool_id] = live

    go_catalog_all = opencode_go_models(opencode_go)
    go_policy_excluded = sorted(
        model
        for model in go_catalog_all
        if model.startswith(OPENCODE_POLICY_EXCLUDED_PREFIXES)
    )
    go_rejected = {
        str(row.get("model"))
        for row in blocked_rows
        if str(row.get("provider") or "") in {"opencode", "opencode-go"}
        and not row.get("variant")
    }
    go_rejected_variants: dict[str, set[str]] = {}
    for row in blocked_rows:
        if str(row.get("provider") or "") not in {"opencode", "opencode-go"}:
            continue
        model_id = str(row.get("model") or "")
        variant = str(row.get("variant") or "")
        if model_id and variant:
            go_rejected_variants.setdefault(model_id, set()).add(variant)
    go_catalog = [
        model
        for model in go_catalog_all
        if model not in go_rejected and model not in go_policy_excluded
    ]

    def go_choice(preferences: list[str]) -> str | None:
        return next((model for model in preferences if model in go_catalog), None)

    go_role_preferences = {
        "efficient": [
                "opencode-go/mimo-v2.5",
                "opencode-go/hy3",
                "opencode-go/qwen3.7-plus",
                "opencode-go/minimax-m2.7",
                "opencode-go/glm-5.1",
                "opencode-go/gpt-5.6-luna",
            ],
        "code": [
                "opencode-go/kimi-k2.7-code",
                "opencode-go/gpt-5.6-luna",
                "opencode-go/qwen3.7-plus",
                "opencode-go/qwen3.6-plus",
                "opencode-go/mimo-v2.5-pro",
            ],
        "hard": [
                "opencode-go/gpt-5.6-luna",
                "opencode-go/qwen3.8-max",
                "opencode-go/glm-5.2",
                "opencode-go/kimi-k3",
                "opencode-go/grok-4.5",
                "opencode-go/qwen3.7-max",
                "opencode-go/minimax-m3",
            ],
    }
    go_roles = {
        role: go_choice(preferences)
        for role, preferences in go_role_preferences.items()
    }
    go_models_by_id = {
        str(row.get("model_id")): row
        for row in ((opencode_go.get("catalog") or {}).get("models") or [])
        if isinstance(row, dict) and row.get("model_id")
    }
    go_model_variants: dict[str, str] = {}
    go_available_variants = {
        model_id: sorted(
            str(variant)
            for variant in (((row.get("metadata") or {}).get("variants") or {}).keys())
        )
        for model_id, row in go_models_by_id.items()
    }
    luna = go_models_by_id.get("opencode-go/gpt-5.6-luna") or {}
    luna_variants = (((luna.get("metadata") or {}).get("variants")) or {})
    if "max" in luna_variants:
        go_model_variants["opencode-go/gpt-5.6-luna"] = "max"
    go_role_candidates = {
        role: [
            {
                "model": model,
                "variant": go_model_variants.get(model),
            }
            for model in preferences
            if model in go_catalog
        ]
        for role, preferences in go_role_preferences.items()
    }
    go_model_costs = {
        model_id: ((row.get("metadata") or {}).get("cost") or {})
        for model_id, row in go_models_by_id.items()
        if (row.get("metadata") or {}).get("cost")
    }
    go_usage_multipliers: dict[str, float] = {}
    for model_id, row in go_models_by_id.items():
        name = str((row.get("metadata") or {}).get("name") or "")
        match = re.search(r"\(([0-9]+(?:\.[0-9]+)?)x\s+usage\)", name, re.I)
        if match:
            go_usage_multipliers[model_id] = float(match.group(1))
    go_source_pool = dict((opencode_go.get("pools") or {}).get("opencode.go") or {})
    go_auth = (opencode_go.get("auth") or {}).get("state")
    go_quota = opencode_go_quota or {}
    go_quota_records = go_quota.get("records") or []
    go_quota_pilot = go_quota.get("pilot") or {}
    go_quota_api = go_quota.get("usage_api") or {}
    go_quota_api_ok = bool(go_quota_api.get("ok"))
    go_quota_effective = go_quota_pilot.get("effective_remaining_percent")
    go_quota_endpoint = (
        ((go_quota_api.get("parsed") or {}).get("api_metadata") or {}).get("endpoint")
    )
    if go_auth == "absent":
        go_health = "blocked"
        go_blocked_reason = "OpenCode Go credential is not configured"
    elif not go_catalog:
        go_health = "blocked"
        go_blocked_reason = "no policy-eligible exact model in the OpenCode Go catalog"
    else:
        # Auth + catalog makes the pool a schedulable candidate. A successful
        # real job remains the evidence required for runtime_state=accepted.
        go_health = str(go_source_pool.get("health") or "unknown")
        go_blocked_reason = None
    if go_quota_api_ok and isinstance(go_quota_effective, (int, float)):
        # A separately verified usage endpoint is account-level evidence for the
        # shared pool; it does not split DeepSeek from other Go models.
        go_source_pool["effective_remaining_percent"] = float(go_quota_effective)
        go_source_pool["quota_state"] = "known"
        go_source_pool["quota_source"] = (
            "official_usage_api"
            if go_quota_endpoint == OFFICIAL_OPENCODE_GO_USAGE_ENDPOINT
            else "verified_usage_api"
        )
        go_source_pool["quota_last_checked_at"] = go_quota.get("fetched_at_utc")
        go_source_pool["quota_evidence"] = {
            "source": "api",
            "records": go_quota_records,
            "usage_api": {
                "endpoint": go_quota_endpoint,
                "http_status": go_quota_api.get("http_status"),
            },
        }
        if float(go_quota_effective) <= 0.0:
            go_health = "quota_exhausted"
            source_name = (
                "official OpenCode Go usage API"
                if go_quota_endpoint == OFFICIAL_OPENCODE_GO_USAGE_ENDPOINT
                else "verified usage API"
            )
            go_blocked_reason = f"OpenCode Go shared quota exhausted according to {source_name}"
    elif go_quota and not go_quota_api_ok and not go_quota.get("skipped"):
        quota_probe = go_quota.get("usage_api")
        quota_probe = quota_probe if isinstance(quota_probe, dict) else {}
        go_source_pool["quota_state"] = "unknown"
        go_source_pool["quota_source"] = (
            "official_usage_api_failed"
            if go_quota_endpoint in {None, OFFICIAL_OPENCODE_GO_USAGE_ENDPOINT}
            else "verified_usage_api_failed"
        )
        go_source_pool["quota_error"] = {
            "error_type": quota_probe.get("error_type"),
            "http_status": quota_probe.get("http_status"),
            "error": quota_probe.get("error"),
        }
    elif go_quota.get("skipped"):
        go_source_pool["quota_state"] = "unknown"
        go_source_pool["quota_source"] = "not_requested"
        go_source_pool["quota_note"] = (
            "OpenCode Go usage probe was skipped; use a console export or an "
            "authorized bounded probe if current balance is required."
        )
    pools["opencode.go"] = {
        **go_source_pool,
        "provider": "opencode",
        "provider_id": "opencode-go",
        # The Go catalogue is a shared, usage-weighted subscription pool.  A
        # role/default member is therefore only a candidate; the task must
        # carry an exact model approval before the planner can spend quota.
        "model_approval_required": True,
        "model_approval_policy": "task_exact_model",
        "health": go_health,
        "runtime_state": go_source_pool.get("runtime_state", "unknown"),
        "effective_remaining_percent": go_source_pool.get("effective_remaining_percent"),
        # OpenCode Go's public CLI does not expose remaining balance.  Permit
        # a bounded, auditable pilot for configured accounts; never claim the
        # pool is quota-free and keep overage state unknown.
        "unknown_quota_policy": "pilot", "unknown_quota_pilot_percent": 5.0,
        "default_model": go_roles["hard"] or go_roles["code"] or go_roles["efficient"],
        "catalog_models": go_catalog,
        "shared_members": go_catalog_all,
        "role_models": go_roles,
        "role_model_candidates": go_role_candidates,
        "model_variants": go_model_variants,
        "available_model_variants": go_available_variants,
        "model_costs_per_million_tokens": go_model_costs,
        "model_usage_multipliers": go_usage_multipliers,
        "rejected_models": sorted(go_rejected),
        "rejected_model_variants": {
            model_id: sorted(variants)
            for model_id, variants in sorted(go_rejected_variants.items())
        },
        "policy_excluded_models": go_policy_excluded,
        "reserve_percent": 10,
        "max_concurrency": 1,
        "inflight": int(observed_inflight.get("opencode.go", 0)),
        "quota_rate_source": "unmeasured_prior_until_attributable_runtime_observation",
        "overage_fallback_state": go_quota.get("overage_fallback_state", "unknown"),
        "blocked_reason": go_blocked_reason,
    }

    for host_id, host in (local_models.get("hosts") or {}).items():
        if host.get("transport") != "ssh":
            continue
        apis = host.get("apis") or []
        ready_apis = [
            api for api in apis
            if api.get("health") == "ready" and api.get("models")
        ]
        ready_api = ready_apis[0] if ready_apis else None
        smoke = host.get("agentic_smoke") or {}
        smoke_matches = False
        smoke_reason: str | None = None
        # A host may expose more than one loopback API.  Select the API whose
        # live identity matches the smoke record instead of letting an
        # unrelated first listener make the host look stale.
        for candidate_api in ready_apis or [None]:
            candidate_matches, candidate_reason = server_local_smoke_match(
                smoke, str(host_id), candidate_api, checked_at
            )
            if candidate_matches:
                ready_api = candidate_api
                smoke_matches = True
                smoke_reason = None
                break
            if smoke_reason is None:
                smoke_reason = candidate_reason
        calibrated = smoke_matches
        ready = ready_api if calibrated else None
        pools[f"server_local.{host_id}"] = {
            "provider": "server_local", "host_id": host_id,
            "health": "ready" if ready else "blocked", "quota_free": True,
            "effective_remaining_percent": 100 if ready else 0, "reserve_percent": 0,
            "runtime": ready_api.get("runtime") if ready_api else None,
            "base_url": ready_api.get("base_url") if ready_api else None,
            "models": ready_api.get("models") if ready_api else [],
            "default_model": ready_api.get("models", [None])[0] if ready_api else None,
            "agentic_smoke": smoke or None,
            "max_difficulty": int(smoke.get("max_difficulty", 2)) if calibrated else 0,
            "requires_provider_review": bool(
                smoke.get("requires_provider_review", True)
            ),
            "max_concurrency": 1, "inflight": 0,
            "blocked_reason": (
                None if ready else smoke_reason
            ),
        }
    return pools


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", default=str(DEFAULT_ROOT / "hosts.json"))
    parser.add_argument("--model-state", default=str(DEFAULT_ROOT / "model-state.json"))
    parser.add_argument("--runtime-state", default=str(DEFAULT_ROOT / "runtime-state.json"))
    parser.add_argument("--output", default=str(DEFAULT_ROOT / "preflight-state.json"))
    parser.add_argument("--cwd", default=str(pathlib.Path.cwd()))
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--verify-racknerd-routes",
        action="store_true",
        help="Explicitly run remote RackNerd helper verify operations during live compute discovery.",
    )
    parser.add_argument(
        "--verify-external-network",
        action="store_true",
        help="Run bounded unauthenticated DNS/HTTPS checks on each compute host.",
    )
    parser.add_argument("--skip-antigravity-usage", action="store_true")
    parser.add_argument(
        "--opencode-go-usage-endpoint",
        default=OFFICIAL_OPENCODE_GO_USAGE_ENDPOINT,
        help=(
            "HTTPS usage endpoint for OpenCode Go. Defaults to the official "
            "endpoint merged upstream; override only with a verified compatible URL."
        ),
    )
    parser.add_argument(
        "--skip-opencode-go-usage",
        action="store_true",
        help="Do not make the authenticated read-only OpenCode Go usage request.",
    )
    parser.add_argument("--continuity-run-dir")
    args = parser.parse_args(argv)
    if args.opencode_go_usage_endpoint and not str(args.opencode_go_usage_endpoint).startswith("https://"):
        parser.error("--opencode-go-usage-endpoint must use https://")
    return args


def build_execution_readiness(
    local_system: Mapping[str, Any],
    compute_hosts: Mapping[str, Any],
    pools: Mapping[str, Any],
    diagnostic_failures: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Separate plan-level candidates from an actually admissible lane.

    ``dispatch_ready`` intentionally remains a planning signal: a visible
    candidate pool is useful for a report even when live probes timed out.
    This stricter projection prevents callers from mistaking that signal for
    permission to execute.  Desktop-authenticated providers require a healthy
    local launch gate; server-local pools require a reachable, writable remote
    host.  Unknown or stale evidence is listed as a blocker rather than
    converted into a guessed ``ready`` state.
    """

    failures = diagnostic_failures if isinstance(diagnostic_failures, Mapping) else {}
    pool_items = {
        str(pool_id): row for pool_id, row in (pools or {}).items()
        if isinstance(row, Mapping)
    }
    schedulable = sorted(
        pool_id for pool_id, row in pool_items.items()
        if row.get("default_model")
        and str(row.get("health") or "unknown") not in {
            "blocked", "cooldown", "quota_exhausted", "unavailable", "unknown"
        }
    )
    host_items = {
        str(host_id): row for host_id, row in (compute_hosts or {}).items()
        if isinstance(row, Mapping)
    }
    writable = lambda row: (
        row.get("reachable") is True
        and row.get("project_path_exists") is True
        and row.get("project_path_writable") is True
    )
    local_hosts = sorted(
        host_id for host_id, row in host_items.items()
        if str(row.get("transport") or "local") == "local"
        and writable(row)
        and row.get("local_agent_launch_allowed") is True
    )
    remote_hosts = sorted(
        host_id for host_id, row in host_items.items()
        if str(row.get("transport") or "local") != "local" and writable(row)
    )
    server_local_pools = sorted(
        pool_id for pool_id in schedulable
        if str(pool_items[pool_id].get("provider") or "") == "server_local"
        or pool_id.startswith("server_local.")
    )
    desktop_pools = sorted(set(schedulable) - set(server_local_pools))
    desktop_ready = bool(local_hosts and desktop_pools)
    server_ready = bool(remote_hosts and server_local_pools)
    blockers: list[str] = []
    if not bool(local_system.get("ok")):
        blockers.append("local_system_scan_failed")
    if not host_items:
        blockers.append("compute_host_evidence_missing")
    if failures.get("compute"):
        blockers.append("compute_probe_failed")
    if not schedulable:
        blockers.append("no_provider_pool_with_fresh_capacity")
    if desktop_pools and not local_hosts:
        blockers.append("desktop_provider_local_launch_blocked_or_unknown")
    if server_local_pools and not remote_hosts:
        blockers.append("server_local_pool_remote_host_unavailable_or_not_writable")
    if not desktop_pools and not server_local_pools and schedulable:
        blockers.append("pool_provider_placement_unknown")
    return {
        "ready": bool(desktop_ready or server_ready),
        "desktop_control_plane_ready": desktop_ready,
        "server_local_execution_ready": server_ready,
        "planning_candidate_ready": bool(schedulable),
        "execution_candidate_pools": schedulable,
        "eligible_local_hosts": local_hosts,
        "eligible_remote_hosts": remote_hosts,
        "blockers": sorted(set(blockers)),
        "semantics": "execution_admission_not_plan_candidate",
    }


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    cwd = pathlib.Path(args.cwd).expanduser().resolve()
    checked_at = now()

    # Stage 1 is deliberately synchronous and local-only.  Provider/catalog
    # probes are selected from this observed inventory, so a public install
    # never assumes that Codex, Cursor, Antigravity, or OpenCode exists.
    system_result = run(
        [
            sys.executable,
            str(SCRIPT_DIR / "local_system_scan.py"),
            "--workspace",
            str(cwd),
            "--timeout",
            str(min(max(args.timeout, 1.0), 30.0)),
            "--output",
            "-",
        ],
        max(10.0, args.timeout + 10.0),
        cwd,
    )
    local_system = as_json(system_result)
    clis = local_system.get("clis") or {}

    def cli_present(name: str) -> bool:
        row = clis.get(name) or {}
        return bool(isinstance(row, dict) and row.get("present"))

    commands: dict[str, list[str]] = {
        "compute": [
            sys.executable,
            str(SCRIPT_DIR / "compute_resource_probe.py"),
            "--inventory",
            args.inventory,
            "--timeout",
            str(max(20.0, args.timeout)),
        ],
        "local_models": [sys.executable, str(SCRIPT_DIR / "server_local_model_scan.py"), "--inventory", args.inventory],
        "local_agent_processes": ["ps", "-axo", "pid=,ppid=,command="],
    }
    if args.verify_racknerd_routes:
        commands["compute"].append("--verify-racknerd-routes")
    if args.verify_external_network:
        commands["compute"].append("--verify-external-network")
    if cli_present("codex"):
        commands.update(
            codex_usage=[sys.executable, str(SCRIPT_DIR / "codex_usage_snapshot.py")],
            codex_luna=[sys.executable, str(SCRIPT_DIR / "codex_model_preflight.py"), "--preset", "luna-max"],
            codex_sol=[sys.executable, str(SCRIPT_DIR / "codex_model_preflight.py"), "--preset", "sol-max"],
            codex_spark=[sys.executable, str(SCRIPT_DIR / "codex_model_preflight.py"), "--preset", "spark-fast"],
        )
    if cli_present("cursor-agent"):
        commands.update(
            cursor_status=["cursor-agent", "status", "--format", "json"],
            cursor_about=["cursor-agent", "about", "--format", "json"],
        )
    if cli_present("opencode"):
        commands["opencode_go"] = [
            sys.executable,
            str(SCRIPT_DIR / "opencode_go_snapshot.py"),
            "--timeout",
            str(max(5.0, args.timeout)),
        ]
        # The official read-only usage endpoint is now part of the upstream
        # console service.  Keep the request opt-out, and preserve unknown on
        # missing auth, HTTP errors, or malformed responses.
        if args.opencode_go_usage_endpoint and not args.skip_opencode_go_usage:
            commands["opencode_go_quota"] = [
                sys.executable,
                str(SCRIPT_DIR / "opencode_go_quota_snapshot.py"),
                "--skip-discovery",
                "--usage-api",
                "--usage-endpoint",
                str(args.opencode_go_usage_endpoint),
                "--usage-use-auth-store",
                "--timeout",
                str(max(5.0, args.timeout)),
            ]
    if cli_present("antigravity") and not args.skip_antigravity_usage:
        commands["antigravity_usage"] = [
            sys.executable, str(SCRIPT_DIR / "antigravity_usage_tui_snapshot.py"),
            "--cwd", str(cwd), "--timeout", str(max(20.0, args.timeout)),
        ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(commands)) as executor:
        futures = {name: executor.submit(run, command, max(10.0, args.timeout + 10), cwd) for name, command in commands.items()}
        results = {name: future.result() for name, future in futures.items()}
    results["local_system"] = system_result
    if cli_present("opencode") and (not args.opencode_go_usage_endpoint or args.skip_opencode_go_usage):
        results["opencode_go_quota"] = skipped_result(
            "OpenCode Go usage probe was explicitly skipped; balance remains unknown"
        )

    for name, cli in (
        ("codex_usage", "codex"),
        ("codex_luna", "codex"),
        ("codex_sol", "codex"),
        ("codex_spark", "codex"),
        ("cursor_status", "cursor-agent"),
        ("cursor_about", "cursor-agent"),
        ("opencode_go", "opencode"),
        ("opencode_go_quota", "opencode"),
        ("antigravity_usage", "antigravity"),
    ):
        results.setdefault(name, skipped_result(f"{cli} was not selected by the local system scan"))

    # Provider catalogs are serialized after the heavier concurrent probes.
    # Cursor and Antigravity can transiently return an empty catalog or wait on
    # an auth/cache lock when several instances start together.
    for name, cli, command, parser in (
        ("cursor_models", "cursor-agent", ["cursor-agent", "--list-models"], cursor_models),
        ("antigravity_models", "antigravity", ["antigravity", "models"], antigravity_models),
    ):
        if not cli_present(cli):
            results[name] = skipped_result(f"{cli} is not installed")
            continue
        result = run(command, max(20.0, args.timeout + 20), cwd)
        if not result.get("ok") or not parser(result.get("stdout") or ""):
            result = run(command, max(20.0, args.timeout + 20), cwd)
        results[name] = result

    def parsed_or(name: str, default: dict[str, Any]) -> dict[str, Any]:
        result = results[name]
        return dict(default, skipped=True) if result.get("skipped") else as_json(result)

    compute = as_json(results["compute"])
    inventory_hosts = load_inventory_compute_hosts(args.inventory)
    local_models = as_json(results["local_models"])
    codex_usage = parsed_or("codex_usage", {"ok": False, "pools": {}})
    codex_luna = parsed_or("codex_luna", {"ok": False})
    codex_sol = parsed_or("codex_sol", {"ok": False})
    codex_spark = parsed_or("codex_spark", {"ok": False})
    cursor_status = parsed_or("cursor_status", {"ok": False, "isAuthenticated": False})
    cursor_status = annotate_cursor_status(
        cursor_status,
        results["cursor_status"],
        results.get("cursor_models", {}),
    )
    cursor_about = parsed_or("cursor_about", {"ok": False})
    opencode_go = parsed_or(
        "opencode_go",
        {"ok": False, "catalog": {"models": []}, "pools": {}, "auth": {"state": "unknown"}},
    )
    opencode_go_quota = parsed_or(
        "opencode_go_quota",
        {"ok": False, "balance_state": "unknown", "usage_api": {"ok": False}},
    )
    process_result = results["local_agent_processes"]
    process_snapshot = (
        local_agent_process_snapshot(process_result.get("stdout") or "", os.getpid())
        if process_result.get("ok")
        else {
            "scan_ok": False,
            "processes": [],
            "inflight_by_pool": {},
            "exclusive_pool_observation": False,
            "attribution": "unknown_process_state_nonexclusive",
        }
    )
    # Compute-host probing is read-only and provider-free.  Merge its
    # privacy-safe remote occupancy before building pools so the shared
    # OpenCode Go account is constrained globally, not only on the host that
    # happened to run the process.
    raw_compute_hosts = compute.get("compute_hosts") or compute.get("hosts") or {}
    compute_hosts = merge_inventory_compute_hosts(
        raw_compute_hosts,
        inventory_hosts,
        compute,
        checked_at,
    )
    compute_hosts = merge_local_system_compute_host(
        compute_hosts,
        local_system,
        cwd,
    )
    external_consumers = aggregate_external_consumers(process_snapshot, compute_hosts)
    cursor_catalog = cursor_models(results["cursor_models"].get("stdout") or "")
    ag_catalog = antigravity_models(results["antigravity_models"].get("stdout") or "")
    go_catalog = opencode_go_models(opencode_go)
    ag_usage = parsed_or("antigravity_usage", {"ok": False, "pools": {}})
    ag_usage.pop("raw_excerpt", None)
    cursor_catalog_valid = bool(results["cursor_models"].get("ok") and cursor_catalog)
    model_state, blocked = merge_model_state(
        pathlib.Path(args.model_state),
        cursor_catalog,
        checked_at,
        cursor_catalog_valid,
        additional_catalogs={
            "opencode": (
                go_catalog,
                bool((opencode_go.get("catalog") or {}).get("state") == "visible" and go_catalog),
            )
        },
    )
    runtime_state = read_json(pathlib.Path(args.runtime_state), {})
    if isinstance(runtime_state, dict):
        # Runtime capability/location evidence is exact model/variant scoped;
        # a shared Antigravity pool may remain usable after one Gemini model
        # is rejected.  Quota and generic FAILED_PRECONDITION rows stay out.
        blocked.extend(runtime_rejection_rows(runtime_state))
    deployment_state = read_json(DEFAULT_ROOT / "server-local-deployment.json", {})
    pools = build_pools(
        codex_usage,
        cursor_status,
        cursor_catalog,
        ag_usage,
        ag_catalog,
        opencode_go,
        local_models,
        blocked,
        external_inflight=external_consumers["inflight_by_pool"],
        checked_at=checked_at,
        opencode_go_quota=opencode_go_quota,
        codex_capabilities={
            "codex.luna": [codex_luna, codex_sol],
            "codex.spark": [codex_spark],
        },
    )
    runtime_overrides = apply_runtime_overrides(pools, runtime_state, checked_at)
    deployment_host = str((deployment_state.get("target") or {}).get("host_id") or "")
    deployment_status = deployment_state.get("status")
    if deployment_host and deployment_status and f"server_local.{deployment_host}" in pools:
        deployment_pool = pools[f"server_local.{deployment_host}"]
        if deployment_pool.get("health") == "ready":
            deployment_status = "ready"
            deployment_state["status"] = "ready"
            deployment_state["readiness_source"] = "live_loopback_api_plus_agentic_smoke"
            deployment_state["ready_observed_at_utc"] = checked_at
            atomic_write(DEFAULT_ROOT / "server-local-deployment.json", deployment_state)
        elif deployment_status != "ready":
            deployment_pool["health"] = "blocked"
            deployment_pool["effective_remaining_percent"] = 0
            deployment_pool["blocked_reason"] = (
                "local-model deployment is not ready: " + str(deployment_status)
            )
        deployment_pool["deployment_status"] = deployment_status
    local_ready = [pool_id for pool_id, row in pools.items() if row.get("provider") == "server_local" and row.get("health") == "ready"]
    continuity = {
        "architecture": "persistent_external_controller",
        "controller_script": str(SCRIPT_DIR / "continuity_controller.py"),
        "chat_independent_after_launch": True,
        "can_accept_new_chat_intent_while_chat_unavailable": False,
        "server_local_ready_pools": local_ready,
        "server_local_status": "ready" if local_ready else "not_ready",
        "server_local_deployment": deployment_state,
        "required_before_quota_loss": [
            "persist task packets and dependencies", "configure ordered attempt/fallback chains",
            "start continuity_controller.py as a durable process", "record PID/log/run directory",
        ],
    }
    if args.continuity_run_dir:
        state = read_json(pathlib.Path(args.continuity_run_dir).expanduser() / "state.json")
        continuity["active_run"] = state
    failures = {
        name: {"returncode": row.get("returncode"), "error": (row.get("stderr") or "")[-800:]}
        for name, row in results.items() if not row.get("ok") and not row.get("skipped")
    }
    schedulable_pools = sorted(
        pool_id
        for pool_id, row in pools.items()
        if row.get("default_model") and str(row.get("health") or "unknown") not in {
            "blocked", "cooldown", "quota_exhausted", "unavailable"
        }
    )
    scan_complete = bool(local_system.get("ok") and compute.get("ok") and compute_hosts)
    dispatch_ready = bool(schedulable_pools)
    execution_readiness = build_execution_readiness(
        local_system, compute_hosts, pools, failures
    )
    payload = {
        "ok": scan_complete,
        "scan_complete": scan_complete,
        "dispatch_ready": dispatch_ready,
        "execution_ready": execution_readiness["ready"],
        "scanned_at_utc": checked_at,
        "scan_policy": "local_system_first_then_catalog_and_health_no_paid_model_prompts",
        "scan_sequence": [
            {"stage": 1, "name": "local_system", "ok": bool(local_system.get("ok"))},
            {
                "stage": 2,
                "name": "compute_and_provider_discovery",
                "ok": bool(compute.get("ok") and compute_hosts),
            },
            {
                "stage": 3,
                "name": "pool_build_and_runtime_overlay",
                "ok": dispatch_ready,
            },
        ],
        "readiness": {
            "schedulable_pool_count": len(schedulable_pools),
            "schedulable_pools": schedulable_pools,
            "provider_failures_are_non_global": True,
            **execution_readiness,
        },
        "local_system": local_system,
        "provider_catalogs": {
            "codex": {"luna": codex_luna, "sol": codex_sol, "spark": codex_spark},
            "cursor": {"status": cursor_status, "about": cursor_about, "models": cursor_catalog},
            "antigravity": {"models": ag_catalog, "usage": ag_usage},
            "opencode_go": opencode_go,
            "opencode_go_quota": opencode_go_quota,
        },
        "pools": pools,
        "compute_hosts": compute_hosts,
        "local_model_hosts": local_models.get("hosts") or {},
        "model_state": model_state,
        "runtime_state": runtime_state,
        "runtime_overrides": runtime_overrides,
        "blocked_models": blocked,
        "external_consumers": external_consumers,
        "exclusive_pool_observation": False,
        "continuity": continuity,
        "diagnostic_failures": failures,
    }
    atomic_write(pathlib.Path(args.output), payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
