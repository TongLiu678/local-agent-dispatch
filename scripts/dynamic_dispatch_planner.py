#!/usr/bin/env python3
"""Build a rolling-horizon local-agent dispatch plan with quota constraints."""

from __future__ import annotations

import argparse
import datetime as dt
import functools
import json
import math
import pathlib
import re
import sys
from collections.abc import Mapping, Sequence
from typing import Any


POOL_PROFILES: dict[str, dict[str, Any]] = {
    "codex.luna": {
        "provider": "codex",
        "model": "gpt-5.6-luna/max",
        "difficulty_center": 4.2,
        "quality": 1.0,
        "speed": 0.45,
        "tasks": {"code", "research", "audit", "text"},
        "reserve": 20,
        "quota_rate_percent_per_minute": 0.0125,
        "primary_bonus": 15,
    },
    "codex.spark": {
        "provider": "codex",
        "model": "gpt-5.3-codex-spark/xhigh",
        "difficulty_center": 1.5,
        "quality": 0.62,
        "speed": 1.0,
        "tasks": {"code", "monitor", "text"},
        "reserve": 10,
        "quota_rate_percent_per_minute": 0.03,
        "primary_bonus": 8,
    },
    "cursor.composer_grok": {
        "provider": "cursor",
        "model": "composer-2.5-fast",
        "difficulty_center": 2.2,
        "quality": 0.72,
        "speed": 0.9,
        "tasks": {"code", "text", "research"},
        "reserve": 10,
        "quota_rate_percent_per_minute": 0.04,
        "primary_bonus": 0,
    },
    "cursor.other": {
        "provider": "cursor",
        "model": None,
        "difficulty_center": 3.2,
        "quality": 0.82,
        "speed": 0.72,
        "tasks": {"code", "text", "research", "audit"},
        "reserve": 10,
        "quota_rate_percent_per_minute": 0.05,
        "primary_bonus": 0,
    },
    "antigravity.gemini": {
        "provider": "antigravity",
        "model": "gemini-3.6-flash-high",
        "difficulty_center": 2.8,
        "quality": 0.78,
        "speed": 0.86,
        "tasks": {"text", "research", "audit", "code"},
        "reserve": 15,
        "quota_rate_percent_per_minute": 0.035,
        "primary_bonus": 0,
    },
    "antigravity.claude_gpt": {
        "provider": "antigravity",
        "model": "gpt-oss-120b-medium",
        "difficulty_center": 3.8,
        "quality": 0.9,
        "speed": 0.55,
        "tasks": {"text", "research", "audit", "code"},
        "reserve": 20,
        "quota_rate_percent_per_minute": 0.06,
        "primary_bonus": 0,
    },
    "opencode.go": {
        "provider": "opencode",
        "model": "opencode-go/gpt-5.6-luna",
        "difficulty_center": 3.4,
        "quality": 0.88,
        "speed": 0.72,
        "tasks": {"code", "text", "research", "audit", "monitor"},
        "reserve": 10,
        # Initial conservative prior until attributable Go usage observations
        # can calibrate the shared 5-hour/weekly/monthly dollar-value pool.
        "quota_rate_percent_per_minute": 0.02,
        "primary_bonus": 0,
    },
}

SERVER_LOCAL_PROFILE: dict[str, Any] = {
    "provider": "server_local",
    "model": None,
    "difficulty_center": 2.5,
    "quality": 0.7,
    "speed": 0.58,
    "tasks": {"code", "research", "monitor", "text"},
    "reserve": 0,
    "quota_rate_percent_per_minute": 0.0,
    "primary_bonus": 0,
}

PRIORITY = {"low": 1, "normal": 2, "high": 3, "critical": 4}
HEALTH_PENALTY = {
    "ready": 0,
    "balanced": 3,
    "degraded": 10,
    "conserve": 22,
    "unknown": 20,
}
BLOCKED_HEALTH = {"blocked", "cooldown", "quota_exhausted", "unavailable"}
DESKTOP_CLI_PROVIDERS = {"codex", "cursor", "antigravity", "opencode"}
EXTERNAL_NETWORK_EVIDENCE_TTL_SECONDS = 900
EXTERNAL_NETWORK_TARGETS = ("github.com", "opencode.ai")
MAX_CLOCK_SKEW_SECONDS = 60.0


def _version_tuple(value: Any) -> tuple[int, ...] | None:
    """Parse a dotted kernel/runtime version without trusting free-form text."""
    if not isinstance(value, str):
        return None
    match = re.search(r"(?<![0-9])([0-9]+(?:\.[0-9]+)+)(?![0-9])", value.strip())
    if not match:
        return None
    try:
        return tuple(int(part) for part in match.group(1).split("."))
    except (TypeError, ValueError):
        return None


def _version_at_least(observed: tuple[int, ...], required: tuple[int, ...]) -> bool:
    """Compare dotted versions while treating omitted trailing components as zero."""
    width = max(len(observed), len(required))
    return tuple((*observed, 0)[:width]) >= tuple((*required, 0)[:width])


def required_linux_kernel(job: Mapping[str, Any]) -> str | None:
    """Return an explicit minimum Linux kernel requirement from a job.

    Runtime compatibility is deliberately opt-in.  A planner must not infer a
    kernel requirement merely from a provider name or a binary label because
    those facts can change independently.  Callers can place the requirement
    directly on the job or under ``runtime_requirements``/``runtime``.
    """
    sources: list[Mapping[str, Any]] = [job]
    for key in ("runtime_requirements", "runtime"):
        value = job.get(key)
        if isinstance(value, Mapping):
            sources.append(value)
    for source in sources:
        for key in ("min_linux_kernel", "minimum_linux_kernel", "required_linux_kernel"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def kernel_evidence_status(
    host: Mapping[str, Any], required: str
) -> str:
    """Classify host kernel evidence against an explicit minimum version."""
    required_version = _version_tuple(required)
    if required_version is None:
        return "unknown"
    observed_value: Any = None
    for key in ("kernel_release", "kernel", "uname_kernel", "os_kernel"):
        value = host.get(key)
        if isinstance(value, str) and value.strip():
            observed_value = value
            break
    observed_version = _version_tuple(observed_value)
    if observed_version is None:
        return "unknown"
    return "verified" if _version_at_least(observed_version, required_version) else "blocked"


def _parse_quota_reset(value: Any) -> dt.datetime | None:
    """Parse a provider reset timestamp without accepting quota buckets."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if not math.isfinite(float(value)) or float(value) <= 0:
            return None
        try:
            return dt.datetime.fromtimestamp(float(value), tz=dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = " ".join(value.split())
    try:
        parsed = dt.datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _pool_quota_reset(pool: Mapping[str, Any]) -> dt.datetime | None:
    """Return the earliest reset exposed for one quota pool."""
    sources: list[Mapping[str, Any]] = [pool]
    for bucket_name in ("primary", "secondary"):
        bucket = pool.get(bucket_name)
        if isinstance(bucket, Mapping):
            sources.append(bucket)
    candidates: list[dt.datetime] = []
    for source in sources:
        for key in ("reset_at_utc", "resets_at_utc", "quota_reset_at_utc", "resets_at"):
            parsed = _parse_quota_reset(source.get(key))
            if parsed is not None:
                candidates.append(parsed)
    return min(candidates) if candidates else None


def _next_blocked_pool_reset(
    pools: Mapping[str, Any], now: dt.datetime
) -> tuple[str, dt.datetime] | None:
    """Find the next future reset for a pool that currently cannot run."""
    candidates: list[tuple[str, dt.datetime]] = []
    for pool_id, raw_pool in pools.items():
        if not isinstance(raw_pool, Mapping):
            continue
        health = str(raw_pool.get("health", "unknown")).lower()
        remaining = raw_pool.get("effective_remaining_percent")
        exhausted = False
        if isinstance(remaining, (int, float)) and not isinstance(remaining, bool):
            exhausted = float(remaining) <= 0
        # A generic ``blocked`` state is also used for missing credentials,
        # rejected model variants, and unreachable CLIs.  Those conditions do
        # not become runnable merely because a stale quota window resets.  Only
        # an explicit quota-like state, or a numeric zero balance, may move the
        # next replan all the way to a reset timestamp.
        reason = str(raw_pool.get("blocked_reason") or "").lower()
        quota_reason = any(
            marker in reason
            for marker in ("quota", "rate limit", "rate_limit", "credit", "spend", "reset")
        )
        quota_health = health in {"cooldown", "quota_exhausted"}
        if not (exhausted or quota_health or (health == "blocked" and quota_reason)):
            continue
        reset = _pool_quota_reset(raw_pool)
        if reset is not None and reset > now:
            candidates.append((str(pool_id), reset))
    return min(candidates, key=lambda item: item[1]) if candidates else None


def _reserve_percent(pool: Mapping[str, Any], profile: Mapping[str, Any]) -> int | None:
    """Parse a quota reserve without letting malformed metadata crash planning."""
    raw = pool.get("reserve_percent", profile.get("reserve"))
    if isinstance(raw, bool):
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(value) or value < 0 or value > 100:
        return None
    return int(value)


def load_json(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def write_json(path: str | None, payload: dict[str, Any]) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if path:
        target = pathlib.Path(path).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(text, encoding="utf-8")
        temporary.replace(target)
    else:
        print(text, end="")


def priority_value(job: dict[str, Any]) -> int:
    value = job.get("priority", "normal")
    if isinstance(value, int):
        return max(1, min(4, value))
    return PRIORITY.get(str(value).lower(), 2)


def estimated_minutes(job: dict[str, Any]) -> float:
    if job.get("estimated_minutes") is not None:
        return max(1.0, float(job["estimated_minutes"]))
    difficulty = int(job.get("difficulty", 2))
    return (5.0, 10.0, 18.0, 30.0, 45.0, 60.0)[max(0, min(5, difficulty))]


def quota_cost(
    job: dict[str, Any], pool_id: str, pool: dict[str, Any], profile: dict[str, Any],
    model: str | None = None,
) -> float:
    if pool.get("quota_free") or profile.get("provider") == "server_local":
        return 0.0
    by_pool = job.get("quota_cost_by_pool") or {}
    if pool_id in by_pool:
        return max(0.0, float(by_pool[pool_id]))
    base = job.get("estimated_quota_cost")
    if base is not None:
        return max(0.0, float(base))
    selected_model = model or pool.get("model") or pool.get("default_model") or profile.get("model")
    model_rates = pool.get("model_quota_rates") or {}
    observed_rate = model_rates.get(selected_model)
    model_specific_rate = observed_rate is not None
    if observed_rate is None:
        observed_rate = pool.get("quota_rate_percent_per_minute")
    rate = float(
        observed_rate
        if observed_rate is not None
        else profile["quota_rate_percent_per_minute"]
    )
    if not model_specific_rate:
        usage_multipliers = pool.get("model_usage_multipliers") or {}
        rate *= max(0.01, float(usage_multipliers.get(selected_model, 1.0)))
    difficulty = max(0, min(5, int(job.get("difficulty", 2))))
    complexity_multiplier = 0.75 + difficulty * 0.08
    return max(0.05, estimated_minutes(job) * rate * complexity_multiplier)


def _token_bound(job: dict[str, Any], name: str) -> float | None:
    """Read a P50 token hint without turning an unknown into zero."""
    aliases = {
        "input": ("estimated_input_tokens", "input_tokens", "prompt_tokens"),
        "output": ("estimated_output_tokens", "output_tokens", "completion_tokens"),
    }.get(name, (name,))
    for source in (job.get("resource_estimate"), job.get("resources"), job):
        if not isinstance(source, dict):
            continue
        for alias in aliases:
            value = source.get(alias)
            if isinstance(value, dict):
                value = value.get("p50")
            if value in (None, ""):
                continue
            try:
                parsed = float(value)
            except (TypeError, ValueError):
                continue
            if math.isfinite(parsed) and parsed >= 0:
                return parsed
    return None


def estimated_usd_cost(job: dict[str, Any], pool: dict[str, Any], model: str | None) -> float | None:
    """Estimate provider USD cost only when both token and price evidence exist.

    This is deliberately separate from subscription quota accounting: an
    unknown OpenCode balance or a shared Antigravity quota must never be
    represented as a zero-dollar cost.  Price metadata is usually supplied by
    OpenCode Go; other providers remain ``None`` until they expose an
    attributable price contract.
    """
    if not model:
        return None
    input_tokens = _token_bound(job, "input")
    output_tokens = _token_bound(job, "output")
    if input_tokens is None or output_tokens is None:
        return None
    prices = pool.get("model_costs_per_million_tokens") or pool.get("model_costs_per_million") or {}
    rate = prices.get(model) if isinstance(prices, dict) else None
    if not isinstance(rate, dict):
        return None
    try:
        input_rate = float(rate.get("input"))
        output_rate = float(rate.get("output"))
    except (TypeError, ValueError):
        return None
    if not math.isfinite(input_rate) or not math.isfinite(output_rate) or input_rate < 0 or output_rate < 0:
        return None
    return round((input_tokens * input_rate + output_tokens * output_rate) / 1_000_000.0, 8)


def scopes_conflict(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    a = str(pathlib.PurePath(left))
    b = str(pathlib.PurePath(right))
    return a == b or a.startswith(b.rstrip("/") + "/") or b.startswith(a.rstrip("/") + "/")


def numeric(mapping: dict[str, Any], key: str, default: float = 0.0) -> float:
    value = mapping.get(key)
    if value in (None, ""):
        return default
    return max(0.0, float(value))


def storage_capacity(host: dict[str, Any]) -> tuple[str | None, float | None, float | None]:
    """Choose the best writable mount for workload artifacts and caches.

    Remote probes may report a small project/root filesystem plus a large
    writable mount such as ``/workspace``.  Placement must consume the
    mount-level evidence instead of treating the first ``disk_free_gib`` field
    as the only capacity.  Read-only data mounts remain useful for locality
    evidence but can never satisfy a write reservation.
    """
    rows = host.get("storage_paths") or host.get("storage_candidates") or host.get("disks") or []
    normalized: list[dict[str, Any]] = [row for row in rows if isinstance(row, dict) and row.get("exists", True)]
    writable = [row for row in normalized if row.get("writable")]
    preferred = str(host.get("best_writable_storage_path") or "")
    if preferred:
        preferred_row = next((row for row in writable if str(row.get("path")) == preferred), None)
        if preferred_row is not None:
            return (
                preferred,
                _finite_float(preferred_row.get("disk_total_gib")),
                _finite_float(preferred_row.get("disk_free_gib")),
            )
    if writable:
        row = max(writable, key=lambda item: float(item.get("disk_free_gib") or 0.0))
        return (
            str(row.get("path")) if row.get("path") else None,
            _finite_float(row.get("disk_total_gib")),
            _finite_float(row.get("disk_free_gib")),
        )
    if normalized:
        # Mounts were discovered but none can receive artifacts/caches.  Do
        # not fall back to a legacy project disk value and accidentally write
        # into a read-only data mount or a full root filesystem.
        return None, None, None
    # Local/system fixtures created before storage_paths existed remain
    # compatible, but their legacy fields are still treated as one mount.
    return (
        str(host.get("project_path") or "") or None,
        _finite_float(host.get("disk_total_gib")),
        _finite_float(host.get("disk_free_gib")),
    )


def storage_evidence_status(
    host: dict[str, Any], *, now: str | None = None
) -> str:
    """Classify mount probe freshness without inventing timestamps.

    The SSH compute probe records ``last_probed_at_utc`` for its exact disk
    paths.  A host carrying mount rows but no timestamp is therefore not
    safely placeable when the caller asks for strict remote placement.  Hosts
    without mount rows retain the legacy compatibility path and return
    ``not_applicable``.
    """
    rows = host.get("storage_paths") or host.get("storage_candidates") or host.get("disks") or []
    if not rows:
        return "not_applicable"
    stamp = host.get("last_probed_at_utc") or host.get("storage_scanned_at_utc")
    if not stamp:
        return "unknown"
    try:
        observed = dt.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=dt.timezone.utc)
        anchor = dt.datetime.fromisoformat(
            str(now or dt.datetime.now(dt.timezone.utc).isoformat()).replace("Z", "+00:00")
        )
        if anchor.tzinfo is None:
            anchor = anchor.replace(tzinfo=dt.timezone.utc)
        ttl = float(host.get("storage_probe_ttl_seconds", 1800))
    except (TypeError, ValueError):
        return "unknown"
    if not math.isfinite(ttl) or ttl <= 0:
        return "unknown"
    age = (anchor - observed).total_seconds()
    return "stale" if age > ttl else "fresh"


def external_network_evidence_status(
    host: dict[str, Any], *, host_id: str | None = None, now: str | None = None
) -> str:
    """Classify bounded public-network evidence for one execution host.

    A reachable SSH session is not proof that the PBS worker can reach the
    public network.  Only the explicit ``compute_resource_probe`` evidence is
    accepted, and a ``verified`` status must include successful DNS and HTTPS
    checks for every allow-listed public control endpoint.  Missing, malformed,
    mismatched, or stale evidence remains unknown so an explicitly
    network-dependent task cannot silently run on an isolated worker.
    """
    evidence = host.get("external_network_evidence")
    if not isinstance(evidence, Mapping):
        return "unknown"
    status = str(evidence.get("status") or "").lower()
    if status not in {"verified", "blocked"}:
        return "unknown"
    observed_host = evidence.get("target_host_id")
    if host_id not in (None, "") and observed_host not in (None, ""):
        if str(observed_host) != str(host_id):
            return "unknown"
    if status == "verified":
        targets = evidence.get("targets")
        if not isinstance(targets, Mapping):
            return "unknown"
        for target in EXTERNAL_NETWORK_TARGETS:
            row = targets.get(target)
            if not isinstance(row, Mapping) or row.get("dns_resolved") is not True or row.get("https_reachable") is not True:
                return "unknown"
    stamp = evidence.get("observed_at_utc")
    if not stamp:
        return "unknown"
    try:
        observed = dt.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=dt.timezone.utc)
        anchor = dt.datetime.fromisoformat(
            str(now or dt.datetime.now(dt.timezone.utc).isoformat()).replace("Z", "+00:00")
        )
        if anchor.tzinfo is None:
            anchor = anchor.replace(tzinfo=dt.timezone.utc)
        ttl = float(evidence.get("ttl_seconds", EXTERNAL_NETWORK_EVIDENCE_TTL_SECONDS))
    except (TypeError, ValueError):
        return "unknown"
    if not math.isfinite(ttl) or ttl <= 0:
        return "unknown"
    age = (anchor - observed).total_seconds()
    return "stale" if age > ttl else status


def time_sync_evidence_status(
    host: dict[str, Any], *, now: str | None = None
) -> str:
    """Classify optional ``ntpstat`` evidence without weakening clock gates.

    ``synchronized`` is only an auxiliary observation: the date-epoch sample
    still has to pass ``clock_evidence_status``.  A fresh explicit
    ``unsynchronized`` result is a hard temporal block, while missing,
    malformed, mismatched, future, or stale evidence remains unknown/stale.
    """

    evidence = host.get("time_sync_evidence")
    if not isinstance(evidence, Mapping):
        return "unknown"
    status = str(evidence.get("status") or "").lower()
    if status not in {"synchronized", "unsynchronized", "unknown"}:
        return "unknown"
    observed_host = evidence.get("target_host_id")
    host_id = host.get("host_id")
    if observed_host not in (None, "") and host_id not in (None, ""):
        if str(observed_host) != str(host_id):
            return "unknown"
    stamp = evidence.get("observed_at_utc")
    if not stamp:
        return "unknown"
    try:
        observed = dt.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        if observed.tzinfo is None:
            return "unknown"
        anchor = dt.datetime.fromisoformat(
            str(now or dt.datetime.now(dt.timezone.utc).isoformat()).replace("Z", "+00:00")
        )
        if anchor.tzinfo is None:
            return "unknown"
        ttl = float(evidence.get("ttl_seconds", EXTERNAL_NETWORK_EVIDENCE_TTL_SECONDS))
    except (TypeError, ValueError):
        return "unknown"
    if not math.isfinite(ttl) or ttl <= 0:
        return "unknown"
    age = (anchor.astimezone(dt.timezone.utc) - observed.astimezone(dt.timezone.utc)).total_seconds()
    if age < -MAX_CLOCK_SKEW_SECONDS:
        return "unknown"
    if age > ttl:
        return "stale"
    return status


def clock_evidence_status(
    host: dict[str, Any], *, now: str | None = None
) -> str:
    """Classify controller/remote clock evidence for temporal workloads.

    The compute probe compares a remote ``date +%s`` sample with the
    controller-side request midpoint.  A large offset is a hard ``blocked``
    result only when a job explicitly asks for clock synchronisation; ordinary
    data/CPU placement remains compatible with legacy hosts that do not emit
    this optional evidence.  Missing, malformed, future, or stale evidence is
    never treated as verified.
    """
    sync_status = time_sync_evidence_status(host, now=now)
    if sync_status in {"unsynchronized", "stale"}:
        return sync_status
    evidence = host.get("clock_evidence")
    if not isinstance(evidence, Mapping):
        return "unknown"
    status = str(evidence.get("status") or "").lower()
    if status not in {"verified", "blocked"}:
        return "unknown"
    try:
        offset = float(evidence.get("offset_seconds"))
        maximum = float(evidence.get("max_allowed_seconds", MAX_CLOCK_SKEW_SECONDS))
        ttl = float(evidence.get("ttl_seconds", EXTERNAL_NETWORK_EVIDENCE_TTL_SECONDS))
    except (TypeError, ValueError):
        return "unknown"
    if not math.isfinite(offset) or not math.isfinite(maximum) or maximum <= 0:
        return "unknown"
    if not math.isfinite(ttl) or ttl <= 0:
        return "unknown"
    if abs(offset) > maximum:
        status = "blocked"
    elif status != "verified":
        return "unknown"
    stamp = evidence.get("observed_at_utc")
    if not stamp:
        return "unknown"
    try:
        observed = dt.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        if observed.tzinfo is None:
            return "unknown"
        anchor = dt.datetime.fromisoformat(
            str(now or dt.datetime.now(dt.timezone.utc).isoformat()).replace("Z", "+00:00")
        )
        if anchor.tzinfo is None:
            return "unknown"
        age = (anchor.astimezone(dt.timezone.utc) - observed.astimezone(dt.timezone.utc)).total_seconds()
    except (TypeError, ValueError):
        return "unknown"
    if age < -MAX_CLOCK_SKEW_SECONDS:
        return "unknown"
    if age > ttl:
        return "stale"
    return status


def _finite_float(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) and parsed >= 0 else None


def resource_estimate(job: dict[str, Any]) -> dict[str, Any]:
    """Normalize explicit resource hints and add conservative task-class defaults."""
    raw: dict[str, Any] = {}
    for source in (job.get("resource_estimate"), job.get("resources")):
        if isinstance(source, dict):
            raw.update(source)
    task_type = str(job.get("task_type", "text"))
    difficulty = max(0, min(5, int(job.get("difficulty", 2))))
    default_cpu = 1 if task_type in {"text", "monitor", "research", "audit"} else min(4, 1 + difficulty // 2)
    default_ram = 0.5 if task_type in {"text", "monitor"} else (1.0 + difficulty * 0.5)
    explicit_keys = {
        "input_gib", "download_gib", "environment_gib", "temporary_gib",
        "cache_gib", "output_gib", "ram_gib", "cpu_cores", "gpu_count",
        "vram_gib", "compute_minutes",
    }
    estimate = {
        "input_gib": numeric(raw, "input_gib", numeric(job, "input_gib")),
        "download_gib": numeric(raw, "download_gib", numeric(job, "download_gib")),
        "environment_gib": numeric(raw, "environment_gib", numeric(job, "environment_gib", 0.1)),
        "temporary_gib": numeric(raw, "temporary_gib", numeric(job, "temporary_gib", 0.05)),
        "cache_gib": numeric(raw, "cache_gib", numeric(job, "cache_gib", 0.05)),
        "output_gib": numeric(raw, "output_gib", numeric(job, "output_gib", 0.05)),
        "ram_gib": numeric(raw, "ram_gib", numeric(job, "ram_gib", default_ram)),
        "cpu_cores": max(1, int(numeric(raw, "cpu_cores", numeric(job, "cpu_cores", default_cpu)))),
        "gpu_count": int(numeric(raw, "gpu_count", numeric(job, "gpu_count"))),
        "vram_gib": numeric(raw, "vram_gib", numeric(job, "vram_gib")),
        # Agent-thinking minutes and workload-compute minutes are deliberately separate.
        "compute_minutes": numeric(raw, "compute_minutes", numeric(job, "compute_minutes")),
    }
    estimate["gpu_useful"] = bool(
        raw.get("gpu_useful", job.get("gpu_useful", False))
        or estimate["gpu_count"] > 0
        or estimate["vram_gib"] > 0
    )
    if estimate["gpu_useful"] and estimate["gpu_count"] == 0:
        estimate["gpu_count"] = 1
    estimate["expected_cpu_utilization_percent"] = numeric(
        raw, "expected_cpu_utilization_percent", 80.0 if estimate["compute_minutes"] else 20.0
    )
    estimate["expected_gpu_utilization_percent"] = numeric(
        raw, "expected_gpu_utilization_percent", 80.0 if estimate["gpu_useful"] else 0.0
    )
    estimate["new_disk_gib"] = round(
        estimate["download_gib"]
        + estimate["environment_gib"]
        + estimate["temporary_gib"]
        + estimate["cache_gib"]
        + estimate["output_gib"],
        3,
    )
    estimate["peak_footprint_gib"] = round(estimate["input_gib"] + estimate["new_disk_gib"], 3)
    estimate["required_free_disk_gib"] = round(max(0.25, estimate["new_disk_gib"] * 1.25), 3)
    estimate["required_available_ram_gib"] = round(max(0.5, estimate["ram_gib"] * 1.2), 3)
    estimate["required_commands"] = list(raw.get("required_commands") or job.get("required_commands") or [])
    estimate["min_linux_kernel"] = required_linux_kernel(job)
    estimate["python_version"] = raw.get("python_version") or job.get("python_version")
    estimate["full_dataset"] = bool(raw.get("full_dataset", job.get("full_dataset", False)))
    estimate["full_model"] = bool(raw.get("full_model", job.get("full_model", False)))
    estimate["parallel_sweep"] = bool(raw.get("parallel_sweep", job.get("parallel_sweep", False)))
    estimate["confidence"] = "user_or_measured" if any(key in raw or key in job for key in explicit_keys) else "heuristic"
    unknowns: list[str] = []
    if (estimate["full_dataset"] or estimate["full_model"]) and not (
        estimate["input_gib"] or estimate["download_gib"]
    ):
        unknowns.append("full_workload_data_size")
    if estimate["gpu_useful"] and not estimate["vram_gib"]:
        unknowns.append("peak_vram")
    estimate["unknowns"] = unknowns
    estimate["pilot_required"] = bool(unknowns) and not bool(job.get("allow_unknown_resource_estimate"))
    server_first_reasons: list[str] = []
    if estimate["peak_footprint_gib"] > 1.0:
        server_first_reasons.append("full_workload_data_over_1_GiB")
    if estimate["compute_minutes"] > 10.0:
        server_first_reasons.append("workload_runtime_over_10_minutes")
    if estimate["gpu_useful"]:
        server_first_reasons.append("GPU_useful")
    if estimate["full_dataset"] or estimate["full_model"]:
        server_first_reasons.append("full_dataset_or_model")
    if estimate["parallel_sweep"]:
        server_first_reasons.append("parallel_sweep_or_batch")
    estimate["server_first"] = bool(server_first_reasons)
    estimate["server_first_reasons"] = server_first_reasons
    return estimate


def normalize_hosts(state: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw_hosts = state.get("compute_hosts") or {}
    if isinstance(raw_hosts, list):
        hosts = {str(host.get("host_id")): dict(host) for host in raw_hosts if host.get("host_id")}
    elif isinstance(raw_hosts, dict):
        hosts = {str(host_id): dict(host or {}, host_id=str(host_id)) for host_id, host in raw_hosts.items()}
    else:
        hosts = {}
    # Capacity must come from a live local/remote scan.  An empty inventory is
    # intentionally unschedulable instead of receiving synthetic resources.
    return hosts


def agent_host_id(
    pool: dict[str, Any], profile: dict[str, Any], hosts: dict[str, dict[str, Any]]
) -> str | None:
    """Resolve where the model CLI/API process is authenticated and runs."""
    provider = str(profile.get("provider") or pool.get("provider") or "")
    if provider == "server_local":
        bound = str(pool.get("host_id") or "")
        return bound if bound in hosts else None
    explicit = str(pool.get("cli_host_id") or "")
    if explicit:
        host = hosts.get(explicit) or {}
        return explicit if host.get("reachable") and host.get("transport") == "local" else None
    if provider in DESKTOP_CLI_PROVIDERS:
        return next(
            (
                host_id
                for host_id, host in hosts.items()
                if host.get("reachable") and str(host.get("transport", "local")) == "local"
            ),
            None,
        )
    return None


def data_route(job: dict[str, Any], estimate: dict[str, Any], host_id: str, host: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    transport = str(host.get("transport", "local"))
    source = str(job.get("data_source", "none"))
    location = str(job.get("data_location", "unknown"))
    transfer_gib = numeric(job, "transfer_gib", estimate["download_gib"] or estimate["input_gib"])
    errors: list[str] = []
    gates: list[str] = []
    if required_linux_kernel(job):
        gates.append("verify_linux_kernel_compatibility")
    if job.get("requires_external_network") is True:
        gates.append("verify_external_network_evidence")
    if transport == "local":
        route = "local_existing_or_small_input"
    elif location == host_id:
        route = "already_on_execution_host"
    elif source == "public" and estimate["download_gib"] > 0:
        route = "download_directly_on_execution_host"
        if estimate["download_gib"] > 1.0:
            gates.extend(["verify_live_egress", "bulk_download_plan_before_execute"])
            if host.get("racknerd_route_helper"):
                gates.append("run_codex-racknerd-route_verify")
            if host.get("large_download_helper"):
                gates.append("run_codex-large-download_plan_then_execute")
    elif transfer_gib <= 0:
        route = "no_bulk_data_transfer"
    elif location in {"local", "local_mac"} and transfer_gib > 1.0:
        route = "blocked_local_mac_bulk_relay"
        errors.append("bulk_data_must_originate_and_terminate_on_remote_server")
    elif bool(job.get("private_local_only")):
        route = "blocked_private_local_only"
        errors.append("private_local_only_data")
    elif not bool(job.get("remote_transfer_authorized")):
        route = "awaiting_remote_transfer_authorization"
        errors.append("remote_transfer_not_authorized")
    else:
        route = "small_authorized_transfer_to_execution_host"
        gates.extend(["verify_license_privacy_sensitivity", "compare_counts_bytes_sha256"])
    return {
        "route": route,
        "source": source,
        "current_location": location,
        "transfer_gib": round(transfer_gib, 3),
        "gates": gates,
    }, errors


def host_fit(job: dict[str, Any], estimate: dict[str, Any], host_id: str, host: dict[str, Any]) -> tuple[bool, float, list[str], dict[str, Any], list[str]]:
    reasons: list[str] = []
    errors: list[str] = []
    tags = set(host.get("tags") or [])
    transport = str(host.get("transport", "local"))
    if not host.get("reachable", False):
        errors.append("host_unreachable")
    if host.get("project_path_exists") is False:
        errors.append("project_path_missing")
    selected_storage_path, selected_disk_total, selected_disk_free = storage_capacity(host)
    storage_status = storage_evidence_status(host)
    if storage_status == "stale":
        errors.append("storage_evidence_stale")
    elif (
        storage_status == "unknown"
        and transport == "ssh"
        and bool(host.get("require_fresh_storage_evidence", True))
    ):
        errors.append("storage_evidence_freshness_unknown")
    if host.get("project_path_writable") is False and selected_storage_path is None:
        errors.append("project_path_not_writable_and_no_writable_storage")
    local_only = bool(
        job.get("requires_local_gui")
        or job.get("requires_usb")
        or job.get("private_local_only")
    )
    if job.get("requires_apple") and "apple" not in tags:
        errors.append("requires_apple_host")
    if local_only and transport != "local":
        errors.append("requires_local_machine")
    if estimate["server_first"] and transport == "local" and not local_only and not job.get("allow_local_full_run"):
        errors.append("server_first_requires_remote_host")
    if estimate["pilot_required"] and not job.get("pilot"):
        errors.append("resource_metadata_or_pilot_required")
    minimum_kernel = estimate.get("min_linux_kernel") or required_linux_kernel(job)
    if minimum_kernel:
        if _version_tuple(minimum_kernel) is None:
            errors.append("linux_kernel_requirement_invalid")
        else:
            kernel_status = kernel_evidence_status(host, minimum_kernel)
            if kernel_status == "blocked":
                errors.append("linux_kernel_below_minimum")
            elif kernel_status != "verified":
                errors.append("linux_kernel_evidence_unknown")
    if job.get("requires_external_network") is True:
        network_status = external_network_evidence_status(host, host_id=host_id)
        if network_status == "stale":
            errors.append("external_network_evidence_stale")
        elif network_status == "blocked":
            errors.append("external_network_blocked")
        elif network_status != "verified":
            errors.append("external_network_unverified")
    # Wall-clock evidence is required only for jobs that explicitly use
    # timestamp-based leases, planned ends, or cross-host temporal windows.
    # This keeps ordinary remote CPU/data work compatible with legacy hosts
    # while preventing a node with a materially skewed clock from accepting a
    # bounded continuous run and immediately expiring its own deadline.
    if job.get("requires_clock_sync") is True:
        clock_status = clock_evidence_status(host)
        if clock_status == "stale":
            errors.append("clock_evidence_stale")
        elif clock_status == "unsynchronized":
            errors.append("clock_sync_service_unsynchronized")
        elif clock_status == "blocked":
            errors.append("clock_skew_exceeds_limit")
        elif clock_status != "verified":
            errors.append("clock_evidence_unverified")

    allow_unknown_capacity = bool(job.get("allow_unknown_resource_capacity"))
    logical_raw = host.get("logical_cpu_cores")
    logical = max(1, int(logical_raw or 1))
    available_raw = host.get("estimated_idle_cpu_cores")
    # An observed value of zero means the host is currently saturated.  Do
    # not treat it as missing and silently fall back to all logical cores;
    # unknown capacity is handled separately by the explicit gate below.
    available_cpu = (
        max(0, int(float(available_raw)))
        if available_raw not in (None, "")
        else logical
    )
    ram_raw = host.get("memory_available_gib")
    ram_available = float(ram_raw or 0)
    disk_raw = selected_disk_free
    disk_free = float(selected_disk_free or 0)
    disk_total = float(selected_disk_total or 0)
    if not allow_unknown_capacity:
        if logical_raw in (None, "") or available_raw in (None, ""):
            errors.append("cpu_capacity_unknown")
        if ram_raw in (None, ""):
            errors.append("available_ram_unknown")
        if disk_raw in (None, ""):
            errors.append("free_disk_unknown")
    load_raw = host.get("load1")
    if transport == "local" and load_raw not in (None, ""):
        try:
            load_value = float(load_raw)
        except (TypeError, ValueError):
            load_value = None
        # A high load average is a placement hard gate.  It is not safe to
        # compensate for a saturated laptop with a small task-size estimate;
        # route server-compatible work to SSH and leave local-only work
        # explicitly blocked for operator review.
        if load_value is not None and load_value > logical * 1.5:
            errors.append("local_load_critical")
    if transport == "local":
        pressure_state = str(host.get("memory_pressure_state") or "unknown").lower()
        if pressure_state in {"critical", "conserve"}:
            errors.append(f"local_memory_pressure_{pressure_state}")
        if host.get("local_agent_launch_allowed") is False:
            errors.append("local_agent_launch_blocked")
    if estimate["cpu_cores"] > available_cpu:
        errors.append("insufficient_idle_cpu")
    if ram_raw not in (None, "") and estimate["required_available_ram_gib"] > ram_available:
        errors.append("insufficient_available_ram")
    if disk_raw not in (None, "") and estimate["required_free_disk_gib"] > disk_free:
        errors.append("insufficient_free_disk")
    if transport == "local" and disk_free and disk_total:
        low_local_disk = disk_free < 20.0 or disk_free / disk_total < 0.10
        if low_local_disk and disk_free < 2.0:
            errors.append("local_disk_critical_below_2_GiB")
        elif low_local_disk and estimate["new_disk_gib"] > 0.25:
            errors.append("local_disk_below_20_GiB_or_10_percent")

    commands = set((host.get("commands") or {}).keys())
    missing_commands = [command for command in estimate["required_commands"] if command not in commands]
    if missing_commands:
        errors.append("missing_commands:" + ",".join(missing_commands))
    if estimate.get("python_version"):
        observed = str((host.get("python") or {}).get("version") or "")
        if not observed.startswith(str(estimate["python_version"])):
            errors.append("python_version_mismatch")

    eligible_gpus = []
    if estimate["gpu_useful"]:
        for gpu in host.get("gpus") or []:
            free_vram = gpu.get("vram_free_gib")
            if gpu.get("unified_memory") and job.get("allow_unified_memory_gpu"):
                free_vram = ram_available
            if free_vram is None and estimate["vram_gib"] > 0:
                continue
            if free_vram is not None and float(free_vram) < estimate["vram_gib"]:
                continue
            if float(gpu.get("utilization_percent") or 0) >= 95:
                continue
            eligible_gpus.append(gpu)
        if len(eligible_gpus) < estimate["gpu_count"]:
            errors.append("insufficient_gpu_or_vram")

    route, route_errors = data_route(job, estimate, host_id, host)
    if selected_storage_path:
        route["storage_path"] = selected_storage_path
        if selected_storage_path != str(host.get("project_path") or ""):
            reasons.append(f"workload_storage_path={selected_storage_path}")
    errors.extend(route_errors)
    score = 25.0
    if estimate["server_first"] and transport == "ssh":
        score += 15
        reasons.append("server_first_remote_fit=15")
    elif not estimate["server_first"] and transport == "local":
        score += 8
        reasons.append("interactive_locality=8")
    if "direct-link" in tags:
        score += 5
        reasons.append("direct_link=5")
    if host.get("paid"):
        score -= 5 if job.get("allow_paid_compute", True) else 40
        reasons.append("paid_compute_penalty")
    load1 = float(host.get("load1") or 0)
    ram_total = float(host.get("memory_total_gib") or ram_available or 1)
    cpu_post_ratio = min(1.0, max(0.0, (logical - available_cpu + estimate["cpu_cores"]) / logical))
    ram_post_ratio = min(1.0, max(0.0, (ram_total - ram_available + estimate["ram_gib"]) / ram_total))
    requested_to_capacity = (cpu_post_ratio + ram_post_ratio) / 2.0
    if transport == "ssh":
        # Kubernetes/Ray-style bin packing: use existing remote capacity densely
        # while the hard-fit stage above preserves RAM/disk/GPU headroom.
        score += requested_to_capacity * 12.0
        reasons.append(f"requested_to_capacity_ratio={requested_to_capacity:.2f}")
    else:
        # Interactive laptops favor spare capacity instead of maximum packing.
        score += (1.0 - requested_to_capacity) * 8.0
        reasons.append(f"least_allocated_interactive_score={1.0-requested_to_capacity:.2f}")
    score += max(-12.0, 8.0 * (1.0 - load1 / logical))
    if not estimate["gpu_useful"] and int(host.get("gpu_count") or len(host.get("gpus") or [])):
        score -= 18
        reasons.append("gpu_node_sparing_penalty=18")
    if estimate["gpu_useful"] and eligible_gpus:
        score += 16
        reasons.append("gpu_vram_fit=16")
        if estimate["vram_gib"]:
            fitting_ratios = [
                estimate["vram_gib"] / float(gpu.get("vram_free_gib") or ram_available or estimate["vram_gib"])
                for gpu in eligible_gpus
            ]
            vram_pack = min(1.0, max(fitting_ratios))
            score += vram_pack * 10
            reasons.append(f"vram_bin_pack_ratio={vram_pack:.2f}")
    if route["route"] in {"already_on_execution_host", "download_directly_on_execution_host"}:
        score += 8
        reasons.append("data_locality=8")
    reasons.extend(
        [
            f"cpu={estimate['cpu_cores']}/{available_cpu}_idle",
            f"ram={estimate['ram_gib']:.2f}/{ram_available:.2f}_GiB_available",
            f"new_disk={estimate['new_disk_gib']:.2f}/{disk_free:.2f}_GiB_free",
        ]
    )
    return not errors, score, reasons, route, errors


def candidate_score(
    job: dict[str, Any], pool_id: str, pool: dict[str, Any], profile: dict[str, Any]
) -> tuple[float, list[str]]:
    difficulty = float(job.get("difficulty", 2))
    task_type = str(job.get("task_type", "text"))
    remaining = pool.get("effective_remaining_percent")
    health = str(pool.get("health", "unknown"))
    priority = priority_value(job)
    score = priority * 18.0
    reasons = [f"priority={priority}"]

    difficulty_fit = max(0.0, 24.0 - abs(difficulty - profile["difficulty_center"]) * 7.0)
    score += difficulty_fit
    reasons.append(f"difficulty_fit={difficulty_fit:.1f}")

    if task_type in profile["tasks"]:
        score += 14.0
        reasons.append("task_fit=14")
    score += float(profile["quality"]) * difficulty * 4.0

    latency = str(job.get("latency_priority", "normal"))
    if latency == "high":
        speed_bonus = float(profile["speed"]) * 16.0
    elif latency == "low":
        speed_bonus = float(profile["speed"]) * 4.0
    else:
        speed_bonus = float(profile["speed"]) * 9.0
    score += speed_bonus
    reasons.append(f"speed_bonus={speed_bonus:.1f}")

    # Unknown quota is bounded by the policy gate in ``plan``; it must not be
    # turned into a fabricated numeric balance merely to influence ranking.
    # A pilot candidate can still compete on quality/latency/cost evidence,
    # with its uncertainty recorded separately in the decision trace.
    if remaining is None:
        reasons.append("quota_remaining_unknown:no_numeric_score")
    else:
        score += math.sqrt(max(0.0, float(remaining))) * 2.0
    score += float(profile.get("primary_bonus", 0))
    if profile.get("primary_bonus"):
        reasons.append(f"user_primary_bonus={profile['primary_bonus']}")
    score -= HEALTH_PENALTY.get(health, 30)
    failures = pool.get("recent_failures") or []
    failure_count = failures if isinstance(failures, int) else len(failures)
    score -= min(30, failure_count * 8)

    preferred = set(job.get("preferred_pools") or [])
    if pool_id in preferred:
        score += 18
        reasons.append("preferred_pool=18")
    avoid = set(job.get("avoid_providers") or [])
    if profile["provider"] in avoid:
        score -= 40
        reasons.append("provider_diversity_penalty=40")
    return score, reasons


def select_pool_model(
    job: dict[str, Any], pool_id: str, pool: dict[str, Any], profile: dict[str, Any]
) -> tuple[str | None, str | None, str | None]:
    """Choose an exact model inside one shared pool without inventing capacity.

    OpenCode Go is a shared subscription pool.  Its catalogue contains several
    models with materially different usage multipliers, so choosing a role
    candidate from the catalogue is a spend decision.  The task must therefore
    carry an exact model approval before this function can select an OpenCode
    model; a role/default candidate is never an implicit approval.  The
    ``needs_approval`` role is consumed by :func:`plan` and surfaced as a
    blocked/deferred item instead of silently switching models.
    """

    def _model_values(value: Any) -> set[str]:
        """Extract exact model ids from the small task-policy dialect."""
        if isinstance(value, str):
            return {value} if value.strip() else set()
        if isinstance(value, Mapping):
            # A single exact approval may be represented as
            # ``{"model": "..."}`` or ``{"exact_model": "..."}``.
            for key in ("model", "exact_model"):
                if value.get(key):
                    return _model_values(value.get(key))
            for key in ("models", "allowed_models", "approved_models"):
                if key in value:
                    return _model_values(value.get(key))
            return set()
        if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
            result: set[str] = set()
            for item in value:
                result.update(_model_values(item))
            return result
        return set()

    def _exact_approvals() -> set[str]:
        """Read only task-level exact approvals, never pool defaults."""
        approved: set[str] = set()
        # ``model_by_pool`` is the legacy exact per-pool contract.  Keep it
        # authoritative and parse it before the broader allow-list fields.
        overrides = job.get("model_by_pool") or {}
        override = overrides.get(pool_id) if isinstance(overrides, Mapping) else None
        if override:
            approved.update(_model_values(override))
        policy = job.get("__dispatch_policy") or job.get("policy")
        for source in (job.get("approved_models"), job.get("allowed_models")):
            if isinstance(source, Mapping):
                approved.update(_model_values(source.get(pool_id)))
            else:
                approved.update(_model_values(source))
        if isinstance(policy, Mapping):
            for key in ("approved_models", "allowed_models"):
                source = policy.get(key)
                if isinstance(source, Mapping):
                    approved.update(_model_values(source.get(pool_id)))
                else:
                    approved.update(_model_values(source))
            # A compact task contract may carry one exact model under a
            # ``model_approval`` object.  It remains task-local and exact.
            approval = policy.get("model_approval")
            if isinstance(approval, Mapping):
                approved.update(_model_values(approval.get(pool_id, approval)))
            else:
                approved.update(_model_values(approval))
        approval = job.get("model_approval")
        if isinstance(approval, Mapping):
            approved.update(_model_values(approval.get(pool_id, approval)))
        else:
            approved.update(_model_values(approval))
        return {model for model in approved if model}

    catalog = set(str(item) for item in (pool.get("catalog_models") or []) if item)
    policy_excluded = set(str(item) for item in (pool.get("policy_excluded_models") or []) if item)
    explicit_policy_opt_in = {
        str(item)
        for item in (job.get("allow_policy_excluded_models") or [])
        if item
    }
    # Keep the default policy exclusion intact, but permit a user-authored,
    # exact-model opt-in for a visible catalog member.  This is intentionally
    # narrow: the model must be named in both the task and the current pool
    # snapshot, and it remains charged to the same shared quota pool.
    catalog.update(policy_excluded & explicit_policy_opt_in)
    rejected = set(str(item) for item in (pool.get("rejected_models") or []) if item)
    rejected_variants = {
        str(model): {str(variant) for variant in (variants or []) if variant}
        for model, variants in (pool.get("rejected_model_variants") or {}).items()
    }
    available_variants = {
        str(model): {str(variant) for variant in (variants or []) if variant}
        for model, variants in (pool.get("available_model_variants") or {}).items()
    }

    def eligible(candidate: str, variant: str | None) -> bool:
        base_eligible = bool(
            candidate
            and candidate not in rejected
            and (not catalog or candidate in catalog)
            and (not variant or variant not in rejected_variants.get(candidate, set()))
        )
        if not base_eligible:
            return False
        if variant and profile.get("provider") == "opencode":
            return variant in available_variants.get(candidate, set())
        return True

    override = (job.get("model_by_pool") or {}).get(pool_id)
    if isinstance(override, dict):
        requested = str(override.get("model") or "")
        variant = str(override.get("variant") or "") or None
    else:
        requested = str(override or "")
        variant = None
    if requested:
        if not eligible(requested, variant):
            return None, None, None
        role = "explicit_policy_override" if requested in policy_excluded else "explicit"
        return requested, variant, role

    exact_approvals = _exact_approvals()
    if profile.get("provider") == "opencode" and not exact_approvals:
        # Never spend from OpenCode Go merely because a catalogue/default role
        # exists.  The caller records this as a durable needs-approval gate.
        return None, None, "needs_approval"

    # Non-OpenCode providers can also expose role candidates from preflight.
    # This keeps Cursor/Antigravity dynamic within their shared pool without
    # pretending each model has an independent quota counter.
    generic_role_models = pool.get("role_models") or {}
    if generic_role_models and profile.get("provider") != "opencode":
        difficulty = int(job.get("difficulty", 2))
        task_type = str(job.get("task_type", "text"))
        latency = str(job.get("latency_priority", "normal"))
        if difficulty <= 1 or task_type == "monitor" or latency == "high":
            role = "efficient"
        elif task_type == "code" and difficulty <= 3:
            role = "code"
        else:
            role = "hard"
        candidates = list((pool.get("role_model_candidates") or {}).get(role) or [])
        if not candidates:
            candidates = [generic_role_models.get(role) or pool.get("default_model") or profile.get("model")]
        for candidate in candidates:
            candidate_name = str(candidate.get("model") if isinstance(candidate, dict) else candidate or "")
            candidate_variant = str(candidate.get("variant") or "") or None if isinstance(candidate, dict) else None
            if eligible(candidate_name, candidate_variant):
                return candidate_name, candidate_variant, role
        return None, None, role

    if profile.get("provider") == "opencode":
        difficulty = int(job.get("difficulty", 2))
        task_type = str(job.get("task_type", "text"))
        latency = str(job.get("latency_priority", "normal"))
        if difficulty <= 1 or task_type == "monitor" or latency == "high":
            role = "efficient"
        elif task_type == "code" and difficulty <= 3:
            role = "code"
        else:
            role = "hard"
        role_candidates = pool.get("role_model_candidates") or {}
        candidates = list(role_candidates.get(role) or [])
        candidate_roles = [role] * len(candidates)
        for fallback_role in ("code", "efficient", "hard"):
            if fallback_role == role:
                continue
            fallback_rows = list(role_candidates.get(fallback_role) or [])
            candidates.extend(fallback_rows)
            candidate_roles.extend([fallback_role] * len(fallback_rows))
        if not candidates:
            role_models = pool.get("role_models") or {}
            candidates = [role_models.get(role) or pool.get("default_model") or profile.get("model")]
            candidate_roles = [role]
        # An allow-list is still an exact task approval, not permission to
        # fall back to any other member of the shared Go pool.  Preserve the
        # role ordering for multiple explicitly approved models, then append
        # any approved catalogue members not advertised by the role table.
        if exact_approvals:
            filtered = [
                (row, candidate_role)
                for row, candidate_role in zip(candidates, candidate_roles)
                if str(row.get("model") if isinstance(row, dict) else row or "") in exact_approvals
            ]
            candidates = [row for row, _candidate_role in filtered]
            candidate_roles = [candidate_role for _row, candidate_role in filtered]
            variants = pool.get("model_variants") or {}
            seen_approved = {
                str(row.get("model") if isinstance(row, dict) else row or "")
                for row in candidates
            }
            for approved in sorted(exact_approvals - seen_approved):
                candidates.append({"model": approved, "variant": variants.get(approved)})
                source_role = next(
                    (
                        candidate_role
                        for candidate_role, rows in role_candidates.items()
                        for row in (rows or [])
                        if str(row.get("model") if isinstance(row, dict) else row or "") == approved
                    ),
                    role,
                )
                candidate_roles.append(source_role)
        variants = pool.get("model_variants") or {}
        seen: set[tuple[str, str | None]] = set()
        for row, candidate_role in zip(candidates, candidate_roles):
            if isinstance(row, dict):
                candidate = str(row.get("model") or "")
                selected_variant = str(row.get("variant") or "") or None
            else:
                candidate = str(row or "")
                selected_variant = str(variants.get(candidate) or "") or None
            exact = (candidate, selected_variant)
            if exact in seen:
                continue
            seen.add(exact)
            if eligible(candidate, selected_variant):
                selected_role = role if candidate_role == role else f"{role}_fallback_{candidate_role}"
                return candidate, selected_variant, selected_role
        return None, None, role

    candidate = str(pool.get("model") or pool.get("default_model") or profile.get("model") or "")
    selected_variant = str(pool.get("default_variant") or "") or None
    if not eligible(candidate, selected_variant):
        return None, None, None
    return candidate, selected_variant, None


def plan(
    state: dict[str, Any], jobs_payload: Any, max_lanes: int, horizon: int
) -> dict[str, Any]:
    jobs = jobs_payload.get("jobs", []) if isinstance(jobs_payload, dict) else jobs_payload
    if not isinstance(jobs, list):
        raise ValueError("jobs input must be a list or an object with a jobs list")
    pools = state.get("pools") or {}
    hosts = normalize_hosts(state)
    completed = {
        item.get("job_id") if isinstance(item, dict) else str(item)
        for item in state.get("completed_jobs", [])
    }
    completed.update(str(job.get("job_id")) for job in jobs if job.get("status") == "completed")
    active = {
        str(worker.get("job_id"))
        for worker in state.get("workers", [])
        if worker.get("status") in {"running", "starting", "healthy", "stalled"}
    }

    dependency_wait: list[dict[str, Any]] = []
    ready: list[dict[str, Any]] = []
    for raw_job in jobs:
        job = dict(raw_job)
        job_id = str(job.get("job_id") or "")
        if not job_id or job_id in completed or job_id in active:
            continue
        missing = [str(dep) for dep in job.get("depends_on", []) if str(dep) not in completed]
        if missing:
            dependency_wait.append({"job_id": job_id, "reason": "dependencies", "missing": missing})
        else:
            ready.append(job)
    # Priority first, then shorter work for safe backfilling, then difficulty.
    ready.sort(
        key=lambda job: (
            -priority_value(job),
            resource_estimate(job)["compute_minutes"] or float("inf"),
            -int(job.get("difficulty", 2)),
            str(job.get("job_id")),
        )
    )
    considered = ready[: max(1, horizon)]
    estimates = [resource_estimate(job) for job in considered]

    pool_ids: list[str] = []
    budgets: list[int] = []
    pool_slots: list[int] = []
    pool_profiles: dict[str, dict[str, Any]] = {}
    quota_uncertainty: dict[str, dict[str, Any]] = {}
    planning_policy = state.get("planning_policy") or {}
    for pool_id, raw_pool in pools.items():
        profile = POOL_PROFILES.get(pool_id)
        if not profile and (
            str((raw_pool or {}).get("provider")) == "server_local"
            or str(pool_id).startswith("server_local.")
        ):
            profile = dict(SERVER_LOCAL_PROFILE)
            profile.update((raw_pool or {}).get("profile") or {})
        if not profile:
            continue
        pool = raw_pool or {}
        if str(pool.get("health", "unknown")) in BLOCKED_HEALTH:
            continue
        remaining = pool.get("effective_remaining_percent")
        reserve = _reserve_percent(pool, profile)
        if reserve is None:
            quota_uncertainty[pool_id] = {
                "state": "invalid",
                "reason": "reserve_percent_must_be_finite_between_0_and_100",
            }
            continue
        unknown_policy = ""
        if remaining is None:
            # Unknown quota is never interpreted as a remaining balance.  A
            # bounded pilot cap is an explicit policy allowance that limits
            # exposure until a provider reports attributable usage. Set
            # ``unknown_quota_policy=pilot`` is an explicit provider/policy
            # opt-in; unknown quota is otherwise fail-closed so a missing
            # usage endpoint cannot silently spend a shared subscription.
            unknown_policy = str(
                pool.get("unknown_quota_policy")
                or planning_policy.get("unknown_quota_policy")
                or "block"
            ).lower()
            if unknown_policy in {"block", "defer", "fail_closed"}:
                continue
            pilot_cap = float(
                pool.get("unknown_quota_pilot_percent")
                or planning_policy.get("unknown_quota_pilot_percent")
                or 5.0
            )
            if pilot_cap <= 0:
                continue
            quota_uncertainty[pool_id] = {
                "state": "unknown",
                "policy": "pilot_cap",
                "pilot_cap_percent": round(pilot_cap, 3),
            }
            budget_units = max(1, int(math.ceil(pilot_cap * 10)))
        else:
            remaining_value = int(remaining)
            budget_units = max(0, (remaining_value - reserve) * 10)
        pool_ids.append(pool_id)
        budgets.append(budget_units)
        configured_slots = max(0, int(pool.get("max_concurrency", 1)) - int(pool.get("inflight", 0)))
        if remaining is None and unknown_policy in {"pilot", "bounded_pilot", "pilot_cap"}:
            # Unknown shared-pool balance is allowed only as a bounded pilot.
            # One lane prevents a parallel probe from consuming the entire
            # unobservable subscription before feedback.
            configured_slots = min(1, configured_slots)
            quota_uncertainty[pool_id]["max_concurrency"] = 1
        pool_slots.append(configured_slots)
        pool_profiles[pool_id] = profile

    host_ids = list(hosts)
    host_slots: list[int] = []
    host_cpu: list[int] = []
    host_ram: list[int] = []
    host_disk: list[int] = []
    host_gpu: list[int] = []
    for host_id in host_ids:
        host = hosts[host_id]
        logical = max(1, int(host.get("logical_cpu_cores") or 1))
        observed_idle = host.get("estimated_idle_cpu_cores")
        available_cpu = (
            max(0, int(float(observed_idle)))
            if observed_idle not in (None, "")
            else 0
        )
        gpu_count = int(host.get("gpu_count") or len(host.get("gpus") or []))
        # GPU presence is a resource capability, not a host-wide lane count.
        # In particular, Apple unified GPU discovery must not serialize four
        # independent CPU-light CLI workers to a single lane.
        default_concurrency = min(4, max(1, logical // 2))
        slots = max(0, int(host.get("max_concurrency", default_concurrency)) - int(host.get("inflight", 0)))
        if str(host.get("transport") or "local") == "local" and host.get("local_agent_launch_allowed") is False:
            slots = 0
        host_slots.append(slots)
        host_cpu.append(available_cpu)
        host_ram.append(max(1, int(math.floor(float(host.get("memory_available_gib") or 0) * 2))))
        _, _, writable_disk_free = storage_capacity(host)
        host_disk.append(max(1, int(math.floor(float(writable_disk_free or 0) * 2))))
        host_gpu.append(gpu_count)

    conflicts = [0] * len(considered)
    for i, left in enumerate(considered):
        for j, right in enumerate(considered):
            if i != j and scopes_conflict(left.get("write_scope"), right.get("write_scope")):
                conflicts[i] |= 1 << j

    host_fit_cache: dict[tuple[int, int], dict[str, Any]] = {}
    host_failures: dict[int, dict[str, list[str]]] = {}
    for job_index, job in enumerate(considered):
        allowed_hosts = set(job.get("allowed_hosts") or host_ids)
        excluded_hosts = set(job.get("excluded_hosts") or [])
        for host_index, host_id in enumerate(host_ids):
            if host_id not in allowed_hosts or host_id in excluded_hosts:
                continue
            fit, score, reasons, route, errors = host_fit(
                job, estimates[job_index], host_id, hosts[host_id]
            )
            if errors:
                host_failures.setdefault(job_index, {})[host_id] = errors
            if fit and host_slots[host_index] > 0:
                host_fit_cache[(job_index, host_index)] = {
                    "score": score,
                    "reasons": reasons,
                    "data_route": route,
                }

    candidate_cache: dict[tuple[int, int, int], dict[str, Any]] = {}
    pool_candidate_jobs: set[int] = set()
    model_approval_blocks: dict[int, list[dict[str, Any]]] = {}
    for job_index, job in enumerate(considered):
        # An exact per-pool model request is also an implicit pool allow-list.
        # Without this boundary, a blocked or saturated requested pool could
        # silently fall back to an unrelated provider/model, violating the
        # task's explicit model contract and potentially spending another
        # subscription's quota.  Callers may still provide ``allowed_pools``
        # to narrow a multi-pool role; explicit model keys always remain the
        # authoritative candidate set.
        explicit_model_pools = {
            str(pool_id)
            for pool_id in (job.get("model_by_pool") or {})
            if pool_id
        }
        allowed = set(job.get("allowed_pools") or (explicit_model_pools or pool_ids))
        excluded = set(job.get("excluded_pools") or [])
        for pool_index, pool_id in enumerate(pool_ids):
            if pool_id not in allowed or pool_id in excluded or pool_slots[pool_index] <= 0:
                continue
            pool = pools[pool_id]
            profile = pool_profiles[pool_id]
            model, model_variant, model_role = select_pool_model(job, pool_id, pool, profile)
            if not model:
                if model_role == "needs_approval":
                    candidates = sorted(
                        {
                            str(row.get("model") if isinstance(row, dict) else row or "")
                            for rows in (pool.get("role_model_candidates") or {}).values()
                            for row in (rows or [])
                            if str(row.get("model") if isinstance(row, dict) else row or "")
                        }
                    )
                    model_approval_blocks.setdefault(job_index, []).append(
                        {
                            "job_id": str(job.get("job_id")),
                            "pool_id": pool_id,
                            "status": "blocked",
                            "reason": "needs_approval",
                            "gate": "exact_model_approval",
                            "candidate_models": candidates,
                            "message": (
                                "OpenCode Go model selection requires a task-level "
                                "exact model approval; role/default candidates are not "
                                "auto-authorized"
                            ),
                        }
                    )
                continue
            if profile.get("provider") == "server_local":
                if job.get("allow_server_local") is False:
                    continue
                max_difficulty = int(pool.get("max_difficulty", 3))
                if int(job.get("difficulty", 2)) > max_difficulty and not job.get("allow_unreviewed_server_local"):
                    continue
                if (job.get("high_stakes") or str(job.get("task_type")) == "audit") and not job.get("allow_unreviewed_server_local"):
                    continue
            cost_percent = quota_cost(job, pool_id, pool, profile, model=model)
            cost_units = max(1, int(math.ceil(cost_percent * 10)))
            allow_reserve = bool(job.get("allow_reserve")) or priority_value(job) >= 4
            if cost_units > budgets[pool_index] and not allow_reserve:
                continue
            model_score, model_reasons = candidate_score(job, pool_id, pool, profile)
            price_efficiency = float(profile["quality"]) * 18.0 / math.sqrt(cost_percent + 0.2)
            model_score += min(30.0, price_efficiency)
            usd_cost = estimated_usd_cost(job, pool, model)
            if usd_cost is None:
                # Missing price metadata is uncertainty, not a free model.
                # Keep the candidate eligible when subscription quota permits,
                # but expose the uncertainty for policy/audit and avoid
                # rewarding it in the cost objective.
                model_score -= 2.0
                model_reasons.append("usd_cost_unknown")
            else:
                # Favor genuinely cheaper models for bounded work while
                # keeping quality/quota/host fit as the primary objective.
                cost_bonus = min(12.0, 0.12 / max(0.001, usd_cost))
                model_score += cost_bonus
                model_reasons.append(f"estimated_usd_cost={usd_cost:.6f}")
                model_reasons.append(f"usd_cost_efficiency={cost_bonus:.1f}")
            remaining_for_penalty = pool.get("effective_remaining_percent")
            if remaining_for_penalty is None:
                model_score -= cost_percent * 1.8
                model_reasons.append("quota_remaining_unknown: bounded pilot cap only")
            else:
                model_score -= cost_percent * (1.4 if int(remaining_for_penalty) < 40 else 0.75)
            model_reasons.extend(
                [
                    f"estimated_agent_minutes={estimated_minutes(job):.1f}",
                    f"estimated_quota_cost={cost_percent:.3f}%",
                    f"price_efficiency={min(30.0, price_efficiency):.1f}",
                ]
            )
            cli_host_id = agent_host_id(pool, profile, hosts)
            if not cli_host_id:
                continue
            if cli_host_id in {str(item) for item in (job.get("excluded_execution_hosts") or [])}:
                continue
            cli_host_index = host_ids.index(cli_host_id)
            pool_candidate_jobs.add(job_index)
            for host_index in range(len(host_ids)):
                bound_host = pool.get("host_id") if profile.get("provider") == "server_local" else None
                if bound_host and host_ids[host_index] != str(bound_host):
                    continue
                workload_excluded = {
                    str(item)
                    for item in (
                        list(job.get("excluded_workload_hosts") or [])
                        + list(job.get("excluded_hosts") or [])
                    )
                }
                if host_ids[host_index] in workload_excluded:
                    continue
                if (
                    profile.get("provider") in DESKTOP_CLI_PROVIDERS
                    and not estimates[job_index]["server_first"]
                    and not job.get("separate_compute_host")
                    and host_index != cli_host_index
                ):
                    continue
                fit = host_fit_cache.get((job_index, host_index))
                if not fit:
                    continue
                candidate_cache[(job_index, pool_index, host_index)] = {
                    "score": model_score + float(fit["score"]),
                    "pool_cost_units": cost_units,
                    "quota_cost_percent": cost_percent,
                    "estimated_usd_cost": usd_cost,
                    "estimated_input_tokens": _token_bound(job, "input"),
                    "estimated_output_tokens": _token_bound(job, "output"),
                    "quota_evidence": (
                        "unknown_pilot_cap" if pool_id in quota_uncertainty else "observed_remaining"
                    ),
                    "model": str(model),
                    "model_variant": model_variant,
                    "model_role": model_role,
                    "model_reasons": model_reasons,
                    "host_reasons": fit["reasons"],
                    "data_route": fit["data_route"],
                    "agent_host_index": cli_host_index,
                }

    @functools.lru_cache(maxsize=None)
    def solve(
        index: int,
        remaining_budgets: tuple[int, ...],
        remaining_pool_slots: tuple[int, ...],
        remaining_host_slots: tuple[int, ...],
        remaining_host_cpu: tuple[int, ...],
        remaining_host_ram: tuple[int, ...],
        remaining_host_disk: tuple[int, ...],
        remaining_host_gpu: tuple[int, ...],
        chosen_mask: int,
        lanes_left: int,
    ) -> tuple[float, tuple[tuple[int, int, int], ...]]:
        if index >= len(considered) or lanes_left <= 0:
            return 0.0, ()
        best_score, best_choices = solve(
            index + 1, remaining_budgets, remaining_pool_slots,
            remaining_host_slots, remaining_host_cpu, remaining_host_ram,
            remaining_host_disk, remaining_host_gpu, chosen_mask, lanes_left,
        )
        if conflicts[index] & chosen_mask:
            return best_score, best_choices
        estimate = estimates[index]
        cpu_units = int(estimate["cpu_cores"])
        ram_units = max(1, int(math.ceil(estimate["ram_gib"] * 2)))
        disk_units = max(1, int(math.ceil(estimate["new_disk_gib"] * 2)))
        gpu_units = int(estimate["gpu_count"])
        for pool_index in range(len(pool_ids)):
            if remaining_pool_slots[pool_index] <= 0:
                continue
            for host_index in range(len(host_ids)):
                candidate = candidate_cache.get((index, pool_index, host_index))
                if not candidate or remaining_host_slots[host_index] <= 0:
                    continue
                agent_index = int(candidate["agent_host_index"])
                if remaining_host_slots[agent_index] <= 0:
                    continue
                if (
                    cpu_units > remaining_host_cpu[host_index]
                    or ram_units > remaining_host_ram[host_index]
                    or disk_units > remaining_host_disk[host_index]
                    or gpu_units > remaining_host_gpu[host_index]
                ):
                    continue
                allow_reserve = bool(considered[index].get("allow_reserve")) or priority_value(considered[index]) >= 4
                cost_units = int(candidate["pool_cost_units"])
                if cost_units > remaining_budgets[pool_index] and not allow_reserve:
                    continue
                next_budgets = list(remaining_budgets)
                next_pool_slots = list(remaining_pool_slots)
                next_host_slots = list(remaining_host_slots)
                next_cpu = list(remaining_host_cpu)
                next_ram = list(remaining_host_ram)
                next_disk = list(remaining_host_disk)
                next_gpu = list(remaining_host_gpu)
                next_budgets[pool_index] = max(0, next_budgets[pool_index] - cost_units)
                next_pool_slots[pool_index] -= 1
                next_host_slots[host_index] -= 1
                if agent_index != host_index:
                    next_host_slots[agent_index] -= 1
                next_cpu[host_index] -= cpu_units
                next_ram[host_index] -= ram_units
                next_disk[host_index] -= disk_units
                next_gpu[host_index] -= gpu_units
                future_score, future_choices = solve(
                    index + 1, tuple(next_budgets), tuple(next_pool_slots),
                    tuple(next_host_slots), tuple(next_cpu), tuple(next_ram),
                    tuple(next_disk), tuple(next_gpu), chosen_mask | (1 << index),
                    lanes_left - 1,
                )
                total = float(candidate["score"]) + future_score
                if total > best_score:
                    best_score = total
                    best_choices = ((index, pool_index, host_index),) + future_choices
        return best_score, best_choices

    total_score, choices = solve(
        0, tuple(budgets), tuple(pool_slots), tuple(host_slots), tuple(host_cpu),
        tuple(host_ram), tuple(host_disk), tuple(host_gpu), 0, max_lanes,
    )
    assignments: list[dict[str, Any]] = []
    selected_jobs: set[int] = set()
    projected_quota = {
        pool_id: pools[pool_id].get("effective_remaining_percent") for pool_id in pool_ids
    }
    projected_hosts: dict[str, dict[str, Any]] = {}
    for job_index, pool_index, host_index in choices:
        job = considered[job_index]
        estimate = estimates[job_index]
        pool_id = pool_ids[pool_index]
        host_id = host_ids[host_index]
        candidate = candidate_cache[(job_index, pool_index, host_index)]
        cli_host_id = host_ids[int(candidate["agent_host_index"])]
        selected_pool = pools[pool_id]
        selected_jobs.add(job_index)
        if isinstance(projected_quota[pool_id], (int, float)):
            projected_quota[pool_id] = max(0, projected_quota[pool_id] - candidate["quota_cost_percent"])
        host_projection = projected_hosts.setdefault(
            host_id,
            {"jobs": [], "cpu_cores": 0, "ram_gib": 0.0, "new_disk_gib": 0.0, "gpu_count": 0},
        )
        host_projection["jobs"].append(str(job.get("job_id")))
        host_projection["cpu_cores"] += estimate["cpu_cores"]
        host_projection["ram_gib"] = round(host_projection["ram_gib"] + estimate["ram_gib"], 3)
        host_projection["new_disk_gib"] = round(host_projection["new_disk_gib"] + estimate["new_disk_gib"], 3)
        host_projection["gpu_count"] += estimate["gpu_count"]
        assignments.append(
            {
                "job_id": str(job.get("job_id")),
                "pool_id": pool_id,
                "model": candidate["model"],
                "variant": candidate.get("model_variant"),
                "model_role": candidate.get("model_role"),
                "execution_host": cli_host_id,
                "execution_transport": hosts[cli_host_id].get("transport"),
                "project_path": hosts[cli_host_id].get("project_path"),
                "workload_host": host_id,
                "workload_transport": hosts[host_id].get("transport"),
                "workload_project_path": (
                    storage_capacity(hosts[host_id])[0]
                    or hosts[host_id].get("project_path")
                ),
                "workload_storage_path": storage_capacity(hosts[host_id])[0],
                "score": round(float(candidate["score"]), 2),
                "estimated_quota_cost_percent": round(candidate["quota_cost_percent"], 3),
                "estimated_usd_cost": candidate.get("estimated_usd_cost"),
                "estimated_input_tokens": candidate.get("estimated_input_tokens"),
                "estimated_output_tokens": candidate.get("estimated_output_tokens"),
                "cost_evidence": (
                    "model_price_and_token_hints"
                    if candidate.get("estimated_usd_cost") is not None
                    else "unknown"
                ),
                "projected_remaining_percent": projected_quota[pool_id],
                "quota_evidence": candidate.get("quota_evidence", "observed_remaining"),
                "quota_policy": quota_uncertainty.get(pool_id),
                "resource_request": {
                    "cpu_cores": estimate["cpu_cores"],
                    "ram_gib": estimate["ram_gib"],
                    "gpu_count": estimate["gpu_count"],
                    "vram_gib_per_gpu": estimate["vram_gib"],
                    "new_disk_gib": estimate["new_disk_gib"],
                    "compute_minutes": estimate["compute_minutes"],
                },
                "resource_limit_or_headroom": {
                    "ram_gib": estimate["required_available_ram_gib"],
                    "free_disk_gib": estimate["required_free_disk_gib"],
                },
                "expected_utilization": {
                    "cpu_percent": estimate["expected_cpu_utilization_percent"],
                    "gpu_percent": estimate["expected_gpu_utilization_percent"],
                },
                "server_first": estimate["server_first"],
                "server_first_reasons": estimate["server_first_reasons"],
                "data_route": candidate["data_route"],
                "write_scope": job.get("write_scope"),
                "required_artifact": job.get("required_artifact"),
                "requires_provider_review": bool(
                    pool_profiles[pool_id].get("provider") == "server_local"
                    and (
                        selected_pool.get("requires_provider_review", True)
                        or int(job.get("difficulty", 2)) >= 3
                        or job.get("needs_independent_review")
                    )
                ),
                "model_reasons": candidate["model_reasons"],
                "host_reasons": candidate["host_reasons"],
            }
        )

    deferred = dependency_wait[:]
    for index, job in enumerate(considered):
        if index in selected_jobs:
            continue
        if index in model_approval_blocks:
            deferred.extend(model_approval_blocks[index])
            continue
        has_joint_candidate = any(key[0] == index for key in candidate_cache)
        if has_joint_candidate:
            reason = "capacity_or_better_global_assignment"
        elif index not in pool_candidate_jobs:
            reason = "no_eligible_model_pool"
        else:
            reason = "no_eligible_compute_host"
        item: dict[str, Any] = {"job_id": str(job.get("job_id")), "reason": reason}
        if reason == "no_eligible_compute_host":
            item["host_failures"] = host_failures.get(index, {})
            item["resource_estimate"] = estimates[index]
        deferred.append(item)
    for job in ready[len(considered):]:
        deferred.append({"job_id": str(job.get("job_id")), "reason": "outside_current_horizon"})

    now = dt.datetime.now(tz=dt.timezone.utc)
    monitor_config = state.get("monitor") or {}
    monitor_seconds = int(state.get("monitor_seconds", monitor_config.get("duration_seconds", 180)))
    monitor_replan_at = now + dt.timedelta(seconds=monitor_seconds)
    blocked_pool_reset = _next_blocked_pool_reset(pools, now)
    has_model_pool_block = any(
        item.get("reason") == "no_eligible_model_pool" for item in deferred
    )
    has_compute_host_block = any(
        item.get("reason") == "no_eligible_compute_host" for item in deferred
    )
    replan_at = monitor_replan_at
    replan_reason = "monitor_interval"
    if (
        not assignments
        and has_model_pool_block
        and not has_compute_host_block
        and blocked_pool_reset is not None
    ):
        reset_pool_id, reset_at = blocked_pool_reset
        replan_at = reset_at
        replan_reason = "blocked_pool_quota_reset"
    else:
        reset_pool_id = blocked_pool_reset[0] if blocked_pool_reset else None
    compute_gate = [
        {
            "job_id": str(job.get("job_id")),
            "resource_estimate": estimates[index],
            "eligible_hosts": [
                host_ids[host_index]
                for host_index in range(len(host_ids))
                if (index, host_index) in host_fit_cache
            ],
            "host_failures": host_failures.get(index, {}),
        }
        for index, job in enumerate(considered)
    ]
    approval_blocks = [
        item
        for index in sorted(model_approval_blocks)
        for item in model_approval_blocks[index]
    ]
    approval_state = (
        "needs_approval"
        if approval_blocks
        else (
            "approved"
            if any(str(item.get("pool_id")) == "opencode.go" for item in assignments)
            else "not_required"
        )
    )
    return {
        "ok": True,
        "planning_method": (
            "filter-score-reserve rolling horizon: resource requests/limits, "
            "bin-packing fit, priority/backfill ordering, separate agent/workload placement, "
            "joint model-pool and host DP"
        ),
        "planned_at_utc": now.isoformat(),
        "horizon_jobs": len(considered),
        "max_lanes": max_lanes,
        "objective_score": round(total_score, 2),
        "decision": "dispatch" if assignments else "pause",
        "model_approval": {
            "state": approval_state,
            "blocked": approval_blocks,
        },
        "compute_gate": compute_gate,
        "assignments": assignments,
        "projected_host_usage": projected_hosts,
        "quota_uncertainty": quota_uncertainty,
        "deferred": deferred,
        "feedback": {
            "monitor_seconds": monitor_seconds,
            "poll_interval_seconds": int(
                state.get("poll_interval_seconds", monitor_config.get("interval_seconds", 30))
            ),
            "replan_at_utc": replan_at.isoformat(),
            "replan_reason": replan_reason,
            "quota_reset_at_utc": (
                blocked_pool_reset[1].isoformat() if blocked_pool_reset else None
            ),
            "quota_reset_pool_id": reset_pool_id,
            "replan_events": [
                "job_completed", "job_failed", "artifact_progress", "stall_detected",
                "quota_changed", "runtime_model_rejected", "host_resource_changed",
                "gpu_memory_pressure", "disk_pressure", "remote_unreachable",
                "data_route_failed", "user_scope_changed",
            ],
        },
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True)
    parser.add_argument("--jobs", required=True)
    parser.add_argument("--max-lanes", type=int, default=4)
    parser.add_argument("--horizon", type=int, default=8)
    parser.add_argument("--output")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        result = plan(
            load_json(args.state),
            load_json(args.jobs),
            max(1, args.max_lanes),
            max(1, args.horizon),
        )
    except Exception as exc:
        result = {"ok": False, "error": str(exc)}
    write_json(args.output, result)
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
