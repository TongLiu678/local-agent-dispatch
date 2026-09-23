#!/usr/bin/env python3
"""Build an auditable, provider-free replan decision from monitor feedback.

This module is deliberately a boundary between observation and planning.  It
does not start a provider, mutate runtime state, or enqueue a job.  Instead it
turns the monitor report into deterministic constraints that the next
``dynamic_dispatch_planner.py`` invocation can consume:

* provider failures constrain a pool or an exact model/variant;
* compute failures constrain the affected ``execution_host`` and/or
  ``workload_host`` independently;
* host pressure alerts become soft/hard host constraints;
* unfinished jobs receive an explicit, copy-on-write retry patch.

The output is a dry-run artifact.  A controller may review/apply it later.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import math
import pathlib
import re
import sys
import tempfile
from typing import Any, Mapping


SCHEMA_VERSION = 1
PROVIDER_CLASSES = {
    "quota",
    "capability",
    "location_restricted",
    "auth",
    "network",
    "rate_limit",
}
COMPUTE_CLASSES = {
    "host_unreachable",
    "resource_exhausted",
    "resource_pressure",
    "disk_pressure",
    "memory_pressure",
    "gpu_memory_pressure",
    "compute",
}
PROVIDER_ORIGINS = {"provider", "provider_log", "worker_log"}
COMPUTE_ORIGINS = {
    "compute",
    "compute_host",
    "execution_host",
    "workload_host",
}
_QUOTA_RE = re.compile(r"usage limit|rate.?limit|quota (?:exhausted|unavailable)|spend limit", re.I)
_CAPABILITY_RE = re.compile(
    r"cannot use this model|unsupported model|not entitled|model (?:is )?not available",
    re.I,
)
_LOCATION_RE = re.compile(
    r"user\s+location\s+is\s+not\s+supported|location\s+is\s+not\s+supported|"
    r"(?:unsupported|unavailable)\s+(?:country|region|location)|"
    r"(?:country|region|location)\s+(?:is\s+)?not\s+supported|"
    r"not\s+available\s+in\s+(?:your\s+)?location|geographic(?:al)?\s+(?:restriction|block)",
    re.I,
)
_AUTH_RE = re.compile(r"unauthorized|forbidden|authentication|login required|invalid_grant", re.I)
_NETWORK_RE = re.compile(
    r"tls|connection (?:failed|reset)|network socket|timed? out|dns|econn", re.I
)
_CONTROLLER_TIMEOUT_RE = re.compile(
    r"(?:continuity|sqlite) controller[^\n]*(?:timed? out|timeout)", re.I
)
_HOST_RE = re.compile(
    r"host unreachable|compute host|disk pressure|out of memory|"
    r"out[- ]of[- ]memory|gpu memory|resource exhausted",
    re.I,
)

DEFAULT_REPLAN_MAX_WAIT_SECONDS = 300.0
MAX_REPLAN_WAIT_SECONDS = 3600.0


class ReplanError(ValueError):
    """Raised when a monitor report cannot be converted safely."""


def _parse_schedule_utc(value: Any, field: str) -> dt.datetime:
    """Parse an explicit timezone-aware UTC timestamp for scheduling.

    A scheduler must never interpret a naive timestamp in the machine's local
    timezone.  The planner emits ISO-8601 values, but this boundary still
    validates and canonicalizes them before they influence a wait decision.
    """

    if not isinstance(value, str) or not value.strip():
        raise ReplanError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise ReplanError(f"{field} must be a timezone-aware ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReplanError(f"{field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _schedule_seconds(value: Any, field: str, *, maximum: float) -> float:
    """Return a finite positive scheduling bound or raise a config error."""

    if isinstance(value, bool):
        raise ReplanError(f"{field} must be a finite positive number")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ReplanError(f"{field} must be a finite positive number") from exc
    if not math.isfinite(parsed) or parsed <= 0 or parsed > maximum:
        raise ReplanError(f"{field} is outside the supported scheduling range")
    return parsed


def build_replan_schedule(
    feedback: Mapping[str, Any] | None,
    *,
    now_utc: str | dt.datetime | None = None,
    max_wait_seconds: float = DEFAULT_REPLAN_MAX_WAIT_SECONDS,
) -> dict[str, Any]:
    """Convert planner feedback into a bounded, fail-closed wake hint.

    This is intentionally a pure consumer contract.  It does not sleep,
    invoke a provider, enqueue work, or mutate a controller.  A caller may
    sleep for ``sleep_seconds`` and then re-probe/replan, but must retain its
    normal heartbeat and resource checks while waiting.  Invalid or missing
    feedback is treated as ``due_now`` so a bad timestamp can never postpone
    safety observation indefinitely.
    """

    bound = _schedule_seconds(
        max_wait_seconds,
        "max_wait_seconds",
        maximum=MAX_REPLAN_WAIT_SECONDS,
    )
    if now_utc is None:
        now = dt.datetime.now(tz=dt.timezone.utc)
    elif isinstance(now_utc, dt.datetime):
        if now_utc.tzinfo is None or now_utc.utcoffset() is None:
            raise ReplanError("now_utc must include a timezone")
        now = now_utc.astimezone(dt.timezone.utc)
    else:
        now = _parse_schedule_utc(now_utc, "now_utc")

    base: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source": "planner_feedback",
        "replan_reason": str(feedback.get("replan_reason") or "unspecified")
        if isinstance(feedback, Mapping)
        else "feedback_missing",
        "max_wait_seconds": bound,
        "observed_at_utc": now.isoformat(),
        "target_replan_at_utc": None,
        "quota_reset_at_utc": None,
        "quota_reset_pool_id": None,
        "invalid_fields": [],
    }
    if not isinstance(feedback, Mapping):
        return {
            **base,
            "ok": False,
            "decision": "due_now",
            "due": True,
            "bounded": False,
            "sleep_seconds": 0.0,
            "wake_at_utc": now.isoformat(),
            "reason": "feedback_missing",
            "invalid_fields": ["feedback"],
        }

    target_value = feedback.get("replan_at_utc")
    try:
        target = _parse_schedule_utc(target_value, "feedback.replan_at_utc")
    except ReplanError:
        # A malformed planner artifact must trigger an immediate safe replan,
        # not a long sleep based on a different or guessed quota field.
        return {
            **base,
            "ok": False,
            "decision": "due_now",
            "due": True,
            "bounded": False,
            "sleep_seconds": 0.0,
            "wake_at_utc": now.isoformat(),
            "reason": "invalid_replan_at_utc",
            "invalid_fields": ["feedback.replan_at_utc"],
        }

    base["target_replan_at_utc"] = target.isoformat()
    for source_key, output_key in (
        ("quota_reset_at_utc", "quota_reset_at_utc"),
        ("quota_reset_pool_id", "quota_reset_pool_id"),
    ):
        value = feedback.get(source_key)
        if value not in (None, ""):
            base[output_key] = str(value)

    wait = max(0.0, (target - now).total_seconds())
    if wait <= 0:
        return {
            **base,
            "ok": True,
            "decision": "due_now",
            "due": True,
            "bounded": False,
            "sleep_seconds": 0.0,
            "wake_at_utc": now.isoformat(),
            "reason": "replan_due",
        }

    sleep_seconds = min(wait, bound)
    wake = now + dt.timedelta(seconds=sleep_seconds)
    return {
        **base,
        "ok": True,
        "decision": "wait_bounded",
        "due": False,
        "bounded": sleep_seconds < wait,
        "sleep_seconds": sleep_seconds,
        "wake_at_utc": wake.isoformat(),
        "reason": "bounded_health_recheck" if sleep_seconds < wait else "target_replan",
    }


def load_json(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def build_quota_window_watch(
    snapshots: list[Mapping[str, Any]],
    *,
    now_utc: str | None = None,
    reserve_percent: float = 10.0,
    poll_seconds: float = 30.0,
    unknown_quota_policy: str = "block",
    unknown_pilot_percent: float = 5.0,
) -> dict[str, Any]:
    """Normalize quota snapshots without contacting a provider.

    The import is lazy so the existing replan boundary remains usable in
    minimal installations.  The watcher itself is a pure observation stage;
    this helper only makes its output available to the replan artifact.
    """

    try:
        from quota_window_watcher import watch
    except ImportError:  # pragma: no cover - package/direct import fallback
        from .quota_window_watcher import watch  # type: ignore
    return watch(
        snapshots,
        now_utc=now_utc,
        reserve_percent=reserve_percent,
        poll_seconds=poll_seconds,
        unknown_quota_policy=unknown_quota_policy,
        unknown_pilot_percent=unknown_pilot_percent,
    )


def _canonical(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def digest(payload: Any) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def atomic_write(path: str, payload: Mapping[str, Any]) -> None:
    """Write a report with a random same-directory temporary file."""

    target = pathlib.Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
            handle.flush()
        pathlib.Path(temporary_name).replace(target)
    finally:
        if temporary_name:
            try:
                pathlib.Path(temporary_name).unlink()
            except FileNotFoundError:
                pass


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    return [value]


def _job_rows(payload: Any) -> list[dict[str, Any]]:
    rows = payload.get("jobs", []) if isinstance(payload, Mapping) else payload
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise ReplanError("jobs input must be a list or an object with a jobs list")
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _worker_key(worker: Mapping[str, Any]) -> str:
    return str(worker.get("worker_id") or worker.get("job_id") or "")


def _merge_workers(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Merge monitor observations with original worker placement metadata."""

    state = report.get("state") if isinstance(report.get("state"), Mapping) else {}
    originals = {
        _worker_key(row): dict(row)
        for row in _as_list(state.get("workers"))
        if isinstance(row, Mapping) and _worker_key(row)
    }
    observations = report.get("final_workers")
    if not isinstance(observations, list):
        observations = state.get("workers")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in _as_list(observations):
        if not isinstance(raw, Mapping):
            continue
        key = _worker_key(raw)
        if not key:
            continue
        merged = dict(originals.get(key, {}))
        # An absent observation field must not erase workload_host, provider,
        # or exact variant carried by the dispatch record.
        merged.update(dict(raw))
        for field in ("execution_host", "workload_host", "pool_id", "model", "variant"):
            if raw.get(field) in (None, "") and field in originals.get(key, {}):
                merged[field] = originals[key][field]
        result.append(merged)
        seen.add(key)
    # Preserve a worker that was in state but absent from final_workers.  It is
    # still an auditable input and should not silently disappear from a replan.
    for key, original in originals.items():
        if key not in seen:
            result.append(original)
    return result


def _infer_error_class(worker: Mapping[str, Any]) -> str | None:
    explicit = str(worker.get("error_class") or "").strip().lower()
    if explicit:
        return explicit
    text = " ".join(
        str(worker.get(field) or "")
        for field in ("error_message", "error", "log_tail", "stderr", "reason")
    )
    if _CONTROLLER_TIMEOUT_RE.search(text):
        return "stall"
    if _QUOTA_RE.search(text):
        return "quota"
    if _LOCATION_RE.search(text):
        return "location_restricted"
    if _CAPABILITY_RE.search(text):
        return "capability"
    if _AUTH_RE.search(text):
        return "auth"
    if _HOST_RE.search(text):
        return "host_unreachable" if "unreach" in text.lower() else "resource_pressure"
    if _NETWORK_RE.search(text):
        return "network"
    return None


def classify_failure(worker: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return a failure record with origin ``provider``, ``compute``, or ``unknown``."""

    status = str(worker.get("status") or "").lower()
    error_class = _infer_error_class(worker)
    explicit_origin = str(worker.get("error_origin") or "").lower()
    if status not in {"failed", "stalled"} and not error_class and not explicit_origin:
        return None

    if explicit_origin in COMPUTE_ORIGINS:
        origin = "compute"
    elif explicit_origin in PROVIDER_ORIGINS:
        origin = "provider"
    elif error_class in COMPUTE_CLASSES:
        origin = "compute"
    elif error_class in PROVIDER_CLASSES:
        origin = "provider"
    else:
        origin = "unknown"

    execution_host = str(worker.get("execution_host") or "") or None
    workload_host = str(worker.get("workload_host") or "") or execution_host
    failed_host = (
        worker.get("failed_host")
        or worker.get("host_id")
        or worker.get("error_host")
        or worker.get("compute_host")
    )
    failed_host = str(failed_host) if failed_host not in (None, "") else None
    if failed_host and failed_host == workload_host and failed_host != execution_host:
        host_role = "workload"
    elif failed_host and failed_host == execution_host and failed_host != workload_host:
        host_role = "execution"
    elif failed_host and failed_host in {execution_host, workload_host}:
        host_role = "both"
    elif origin == "compute" and execution_host == workload_host:
        host_role = "both"
    elif origin == "compute":
        # A remote observation failure is a failure to reach the agent process
        # host.  Workload failures must carry failed_host/error_host explicitly
        # so that a split placement is never guessed.
        host_role = "execution"
    else:
        host_role = None

    return {
        "origin": origin,
        "class": error_class or "unknown",
        "error_origin": explicit_origin or None,
        "execution_host": execution_host,
        "workload_host": workload_host,
        "failed_host": failed_host,
        "host_role": host_role,
        "pool_id": str(worker.get("pool_id") or "") or None,
        "model": str(worker.get("model") or "") or None,
        "variant": str(worker.get("variant") or worker.get("model_variant") or "") or None,
    }


def _unique(values: list[Any]) -> list[Any]:
    result: list[Any] = []
    seen: set[str] = set()
    for value in values:
        marker = json.dumps(value, ensure_ascii=False, sort_keys=True)
        if marker in seen or value in (None, ""):
            continue
        seen.add(marker)
        result.append(value)
    return result


def _failure_action(failure: Mapping[str, Any]) -> tuple[str, list[str]]:
    origin = failure.get("origin")
    error_class = failure.get("class")
    if origin == "provider":
        if error_class == "location_restricted":
            return "block_location_restricted_model", [
                "provider_location_restriction_requires_gcp_or_supported_region"
            ]
        if error_class == "capability":
            return "reject_exact_model", ["provider_capability_rejection"]
        if error_class in {"quota", "rate_limit"}:
            return "cooldown_pool", ["provider_quota_or_rate_limit"]
        if error_class == "auth":
            return "pause_provider_pool", ["provider_authentication_failure"]
        if error_class == "network":
            return "retry_provider_alternate", ["provider_network_failure"]
        return "pause_and_inspect", ["provider_failure_origin_uncertain"]
    if origin == "compute":
        role = failure.get("host_role")
        if role == "workload":
            return "reroute_workload_host", ["workload_compute_failure"]
        if role == "execution":
            return "reroute_execution_host", ["agent_execution_host_failure"]
        if role == "both":
            return "reroute_execution_and_workload_host", ["coupled_compute_host_failure"]
        return "reroute_compute_host", ["compute_failure_host_role_unknown"]
    return "pause_and_inspect", ["failure_origin_unknown"]


def _empty_constraints() -> dict[str, Any]:
    return {
        "excluded_pools": [],
        "cooldown_pools": [],
        "excluded_models": [],
        "rejected_model_variants": {},
        "excluded_execution_hosts": [],
        "excluded_workload_hosts": [],
        "avoid_hosts": [],
        "soft_host_pressure": [],
    }


def _apply_failure_constraints(
    constraints: dict[str, Any], failure: Mapping[str, Any]
) -> None:
    origin = failure.get("origin")
    if origin == "provider":
        pool_id = failure.get("pool_id")
        model = failure.get("model")
        variant = failure.get("variant")
        if failure.get("class") in {"quota", "rate_limit", "auth", "network"} and pool_id:
            constraints["excluded_pools"].append(pool_id)
            if failure.get("class") in {"quota", "rate_limit"}:
                constraints["cooldown_pools"].append(pool_id)
        if failure.get("class") in {"capability", "location_restricted"} and model:
            constraints["excluded_models"].append(model)
            if variant:
                constraints["rejected_model_variants"].setdefault(model, []).append(variant)
        return

    if origin != "compute":
        return
    role = failure.get("host_role")
    execution_host = failure.get("execution_host")
    workload_host = failure.get("workload_host")
    if role in {"execution", "both"} and execution_host:
        constraints["excluded_execution_hosts"].append(execution_host)
    if role in {"workload", "both"} and workload_host:
        constraints["excluded_workload_hosts"].append(workload_host)


def _host_alerts(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    alerts = report.get("compute_alerts")
    if not isinstance(alerts, list):
        return []
    result: list[dict[str, Any]] = []
    for raw in alerts:
        if not isinstance(raw, Mapping):
            continue
        host_id = str(raw.get("host_id") or "")
        if not host_id:
            continue
        severity = str(raw.get("severity") or "observe").lower()
        reason = str(raw.get("reason") or "compute_alert")
        result.append(
            {
                "host_id": host_id,
                "severity": severity,
                "reason": reason,
                "origin": "compute",
                "action": "exclude_host" if severity == "stop" else "reduce_host_concurrency",
            }
        )
    return result


def _apply_host_alerts(
    constraints: dict[str, Any], alerts: list[dict[str, Any]]
) -> None:
    for alert in alerts:
        host_id = alert["host_id"]
        if alert["severity"] == "stop":
            constraints["excluded_execution_hosts"].append(host_id)
            constraints["excluded_workload_hosts"].append(host_id)
        elif alert["severity"] in {"conserve", "reduce"}:
            constraints["avoid_hosts"].append(host_id)
            constraints["soft_host_pressure"].append(
                {"host_id": host_id, "severity": alert["severity"], "reason": alert["reason"]}
            )
        else:
            constraints["soft_host_pressure"].append(
                {"host_id": host_id, "severity": alert["severity"], "reason": alert["reason"]}
            )


def _append_job_constraint(job: dict[str, Any], key: str, values: list[Any]) -> None:
    existing = [str(value) for value in _as_list(job.get(key)) if value not in (None, "")]
    job[key] = sorted(set(existing + [str(value) for value in values if value not in (None, "")]))


def _replan_jobs(
    jobs_payload: Any,
    worker_decisions: list[Mapping[str, Any]],
    constraints: Mapping[str, Any],
) -> list[dict[str, Any]]:
    jobs = _job_rows(jobs_payload)
    by_job = {
        str(row.get("job_id")): row
        for row in worker_decisions
        if row.get("job_id")
    }
    result: list[dict[str, Any]] = []
    for source in jobs:
        job = dict(source)
        job_id = str(job.get("job_id") or "")
        decision = by_job.get(job_id)
        if decision and decision.get("action") not in {"keep", "monitor"}:
            local = decision.get("constraints") or {}
            _append_job_constraint(job, "excluded_pools", local.get("excluded_pools", []))
            # dynamic_dispatch_planner uses ``excluded_hosts`` for the
            # workload-placement dimension.  Keep that compatibility alias
            # alongside the explicit split-placement field below; execution
            # host exclusions remain separate for the controller/adapter.
            _append_job_constraint(job, "excluded_hosts", local.get("excluded_workload_hosts", []))
            _append_job_constraint(
                job, "excluded_workload_hosts", local.get("excluded_workload_hosts", [])
            )
            _append_job_constraint(
                job, "excluded_execution_hosts", local.get("excluded_execution_hosts", [])
            )
            _append_job_constraint(job, "excluded_models", local.get("excluded_models", []))
            job["replan_reason"] = list(decision.get("reason_codes") or [])
            job["retry_of"] = job_id
            if str(job.get("status") or "").lower() in {"failed", "stalled", "running"}:
                job["status"] = "pending"
        result.append(job)
    return result


def build_replan_decision(
    monitor_report: Mapping[str, Any],
    jobs_payload: Any | None = None,
    plan: Mapping[str, Any] | None = None,
    *,
    generated_at_utc: str | None = None,
    schedule_max_wait_seconds: float = DEFAULT_REPLAN_MAX_WAIT_SECONDS,
    quota_watch: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Convert a monitor report into a pure, auditable replan artifact."""

    if not isinstance(monitor_report, Mapping):
        raise ReplanError("monitor report must be a JSON object")
    workers = _merge_workers(monitor_report)
    constraints = _empty_constraints()
    host_alerts = _host_alerts(monitor_report)
    _apply_host_alerts(constraints, host_alerts)

    worker_decisions: list[dict[str, Any]] = []
    unknown_failures = 0
    actionable_failures = 0
    for worker in workers:
        failure = classify_failure(worker)
        worker_id = _worker_key(worker)
        status = str(worker.get("status") or "unknown").lower()
        if failure is None:
            action = "keep" if status in {"completed", "healthy", "artifact_ready"} else "monitor"
            reason_codes = (
                ["worker_completed"]
                if status == "completed"
                else [f"worker_status_{status}"]
            )
            worker_decision = {
                "worker_id": worker_id,
                "job_id": str(worker.get("job_id") or "") or None,
                "pool_id": worker.get("pool_id"),
                "model": worker.get("model"),
                "variant": worker.get("variant") or worker.get("model_variant"),
                "execution_host": worker.get("execution_host"),
                "workload_host": worker.get("workload_host") or worker.get("execution_host"),
                "status": status,
                "action": action,
                "reason_codes": reason_codes,
                "constraints": _empty_constraints(),
                "failure": None,
            }
            worker_decisions.append(worker_decision)
            continue

        actionable_failures += 1
        action, reason_codes = _failure_action(failure)
        if failure.get("origin") == "unknown":
            unknown_failures += 1
        local_constraints = _empty_constraints()
        _apply_failure_constraints(local_constraints, failure)
        _apply_failure_constraints(constraints, failure)
        worker_decisions.append(
            {
                "worker_id": worker_id,
                "job_id": str(worker.get("job_id") or "") or None,
                "pool_id": worker.get("pool_id"),
                "model": worker.get("model"),
                "variant": worker.get("variant") or worker.get("model_variant"),
                "execution_host": worker.get("execution_host"),
                "workload_host": worker.get("workload_host") or worker.get("execution_host"),
                "status": status,
                "action": action,
                "reason_codes": reason_codes,
                "constraints": local_constraints,
                "failure": failure,
            }
        )

    if quota_watch is not None:
        # Quota observations are an additional hard admission constraint.  A
        # pool that is stale, unknown, quota-blocked, or auth-conflicted cannot
        # be selected merely because a model name remains in its catalog.
        for row in quota_watch.get("pools", []):
            if not isinstance(row, Mapping):
                continue
            if str(row.get("decision") or "") not in {"ready", "bounded_pilot"}:
                pool_id = str(row.get("pool_id") or "")
                if pool_id:
                    constraints["excluded_pools"].append(pool_id)

    # The planner understands these lists as hard exclusions.  Make the output
    # stable for easy diffing and audit replay.
    for key in (
        "excluded_pools",
        "cooldown_pools",
        "excluded_models",
        "excluded_execution_hosts",
        "excluded_workload_hosts",
        "avoid_hosts",
    ):
        constraints[key] = sorted({str(value) for value in constraints[key] if value})
    constraints["rejected_model_variants"] = {
        str(model): sorted({str(variant) for variant in variants if variant})
        for model, variants in sorted(constraints["rejected_model_variants"].items())
    }
    constraints["soft_host_pressure"] = _unique(constraints["soft_host_pressure"])

    if actionable_failures == 0 and not host_alerts:
        decision = "keep"
        mode = "no_replan_needed"
    elif unknown_failures or any(
        row["action"] == "pause_and_inspect" for row in worker_decisions
    ):
        decision = "pause"
        mode = "human_review_required"
    elif constraints["excluded_execution_hosts"] or constraints["excluded_workload_hosts"]:
        decision = "reroute"
        mode = "immediate_replan"
    else:
        decision = "replan"
        mode = "immediate_replan"

    jobs = (
        _replan_jobs(jobs_payload, worker_decisions, constraints)
        if jobs_payload is not None
        else []
    )
    source_digests: dict[str, str] = {"monitor_report": digest(monitor_report)}
    if jobs_payload is not None:
        source_digests["jobs"] = digest(jobs_payload)
    if plan is not None:
        source_digests["dispatch_plan"] = digest(plan)
    if quota_watch is not None:
        source_digests["quota_window_watch"] = digest(quota_watch)

    generated_timestamp = generated_at_utc or dt.datetime.now(tz=dt.timezone.utc).isoformat()
    schedule: dict[str, Any] | None = None
    if isinstance(plan, Mapping) and isinstance(plan.get("feedback"), Mapping):
        # Use the decision's observation timestamp as the schedule clock so a
        # replay with a fixed generated_at_utc remains byte-stable.  If a
        # caller supplied a non-ISO label (for example ``"fixed"``), omit the
        # schedule rather than introducing a hidden wall-clock dependency.
        try:
            _parse_schedule_utc(generated_timestamp, "generated_at_utc")
        except ReplanError:
            schedule = {
                "schema_version": SCHEMA_VERSION,
                "source": "planner_feedback",
                "ok": False,
                "decision": "due_now",
                "due": True,
                "bounded": False,
                "sleep_seconds": 0.0,
                "wake_at_utc": None,
                "target_replan_at_utc": None,
                "replan_reason": "invalid_generated_at_utc",
                "reason": "invalid_generated_at_utc",
                "invalid_fields": ["generated_at_utc"],
            }
        else:
            schedule = build_replan_schedule(
                plan["feedback"],
                now_utc=generated_timestamp,
                max_wait_seconds=schedule_max_wait_seconds,
            )

    quota_schedule: dict[str, Any] | None = None
    if quota_watch is not None and isinstance(quota_watch.get("replan_feedback"), Mapping):
        try:
            quota_schedule = build_replan_schedule(
                quota_watch["replan_feedback"],
                now_utc=generated_timestamp,
                max_wait_seconds=schedule_max_wait_seconds,
            )
        except ReplanError:
            # A malformed external watch must trigger an immediate visible
            # replan rather than creating a hidden long sleep.
            quota_schedule = {
                "schema_version": SCHEMA_VERSION,
                "source": "quota_window_watch",
                "ok": False,
                "decision": "due_now",
                "due": True,
                "bounded": False,
                "sleep_seconds": 0.0,
                "wake_at_utc": generated_timestamp,
                "reason": "invalid_quota_watch_feedback",
                "invalid_fields": ["quota_watch.replan_feedback"],
            }

    output: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "ok": True,
        "read_only": True,
        "provider_invocations": [],
        "side_effects": [],
        "decision": decision,
        "mode": mode,
        "generated_at_utc": generated_timestamp,
        "source_digests": source_digests,
        "worker_decisions": worker_decisions,
        "host_alerts": host_alerts,
        "constraints": constraints,
        "planner_constraints": {
            "excluded_pools": constraints["excluded_pools"],
            "excluded_models": constraints["excluded_models"],
            # Planner host fit is the workload dimension.  The explicit
            # execution list is retained for provider/adapter routing.
            "excluded_hosts": constraints["excluded_workload_hosts"],
            "excluded_execution_hosts": constraints["excluded_execution_hosts"],
            "rejected_model_variants": constraints["rejected_model_variants"],
            "avoid_hosts": constraints["avoid_hosts"],
        },
        "replan_jobs": jobs,
        "summary": {
            "workers_observed": len(workers),
            "actionable_failures": actionable_failures,
            "unknown_failures": unknown_failures,
            "provider_failures": sum(
                row["failure"] is not None and row["failure"]["origin"] == "provider"
                for row in worker_decisions
            ),
            "compute_failures": sum(
                row["failure"] is not None and row["failure"]["origin"] == "compute"
                for row in worker_decisions
            ),
            "hard_host_exclusions": len(
                set(constraints["excluded_execution_hosts"])
                | set(constraints["excluded_workload_hosts"])
            ),
        },
        # This is an advisory, bounded consumer result.  The controller must
        # continue heartbeats/resource checks and may only use it to decide
        # when to invoke the next read-only replan.
        "replan_schedule": schedule,
        "quota_window_watch": quota_watch,
        "quota_replan_schedule": quota_schedule,
        "next": (
            "review constraints, then invoke dynamic_dispatch_planner.py with updated state; "
            "use replan_schedule only as a bounded wake hint; do not execute provider commands "
            "from this artifact"
        ),
    }
    # Hash the complete decision without the hash field itself.  A consumer can
    # verify provenance without trusting a generated timestamp or process.
    output["decision_digest"] = digest(output)
    return output


def _job_status_is_terminal(job: Mapping[str, Any]) -> bool:
    return str(job.get("status") or "").lower() in {
        "completed",
        "complete",
        "succeeded",
        "success",
    }


def _merge_unique_constraint(
    job: dict[str, Any], key: str, values: Any
) -> None:
    """Merge a list-valued planner constraint without mutating its source."""

    _append_job_constraint(job, key, _as_list(values))


def _local_pool_failures(
    decision: Mapping[str, Any],
) -> dict[str, list[Mapping[str, Any]]]:
    """Group provider failure records by pool for state-only overlays."""

    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for row in _as_list(decision.get("worker_decisions")):
        if not isinstance(row, Mapping):
            continue
        failure = row.get("failure")
        if not isinstance(failure, Mapping) or failure.get("origin") != "provider":
            continue
        pool_id = str(row.get("pool_id") or failure.get("pool_id") or "")
        if pool_id:
            grouped.setdefault(pool_id, []).append(row)
    return grouped


def merge_replan_constraints(
    decision: Mapping[str, Any],
    jobs_payload: Any,
    state: Mapping[str, Any],
) -> dict[str, Any]:
    """Copy-on-write merge of a reviewable replan into planner inputs.

    The input decision, jobs, and state are never modified.  The returned
    ``jobs`` payload contains hard exclusions for the next planning wave;
    ``state`` contains non-destructive pool/model/host overlays that preserve
    observed facts while making the replan evidence auditable.  This function
    does not enqueue, invoke a provider, or write a file.
    """

    if not isinstance(decision, Mapping) or not decision.get("ok"):
        raise ReplanError("a successful replan decision is required")
    if not isinstance(state, Mapping):
        raise ReplanError("planner state must be a JSON object")
    constraints = decision.get("constraints")
    if not isinstance(constraints, Mapping):
        raise ReplanError("replan decision is missing constraints")

    source_jobs = _job_rows(jobs_payload)
    patched_by_id = {
        str(row.get("job_id")): dict(row)
        for row in _as_list(decision.get("replan_jobs"))
        if isinstance(row, Mapping) and row.get("job_id")
    }
    merged_jobs: list[dict[str, Any]] = []
    hard_pool_exclusions = [str(value) for value in _as_list(constraints.get("excluded_pools"))]
    hard_model_exclusions = [str(value) for value in _as_list(constraints.get("excluded_models"))]
    hard_workload_exclusions = [
        str(value) for value in _as_list(constraints.get("excluded_workload_hosts"))
    ]
    hard_execution_exclusions = [
        str(value) for value in _as_list(constraints.get("excluded_execution_hosts"))
    ]

    for source in source_jobs:
        job_id = str(source.get("job_id") or "")
        # Start from the source and overlay only the decision's copy-on-write
        # patch.  This preserves unknown job fields for future planner stages.
        job = copy.deepcopy(patched_by_id.get(job_id, source))
        if not _job_status_is_terminal(job):
            # Pool/host failures are shared scheduling constraints.  Applying
            # them to every unfinished job prevents a different queued job
            # from immediately reusing the failed resource.
            _merge_unique_constraint(job, "excluded_pools", hard_pool_exclusions)
            _merge_unique_constraint(job, "excluded_models", hard_model_exclusions)
            _merge_unique_constraint(job, "excluded_hosts", hard_workload_exclusions)
            _merge_unique_constraint(job, "excluded_workload_hosts", hard_workload_exclusions)
            _merge_unique_constraint(job, "excluded_execution_hosts", hard_execution_exclusions)
            if hard_pool_exclusions or hard_model_exclusions or hard_workload_exclusions or hard_execution_exclusions:
                job.setdefault("replan_reason", [])
                if isinstance(job["replan_reason"], list):
                    job["replan_reason"] = sorted(
                        {str(item) for item in job["replan_reason"]}
                        | {"shared_replan_constraints"}
                    )
        merged_jobs.append(job)

    # Preserve whether the caller used a list or {jobs: [...]} envelope.
    if isinstance(jobs_payload, Mapping):
        merged_jobs_payload: Any = copy.deepcopy(dict(jobs_payload))
        merged_jobs_payload["jobs"] = merged_jobs
    else:
        merged_jobs_payload = merged_jobs

    merged_state: dict[str, Any] = copy.deepcopy(dict(state))
    state_constraints = copy.deepcopy(dict(constraints))
    merged_state["replan_constraints"] = state_constraints
    merged_state["last_replan"] = {
        "decision_digest": decision.get("decision_digest"),
        "decision": decision.get("decision"),
        "mode": decision.get("mode"),
        "applied_copy_on_write": True,
        "read_only_source": True,
        "observed_at_utc": decision.get("generated_at_utc"),
    }

    # Pool state is an overlay, not a replacement of live quota evidence.  A
    # quota/rate failure cools the shared pool; auth/network failures remain a
    # dispatch exclusion without pretending the quota is exhausted.
    pools = merged_state.setdefault("pools", {})
    if isinstance(pools, dict):
        cooldown_pools = {
            str(value) for value in _as_list(constraints.get("cooldown_pools"))
        }
        excluded_pools = {
            str(value) for value in _as_list(constraints.get("excluded_pools"))
        }
        for pool_id in sorted(excluded_pools | cooldown_pools):
            pool = pools.setdefault(pool_id, {})
            if not isinstance(pool, dict):
                pool = {}
                pools[pool_id] = pool
            pool["replan_excluded"] = True
            pool["replan_decision_digest"] = decision.get("decision_digest")
            if pool_id in cooldown_pools and str(pool.get("health") or "") not in {
                "blocked",
                "unavailable",
            }:
                pool["health"] = "cooldown"

        for pool_id, rows in _local_pool_failures(decision).items():
            pool = pools.setdefault(pool_id, {})
            if not isinstance(pool, dict):
                pool = {}
                pools[pool_id] = pool
            rejected_models = {
                str(item) for item in _as_list(pool.get("rejected_models")) if item
            }
            rejected_variants = {
                str(model): {str(variant) for variant in _as_list(variants) if variant}
                for model, variants in (pool.get("rejected_model_variants") or {}).items()
            }
            for row in rows:
                failure = row.get("failure") or {}
                if failure.get("class") != "capability":
                    continue
                model = str(row.get("model") or failure.get("model") or "")
                variant = str(row.get("variant") or failure.get("variant") or "")
                if model:
                    rejected_models.add(model)
                if model and variant:
                    rejected_variants.setdefault(model, set()).add(variant)
            if rejected_models:
                pool["rejected_models"] = sorted(rejected_models)
            if rejected_variants:
                pool["rejected_model_variants"] = {
                    model: sorted(variants)
                    for model, variants in sorted(rejected_variants.items())
                }

    # Do not overwrite live reachability or utilization.  These metadata
    # overlays let a later controller/observer distinguish a replan exclusion
    # from a fresh probe result.
    hosts = merged_state.setdefault("compute_hosts", {})
    if isinstance(hosts, dict):
        execution_hosts = set(hard_execution_exclusions)
        workload_hosts = set(hard_workload_exclusions)
        for host_id in sorted(execution_hosts | workload_hosts):
            host = hosts.setdefault(host_id, {})
            if not isinstance(host, dict):
                host = {}
                hosts[host_id] = host
            overlay = dict(host.get("replan_constraints") or {})
            if host_id in execution_hosts:
                overlay["execution_excluded"] = True
            if host_id in workload_hosts:
                overlay["workload_excluded"] = True
            overlay["decision_digest"] = decision.get("decision_digest")
            host["replan_constraints"] = overlay

    return {
        "schema_version": SCHEMA_VERSION,
        "ok": True,
        "read_only": True,
        "provider_invocations": [],
        "enqueue_performed": False,
        "source_decision_digest": decision.get("decision_digest"),
        "state": merged_state,
        "jobs": merged_jobs_payload,
        "jobs_list": merged_jobs,
    }


def plan_after_replan(
    decision: Mapping[str, Any],
    jobs_payload: Any,
    state: Mapping[str, Any],
    *,
    max_lanes: int = 4,
    horizon: int = 8,
) -> dict[str, Any]:
    """Merge constraints and run the pure planner for the next wave.

    Importing and calling ``dynamic_dispatch_planner.plan`` is intentionally
    local and deterministic.  No provider, SSH probe, queue mutation, or
    controller is reached by this function.
    """

    merged = merge_replan_constraints(decision, jobs_payload, state)
    try:
        from dynamic_dispatch_planner import plan as planner_plan
    except ImportError:  # pragma: no cover - package/direct import fallback
        from .dynamic_dispatch_planner import plan as planner_plan  # type: ignore
    next_plan = planner_plan(
        merged["state"],
        merged["jobs"],
        max(1, int(max_lanes)),
        max(1, int(horizon)),
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "ok": bool(next_plan.get("ok")),
        "read_only": True,
        "provider_invocations": [],
        "enqueue_performed": False,
        "source_decision_digest": decision.get("decision_digest"),
        "merged": merged,
        "next_plan": next_plan,
    }


# Explicit aliases make the boundary discoverable without implying mutation.
apply_replan = merge_replan_constraints


# Short public alias for callers that treat this module as the replan stage.
replan = build_replan_decision


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--monitor-report", "--monitor", dest="monitor_report", required=True)
    parser.add_argument("--jobs")
    parser.add_argument("--plan")
    parser.add_argument(
        "--state",
        help="optional planner state used for copy-on-write merge and the next plan",
    )
    parser.add_argument(
        "--run-planner",
        action="store_true",
        help="after the in-memory merge, run the deterministic planner",
    )
    parser.add_argument("--max-lanes", type=int, default=4)
    parser.add_argument("--horizon", type=int, default=8)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="write only the explicitly supplied merged output paths; never edits inputs",
    )
    parser.add_argument("--merged-state-out")
    parser.add_argument("--merged-jobs-out")
    parser.add_argument("--next-plan-out")
    parser.add_argument("--output")
    parser.add_argument("--generated-at-utc")
    parser.add_argument(
        "--schedule-max-wait-seconds",
        type=float,
        default=DEFAULT_REPLAN_MAX_WAIT_SECONDS,
        help="bound each scheduler wake hint; heartbeat/resource checks remain mandatory",
    )
    parser.add_argument(
        "--quota-snapshot",
        action="append",
        help="optional saved quota snapshot; repeatable and provider-free",
    )
    parser.add_argument("--quota-now-utc")
    parser.add_argument("--quota-reserve-percent", type=float, default=10.0)
    parser.add_argument("--quota-poll-seconds", type=float, default=30.0)
    parser.add_argument(
        "--unknown-quota-policy",
        choices=("block", "pilot"),
        default="block",
        help="explicitly permit only a bounded pilot when balance is unknown",
    )
    parser.add_argument("--unknown-quota-pilot-percent", type=float, default=5.0)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.state and not args.jobs:
            raise ReplanError("--state requires --jobs for a copy-on-write merge")
        if args.run_planner and not args.state:
            raise ReplanError("--run-planner requires --state and --jobs")
        if args.apply and not (args.merged_state_out and args.merged_jobs_out):
            raise ReplanError(
                "--apply requires both --merged-state-out and --merged-jobs-out; "
                "inputs are never overwritten"
            )
        if (args.merged_state_out or args.merged_jobs_out) and not args.apply:
            raise ReplanError("merged output paths require explicit --apply")
        if args.next_plan_out and not args.run_planner:
            raise ReplanError("--next-plan-out requires --run-planner")

        report = load_json(args.monitor_report)
        jobs = load_json(args.jobs) if args.jobs else None
        plan = load_json(args.plan) if args.plan else None
        quota_watch = None
        if args.quota_snapshot:
            quota_watch = build_quota_window_watch(
                [load_json(path) for path in args.quota_snapshot],
                now_utc=args.quota_now_utc or args.generated_at_utc,
                reserve_percent=args.quota_reserve_percent,
                poll_seconds=args.quota_poll_seconds,
                unknown_quota_policy=args.unknown_quota_policy,
                unknown_pilot_percent=args.unknown_quota_pilot_percent,
            )
        result = build_replan_decision(
            report,
            jobs,
            plan,
            generated_at_utc=args.generated_at_utc,
            schedule_max_wait_seconds=args.schedule_max_wait_seconds,
            quota_watch=quota_watch,
        )
        merged: dict[str, Any] | None = None
        if args.state:
            state = load_json(args.state)
            if args.run_planner:
                planned = plan_after_replan(
                    result,
                    jobs,
                    state,
                    max_lanes=args.max_lanes,
                    horizon=args.horizon,
                )
                merged = planned["merged"]
                result["next_plan"] = planned["next_plan"]
                result["next_plan_read_only"] = True
                if args.next_plan_out:
                    atomic_write(args.next_plan_out, planned["next_plan"])
                    result["next_plan_out"] = str(pathlib.Path(args.next_plan_out).expanduser().resolve())
            else:
                merged = merge_replan_constraints(result, jobs, state)
            result["merged_inputs"] = {
                "state": merged["state"],
                "jobs": merged["jobs"],
                "read_only": True,
                "enqueue_performed": False,
            }
            if args.apply:
                atomic_write(args.merged_state_out, merged["state"])
                atomic_write(args.merged_jobs_out, merged["jobs"])
                result["apply"] = {
                    "explicit": True,
                    "inputs_overwritten": False,
                    "state_out": str(pathlib.Path(args.merged_state_out).expanduser().resolve()),
                    "jobs_out": str(pathlib.Path(args.merged_jobs_out).expanduser().resolve()),
                    "read_only": False,
                    "provider_invocations": [],
                    "enqueue_performed": False,
                }
        result["read_only"] = not bool(args.apply)
        result.setdefault("provider_invocations", [])
        result["enqueue_performed"] = False
        if args.output:
            atomic_write(args.output, result)
        else:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        result = {
            "schema_version": SCHEMA_VERSION,
            "ok": False,
            "read_only": True,
            "error": str(exc),
        }
        if args.output:
            atomic_write(args.output, result)
        else:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
