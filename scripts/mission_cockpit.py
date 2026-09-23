#!/usr/bin/env python3
"""Build a compact, provenance-aware L0 Mission Cockpit report.

This is a read-only projection over saved mission, controller, monitor and
governor snapshots.  It intentionally omits prompt/argv/log contents.  The
full event stream remains the L3 forensic source; this report is the user's
first screen after returning to a long-running task.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import pathlib
import re
from typing import Any, Mapping


SCHEMA_VERSION = 1
_MAX_MONITOR_TAIL_BYTES = 1024 * 1024


def _obj(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _safe_number(value: Any) -> int | float | None:
    """Return a finite progress number, never an untrusted JSON value."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(float(value)):
        return None
    return value


def _safe_non_negative_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _safe_text(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        return None
    return value.strip()


_SAFE_EVIDENCE_LABEL = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_SAFE_EVIDENCE_CODE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_CAPABILITY_STATUSES = {
    "catalogued",
    "installed_attested",
    "auth_validated",
    "probe_accepted",
    "execution_validated",
    "degraded",
    "blocked",
    "unknown",
}
_ROUTE_STATUSES = {
    "verified",
    "ready",
    "blocked",
    "offline",
    "timeout",
    "degraded",
    "pending",
    "unverified",
    "unknown",
}
_SAFE_HOST_LABELS = {
    "local",
    "EDGE_WORKER",
    "westd",
    "central",
    "CLUSTER_ROUTE",
    "CLUSTER_ROUTE",
    "bjb2",
}


def _safe_evidence_label(value: Any) -> str | None:
    """Keep a short logical label while rejecting paths/endpoints/hosts."""

    text = _safe_text(value)
    if text is None or not _SAFE_EVIDENCE_LABEL.fullmatch(text):
        return None
    return text


def _safe_evidence_code(value: Any) -> str | None:
    text = _safe_text(value)
    if text is None or not _SAFE_EVIDENCE_CODE.fullmatch(text):
        return None
    return text


def _placement_summary(placement: Mapping[str, Any] | None) -> dict[str, Any]:
    """Project capability/route evidence without copying private topology."""

    raw = _obj(placement)
    capabilities: list[dict[str, Any]] = []
    for source in raw.get("capabilities") or []:
        if not isinstance(source, Mapping):
            continue
        name = _safe_evidence_label(source.get("name"))
        status = _safe_evidence_code(source.get("status"))
        if name is None or status not in _CAPABILITY_STATUSES:
            continue
        row: dict[str, Any] = {"name": name, "status": status}
        for key in ("execution_validated", "auth_validated", "probe_accepted"):
            if isinstance(source.get(key), bool):
                row[key] = source[key]
        observed = _safe_text(source.get("observed_at_utc"))
        if observed is not None:
            row["observed_at_utc"] = observed
        capabilities.append(row)

    routes: list[dict[str, Any]] = []
    for source in raw.get("routes") or []:
        if not isinstance(source, Mapping):
            continue
        name = _safe_evidence_label(source.get("name") or source.get("route_id"))
        status = _safe_evidence_code(source.get("status"))
        if name is None or status not in _ROUTE_STATUSES:
            continue
        row = {"name": name, "status": status}
        if isinstance(source.get("verified"), bool):
            row["verified"] = source["verified"]
        reason = _safe_evidence_code(source.get("reason") or source.get("error_class"))
        if reason is not None:
            row["reason"] = reason
        observed = _safe_text(source.get("observed_at_utc"))
        if observed is not None:
            row["observed_at_utc"] = observed
        routes.append(row)

    host_label = _safe_evidence_label(raw.get("host_label") or raw.get("host"))
    if host_label not in _SAFE_HOST_LABELS:
        host_label = None
    return {
        "observed": bool(capabilities or routes),
        "host_label": host_label,
        "capabilities": capabilities[:32],
        "routes": routes[:32],
        "evidence_gaps": [
            {
                "kind": "capability_unvalidated",
                "name": row["name"],
                "status": row["status"],
            }
            for row in capabilities
            if row.get("execution_validated") is not True
            and row["status"] != "execution_validated"
        ][:32],
    }


def project_continuous_monitor(record: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Project one continuous-loop monitor row into an L0-safe summary.

    Older real-clock runs put ``remaining_seconds`` inside ``report`` and
    newer runs additionally expose monotonic whole-loop progress fields.  The
    projection keeps those clocks separate and only emits an allow-listed
    identity/status view; prompts, argv, environment and payloads are never
    copied into the cockpit.
    """

    raw = _obj(record)
    report = _obj(raw.get("report")) or raw
    heartbeat = _obj(report.get("heartbeat"))
    lease = _obj(heartbeat.get("lease"))
    reconciliation = _obj(report.get("reconciliation"))
    controller = _obj(reconciliation.get("controller"))

    run_id = _safe_text(raw.get("run_id")) or _safe_text(report.get("run_id"))
    if run_id is None:
        run_id = _safe_text(controller.get("run_id"))

    active_segments = [
        _obj(row)
        for row in controller.get("active_segments") or []
        if isinstance(row, Mapping)
    ]
    active_segment: dict[str, Any] | None = None
    if active_segments:
        active_segment = max(
            active_segments,
            key=lambda row: (
                int(row.get("sequence") or 0)
                if isinstance(row.get("sequence"), int) and not isinstance(row.get("sequence"), bool)
                else 0,
                str(row.get("started_at_utc") or ""),
            ),
        )

    segment_id = (
        _safe_text(report.get("segment_id"))
        or _safe_text(heartbeat.get("segment_id"))
        or (_safe_text(active_segment.get("segment_id")) if active_segment else None)
    )
    sequence = (
        active_segment.get("sequence")
        if active_segment and isinstance(active_segment.get("sequence"), int)
        and not isinstance(active_segment.get("sequence"), bool)
        else None
    )
    action = _safe_text(report.get("action")) or "unknown"
    status = {
        "continue": "running",
        "checkpoint_and_roll": "rolling",
        "stop": "stopped",
        "completed": "completed",
    }.get(action, "unknown")

    segment_remaining = _safe_number(report.get("segment_remaining_seconds"))
    if segment_remaining is None:
        # This is the legacy field's *segment* clock, not the whole-loop clock.
        segment_remaining = _safe_number(report.get("remaining_seconds"))

    loop_elapsed = _safe_number(report.get("loop_elapsed_seconds"))
    loop_remaining = _safe_number(report.get("loop_remaining_seconds"))
    progress_clock = _safe_text(report.get("progress_clock")) or "unknown"
    provider_execution = report.get("provider_execution")
    if not isinstance(provider_execution, bool):
        provider_execution = None
    heartbeat_ok = heartbeat.get("ok")
    if not isinstance(heartbeat_ok, bool):
        heartbeat_ok = None
    transport_pending = _safe_non_negative_int(controller.get("transport_pending"))
    fence_token = _safe_non_negative_int(lease.get("fence_token"))

    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": "local-agent-dispatch.continuous-monitor-projection",
        "read_only": True,
        "record_type": _safe_text(raw.get("record_type")) or "unknown",
        "run_id": run_id,
        "tick": _safe_non_negative_int(raw.get("tick")),
        "observed_at_utc": (
            _safe_text(raw.get("observed_at_utc"))
            or _safe_text(report.get("now_utc"))
        ),
        "action": action,
        "status": status,
        "segment_id": segment_id,
        "segment_sequence": sequence,
        "segment_count": _safe_non_negative_int(controller.get("segment_count")),
        "segment_remaining_seconds": segment_remaining,
        "loop_elapsed_seconds": loop_elapsed,
        "loop_remaining_seconds": loop_remaining,
        "progress_clock": progress_clock,
        "heartbeat_ok": heartbeat_ok,
        "lease_status": _safe_text(lease.get("status")),
        "fence_token": fence_token,
        "provider_execution": provider_execution,
        "transport_pending": transport_pending,
    }


def _status_counts(rows: list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for raw in rows:
        row = _obj(raw)
        status = str(row.get("status") or row.get("controller_status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def _record_status(row: Mapping[str, Any]) -> str:
    """Prefer durable controller state, then fall back to observation state."""
    return str(row.get("controller_status") or row.get("status") or "unknown").strip().lower()


def _validation_ok(row: Mapping[str, Any]) -> bool:
    validation = row.get("validation") or row.get("validation_result")
    return bool(
        row.get("validation_ok") is True
        or (isinstance(validation, Mapping) and validation.get("ok") is True)
    )


def _freshness_ok(row: Mapping[str, Any]) -> bool:
    return bool(
        row.get("artifact_freshness_verified") is True
        or row.get("artifact_fresh") is True
    )


def _lifecycle_counts(rows: list[Mapping[str, Any]]) -> dict[str, int]:
    """Keep execution, validation, and claim promotion as separate facts."""
    completed = sum(1 for row in rows if _record_status(row) == "completed")
    validated = sum(
        1
        for row in rows
        if _record_status(row) == "completed" and _validation_ok(row) and _freshness_ok(row)
    )
    promoted = sum(
        1
        for row in rows
        if row.get("claim_promoted") is True
        or str(row.get("claim_status") or "").strip().lower() in {"promoted", "claim_promoted"}
        or str(row.get("lifecycle_status") or "").strip().lower() == "claim_promoted"
    )
    return {
        "execution_completed": completed,
        "validated_completed": validated,
        "claim_promoted": promoted,
    }


def _safe_recent_receipt(snapshot: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return only stable metadata for the most recent durable event/receipt."""

    candidates: list[Mapping[str, Any]] = []
    for key in ("receipts", "events"):
        values = snapshot.get(key)
        if isinstance(values, list):
            candidates.extend(row for row in values if isinstance(row, Mapping))
    if not candidates:
        return None
    row = candidates[-1]
    allowed = (
        "receipt_id", "receipt_type", "event_id", "event_type", "event_seq",
        "job_id", "attempt_id", "state", "status", "at_utc", "observed_at_utc",
        "digest", "receipt_digest", "artifact_digest",
    )
    result = {key: row[key] for key in allowed if key in row}
    return result or None


def _safe_active_segment(snapshot: Mapping[str, Any]) -> dict[str, Any] | None:
    """Project the currently running segment without exposing payload data.

    SQLite snapshots call the collection ``run_segments`` while the monitor
    and fake supervisors historically used ``segments``/``active_segments``.
    Accept all three forms, but only publish stable identity and timing
    fields.  A segment is active only while its durable status is ``running``
    or ``closing``; an old terminal row must not make the cockpit look live.
    """

    candidates: list[Mapping[str, Any]] = []
    for key in ("active_segment", "segment"):
        value = snapshot.get(key)
        if isinstance(value, Mapping):
            candidates.append(value)
    for key in ("active_segments", "run_segments", "segments"):
        value = snapshot.get(key)
        if isinstance(value, list):
            candidates.extend(row for row in value if isinstance(row, Mapping))
    active = [
        row
        for row in candidates
        if str(row.get("status") or row.get("segment_status") or "").lower()
        in {"running", "closing"}
    ]
    if not active:
        return None
    # Multiple active rows indicate a malformed snapshot.  Keep the newest
    # sequence for a compact display; the underlying event ledger remains the
    # source for diagnosing the invariant violation.
    def sort_key(row: Mapping[str, Any]) -> tuple[int, str]:
        try:
            sequence = int(row.get("sequence") or 0)
        except (TypeError, ValueError):
            sequence = 0
        return sequence, str(row.get("started_at_utc") or row.get("created_at_utc") or "")

    row = max(active, key=sort_key)
    allowed = (
        "run_id", "segment_id", "sequence", "status", "segment_status",
        "owner_id", "fence_token", "manifest_digest", "capsule_digest",
        "started_at_utc", "updated_at_utc", "closed_at_utc",
    )
    result = {key: row[key] for key in allowed if key in row}
    if "status" not in result and "segment_status" in result:
        result["status"] = result["segment_status"]
    return result or None


def _attention_inbox(
    risks: list[Mapping[str, Any]],
    *,
    decision: Mapping[str, Any] | None,
    gate: str,
    health_level: str,
) -> list[dict[str, Any]]:
    """Return only operator-worthy notices for the L0 control surface.

    Ordinary retries and monitor ticks intentionally do not appear here.  The
    inbox is an attention budget: each item is a concise, deterministic
    pointer to a safety stop, an action the operator must take, or a review
    that should happen soon.
    """

    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for risk in risks:
        kind = str(risk.get("kind") or "unknown")
        if kind in seen:
            continue
        seen.add(kind)
        if kind in {"local_memory_pressure", "local_admission"} and health_level == "critical":
            level = "safety_stop"
            action = "stop_new_admission_and_preserve_checkpoint"
        elif kind in {"local_memory_pressure", "local_admission"}:
            level = "action_required"
            action = "keep_new_local_lanes_blocked"
        elif kind in {"controller_snapshot_missing", "legacy_state_stale"}:
            level = "action_required"
            action = "reconcile_controller_state_before_dispatch"
        elif kind == "quota_pool_blocked":
            level = "review_soon"
            action = "wait_for_bounded_quota_reprobe"
        elif kind == "route_blocked":
            level = "action_required"
            action = "restore_or_verify_route_before_dispatch"
        else:
            level = "review_soon"
            action = "review_blocker"
        items.append({
            "level": level,
            "code": kind,
            "action": action,
            "source": risk.get("source"),
            "pool_id": risk.get("pool_id"),
            "reset_at_utc": risk.get("reset_at_utc"),
        })
    if decision and not items:
        items.append({
            "level": "action_required",
            "code": str(decision.get("type") or "operator_decision"),
            "action": str(decision.get("safe_default") or "review_before_dispatch"),
            "source": "cockpit_decision",
        })
    if not items and gate in {"claim_or_release_review", "validation_review"}:
        items.append({
            "level": "review_soon",
            "code": gate,
            "action": "review_evidence_before_claim_or_release",
            "source": "cockpit_gate",
        })
    return items


def _l3_references(
    snapshot: Mapping[str, Any],
    *,
    replan: Mapping[str, Any],
) -> dict[str, Any]:
    """Expose allow-listed pointers into the forensic layer, never its body."""

    events = [row for row in snapshot.get("events") or [] if isinstance(row, Mapping)]
    attempts = [row for row in snapshot.get("attempts") or [] if isinstance(row, Mapping)]
    receipts = [row for row in snapshot.get("receipts") or [] if isinstance(row, Mapping)]
    watch = _obj(replan.get("quota_window_watch"))
    event_sequences: list[int] = []
    for row in events:
        try:
            event_sequences.append(int(row.get("event_seq")))
        except (TypeError, ValueError):
            continue
    attempt_ids = [str(row["attempt_id"]) for row in attempts if row.get("attempt_id")]
    receipt_ids = [
        str(row.get("receipt_id") or row.get("event_id"))
        for row in receipts
        if row.get("receipt_id") or row.get("event_id")
    ]
    return {
        "event_seq_min": min(event_sequences) if event_sequences else None,
        "event_seq_max": max(event_sequences) if event_sequences else None,
        "attempt_ids": attempt_ids[-32:],
        "receipt_ids": receipt_ids[-32:],
        "quota_snapshot_digests": [
            str(value) for value in watch.get("snapshot_digests") or []
            if isinstance(value, str)
        ][-16:],
        "redaction": "allowlisted_identity_only",
    }


def _resume_digest(
    *,
    mission: Mapping[str, Any],
    gate: str,
    health_level: str,
    active_segment: Mapping[str, Any] | None,
    verified_progress: Mapping[str, Any],
    blocker: Mapping[str, Any] | None,
    next_action: str,
    recent_receipt: Mapping[str, Any] | None,
    attention_inbox: list[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build a stable handoff digest suitable for a chat/session resume."""

    content = {
        "mission_id": mission.get("mission_id"),
        "gate": gate,
        "health_level": health_level,
        "active_segment": dict(active_segment) if active_segment else None,
        "verified_progress": dict(verified_progress),
        "blocker": dict(blocker) if blocker else None,
        "next_action": next_action,
        "recent_receipt": dict(recent_receipt) if recent_receipt else None,
        "attention_inbox": [dict(item) for item in attention_inbox],
    }
    encoded = json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "schema_version": SCHEMA_VERSION,
        "digest": "sha256:" + hashlib.sha256(encoded).hexdigest(),
        "content": content,
        "raw_prompt_persisted": False,
        "raw_argv_persisted": False,
    }


def _quota_summary(replan: Mapping[str, Any]) -> dict[str, Any]:
    """Project quota evidence into a small L0-safe summary."""

    watch = _obj(replan.get("quota_window_watch"))
    rows = [dict(row) for row in watch.get("pools") or [] if isinstance(row, Mapping)]
    blocked = [
        {
            "pool_id": row.get("pool_id"),
            "decision": row.get("decision"),
            "execution_state": row.get("execution_state"),
            "reset_at_utc": row.get("reset_at_utc"),
        }
        for row in rows
        if str(row.get("decision") or "") not in {"ready", "bounded_pilot"}
    ]
    schedule = _obj(replan.get("quota_replan_schedule"))
    return {
        "observed": bool(rows),
        "ready_pool_count": sum(
            1 for row in rows if str(row.get("decision") or "") in {"ready", "bounded_pilot"}
        ),
        "blocked_pools": blocked,
        "schedule": {
            key: schedule.get(key)
            for key in ("decision", "due", "sleep_seconds", "wake_at_utc", "target_replan_at_utc", "quota_reset_pool_id")
            if key in schedule
        },
    }


def _mission_goal(mission: Mapping[str, Any]) -> str | None:
    goal = mission.get("goal")
    if isinstance(goal, Mapping):
        value = goal.get("value")
        return str(value) if value else None
    return str(goal) if isinstance(goal, str) and goal.strip() else None


def _claim_ceiling(mission: Mapping[str, Any]) -> dict[str, Any]:
    envelope = _obj(mission.get("claim_envelope"))
    return {
        "allowed": envelope.get("allowed") or [],
        "deferred": envelope.get("deferred") or [],
        "forbidden": envelope.get("forbidden") or [],
        "evidence_level": _obj(envelope.get("evidence_level")).get("value"),
    }


def build_cockpit(
    snapshot: Mapping[str, Any] | None = None,
    *,
    mission: Mapping[str, Any] | None = None,
    governor: Mapping[str, Any] | None = None,
    history: Mapping[str, Any] | None = None,
    replan: Mapping[str, Any] | None = None,
    monitor: Mapping[str, Any] | None = None,
    placement: Mapping[str, Any] | None = None,
    now_utc: str | None = None,
) -> dict[str, Any]:
    """Return an L0 report with explicit unknowns and source timestamps."""
    snap = _obj(snapshot)
    mission_obj = _obj(mission)
    gov = _obj(governor)
    replan_obj = _obj(replan)
    placement_projection = _placement_summary(placement)
    monitor_projection = project_continuous_monitor(monitor) if monitor is not None else None
    jobs = [dict(row) for row in snap.get("jobs") or [] if isinstance(row, Mapping)]
    workers = [dict(row) for row in snap.get("workers") or [] if isinstance(row, Mapping)]
    # A monitor-only snapshot is still an observable task set.  When a durable
    # controller snapshot exists, merge only the lifecycle evidence exposed by
    # its worker projection so validation/freshness is not lost.
    if jobs:
        worker_by_id = {
            str(row.get("job_id") or row.get("worker_id")): row for row in workers
        }
        records: list[dict[str, Any]] = []
        for job in jobs:
            key = str(job.get("job_id") or job.get("worker_id"))
            merged = dict(job)
            worker = worker_by_id.get(key, {})
            for field in (
                "pool_id",
                "provider",
                "model",
                "variant",
                "execution_host",
                "workload_host",
                "lane_id",
                "validation",
                "validation_result",
                "validation_ok",
                "artifact_fresh",
                "artifact_freshness_verified",
                "claim_promoted",
                "claim_status",
                "lifecycle_status",
            ):
                if field in worker:
                    merged[field] = worker[field]
            records.append(merged)
    else:
        records = workers
    counts = _status_counts(records)
    lifecycle = _lifecycle_counts(records)
    completed = lifecycle["execution_completed"]
    validated = lifecycle["validated_completed"]
    total = len(records)
    governor_admission = _obj(gov.get("admission"))
    pressure = _obj(gov.get("ram"))

    if mission_obj.get("ambiguous"):
        gate = "mission_compile_review"
    elif any(_record_status(row) in {"failed", "blocked", "review"} for row in records):
        gate = "incident_or_replan_review"
    elif any(_record_status(row) in {"queued", "retry"} for row in records):
        gate = "plan_and_resource_admission"
    elif any(_record_status(row) in {"running", "unknown"} for row in records):
        gate = "execution_and_validation"
    elif total and completed == total:
        gate = "claim_or_release_review" if validated == total else "validation_review"
    else:
        gate = "mission_or_plan_review"

    risks: list[dict[str, Any]] = []
    if pressure.get("pressure_tier") in {"conserve", "critical", "emergency"}:
        risks.append({"kind": "local_memory_pressure", "tier": pressure.get("pressure_tier"), "source": "resource_governor"})
    if governor_admission.get("decision") in {"throttle", "pause", "emergency_pause_owned"}:
        risks.append({"kind": "local_admission", "decision": governor_admission.get("decision"), "source": "resource_governor"})
    if not snap:
        risks.append({"kind": "controller_snapshot_missing", "source": "input"})
    if history and history.get("counts", {}).get("stale_running_or_queued"):
        risks.append({"kind": "legacy_state_stale", "count": history["counts"]["stale_running_or_queued"], "source": "legacy_history"})

    for route in placement_projection["routes"]:
        if route["status"] not in {"verified", "ready"} or route.get("verified") is False:
            risks.append({
                "kind": "route_blocked",
                "route_id": route["name"],
                "status": route["status"],
                "reason": route.get("reason"),
                "source": "placement_evidence",
            })
            break

    quota = _quota_summary(replan_obj)
    if quota["blocked_pools"]:
        # Quota evidence is a distinct blocker: it must not be folded into
        # generic model or compute health, because the safe next action is a
        # bounded re-probe rather than model rotation.
        first = quota["blocked_pools"][0]
        risks.append({
            "kind": "quota_pool_blocked",
            "pool_id": first.get("pool_id"),
            "decision": first.get("decision"),
            "reset_at_utc": first.get("reset_at_utc"),
            "source": "quota_window_watch",
        })

    active = []
    for row in records:
        value = _obj(row)
        status = _record_status(value)
        if status not in {"running", "queued", "retry", "unknown"}:
            continue
        active.append({
            "job_id": value.get("job_id") or value.get("worker_id"),
            "pool_id": value.get("pool_id"),
            "model": value.get("model"),
            "variant": value.get("variant"),
            "execution_host": value.get("execution_host"),
            "workload_host": value.get("workload_host"),
            "status": status,
        })

    decision = None
    if risks:
        safe_default = (
            "do_not_dispatch_to_route"
            if risks[0].get("kind") == "route_blocked"
            else "keep_new_local_lanes_blocked"
        )
        decision = {
            "type": "review_resource_or_state",
            "reason": risks[0].get("kind"),
            "safe_default": safe_default,
        }
    elif mission_obj.get("ambiguous"):
        decision = {"type": "resolve_mission_ambiguity", "safe_default": "do_not_dispatch"}
    elif gate == "claim_or_release_review":
        decision = {"type": "claim_or_release_review", "safe_default": "keep_claim_ceiling"}

    pressure_tier = str(pressure.get("pressure_tier") or "").lower()
    if pressure_tier in {"emergency", "critical"}:
        health_level = "critical"
    elif risks or governor_admission.get("decision") in {"throttle", "pause", "emergency_pause_owned"}:
        health_level = "degraded"
    else:
        health_level = "healthy"

    blocker = risks[0] if risks else None
    schedule = quota.get("schedule") or {}
    if blocker is not None:
        next_action = (
            "restore_or_verify_route_before_dispatch"
            if blocker.get("kind") == "route_blocked"
            else str((decision or {}).get("safe_default") or "review_blocker")
        )
    elif schedule.get("decision") == "wait_bounded":
        next_action = "bounded_wait_then_reprobe_quota"
    elif gate in {"execution_and_validation", "plan_and_resource_admission"}:
        next_action = "continue_heartbeat_monitor_and_validation"
    elif gate == "claim_or_release_review":
        next_action = "review_claim_ceiling_before_release"
    else:
        next_action = "review_mission_or_plan"

    recent_receipt = _safe_recent_receipt(snap)
    active_segment = _safe_active_segment(snap)
    verified_progress = {
        "completed_jobs": validated,
        "total_jobs": total,
        "completion_fraction": (validated / total) if total else None,
        "evidence": "validator_and_freshness_verified" if validated else ("execution_only" if completed else "unknown"),
    }
    attention_inbox = _attention_inbox(
        risks,
        decision=decision,
        gate=gate,
        health_level=health_level,
    )
    resume_digest = _resume_digest(
        mission=mission_obj,
        gate=gate,
        health_level=health_level,
        active_segment=active_segment,
        verified_progress=verified_progress,
        blocker=blocker,
        next_action=next_action,
        recent_receipt=recent_receipt,
        attention_inbox=attention_inbox,
    )
    l3_references = _l3_references(snap, replan=replan_obj)

    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": "local-agent-dispatch.mission-cockpit",
        "read_only": True,
        "provider_execution": False,
        "observed_at_utc": now_utc or dt.datetime.now(dt.timezone.utc).isoformat(),
        "mission": {
            "mission_id": mission_obj.get("mission_id"),
            "goal": _mission_goal(mission_obj),
            "claim_ceiling": _claim_ceiling(mission_obj),
            "ambiguous": mission_obj.get("ambiguous") or [],
        },
        "current_gate": gate,
        "health_level": health_level,
        "blocker": blocker,
        "next_action": next_action,
        "recent_receipt": recent_receipt,
        "active_segment": active_segment,
        "continuous_monitor": monitor_projection,
        "placement": placement_projection,
        "attention_inbox": attention_inbox,
        "resume_digest": resume_digest,
        "l3_references": l3_references,
        "delta": {
            "job_status_counts": counts,
            "execution_completed": completed,
            "validated_completed": validated,
            "claim_promoted": lifecycle["claim_promoted"],
            "total_jobs": total,
            "history_source": "controller_snapshot" if jobs else ("monitor_workers" if workers else "unknown"),
        },
        "verified_progress": verified_progress,
        "risks": risks,
        "evidence_gaps": placement_projection["evidence_gaps"],
        "active_assignments": active,
        "decision_required": decision,
        "resource_summary": {
            "pressure_tier": pressure.get("pressure_tier"),
            "available_bytes": pressure.get("available_bytes"),
            "max_new_local_lanes": governor_admission.get("max_new_local_lanes"),
            "source": gov.get("observed_at_utc"),
        },
        "quota_summary": quota,
        "sources": {
            "controller_snapshot": bool(snap),
            "mission_spec": bool(mission_obj),
            "resource_governor": bool(gov),
            "legacy_history": bool(history),
            "replan": bool(replan_obj),
            "placement_evidence": placement_projection["observed"],
            "active_segment": active_segment is not None,
            "continuous_monitor": monitor_projection is not None,
            "raw_prompt_persisted": False,
            "raw_argv_persisted": False,
        },
    }


def _load(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    value = json.loads(pathlib.Path(path).expanduser().read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _load_monitor(path: str | None) -> dict[str, Any]:
    """Load one monitor record from either JSON or append-only JSONL."""

    if not path:
        return {}
    source = pathlib.Path(path).expanduser()
    try:
        size = source.stat().st_size
    except OSError as exc:
        raise ValueError(f"{path} monitor file cannot be read") from exc
    if size <= _MAX_MONITOR_TAIL_BYTES:
        text = source.read_text(encoding="utf-8")
    else:
        # A 24-hour stream can grow without bound.  Keep only a bounded tail;
        # the first partial line is discarded so an older JSONL record is
        # never mistaken for a complete one.
        try:
            with source.open("rb") as handle:
                handle.seek(-_MAX_MONITOR_TAIL_BYTES, os.SEEK_END)
                tail = handle.read(_MAX_MONITOR_TAIL_BYTES)
            text = tail.decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise ValueError(f"{path} monitor tail cannot be read") from exc
        first_newline = text.find("\n")
        if first_newline < 0:
            raise ValueError(f"{path} monitor record is too large")
        text = text[first_newline + 1 :]
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = None
    if isinstance(value, dict):
        return value
    if value is not None:
        raise ValueError(f"{path} must contain a JSON object or JSONL records")
    for line in reversed(text.splitlines()):
        if not line.strip():
            continue
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path} has a malformed trailing monitor record") from exc
        if not isinstance(candidate, dict):
            raise ValueError(f"{path} monitor record must be a JSON object")
        return candidate
    raise ValueError(f"{path} does not contain a monitor record")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--mission")
    parser.add_argument("--governor")
    parser.add_argument("--history")
    parser.add_argument("--replan")
    parser.add_argument("--monitor", help="one monitor JSON object or an append-only JSONL file")
    parser.add_argument("--placement", help="capability and route evidence JSON")
    parser.add_argument("--output", default="-")
    args = parser.parse_args(argv)
    try:
        report = build_cockpit(
            _load(args.snapshot),
            mission=_load(args.mission),
            governor=_load(args.governor),
            history=_load(args.history),
            replan=_load(args.replan),
            monitor=_load_monitor(args.monitor) if args.monitor else None,
            placement=_load(args.placement),
        )
        text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.output == "-":
            print(text, end="")
        else:
            target = pathlib.Path(args.output).expanduser().resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(f".{target.name}.tmp")
            temporary.write_text(text, encoding="utf-8")
            temporary.replace(target)
        return 0
    except Exception as exc:
        print(json.dumps({"schema_version": SCHEMA_VERSION, "ok": False, "error": f"{type(exc).__name__}: {exc}"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
