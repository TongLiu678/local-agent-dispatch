#!/usr/bin/env python3
"""Parse bounded, read-only Torque/PBS scheduler health output.

The central cluster exposes its Torque clients outside ``PATH`` and has
occasionally returned contradictory node resource fields.  This module keeps
the scheduler command output at the controller boundary: it extracts only
small, allow-listed fields and never stores queue rows, host status strings,
job ids, or command output verbatim.

The parser is intentionally not a scheduler client.  A caller must collect
the output with its own fixed, bounded command and pass the result here.  A
``verified`` report means that the supplied queue/node evidence is internally
consistent; it is not a claim that a future PBS submission will succeed.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any


SCHEMA_VERSION = 1
SOURCE = "pbs_scheduler_health.bounded_output_parser"
_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_STATE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
_MEMORY_KEYS = ("totmem", "availmem", "physmem")
_MEMINFO_KEYS = (
    "MemTotal",
    "MemFree",
    "MemAvailable",
    "Buffers",
    "Cached",
    "SReclaimable",
    "SwapTotal",
    "SwapFree",
)
_DEFAULT_RECEIPT_MAX_AGE_SECONDS = 900
_DEFAULT_CLOCK_SKEW_SECONDS = 60


def _validate_name(value: str, label: str) -> str:
    if not isinstance(value, str) or not _NAME_RE.fullmatch(value):
        raise ValueError(f"{label} is invalid")
    return value


def _nonnegative_int(value: str) -> int | None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+", value.strip()):
        return None
    try:
        parsed = int(value.strip())
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def parse_qstat_queue(text: str, *, queue_name: str = "workq") -> dict[str, Any]:
    """Parse one ``qstat -Q`` row without retaining unbounded output."""

    queue_name = _validate_name(queue_name, "queue_name")
    if not isinstance(text, str):
        raise ValueError("queue output must be text")
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0] != queue_name:
            continue
        # Torque's qstat -Q columns are Queue, Max, Tot, Ena, Str, Que, Run,
        # Hld, Wat, Trn, Ext, T.  Reject a short or malformed row rather than
        # filling absent values with zero and accidentally admitting work.
        if len(fields) < 12:
            return {"present": False, "name": queue_name, "reason": "malformed_queue_row"}
        numeric_indexes = (1, 2, 5, 6, 7, 8, 9, 10)
        numbers = [_nonnegative_int(fields[index]) for index in numeric_indexes]
        if any(value is None for value in numbers) or fields[3] not in {"yes", "no"} or fields[4] not in {"yes", "no"}:
            return {"present": False, "name": queue_name, "reason": "malformed_queue_row"}
        return {
            "present": True,
            "name": queue_name,
            "enabled": fields[3] == "yes",
            "started": fields[4] == "yes",
            "max_jobs": numbers[0],
            "total_jobs": numbers[1],
            "queued_jobs": numbers[2],
            "running_jobs": numbers[3],
            "held_jobs": numbers[4],
            "waiting_jobs": numbers[5],
            "transiting_jobs": numbers[6],
            "external_jobs": numbers[7],
        }
    return {"present": False, "name": queue_name, "reason": "queue_not_found"}


def _status_fields(value: str) -> dict[str, str]:
    """Extract only the finite node status keys needed for health checks."""

    wanted = set(_MEMORY_KEYS) | {"ncpus", "loadave", "state"}
    fields: dict[str, str] = {}
    for token in value.split(","):
        key, separator, item = token.partition("=")
        if separator and key in wanted and item and len(item) <= 128:
            fields[key] = item.strip()
    return fields


def parse_linux_meminfo(text: str) -> dict[str, int]:
    """Parse a bounded subset of Linux ``/proc/meminfo`` into bytes.

    Older kernels do not expose ``MemAvailable``.  The caller may therefore
    use the reclaimable/free fields as a diagnostic lower bound, but this
    parser never treats that estimate as a scheduler guarantee.
    """

    if not isinstance(text, str):
        raise ValueError("meminfo output must be text")
    parsed: dict[str, int] = {}
    for raw in text.splitlines():
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9_]*):\s*([0-9]+)\s*kB", raw.strip())
        if not match or match.group(1) not in _MEMINFO_KEYS:
            continue
        value = _nonnegative_int(match.group(2))
        if value is not None:
            parsed[match.group(1)] = value * 1024
    return parsed


def diagnose_memory_report(node: Mapping[str, Any], meminfo_text: str | None) -> dict[str, Any]:
    """Compare Torque memory fields with node-local ``/proc/meminfo``.

    Torque documentation defines ``physmem``/``availmem`` as real RAM and
    ``totmem`` as virtual memory/swap.  Some legacy MOM builds instead report
    ``availmem`` using a free-virtual-memory calculation.  Detect that pattern
    explicitly so operators can repair the MOM or choose a separately
    evidenced policy; never silently promote it to memory admission.
    """

    if meminfo_text is None:
        return {"present": False, "reason": "meminfo_not_provided"}
    meminfo = parse_linux_meminfo(meminfo_text)
    pbs_memory = dict(node.get("memory_bytes") or {})
    if not meminfo or not pbs_memory:
        return {"present": False, "reason": "memory_fields_missing", "meminfo_fields": sorted(meminfo)}

    def close(actual: int | None, expected: int | None, tolerance: float = 0.02) -> bool | None:
        if actual is None or expected is None or expected <= 0:
            return None
        return abs(actual - expected) <= max(4 * 1024 * 1024, int(expected * tolerance))

    mem_total = meminfo.get("MemTotal")
    swap_total = meminfo.get("SwapTotal")
    avail_virtual = None
    if meminfo.get("MemAvailable") is not None:
        avail_virtual = meminfo["MemAvailable"] + (meminfo.get("SwapFree") or 0)
    else:
        avail_virtual = sum(
            meminfo.get(key, 0)
            for key in ("MemFree", "Buffers", "Cached", "SReclaimable", "SwapFree")
        )
    physmem_matches = close(pbs_memory.get("physmem"), mem_total)
    totmem_matches_virtual = close(
        pbs_memory.get("totmem"),
        (mem_total + swap_total) if mem_total is not None and swap_total is not None else None,
    )
    availmem_matches_virtual = close(pbs_memory.get("availmem"), avail_virtual)
    if (
        pbs_memory.get("availmem") is not None
        and pbs_memory.get("physmem") is not None
        and pbs_memory["availmem"] > pbs_memory["physmem"]
        and totmem_matches_virtual is True
        and availmem_matches_virtual is True
    ):
        semantics = "virtual_availmem_includes_swap"
    elif pbs_memory.get("availmem", 0) <= pbs_memory.get("physmem", 0):
        semantics = "real_memory_or_unknown"
    else:
        semantics = "inconsistent"
    return {
        "present": True,
        "semantics": semantics,
        "physmem_matches_memtotal": physmem_matches,
        "totmem_matches_memtotal_plus_swaptotal": totmem_matches_virtual,
        "availmem_matches_free_virtual_estimate": availmem_matches_virtual,
        "meminfo_fields": sorted(meminfo),
        "memtotal_bytes": mem_total,
        "swaptotal_bytes": swap_total,
        "free_virtual_estimate_bytes": avail_virtual,
        "memory_admission_waiver": False,
    }


def parse_pbs_node(text: str, *, node_name: str = "compute-01") -> dict[str, Any]:
    """Parse one ``pbsnodes -a NODE`` response into bounded evidence."""

    node_name = _validate_name(node_name, "node_name")
    if not isinstance(text, str):
        raise ValueError("node output must be text")

    in_node = False
    direct: dict[str, str] = {}
    status: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line == node_name:
            in_node = True
            continue
        if not in_node or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key in {"state", "np", "jobs"}:
            direct[key] = value[:4096]
        elif key == "status":
            status.update(_status_fields(value))

    if not in_node:
        return {"present": False, "name": node_name, "reason": "node_not_found"}

    state = direct.get("state") or status.get("state")
    if not isinstance(state, str) or not _STATE_RE.fullmatch(state):
        state = None
    np_value = _nonnegative_int(direct.get("np", ""))
    ncpus = _nonnegative_int(status.get("ncpus", ""))

    # The top-level jobs field is reduced to a count.  Job ids are neither
    # needed for admission nor safe to persist in a generic health snapshot.
    assigned_job_count = 0
    jobs_value = direct.get("jobs", "")
    if jobs_value:
        assigned_job_count = sum(1 for item in jobs_value.split(",") if "/" in item and item.strip())

    memory_bytes: dict[str, int] = {}
    for key in _MEMORY_KEYS:
        value = status.get(key, "")
        match = re.fullmatch(r"([0-9]+)(?:kb|KB)", value)
        if match:
            parsed = _nonnegative_int(match.group(1))
            if parsed is not None:
                memory_bytes[key] = parsed * 1024

    physmem = memory_bytes.get("physmem")
    availmem = memory_bytes.get("availmem")
    memory_consistent: bool | None = None
    if physmem is not None and availmem is not None:
        memory_consistent = availmem <= physmem

    state_jobs_consistent: bool | None = None
    if state is not None:
        # In Torque, ``free`` means that the node is ready to accept
        # additional work; it does not mean that every virtual processor is
        # idle.  A partially allocated node can therefore report
        # ``state=free`` together with a non-empty jobs list.  Treating that
        # combination as contradictory blocks healthy shared-node queues.
        state_jobs_consistent = True

    report: dict[str, Any] = {
        "present": True,
        "name": node_name,
        "state": state,
        "np": np_value,
        "ncpus": ncpus,
        "assigned_job_count": assigned_job_count,
        "memory_metadata_consistent": memory_consistent,
        "state_jobs_consistent": state_jobs_consistent,
    }
    if memory_bytes:
        report["memory_bytes"] = memory_bytes
    return report


def scheduler_health_from_outputs(
    queue_text: str,
    node_text: str,
    *,
    queue_name: str = "workq",
    node_name: str = "compute-01",
    meminfo_text: str | None = None,
) -> dict[str, Any]:
    """Assess queue/node evidence with a fail-closed admission result."""

    queue = parse_qstat_queue(queue_text, queue_name=queue_name)
    node = parse_pbs_node(node_text, node_name=node_name)
    memory_diagnostic = diagnose_memory_report(node, meminfo_text)
    issues: list[str] = []

    if not queue.get("present"):
        issues.append(str(queue.get("reason") or "queue_unknown"))
    else:
        if not queue.get("enabled"):
            issues.append("queue_disabled")
        if not queue.get("started"):
            issues.append("queue_stopped")

    if not node.get("present"):
        issues.append(str(node.get("reason") or "node_unknown"))
    else:
        if node.get("memory_metadata_consistent") is False:
            issues.append("availmem_exceeds_physmem")
        if node.get("state_jobs_consistent") is False:
            issues.append("node_free_with_assigned_jobs")
        if node.get("state") is None or node.get("np") is None:
            issues.append("node_fields_missing")

    hard_queue_block = any(issue in {"queue_disabled", "queue_stopped"} for issue in issues)
    contradiction = any(
        issue in {"availmem_exceeds_physmem", "node_free_with_assigned_jobs"} for issue in issues
    )
    missing = any(issue.endswith("_not_found") or issue.endswith("_unknown") or issue == "node_fields_missing" for issue in issues)
    if hard_queue_block:
        status = "blocked"
    elif contradiction:
        status = "degraded"
    elif missing:
        status = "unknown"
    else:
        status = "verified"

    return {
        "schema_version": SCHEMA_VERSION,
        "source": SOURCE,
        "status": status,
        "admission_ready": status == "verified",
        "transport_ready": bool(
            queue.get("present")
            and queue.get("enabled")
            and queue.get("started")
            and node.get("present")
        ),
        # A scheduler row without node-local meminfo is not enough to promise
        # physical RAM.  Only the explicitly diagnosed real/unknown branch
        # (where availmem does not exceed physmem) may pass this gate; missing
        # or virtual-memory evidence remains fail-closed.
        "memory_admission_ready": (
            status == "verified"
            and memory_diagnostic.get("present") is True
            and memory_diagnostic.get("semantics") == "real_memory_or_unknown"
        ),
        "issues": sorted(set(issues)),
        "queue": queue,
        "node": node,
        "memory_diagnostic": memory_diagnostic,
    }


def _receipt_time(value: Any) -> dt.datetime | None:
    """Parse an RFC3339-ish UTC timestamp without accepting naive clocks."""

    if not isinstance(value, str) or len(value) > 80:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def validate_scheduler_health_receipt(
    receipt: Mapping[str, Any] | None,
    *,
    now_utc: dt.datetime | str | None = None,
    max_age_seconds: int = _DEFAULT_RECEIPT_MAX_AGE_SECONDS,
    clock_skew_seconds: int = _DEFAULT_CLOCK_SKEW_SECONDS,
    expected_queue: str = "workq",
    expected_node: str = "compute-01",
    expected_host: str | None = None,
) -> dict[str, Any]:
    """Validate a bounded scheduler-health receipt before a PBS side effect.

    ``scheduler_health_from_outputs`` intentionally accepts only command
    output and does not know whether that evidence is fresh.  This second
    gate is the controller boundary: it checks receipt freshness, queue/node
    binding, and the physical-memory admission bit.  It returns a redacted
    decision and never copies raw scheduler status or job ids into the result.
    A degraded or stale receipt is a hard block; callers must not turn this
    into an override without a separately reviewed policy.
    """

    reasons: list[str] = []
    try:
        max_age = int(max_age_seconds)
        skew = int(clock_skew_seconds)
    except (TypeError, ValueError):
        max_age, skew = -1, -1
    if max_age < 1 or max_age > 86_400:
        reasons.append("scheduler_health_max_age_invalid")
    if skew < 0 or skew > 3_600:
        reasons.append("scheduler_health_clock_skew_invalid")

    if not isinstance(expected_queue, str) or not _NAME_RE.fullmatch(expected_queue):
        reasons.append("scheduler_health_expected_queue_invalid")
    if not isinstance(expected_node, str) or not _NAME_RE.fullmatch(expected_node):
        reasons.append("scheduler_health_expected_node_invalid")
    if expected_host is not None and (
        not isinstance(expected_host, str) or not _NAME_RE.fullmatch(expected_host)
    ):
        reasons.append("scheduler_health_expected_host_invalid")

    if not isinstance(receipt, Mapping):
        reasons.append("scheduler_health_missing")
        receipt_obj: Mapping[str, Any] = {}
    else:
        receipt_obj = receipt

    if receipt_obj.get("schema_version") != SCHEMA_VERSION:
        reasons.append("scheduler_health_schema_unsupported")
    kind = receipt_obj.get("kind")
    if not isinstance(kind, str) or not _NAME_RE.fullmatch(kind):
        reasons.append("scheduler_health_kind_invalid")

    observed = _receipt_time(receipt_obj.get("observed_at"))
    if observed is None:
        reasons.append("scheduler_health_observed_at_invalid")
    if isinstance(now_utc, str):
        current = _receipt_time(now_utc)
    elif isinstance(now_utc, dt.datetime):
        current = now_utc.astimezone(dt.timezone.utc) if now_utc.tzinfo else None
    elif now_utc is None:
        current = dt.datetime.now(dt.timezone.utc)
    else:
        current = None
    if current is None:
        reasons.append("scheduler_health_now_invalid")
    age_seconds: float | None = None
    if observed is not None and current is not None and max_age >= 1 and skew >= 0:
        age_seconds = (current - observed).total_seconds()
        if age_seconds < -float(skew):
            reasons.append("scheduler_health_future")
        elif age_seconds > float(max_age):
            reasons.append("scheduler_health_stale")

    report = receipt_obj.get("report")
    if not isinstance(report, Mapping):
        reasons.append("scheduler_health_report_missing")
        report_obj: Mapping[str, Any] = {}
    else:
        report_obj = report

    if report_obj.get("status") != "verified":
        reasons.append("scheduler_health_status_not_verified")
    for key in ("transport_ready", "admission_ready", "memory_admission_ready"):
        if report_obj.get(key) is not True:
            reasons.append(f"scheduler_health_{key}_false")
    issues = report_obj.get("issues")
    if not isinstance(issues, list) or any(not isinstance(item, str) for item in issues):
        reasons.append("scheduler_health_issues_invalid")
    elif issues:
        reasons.append("scheduler_health_issues_present")

    queue = report_obj.get("queue")
    if not isinstance(queue, Mapping) or queue.get("name") != expected_queue:
        reasons.append("scheduler_health_queue_mismatch")
    node = report_obj.get("node")
    if not isinstance(node, Mapping) or node.get("name") != expected_node:
        reasons.append("scheduler_health_node_mismatch")
    if expected_host is not None and receipt_obj.get("resource_host") != expected_host:
        reasons.append("scheduler_health_host_mismatch")

    safe_summary = {
        "schema_version": SCHEMA_VERSION,
        "kind": kind if isinstance(kind, str) else None,
        "observed_at": receipt_obj.get("observed_at") if observed is not None else None,
        "age_seconds": round(age_seconds, 3) if age_seconds is not None else None,
        "queue": expected_queue,
        "node": expected_node,
        "host": expected_host,
        "status": report_obj.get("status") if isinstance(report_obj.get("status"), str) else None,
        "transport_ready": report_obj.get("transport_ready") is True,
        "admission_ready": report_obj.get("admission_ready") is True,
        "memory_admission_ready": report_obj.get("memory_admission_ready") is True,
    }
    digest = hashlib.sha256(
        json.dumps(safe_summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    unique_reasons = sorted(set(reasons))
    return {
        "valid": not unique_reasons,
        "decision": "admit" if not unique_reasons else "block",
        "reason": "scheduler_health_verified" if not unique_reasons else unique_reasons[0],
        "reasons": unique_reasons,
        "evidence_digest": digest,
        "summary": safe_summary,
    }


__all__ = [
    "SCHEMA_VERSION",
    "SOURCE",
    "diagnose_memory_report",
    "parse_linux_meminfo",
    "parse_pbs_node",
    "parse_qstat_queue",
    "validate_scheduler_health_receipt",
    "scheduler_health_from_outputs",
]
